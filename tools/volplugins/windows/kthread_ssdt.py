# Sudo-Z Volatility 3 plugin: per-thread service table check.
#
# Every thread's _KTHREAD.ServiceTable says which system service descriptor
# table its syscalls are dispatched through. Normally that is
# nt!KeServiceDescriptorTable (or ...Shadow for GUI threads). A rootkit can
# leave the global SSDT untouched, so windows.ssdt looks clean, and instead
# point chosen threads at a private copy with hooked entries. This plugin
# walks every thread (process thread lists, so DKOM-unlinked threads are also
# picked up via thread pool scanning when available) and reports any thread
# whose ServiceTable is not one of the kernel's own tables, plus the module
# that owns the table and how many of its entries point outside the kernel.
#
# On kernels whose _KTHREAD has no ServiceTable member (x64 and newer builds
# dispatch from the global tables only) it says so in a single row.
#
# usage: vol -p <sudo-z>/tools/volplugins -f mem.raw windows.kthread_ssdt

import logging
from typing import Iterable, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

try:  # pool scanning finds threads unlinked from their process (DKOM)
    from volatility3.plugins.windows import thrdscan as _thrdscan
except Exception:  # pragma: no cover
    _thrdscan = None

vollog = logging.getLogger(__name__)

KERNEL_NAMES = ("ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe", "win32k.sys", "win32kfull.sys", "win32kbase.sys")


class KThreadSSDT(interfaces.plugins.PluginInterface):
    """Finds threads whose KTHREAD.ServiceTable points at a service table other than the kernel's own (per-thread SSDT hooking)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
        ]

    # ------------------------------------------------------------- helpers that do not depend on other plugins' versions
    def _kernel(self):
        return self.context.modules[self.config["kernel"]]

    def _sym_addr(self, name: str) -> Optional[int]:
        k = self._kernel()
        try:
            return k.get_absolute_symbol_address(name)
        except Exception:
            try:
                return k.offset + k.get_symbol(name).address
            except Exception:
                return None

    def _modules(self) -> List[Tuple[int, int, str]]:
        k = self._kernel(); st = k.symbol_table_name; out = []
        head_addr = self._sym_addr("PsLoadedModuleList")
        if head_addr is None:
            return out
        try:
            head = self.context.object(st + constants.BANG + "_LIST_ENTRY", layer_name=k.layer_name, offset=head_addr)
            for mod in head.to_list(st + constants.BANG + "_KLDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"):
                try:
                    name = mod.BaseDllName.get_string()
                except Exception:
                    name = "?"
                out.append((int(mod.DllBase), int(mod.SizeOfImage), name))
        except exceptions.InvalidAddressException:
            pass
        return out

    @staticmethod
    def _owner(mods, addr: int) -> str:
        for base, size, name in mods:
            if base <= addr < base + size:
                return name
        return "UNKNOWN"

    def _processes(self) -> Iterable:
        k = self._kernel(); st = k.symbol_table_name
        head_addr = self._sym_addr("PsActiveProcessHead")
        head = self.context.object(st + constants.BANG + "_LIST_ENTRY", layer_name=k.layer_name, offset=head_addr)
        seen = set()
        for proc in head.to_list(st + constants.BANG + "_EPROCESS", "ActiveProcessLinks"):
            if proc.vol.offset in seen:
                break
            seen.add(proc.vol.offset)
            yield proc

    def _threads(self, proc) -> Iterable:
        st = self._kernel().symbol_table_name
        try:
            yield from proc.ThreadListHead.to_list(st + constants.BANG + "_ETHREAD", "ThreadListEntry")
        except exceptions.InvalidAddressException:
            return

    def _table_entries_outside(self, table_addr: int, mods) -> Tuple[int, int]:
        """Read a _KSERVICE_TABLE_DESCRIPTOR by hand (Base, Count, Limit) and count service
        entries of its first table that point outside the kernel images."""
        k = self._kernel()
        layer = self.context.layers[k.layer_name]
        is64 = symbols.symbol_table_is_64bit(context=self.context, symbol_table_name=k.symbol_table_name)
        ps = 8 if is64 else 4
        try:
            base = int.from_bytes(layer.read(table_addr, ps), "little")
            limit = int.from_bytes(layer.read(table_addr + 2 * ps, 4), "little")
        except exceptions.InvalidAddressException:
            return (0, 0)
        if not 0 < limit < 4096:
            return (0, 0)
        bad = 0
        for i in range(limit):
            try:
                if is64:  # x64 tables hold signed 32-bit offsets (<< 4) from the table base
                    raw = int.from_bytes(layer.read(base + i * 4, 4), "little", signed=True)
                    target = base + (raw >> 4)
                else:
                    target = int.from_bytes(layer.read(base + i * 4, 4), "little")
            except exceptions.InvalidAddressException:
                continue
            if self._owner(mods, target).lower() not in KERNEL_NAMES:
                bad += 1
        return (limit, bad)

    def _all_threads(self):
        """(pid, process name, thread, found_in_list) for every thread in process lists and in pool scans."""
        seen = set()
        for proc in self._processes():
            try:
                pid = int(proc.UniqueProcessId)
                pname = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
            except exceptions.InvalidAddressException:
                continue
            for th in self._threads(proc):
                seen.add(th.vol.offset)
                yield pid, pname, th, True
        if _thrdscan is None:
            return
        try:
            for th in _thrdscan.ThrdScan.scan_threads(self.context, self.config["kernel"]):
                if th.vol.offset in seen:
                    continue
                try:
                    pid = int(th.Cid.UniqueProcess)
                    try:
                        owner = th.owning_process()
                        pname = owner.ImageFileName.cast("string", max_length=owner.ImageFileName.vol.count, errors="replace")
                    except Exception:
                        pname = "?"
                    if th.ExitTime.QuadPart:
                        continue
                except (exceptions.InvalidAddressException, AttributeError):
                    continue
                yield pid, pname, th, False
        except Exception as e:  # scanning is best effort
            vollog.info(f"thread pool scan unavailable: {e}")

    # ------------------------------------------------------------- output
    def _generator(self):
        k = self._kernel(); st = k.symbol_table_name
        if not self.context.symbol_space.get_type(st + constants.BANG + "_KTHREAD").has_member("ServiceTable"):
            yield (0, (0, "", 0, format_hints.Hex(0), "N/A", "N/A", 0, 0, "This kernel's _KTHREAD has no ServiceTable member: per-thread SSDT redirection is not possible here; use windows.ssdt for global hooks."))
            return
        sdt = self._sym_addr("KeServiceDescriptorTable")
        shadow = self._sym_addr("KeServiceDescriptorTableShadow")
        good = {a for a in (sdt, shadow) if a}
        mods = self._modules()
        checked: dict = {}
        for pid, pname, th, listed in self._all_threads():
            try:
                tid = int(th.Cid.UniqueThread)
                table = int(th.Tcb.ServiceTable)
            except exceptions.InvalidAddressException:
                continue
            if not table or table in good:
                continue
            if table not in checked:
                checked[table] = self._table_entries_outside(table, mods)
            limit, bad = checked[table]
            note = "differs from KeServiceDescriptorTable and ...Shadow" + ("" if listed else "; thread is missing from its process thread list (found by pool scan)")
            yield (0, (pid, pname, tid, format_hints.Hex(table), self._owner(mods, table), ", ".join(hex(a) for a in sorted(good)) or "?", limit, bad, note))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("TID", int), ("ServiceTable", format_hints.Hex), ("Table owner", str), ("Expected", str), ("Entries", int), ("Hooked entries", int), ("Note", str)],
            self._generator(),
        )
