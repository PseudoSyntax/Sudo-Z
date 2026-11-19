# Sudo-Z Volatility 3 plugin: user mode API hooks (inline and IAT).
#
# Volatility 2 had "apihooks"; Volatility 3 never ported it. Volatility 3 can
# see ntdll syscall stub tampering (unhooked_system_calls and the direct /
# indirect syscall plugins), but nothing in it looks at ordinary exported
# functions. That is where EDR, injected DLLs and user mode rootkits all live:
# the first instruction of a function such as kernel32!CreateProcessW is
# replaced with a jump into someone else's code.
#
# Two kinds of hook are reported.
#
#   inline  the function's own prologue was overwritten with an unconditional
#           transfer (jmp rel, jmp [mem], push/ret, mov reg + jmp reg) whose
#           destination is outside the module that exports it.
#   iat     an Import Address Table entry points somewhere other than the
#           module that is supposed to export the function.
#
# A destination that belongs to no loaded module at all is the serious case:
# that is private, usually injected memory. A destination inside another
# loaded module is normal for EDR and application compatibility shims, so it
# is reported separately and left for the analyst to confirm.
#
# Forwarded exports are skipped, because a forwarder legitimately points into
# another DLL. Microsoft's hot patch prologue (mov edi,edi) is not a hook.
#
# usage: vol -p <sudo-z>/tools/volplugins -f mem.raw windows.apihooks
#        ... windows.apihooks --all-modules      every loaded DLL, not just the common targets
#        ... windows.apihooks --pid 1234

import io
import logging
from typing import Dict, Iterator, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist

try:
    import pefile
    HAS_PEFILE = True
except ImportError:  # pragma: no cover
    HAS_PEFILE = False

vollog = logging.getLogger(__name__)

# the modules whose exports attackers and EDR hook; --all-modules covers the rest
COMMON_TARGETS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "user32.dll", "gdi32.dll",
    "ws2_32.dll", "wininet.dll", "winhttp.dll", "urlmon.dll", "crypt32.dll", "secur32.dll",
    "shell32.dll", "ole32.dll", "oleaut32.dll", "msvcrt.dll", "psapi.dll", "wsock32.dll",
    "dnsapi.dll", "mswsock.dll", "iphlpapi.dll", "amsi.dll", "bcrypt.dll", "ncrypt.dll",
    "sspicli.dll", "samlib.dll", "netapi32.dll", "wldap32.dll", "mpr.dll", "wtsapi32.dll",
}
# an api set name is a forwarder by design; its import never resolves to itself
API_SET = ("api-ms-win-", "ext-ms-win-")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little", signed=False)


def _s32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little", signed=True)


def classify_prologue(code: bytes, addr: int, is_64: bool) -> Optional[Tuple[str, int]]:
    """Returns (how, destination) when the first instruction is an unconditional transfer."""
    if len(code) < 6:
        return None
    b = code
    # E9 rel32: jmp near
    if b[0] == 0xE9:
        return "jmp rel32", (addr + 5 + _s32(b, 1)) & (0xFFFFFFFFFFFFFFFF if is_64 else 0xFFFFFFFF)
    # EB rel8: jmp short (a hook trampoline usually jumps far, but a short jump into a nearby stub happens)
    if b[0] == 0xEB:
        rel = b[1] - 256 if b[1] > 127 else b[1]
        return "jmp rel8", (addr + 2 + rel) & (0xFFFFFFFFFFFFFFFF if is_64 else 0xFFFFFFFF)
    # FF 25: jmp [mem]; x64 is RIP relative, x86 absolute. The pointer itself has to be read later.
    if b[0] == 0xFF and b[1] == 0x25:
        target = (addr + 6 + _s32(b, 2)) if is_64 else _u32(b, 2)
        return ("jmp [rip+disp]" if is_64 else "jmp [addr]"), target
    # 68 imm32 C3: push imm32 / ret
    if b[0] == 0x68 and len(b) >= 6 and b[5] == 0xC3:
        return "push/ret", _u32(b, 1)
    # 48 B8 imm64 FF E0: mov rax, imm64 / jmp rax (any register via the +rb encoding)
    if is_64 and b[0] in (0x48, 0x49) and 0xB8 <= b[1] <= 0xBF and len(b) >= 12 and b[10] == 0xFF and 0xE0 <= b[11] <= 0xE7:
        return "mov reg,imm64 + jmp reg", int.from_bytes(b[2:10], "little")
    # B8 imm32 FF E0: mov eax, imm32 / jmp eax
    if not is_64 and 0xB8 <= b[0] <= 0xBF and len(b) >= 7 and b[5] == 0xFF and 0xE0 <= b[6] <= 0xE7:
        return "mov reg,imm32 + jmp reg", _u32(b, 1)
    return None


class ApiHooks(interfaces.plugins.PluginInterface):
    """Finds inline and IAT hooks on exported functions in user mode processes."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.ListRequirement(name="pid", description="Process IDs to include (all other processes are excluded)", element_type=int, optional=True),
            requirements.BooleanRequirement(name="all-modules", description="Check every loaded module, not only the commonly hooked ones", default=False, optional=True),
            requirements.BooleanRequirement(name="skip-iat", description="Only check for inline hooks", default=False, optional=True),
        ]

    # ------------------------------------------------------------------ helpers
    def _modules(self, proc) -> List[Tuple[int, int, str]]:
        out = []
        for mod in proc.load_order_modules():
            try:
                name = mod.BaseDllName.get_string()
                base = int(mod.DllBase)
                size = int(mod.SizeOfImage)
            except (exceptions.InvalidAddressException, AttributeError, TypeError):
                continue
            if base and size:
                out.append((base, size, name))
        return out

    @staticmethod
    def _owner(mods: List[Tuple[int, int, str]], addr: int) -> Optional[str]:
        for base, size, name in mods:
            if base <= addr < base + size:
                return name
        return None

    def _pe(self, layer_name: str, base: int, pe_table_name: str, directories):
        dos = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER", offset=base, layer_name=layer_name)
        data = io.BytesIO()
        try:
            for offset, chunk in dos.reconstruct():
                data.seek(offset)
                data.write(chunk)
        except (exceptions.InvalidAddressException, ValueError) as e:
            vollog.debug(f"module at {base:#x} only partly readable: {e}")
        try:
            obj = pefile.PE(data=data.getvalue(), fast_load=True)
            obj.parse_data_directories(directories)
            return obj
        except Exception as e:
            vollog.debug(f"module at {base:#x} is not a readable PE: {e}")
            return None

    # ------------------------------------------------------------------ the checks
    def _inline(self, layer, mods, base, size, name, pe_obj, is_64) -> Iterator[Tuple]:
        if not hasattr(pe_obj, "DIRECTORY_ENTRY_EXPORT"):
            return
        for exp in pe_obj.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.forwarder:  # a forwarder points into another DLL on purpose
                continue
            if not exp.address:
                continue
            func = base + exp.address
            if not (base <= func < base + size):  # export outside its own image: already wrong
                yield ("inline", name, (exp.name or b"").decode(errors="replace") or f"ordinal {exp.ordinal}", func, func, "export outside its own image", self._owner(mods, func))
                continue
            try:
                code = layer.read(func, 16, pad=True)
            except exceptions.InvalidAddressException:
                continue
            hooked = classify_prologue(code, func, is_64)
            if not hooked:
                continue
            how, dest = hooked
            if how.startswith("jmp ["):  # the instruction jumps through a pointer; read it
                try:
                    raw = layer.read(dest, 8 if is_64 else 4, pad=True)
                    dest = int.from_bytes(raw, "little")
                except exceptions.InvalidAddressException:
                    pass
            if base <= dest < base + size:  # jumping inside itself is normal (thunks, /hotpatch)
                continue
            yield ("inline", name, (exp.name or b"").decode(errors="replace") or f"ordinal {exp.ordinal}", func, dest, how, self._owner(mods, dest))

    def _iat(self, mods, base, name, pe_obj) -> Iterator[Tuple]:
        if not hasattr(pe_obj, "DIRECTORY_ENTRY_IMPORT"):
            return
        by_name = {n.lower(): (b, s) for b, s, n in mods}
        for entry in pe_obj.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b"").decode(errors="replace").lower()
            if dll.startswith(API_SET):  # resolves to whatever the api set maps to
                expected = None
            else:
                expected = by_name.get(dll)
            for imp in entry.imports:
                dest = imp.address
                if not dest:
                    continue
                owner = self._owner(mods, dest)
                func = (imp.name or b"").decode(errors="replace") if imp.name else f"ordinal {imp.ordinal}"
                if owner is None:
                    yield ("iat", name, f"{dll}!{func}", imp.address_rva or 0, dest, "points outside every loaded module", None)
                elif expected and owner.lower() != dll:
                    yield ("iat", name, f"{dll}!{func}", imp.address_rva or 0, dest, f"should resolve into {dll}", owner)

    def _generator(self, procs):
        if not HAS_PEFILE:
            vollog.error("pefile is required: pip install pefile")
            return
        kernel = self.context.modules[self.config["kernel"]]
        is_64 = symbols.symbol_table_is_64bit(context=self.context, symbol_table_name=kernel.symbol_table_name)
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context, self.config_path, "windows", "pe", class_types=pe.class_types)
        want_all = bool(self.config.get("all-modules"))
        skip_iat = bool(self.config.get("skip-iat"))
        dirs = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        if not skip_iat:
            dirs.append(pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"])

        for proc in procs:
            try:
                pid = int(proc.UniqueProcessId)
                pname = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
                layer_name = proc.add_process_layer()
            except (exceptions.InvalidAddressException, TypeError, AttributeError):
                continue
            if layer_name is None:
                continue
            layer = self.context.layers[layer_name]
            try:
                mods = self._modules(proc)
            except exceptions.InvalidAddressException:
                continue
            wow64 = False
            try:
                wow64 = bool(proc.get_is_wow64())
            except Exception:
                pass
            for base, size, mname in mods:
                if not want_all and mname.lower() not in COMMON_TARGETS:
                    continue
                pe_obj = self._pe(layer_name, base, pe_table_name, dirs)
                if pe_obj is None:
                    continue
                checks = list(self._inline(layer, mods, base, size, mname, pe_obj, is_64 and not wow64))
                if not skip_iat:
                    checks += list(self._iat(mods, base, mname, pe_obj))
                for kind, modname, func, where, dest, how, owner in checks:
                    yield (0, (pid, str(pname), modname, func, kind, format_hints.Hex(where), format_hints.Hex(dest),
                               owner or "unknown memory (not in any loaded module)", how))

    def run(self) -> renderers.TreeGrid:
        filt = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Module", str), ("Function", str), ("Type", str),
             ("Hooked at", format_hints.Hex), ("Destination", format_hints.Hex), ("Destination owner", str), ("How", str)],
            self._generator(pslist.PsList.list_processes(context=self.context, kernel_module_name=self.config["kernel"], filter_func=filt)),
        )
