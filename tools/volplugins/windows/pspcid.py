# Sudo-Z Volatility 3 plugin: PspCidTable process view.
#
# Volatility 2's psxview had a "pspcid" column. Volatility 3's psxview dropped
# it ("I could not for the life of me get it to work" in the upstream source),
# which leaves a real gap: PspCidTable is the kernel's own handle table of
# every process and thread object, indexed by PID/TID. The scheduler and
# ObOpenObjectByPointer rely on it, so a rootkit that unlinks an EPROCESS from
# ActiveProcessLinks usually leaves the PspCidTable entry in place. A process
# that is missing from pslist but present here is hidden by DKOM.
#
# usage: vol -p <sudo-z>/tools/volplugins -f mem.raw windows.pspcid

import logging
import datetime
from typing import Iterator, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import handles

vollog = logging.getLogger(__name__)


class PspCid(interfaces.plugins.PluginInterface):
    """Lists processes found in the kernel's PspCidTable (object table of every process and thread ID)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="handles", component=handles.Handles, version=(4, 0, 0)),
        ]

    @classmethod
    def list_pspcid_processes(cls, context: interfaces.context.ContextInterface, kernel_module_name: str) -> Iterator[Tuple[int, interfaces.objects.ObjectInterface]]:
        """Yields (offset, _EPROCESS) for every Process object in PspCidTable."""
        kernel = context.modules[kernel_module_name]
        try:
            addr = kernel.get_absolute_symbol_address("PspCidTable")
        except Exception as e:
            raise exceptions.SymbolError("PspCidTable", kernel.symbol_table_name, f"PspCidTable symbol not available: {e}")
        table_ptr = kernel.object(object_type="pointer", offset=addr, absolute=True)
        if not table_ptr:
            return
        table = kernel.object(object_type="_HANDLE_TABLE", offset=table_ptr, absolute=True)
        type_map = handles.Handles.get_type_map(context=context, kernel_module_name=kernel_module_name)
        cookie = handles.Handles.find_cookie(context=context, kernel_module_name=kernel_module_name)
        seen = set()
        for entry in handles.Handles.handles(context=context, kernel_module_name=kernel_module_name, handle_table=table):
            try:
                if entry.get_object_type(type_map, cookie) != "Process":
                    continue
                proc = entry.Body.cast("_EPROCESS")
                if not proc.is_valid():
                    continue
                off = proc.vol.offset
                if off in seen:
                    continue
                seen.add(off)
                yield off, proc
            except exceptions.InvalidAddressException:
                continue
            except AttributeError:
                continue

    def _generator(self):
        for off, proc in self.list_pspcid_processes(self.context, self.config["kernel"]):
            try:
                name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
            except exceptions.InvalidAddressException:
                name = renderers.UnreadableValue()
            try:
                pid = int(proc.UniqueProcessId)
            except Exception:
                continue
            try:
                ppid = int(proc.InheritedFromUniqueProcessId)
            except Exception:
                ppid = 0
            created = proc.get_create_time()
            exited = proc.get_exit_time()
            yield (0, (format_hints.Hex(off), str(name), pid, ppid,
                       created if not isinstance(created, renderers.BaseAbsentValue) else renderers.NotApplicableValue(),
                       str(exited) if not isinstance(exited, renderers.BaseAbsentValue) else ""))

    def run(self):
        return renderers.TreeGrid(
            [("Offset(V)", format_hints.Hex), ("Name", str), ("PID", int), ("PPID", int), ("CreateTime", datetime.datetime), ("ExitTime", str)],
            self._generator(),
        )
