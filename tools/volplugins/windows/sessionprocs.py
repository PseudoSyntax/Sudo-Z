# Sudo-Z Volatility 3 plugin: processes reached through session spaces.
#
# Volatility 2's psxview had a "session" column. Volatility 3's psxview dropped
# it because its own windows.sessions plugin starts from pslist, so it adds no
# independent view. This plugin builds the view the way the old one did: it
# collects every _MM_SESSION_SPACE it can reach, starting from pool-scanned
# processes rather than the active process list, then walks each session's
# ProcessList. A process unlinked from ActiveProcessLinks (DKOM) is normally
# still on its session's list.
#
# Processes that start before the first session exists (System, smss.exe) have
# no session and are absent here for good reason; that is handled in Sudo-Z's
# cross-view rules, not by hiding them.
#
# usage: vol -p <sudo-z>/tools/volplugins -f mem.raw windows.sessionprocs

import datetime
import logging
from typing import List

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, psscan

vollog = logging.getLogger(__name__)


class SessionProcs(interfaces.plugins.PluginInterface):
    """Lists processes found by walking each session space's process list (psxview 'session' view)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="pslist", component=pslist.PsList, version=(3, 0, 0)),
            requirements.VersionRequirement(name="psscan", component=psscan.PsScan, version=(2, 0, 0)),
        ]

    def _session_space(self, proc):
        kernel = self.context.modules[self.config["kernel"]]
        try:
            ptr = proc.Session
        except exceptions.InvalidAddressException:
            return None, None
        if not ptr:
            return None, None
        try:
            space = self.context.object(
                kernel.symbol_table_name + constants.BANG + "_MM_SESSION_SPACE",
                layer_name=kernel.layer_name,
                offset=ptr,
            )
            return space, int(space.SessionId)
        except exceptions.SymbolError:
            # Windows 11 24H2 renamed the type; the session id still sits at offset 8
            try:
                sid = self.context.object(
                    layer_name=kernel.layer_name,
                    object_type=kernel.symbol_table_name + constants.BANG + "unsigned long",
                    offset=ptr + 8,
                )
                return None, int(sid)
            except exceptions.InvalidAddressException:
                return None, None
        except exceptions.InvalidAddressException:
            return None, None

    def _generator(self):
        kernel_module_name = self.config["kernel"]
        # start from pool-scanned processes so an unlinked EPROCESS still leads us to its session
        sources = list(psscan.PsScan.scan_processes(context=self.context, kernel_module_name=kernel_module_name))
        try:
            sources += list(pslist.PsList.list_processes(context=self.context, kernel_module_name=kernel_module_name))
        except Exception as e:
            vollog.debug(f"pslist unavailable: {e}")

        spaces = {}
        for proc in sources:
            try:
                ptr = int(proc.Session or 0)
            except Exception:
                continue
            if not ptr or ptr in spaces:
                continue
            space, sid = self._session_space(proc)
            spaces[ptr] = (space, sid)

        if not spaces:
            vollog.info("No session spaces reachable in this image")

        seen = set()
        for ptr, (space, sid) in spaces.items():
            members = []
            if space is not None:
                eproc = self.context.modules[kernel_module_name].symbol_table_name + constants.BANG + "_EPROCESS"
                try:
                    members = list(space.ProcessList.to_list(eproc, "SessionProcessLinks"))
                except (exceptions.InvalidAddressException, AttributeError, exceptions.SymbolError) as e:
                    vollog.debug(f"session {sid} process list unreadable: {e}")
                    members = []
            for proc in members:
                try:
                    off = proc.vol.offset
                    if off in seen or not proc.is_valid():
                        continue
                    seen.add(off)
                    name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
                    exited = proc.get_exit_time()
                    created = proc.get_create_time()
                    yield (0, (format_hints.Hex(off), str(name), int(proc.UniqueProcessId),
                               sid if sid is not None else -1,
                               created if not isinstance(created, renderers.BaseAbsentValue) else renderers.NotApplicableValue(),
                               str(exited) if not isinstance(exited, renderers.BaseAbsentValue) else ""))
                except exceptions.InvalidAddressException:
                    continue

    def run(self):
        return renderers.TreeGrid(
            [("Offset(V)", format_hints.Hex), ("Name", str), ("PID", int), ("SessionId", int), ("CreateTime", datetime.datetime), ("ExitTime", str)],
            self._generator(),
        )
