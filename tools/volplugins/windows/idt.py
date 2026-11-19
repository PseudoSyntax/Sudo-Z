# Sudo-Z Volatility 3 plugin: Interrupt Descriptor Table.
#
# Volatility 2 had an "idt" plugin; Volatility 3 never ported it. The IDT maps
# each interrupt and exception vector to the routine that handles it. Those
# routines belong in the kernel (ntoskrnl / hal). A vector pointing anywhere
# else is an interrupt hook: the classic ones are int 0x2e (the legacy system
# call gate), int 1 and int 3 (debug and breakpoint, hooked by anti-debug and
# by hypervisor-assisted rootkits), and int 0x0e (page fault, hooked by
# Shadow Walker style memory hiding).
#
# One IDT exists per processor, so this reads every CPU's table: a rootkit that
# only hooks one core is a known evasion.
#
# On x64, PatchGuard protects the IDT and unsigned drivers cannot load, so hits
# are rarer but far more serious when they appear. On x86 this is still the
# first place to look for an interrupt-hooking rootkit.
#
# usage: vol -p <sudo-z>/tools/volplugins -f mem.raw windows.idt

import logging
from typing import Iterator, List, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import kpcrs, ssdt

vollog = logging.getLogger(__name__)

# vectors worth naming in the output; everything else is reported by number
KNOWN = {
    0x00: "divide error", 0x01: "debug / single step", 0x02: "NMI", 0x03: "breakpoint (int3)",
    0x04: "overflow", 0x05: "bound range", 0x06: "invalid opcode", 0x07: "device not available",
    0x08: "double fault", 0x0A: "invalid TSS", 0x0B: "segment not present", 0x0C: "stack fault",
    0x0D: "general protection", 0x0E: "page fault", 0x10: "x87 FPU error", 0x11: "alignment check",
    0x12: "machine check", 0x13: "SIMD FP exception", 0x14: "virtualization exception",
    0x1F: "APC interrupt", 0x2C: "assertion", 0x2D: "debug service", 0x2E: "legacy system call gate",
    0x2F: "DPC interrupt", 0xD1: "clock interrupt", 0xDF: "spurious interrupt", 0xE1: "IPI",
    0xE3: "deferred recovery", 0xFD: "profile interrupt", 0xFE: "performance interrupt",
}
KERNEL_MODULES = ("ntoskrnl", "ntkrnlmp", "ntkrnlpa", "ntkrpamp", "hal", "halmacpi", "halacpi", "halaacpi")


class IDT(interfaces.plugins.PluginInterface):
    """Lists each processor's Interrupt Descriptor Table and the module owning every handler (interrupt hooks)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Windows kernel", architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(name="kpcrs", component=kpcrs.KPCRs, version=(1, 0, 0)),
            requirements.VersionRequirement(name="ssdt", component=ssdt.SSDT, version=(2, 0, 0)),
            requirements.BooleanRequirement(name="all", description="Show every vector, not only the ones outside the kernel", default=False, optional=True),
        ]

    @staticmethod
    def _handler_address(entry, is_64: bool) -> int:
        """Rebuilds the handler address from the split offset fields of a gate descriptor."""
        try:
            if is_64:
                low = int(entry.OffsetLow); mid = int(entry.OffsetMiddle); high = int(entry.OffsetHigh)
                return (high << 32) | (mid << 16) | low
            # x86: _KIDTENTRY has Offset (low 16) and ExtendedOffset (high 16)
            return (int(entry.ExtendedOffset) << 16) | int(entry.Offset)
        except (AttributeError, exceptions.InvalidAddressException):
            return 0

    def _idt_base(self, kpcr, is_64: bool):
        """The IDT lives off the KPCR: IdtBase on x64, the IDT array on x86."""
        for member in ("IdtBase", "IDT", "Idt"):
            try:
                if kpcr.has_member(member):
                    return int(getattr(kpcr, member)), member
            except (AttributeError, exceptions.InvalidAddressException, TypeError):
                continue
        return 0, ""

    def _generator(self) -> Iterator[Tuple[int, Tuple]]:
        kernel = self.context.modules[self.config["kernel"]]
        is_64 = symbols.symbol_table_is_64bit(context=self.context, symbol_table_name=kernel.symbol_table_name)
        collection = ssdt.SSDT.build_module_collection(context=self.context, kernel_module_name=self.config["kernel"])
        entry_type = None
        for cand in ("_KIDTENTRY64", "_KIDTENTRY"):
            try:
                kernel.get_type(cand); entry_type = cand; break
            except Exception:
                continue
        if entry_type is None:
            vollog.warning("No IDT entry type in the symbol table for this kernel")
            return

        cpus = 0
        for kpcr, _prcb in kpcrs.KPCRs.list_kpcrs(context=self.context, kernel_module_name=self.config["kernel"]):
            base, member = self._idt_base(kpcr, is_64)
            if not base:
                continue
            cpus += 1
            try:
                table = kernel.object(object_type="array", offset=base, subtype=kernel.get_type(entry_type), count=256, absolute=True)
            except exceptions.InvalidAddressException:
                vollog.debug(f"IDT at {base:#x} unreadable")
                continue
            for idx, entry in enumerate(table):
                addr = self._handler_address(entry, entry_type.endswith("64"))
                if not addr:
                    continue
                owner = renderers.NotAvailableValue()
                symbol = renderers.NotAvailableValue()
                in_kernel = False
                for module_name, symbol_generator in collection.get_module_symbols_by_absolute_location(addr):
                    owner = module_name
                    in_kernel = module_name.lower() in KERNEL_MODULES
                    for sym in symbol_generator:
                        symbol = sym.split(constants.BANG)[-1]
                        break
                    break
                if in_kernel and not self.config.get("all"):
                    continue
                yield (0, (cpus - 1, format_hints.Hex(idx), KNOWN.get(idx, ""), format_hints.Hex(addr),
                           owner if not isinstance(owner, renderers.BaseAbsentValue) else renderers.NotAvailableValue(),
                           symbol,
                           "kernel" if in_kernel else ("unknown memory" if isinstance(owner, renderers.BaseAbsentValue) else "other module")))
        if not cpus:
            vollog.warning("No KPCR with a readable IDT was found in this image")

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("CPU", int), ("Vector", format_hints.Hex), ("Meaning", str), ("Handler", format_hints.Hex), ("Module", str), ("Symbol", str), ("Owner", str)],
            self._generator(),
        )
