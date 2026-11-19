// Kernel rootkit checks on Volatility 3 output: system call table hooks (global
// SSDT and per-thread KTHREAD.ServiceTable), DKOM (processes, threads and
// drivers unlinked from the kernel's lists but still found by pool scanning),
// kernel callbacks, IRP and timer routines in unknown memory, and kernel
// threads that do not belong to any driver.
import { classifyPath } from '../ioc/heuristics.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });
const KERNEL = /^(ntoskrnl|ntkrnlmp|ntkrnlpa|ntkrpamp|nt|win32k|win32kfull|win32kbase|hal)(\.exe|\.sys|\.dll)?$/i;
// drivers whose dispatch routines are commonly shared by other Microsoft drivers
const FRAMEWORK = /^(wdf01000|wdfldr|ndis|classpnp|storport|scsiport|ataport|portcls|ks|ksthunk|videoprt|dxgkrnl|watchdog|fltmgr|usbport|usbhub3?|ucx01000|hidclass|kbdclass|mouclass|netio|wudfrd|tdi|tdx|pci|acpi|volmgr|partmgr|disk|mountmgr|cng|ksecdd|ntfs|refs|fastfat|mup|rdbss|afd|tcpip|wmilib|serenum|npfs|msfs|fs_rec|spaceport|stornvme|storahci|wfplwfs|vmbus|vmbkmcl|hdaudbus|bthport|wmiacpi)$/i;
const hex = (v) => (typeof v === 'number' ? '0x' + v.toString(16) : String(v ?? ''));
const unknown = (m) => !m || /^(unknown|n\/a|-)$/i.test(String(m).trim());
const stem = (n) => String(n || '').toLowerCase().replace(/\.(sys|exe|dll)$/, '').split('\\').pop();

/** Per-file handlers. Returns true when the plugin was handled. */
export function rootkitPlugin(key, rows, note, tables, cols) {
  switch (key) {
    case 'ssdt': {
      const byMod = new Map(); const idx = new Set(); let max = -1;
      for (const r of rows) {
        idx.add(+r.Index); max = Math.max(max, +r.Index);
        const m = String(r.Module || '');
        if (!KERNEL.test(stem(m))) { if (!byMod.has(m)) byMod.set(m, []); byMod.get(m).push(r); }
      }
      for (const [m, list] of byMod) note('critical', `System call table hooked: ${list.length} entr${list.length > 1 ? 'ies' : 'y'} point into ${m || 'unknown memory'}`, 'Global SSDT entries must point into the kernel (ntoskrnl / win32k). Anything else intercepts system calls for every process: a kernel rootkit hiding files, processes or registry keys.', list.slice(0, 30).map((r) => `#${r.Index} ${hex(r.Address)} ${r.Module} ${r.Symbol || ''}`).join('\n'), ['T1014', 'T1562.001'], 'Defense Evasion');
      const missing = []; for (let i = 0; i <= max; i++) if (!idx.has(i)) missing.push(i);
      if (missing.length) note('critical', `${missing.length} system call table entr${missing.length > 1 ? 'ies' : 'y'} point outside every loaded module`, 'windows.ssdt prints nothing for an entry whose target is not inside any loaded module, so gaps in the index sequence are entries redirected into pool or hidden-driver memory.', `missing indexes: ${missing.slice(0, 80).join(', ')}`, ['T1014'], 'Defense Evasion');
      tables.push(T('System service descriptor table', ['Index', 'Address', 'Module', 'Symbol'], rows.map((r) => [r.Index, hex(r.Address), r.Module, r.Symbol]), `${rows.length} entries; kernel targets are expected.`));
      return true;
    }
    case 'kthread_ssdt': {
      const na = rows.filter((r) => /no ServiceTable member/i.test(r.Note || ''));
      const hits = rows.filter((r) => !na.includes(r));
      const byTable = new Map(); for (const r of hits) { const k = hex(r.ServiceTable); if (!byTable.has(k)) byTable.set(k, []); byTable.get(k).push(r); }
      for (const [t, list] of byTable) {
        const hidden = list.filter((r) => /missing from its process thread list/i.test(r.Note || ''));
        note('critical', `${list.length} thread(s) dispatch system calls through a private service table at ${t} (${list[0]['Table owner'] || 'unknown owner'})`, `KTHREAD.ServiceTable should point at KeServiceDescriptorTable or ...Shadow (${list[0].Expected}). A private copy lets a rootkit hook system calls for chosen threads only, so the global SSDT still looks clean.${list[0]['Hooked entries'] ? ` ${list[0]['Hooked entries']} of ${list[0].Entries} entries in that table point outside the kernel.` : ''}${hidden.length ? ` ${hidden.length} of these threads are also unlinked from their process (DKOM).` : ''}`, list.slice(0, 30).map((r) => `PID ${r.PID} ${r.Process} TID ${r.TID} table ${hex(r.ServiceTable)} owner ${r['Table owner']}${/missing/.test(r.Note) ? ' [hidden thread]' : ''}`).join('\n'), ['T1014', 'T1562.001', ...(hidden.length ? ['T1564'] : [])], 'Defense Evasion');
      }
      tables.push(T('Per-thread service tables (KTHREAD.ServiceTable)', ['PID', 'Process', 'TID', 'ServiceTable', 'Table owner', 'Expected', 'Entries', 'Hooked entries', 'Note'], rows.map((r) => [r.PID, r.Process, r.TID, hex(r.ServiceTable), r['Table owner'], r.Expected, r.Entries, r['Hooked entries'], r.Note]), na.length ? na[0].Note : `${hits.length} thread(s) with a non-standard service table. An empty table means every thread uses the kernel's own tables.`));
      return true;
    }
    case 'callbacks': {
      const bad = rows.filter((r) => unknown(r.Module));
      if (bad.length) note('critical', `${bad.length} kernel callback(s) registered from unknown memory`, 'Process/thread/image-load and registry callbacks let a driver watch or block activity. A callback outside every loaded module belongs to a hidden or unloaded-but-resident driver.', bad.slice(0, 30).map((r) => `${r.Type} ${hex(r.Callback)} ${r.Detail || ''}`).join('\n'), ['T1014', 'T1547.006'], 'Defense Evasion');
      tables.push(T('Kernel callbacks', ['Type', 'Callback', 'Module', 'Symbol', 'Detail'], rows.map((r) => [r.Type, hex(r.Callback), r.Module, r.Symbol, r.Detail]), 'Third-party modules here are normal for AV/EDR, VPN and backup software; confirm any you do not recognise.'));
      return true;
    }
    case 'driverirp': {
      const unk = []; const foreign = new Map();
      for (const r of rows) {
        const drv = stem(String(r['Driver Name'] || '').split('\\').pop()); const mod = stem(r.Module);
        if (unknown(r.Module)) { unk.push(r); continue; }
        if (KERNEL.test(mod) || FRAMEWORK.test(mod) || mod === drv || mod.startsWith(drv) || drv.startsWith(mod)) continue;
        const k = `${r['Driver Name']}|${mod}`; if (!foreign.has(k)) foreign.set(k, []); foreign.get(k).push(r);
      }
      if (unk.length) note('critical', `${unk.length} driver IRP handler(s) point into unknown memory`, 'An IRP dispatch routine outside every loaded module is an inline or table hook (classic for hiding files and network connections).', unk.slice(0, 30).map((r) => `${r['Driver Name']} ${r.IRP} -> ${hex(r.Address)}`).join('\n'), ['T1014'], 'Defense Evasion');
      for (const [k, list] of foreign) { const [d, m] = k.split('|'); note('medium', `${d}: ${list.length} IRP handler(s) owned by ${m}`, 'Dispatch routines handled by another driver. Filter or framework drivers do this legitimately; a non-Microsoft module here can be an IRP hook.', list.map((r) => `${r.IRP} -> ${hex(r.Address)} ${r.Module}!${r.Symbol || ''}`).join('\n'), ['T1014'], 'Defense Evasion'); }
      tables.push(T('Driver IRP handlers', ['Driver Name', 'IRP', 'Address', 'Module', 'Symbol'], rows.map((r) => [r['Driver Name'], r.IRP, hex(r.Address), r.Module, r.Symbol])));
      return true;
    }
    case 'timers': {
      const bad = rows.filter((r) => unknown(r.Module));
      if (bad.length) note('high', `${bad.length} kernel timer(s) run code from unknown memory`, 'Kernel timers (DPCs) fire periodically. Routines outside every module are a known rootkit persistence and watchdog trick.', bad.slice(0, 30).map((r) => `${hex(r.Routine)} period ${r['Period(ms)']}ms due ${r.DueTime}`).join('\n'), ['T1014'], 'Defense Evasion');
      tables.push(T('Kernel timers', ['DueTime', 'Period(ms)', 'Signaled', 'Routine', 'Module', 'Symbol'], rows.map((r) => [r.DueTime, r['Period(ms)'], r.Signaled, hex(r.Routine), r.Module, r.Symbol])));
      return true;
    }
    case 'orphan_kernel_threads': {
      if (rows.length) note('critical', `${rows.length} kernel thread(s) running from memory that belongs to no driver`, 'A system thread whose start address is outside every loaded module is the signature of a driver that unlinked itself (DKOM) or was manually mapped.', rows.slice(0, 30).map((r) => `PID ${r.PID} TID ${r.TID} start ${hex(r.StartAddress)} ${r.StartPath || ''}`).join('\n'), ['T1014', 'T1564'], 'Defense Evasion');
      tables.push(T('Orphan kernel threads', ['PID', 'TID', 'StartAddress', 'StartPath', 'CreateTime'], rows.map((r) => [r.PID, r.TID, hex(r.StartAddress), r.StartPath, r.CreateTime])));
      return true;
    }
    case 'modules': case 'modscan': {
      if (key === 'modules') for (const r of rows) { const pc = classifyPath(String(r.Path || '').replace(/^\\SystemRoot/i, 'C:\\Windows').replace(/^\\\?\?\\/, '')); if (pc.sev && pc.sev !== 'low') note('high', `Kernel driver loaded from ${r.Path}`, `Drivers live in System32\\drivers or DriverStore. ${pc.reasons.join('; ')}`, `${r.Name} base ${hex(r.Base)}`, ['T1014', 'T1543.003'], 'Persistence'); }
      tables.push(T(key === 'modules' ? 'Loaded kernel modules (PsLoadedModuleList)' : 'Kernel modules found by pool scanning', ['Base', 'Size', 'Name', 'Path'], rows.map((r) => [hex(r.Base), hex(r.Size), r.Name, r.Path])));
      return true;
    }
    case 'driverscan': tables.push(T('Driver objects (pool scan)', ['Start', 'Size', 'Service Key', 'Driver Name', 'Name'], rows.map((r) => [hex(r.Start), hex(r.Size), r['Service Key'], r['Driver Name'], r.Name]))); return true;
    case 'unloadedmodules': tables.push(T('Recently unloaded drivers', ['Name', 'StartAddress', 'EndAddress', 'Time'], rows.map((r) => [r.Name, hex(r.StartAddress), hex(r.EndAddress), r.Time]), 'A rootkit loader often loads a vulnerable or helper driver and unloads it again; check names you do not recognise.')); return true;
    default: return false;
  }
}

/** Cross-view checks (DKOM) once every plugin is in. */
export function rootkitFinal(v, shared, ctx) {
  const add = (sev, title, detail, evidence, mitre, file) => ctx.finding({ sev, category: 'Defense Evasion', tool: 'Volatility 3', file, title: `Memory: ${title}`, detail, evidence, mitre });
  // drivers: pool scan vs PsLoadedModuleList
  if (v.modules && v.modscan) {
    const listed = new Set(v.modules.map((r) => Number(r.Base)));
    const unloaded = new Set((v.unloadedmodules || []).map((r) => String(r.Name).toLowerCase()));
    const hidden = v.modscan.filter((r) => Number(r.Base) && !listed.has(Number(r.Base)) && !unloaded.has(String(r.Name).toLowerCase()));
    if (hidden.length) add(hidden.some((r) => classifyPath(String(r.Path || '')).sev) ? 'critical' : 'high', `${hidden.length} kernel driver(s) found in memory but unlinked from the loaded module list (DKOM)`, 'modscan finds the driver in pool memory, but it is missing from PsLoadedModuleList, which is what Task Manager, driverquery and most tools read. Rootkits unlink themselves to hide. (A driver that was being unloaded at capture time can look the same.)', hidden.slice(0, 30).map((r) => `${r.Name} base ${hex(r.Base)} ${r.Path}`).join('\n'), ['T1014', 'T1564'], shared.volFile.modscan);
  }
  // driver objects whose code is not inside any listed module
  if (v.driverscan && v.modules && !v.drivermodule) {
    const ranges = v.modules.map((r) => [Number(r.Base), Number(r.Base) + Number(r.Size)]);
    const orphan = v.driverscan.filter((r) => Number(r.Start) && !ranges.some(([a, b]) => Number(r.Start) >= a && Number(r.Start) < b));
    if (orphan.length) add('high', `${orphan.length} driver object(s) whose code is in no listed module`, 'The driver object exists but its image is not in PsLoadedModuleList: unlinked (DKOM) or manually mapped driver.', orphan.slice(0, 30).map((r) => `${r['Driver Name']} start ${hex(r.Start)} key ${r['Service Key']}`).join('\n'), ['T1014'], shared.volFile.driverscan);
  }
  // threads: pool scan vs process thread lists via psxview's thrdscan column is handled per process; orphaned kernel threads per plugin
}

/** windows.idt and windows.apihooks (Sudo-Z's Volatility plugins; Volatility 3 ships neither). */
export function hookPlugin(key, rows, note, tables) {
  switch (key) {
    case 'idt': {
      const byVector = new Map();
      for (const r of rows) { const k = String(r.Vector); if (!byVector.has(k)) byVector.set(k, new Map()); byVector.get(k).set(String(r.Handler), r); }
      const unknown = rows.filter((r) => /unknown memory/i.test(r.Owner || ''));
      const other = rows.filter((r) => /other module/i.test(r.Owner || ''));
      const label = (r) => `vector ${r.Vector}${r.Meaning ? ` (${r.Meaning})` : ''} on CPU ${r.CPU} -> ${hex(r.Handler)} ${r.Module || 'no module'}${r.Symbol && r.Symbol !== 'N/A' ? '!' + r.Symbol : ''}`;
      if (unknown.length) note('critical', `${unknown.length} interrupt handler(s) point into memory that belongs to no module`, 'Every IDT entry should land in ntoskrnl or hal. A handler in unmapped or private memory is an interrupt hook: int 0x2e is the legacy system call gate, int 1 and 3 are used for anti-debugging, and int 0x0e (page fault) is how Shadow Walker style rootkits hide memory.', unknown.slice(0, 40).map(label).join('\n'), ['T1014', 'T1562.001'], 'Defense Evasion');
      if (other.length) {
        const mods = [...new Set(other.map((r) => r.Module))];
        note('high', `${other.length} interrupt handler(s) owned by ${mods.join(', ')} rather than the kernel`, 'A third-party driver holding an interrupt vector is unusual outside virtualisation and some hardware drivers. Confirm the driver and its signature.', other.slice(0, 40).map(label).join('\n'), ['T1014'], 'Defense Evasion');
      }
      const split = [...byVector].filter(([, h]) => h.size > 1);
      if (split.length) note('critical', `${split.length} interrupt vector(s) have a different handler on different processors`, 'The IDT is per CPU. A rootkit that hooks only one core stays hidden from a tool that reads a single processor, and the mismatch itself is proof of tampering.', split.slice(0, 20).map(([v, h]) => `vector ${v}: ` + [...h.values()].map((r) => `CPU ${r.CPU} ${hex(r.Handler)} ${r.Module || 'unknown'}`).join(' | ')).join('\n'), ['T1014'], 'Defense Evasion');
      tables.push(T('Interrupt Descriptor Table', ['CPU', 'Vector', 'Meaning', 'Handler', 'Module', 'Symbol', 'Owner'], rows.map((r) => [r.CPU, r.Vector, r.Meaning, hex(r.Handler), r.Module, r.Symbol, r.Owner]), 'By default only vectors outside the kernel are listed, so an empty table is the healthy result.'));
      return true;
    }
    case 'apihooks': {
      const groups = new Map();
      for (const r of rows) {
        const owner = String(r['Destination owner'] || '');
        const k = `${r.PID}|${r.Process}|${owner}|${r.Type}`;
        if (!groups.has(k)) groups.set(k, { pid: r.PID, proc: r.Process, owner, type: r.Type, list: [] });
        groups.get(k).list.push(r);
      }
      for (const g of groups.values()) {
        const injected = /unknown memory/i.test(g.owner);
        const mods = [...new Set(g.list.map((r) => r.Module))];
        const fns = g.list.slice(0, 25).map((r) => `${r.Module}!${r.Function} ${hex(r['Hooked at'])} -> ${hex(r.Destination)} (${r.How})`);
        note(injected ? 'critical' : 'medium',
          injected
            ? `${g.list.length} ${g.type === 'iat' ? 'import table entr' : 'API hook'}${g.type === 'iat' ? (g.list.length > 1 ? 'ies' : 'y') : g.list.length > 1 ? 's' : ''} in ${g.proc} (PID ${g.pid}) point into memory that belongs to no module`
            : `${g.list.length} ${g.type === 'iat' ? 'import table entries' : 'API hooks'} in ${g.proc} (PID ${g.pid}) redirected into ${g.owner}`,
          injected
            ? `The ${g.type === 'iat' ? 'import address table entries' : 'first instructions of these exported functions'} in ${mods.join(', ')} jump into private memory. That is injected code deciding what the process sees: credential theft, AMSI and ETW bypasses, and hiding files and processes from the program itself all work this way. Dump the destination with windows.vadinfo and windows.vaddump.`
            : `${g.owner} has redirected these functions. Endpoint security, application compatibility shims and some DRM hook this way, so confirm the module is one you expect before treating it as malicious.`,
          fns.join('\n'), injected ? ['T1055', 'T1562.001', 'T1574'] : ['T1574'], 'Defense Evasion');
      }
      tables.push(T('User mode API hooks', ['PID', 'Process', 'Module', 'Function', 'Type', 'Hooked at', 'Destination', 'Destination owner', 'How'], rows.map((r) => [r.PID, r.Process, r.Module, r.Function, r.Type, hex(r['Hooked at']), hex(r.Destination), r['Destination owner'], r.How]), 'inline = the function prologue was overwritten; iat = an import points somewhere unexpected. Forwarded exports and jumps inside the same module are not reported.'));
      return true;
    }
    default: return false;
  }
}
