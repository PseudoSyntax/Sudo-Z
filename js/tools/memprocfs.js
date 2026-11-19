// MemProcFS (Ulf Frisk) forensic mode output.
//
// MemProcFS mounts a memory image as a file system and, in forensic mode,
// writes a set of CSVs under forensic/csv/. They are a second engine's view of
// the same memory Volatility 3 parses, with one thing Volatility has no
// equivalent of: FindEvil, which scores memory anomalies by type.
//
// Everything here is keyed off the exact CSV headers MemProcFS writes, so a
// folder of forensic CSVs can be dropped into the browser with no home install.
import { classifyCommand, classifyPath, baseName, isLolbin } from '../ioc/heuristics.js';
import { isPrivateIp } from '../ioc/indicators.js';
import { parseCsv } from './ezcsv.js';
import { classifyPort, portPatterns } from '../ioc/ports.js';
import { utf8 } from '../core/bytes.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });

// forensic/csv headers, verbatim from the MemProcFS source (vmm/fc.c and vmm/modules/*)
export const MPFS_CSV = [
  ['findevil', 'PID,ProcessName,Type,Address,Description'],
  ['process', 'PID,PPID,State,ShortName,Name,IntegrityLevel,User,CreateTime,ExitTime,Wow64,EPROCESS,PEB,PEB32,DTB,UserDTB,UserPath,KernelPath,CommandLine,Flag'],
  ['net', 'Proto,State,SrcAddr,SrcPort,DstAddr,DstPort,Time,Object,PID,Process,ProcessPath'],
  ['services', 'PID,Ordinal,ServiceName,DisplayName,User,StartType,State,Type1,Type2,ObjectAddress,ImagePath,DriverpathOrCmdline'],
  ['tasks', 'GUID,TaskName,TaskPath,User,TimeMostRecent,CommandLine,Parameters,TimeReg,TimeCreate,TimeLastRun,TimeCompleted'],
  ['drivers', 'Name,ObjectAddress,Size,Start,End,ServiceKey,DriverName,DriverPath'],
  ['devices', 'Name,ObjectAddress,Depth,AttachedDeviceAddress,DriverName,DriverPath,DriverObjectAddress,ExtraInfo'],
  ['modules', 'PID,Process,Name,Wow64,Size,Start,End,#Imports,#Exports,#Sections,Path,KernelPath'],
  ['unloaded_modules', 'PID,Process,ModuleName,UnloadTime,Wow64,Size,Start,End'],
  ['threads', 'PID,TID,ETHREAD,State,WaitReason,CreateTime,ExitTime,Running,BasePriority,Priority,ExitStatus,StartAddress,Win32StartAddress'],
  ['handles', 'PID,Handle,Object,Access,Type,Tag,HandleCount,Device,Description'],
  ['prefetch', 'Process,RunCount,FileCount,PrefetchFile,RunTime1'],
  ['files', 'Object,Type,SignInfo,Size,File,Path'],
  ['timeline', 'Time,Type,Action,PID,Value32,Value64,Text,Pad'],
  ['yara', 'MatchIndex,Tags,Description,RuleAuthor,RuleVersion,MemoryType,MemoryTag,MemoryBaseAddress,ObjectAddress,PID,ProcessName'],
  ['virtualmachines', 'Name,Type,MaxGPA,Build,SystemType,PartitionID,IsActive'],
];

/** Recognise a MemProcFS forensic CSV from its header line alone. */
export function detectMemProcFs(name, head) {
  const first = String(head).split(/\r?\n/)[0].replace(/^\ufeff/, '').trim();
  if (!first) return null;
  for (const [kind, cols] of MPFS_CSV) {
    if (first === cols || first.startsWith(cols + ',')) return kind;
  }
  // the file name alone is enough when a later MemProcFS version adds columns
  const b = String(name).split(/[\\/]/).pop().toLowerCase();
  const m = b.match(/^(findevil|process|net|netdns|services|tasks|drivers|devices|modules|unloaded_modules|threads|handles|prefetch|files|yara|virtualmachines|timeline_all|eventlog)\.csv$/);
  if (m && /,/.test(first)) {
    const kind = m[1] === 'timeline_all' ? 'timeline' : m[1];
    const want = MPFS_CSV.find(([k]) => k === kind);
    if (want && want[1].split(',').slice(0, 3).every((c) => first.includes(c))) return kind;
  }
  return null;
}

/**
 * FindEvil detection types, with MemProcFS's own severity order (vmm/modules/modules.h)
 * and what each one means. sev is Sudo-Z's grading, not MemProcFS's number.
 */
export const EVIL = {
  AV_DETECT: { sev: 'critical', cat: 'Defense Evasion', mitre: ['T1059'], what: 'Windows Defender logged a detection for this process in memory. The antivirus already named it; confirm what it detected and whether it was allowed to run.' },
  PE_INJECT: { sev: 'critical', cat: 'Defense Evasion', mitre: ['T1055.001', 'T1055.012'], what: 'An executable image is mapped in the process but there is no file behind it on disk. That is a manually mapped or reflectively loaded DLL or EXE: the loader never saw it, so it has no module entry, no file and no signature. Dump it and treat the process as compromised.' },
  PROC_NOLINK: { sev: 'critical', cat: 'Defense Evasion', mitre: ['T1014', 'T1564'], what: 'The EPROCESS is missing from the kernel\'s doubly linked active process list. Task Manager, tasklist and any tool that walks ActiveProcessLinks cannot see this process. Unlinking is direct kernel object manipulation (DKOM) and has no legitimate use.' },
  PROC_BAD_DTB: { sev: 'critical', cat: 'Defense Evasion', mitre: ['T1014'], what: 'The process directory table base does not match what the kernel structures say it should be. A wrong DTB breaks every tool that walks page tables from the process, which is how some rootkits hide memory.' },
  PE_HDR_SPOOF: { sev: 'critical', cat: 'Defense Evasion', mitre: ['T1036', 'T1055.012'], what: 'The PE header in memory does not match the image it claims to be. Headers are rewritten to make injected code look like a legitimate module, or wiped so tools cannot parse it.' },
  PEB_MASQ: { sev: 'critical', cat: 'Defense Evasion', mitre: ['T1036.005'], what: 'The process environment block was edited so the process reports a different image path or command line than the one it actually runs. Anything reading the PEB, which includes most tooling, is told a lie.' },
  PROC_PARENT: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1134.004', 'T1036'], what: 'The parent of this process is not one it should normally have. That is either a legitimate oddity worth explaining or parent process ID spoofing, which attackers use so the process tree looks ordinary.' },
  PROC_USER: { sev: 'high', cat: 'Privilege Escalation', mitre: ['T1134'], what: 'The process token says it runs as a user that does not fit the process. Token theft and impersonation produce exactly this: the image is ordinary but the security context is somebody else\'s.' },
  PROC_BASEADDR: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055.012'], what: 'The image base address of the process does not match its PE header. Process hollowing unmaps the original image and writes another one, which leaves this mismatch.' },
  UM_APC: { sev: 'high', cat: 'Execution', mitre: ['T1055.004'], what: 'A queued user mode asynchronous procedure call points at code that does not belong to a module. Early bird APC injection and sleeping beacons queue an APC so the payload runs the next time the thread is alerted.' },
  THREAD: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055'], what: 'A thread starts in memory that is not backed by any module, or its start address was tampered with. This is the thread creation trampoline pattern that injected code uses to begin running.' },
  DRIVER_PATH: { sev: 'high', cat: 'Persistence', mitre: ['T1543.003', 'T1014'], what: 'A loaded kernel driver sits outside the folders drivers normally live in. Check its signature and whether it is a known vulnerable driver brought along by the attacker.' },
  PEB_BAD_LDR: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055.001'], what: 'The loader data in the process environment block is damaged or inconsistent. Unlinking a DLL from the loader lists to hide it leaves the structures in this state.' },
  PE_NOLINK: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055.001'], what: 'A PE image is mapped in the process but is not in the loader module lists. The DLL was unlinked after loading so that module listings do not show it.' },
  PE_PATCHED: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055', 'T1562.001'], what: 'The code of a mapped module in memory differs from the file on disk. That is an inline patch: AMSI and ETW bypasses, hooked exports and patched security checks all show up here.' },
  PRIVATE_RWX: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055'], what: 'Private memory that is readable, writable and executable at the same time. Compilers do not produce this; shellcode loaders allocate it so they can write code and then run it. The most reliable single sign of injected code.' },
  NOIMAGE_RWX: { sev: 'high', cat: 'Defense Evasion', mitre: ['T1055'], what: 'Executable and writable pages that are not mapped from any image file. Code is running from memory that has no file behind it.' },
  HIGH_ENTROPY: { sev: 'medium', cat: 'Defense Evasion', mitre: ['T1027'], what: 'A region of process memory has entropy high enough to look packed or encrypted. Normal for compressed resources and some runtimes, so confirm it rather than acting on it alone.' },
  PROC_DEBUG: { sev: 'medium', cat: 'Defense Evasion', mitre: ['T1622'], what: 'The process holds debug privileges or is being debugged. Legitimate for developer tooling, and the first thing a credential dumper enables so it can open LSASS.' },
  PRIVATE_RX: { sev: 'medium', cat: 'Defense Evasion', mitre: ['T1055'], what: 'Private memory marked executable but not writable. Often shellcode that allocated as RWX, wrote itself and then changed protection to RX to look less obvious. Also produced legitimately by JIT compilers.' },
  NOIMAGE_RX: { sev: 'medium', cat: 'Defense Evasion', mitre: ['T1055'], what: 'Executable pages not mapped from an image file. Common for .NET and other JIT runtimes, so judge it by the process it appears in.' },
  TIME_CHANGE: { sev: 'info', cat: 'Defense Evasion', mitre: ['T1070.006'], what: 'The system clock changed. Every timestamp either side of it has to be read with that in mind, and attackers move the clock to confuse timelines.' },
};
// JIT runtimes allocate executable memory as part of normal work
const JIT = /^(w3wp|powershell|pwsh|devenv|msbuild|java|javaw|chrome|msedge|firefox|node|python\d*|dotnet|iisexpress|sqlservr|mongod|unity|code)\.exe$/i;
const NOISY = new Set(['NOIMAGE_RX', 'PRIVATE_RX', 'HIGH_ENTROPY']);

const num = (v) => { const n = Number(String(v ?? '').replace(/^0x/i, (m) => m)); return isNaN(n) ? 0 : n; };
const t = (v) => { const s = String(v || '').trim(); return !s || /^0$/.test(s) || /^1601-/.test(s) ? '' : s.replace(' ', 'T') + (/[Z+]/.test(s) ? '' : 'Z'); };

export function runMemProcFs(u8, f, ctx, kind, shared) {
  const { head: header, rows } = parseCsv(utf8(u8));
  const col = (n) => header.indexOf(n);
  const g = (r, n) => (col(n) >= 0 ? String(r[col(n)] ?? '') : '');
  const tool = 'MemProcFS';
  const file = f.name;
  shared.mpfs = shared.mpfs || {};
  shared.mpfs[kind] = rows.length;
  const tables = [T(`MemProcFS ${kind}.csv`, header, rows)];
  const note = (sev, category, title, detail, evidence, mitre, time) => ctx.finding({ sev, category, tool, file, time, title: `Memory (MemProcFS): ${title}`, detail, evidence, mitre });

  switch (kind) {
    case 'findevil': {
      const byType = new Map(); const seenProc = new Map();
      for (const r of rows) {
        const type = g(r, 'Type').trim().toUpperCase();
        if (!type) continue;
        const e = byType.get(type) || [];
        e.push({ pid: g(r, 'PID'), proc: g(r, 'ProcessName'), addr: g(r, 'Address'), desc: g(r, 'Description') });
        byType.set(type, e);
      }
      for (const [type, list] of byType) {
        const meta = EVIL[type] || EVIL[type.replace(/_START$/, '')] || { sev: 'medium', cat: 'Defense Evasion', mitre: ['T1055'], what: 'A FindEvil detection type this build of Sudo-Z does not have a description for. Check the MemProcFS documentation for what it covers.' };
        // JIT runtimes produce executable private memory legitimately
        const allJit = NOISY.has(type) && list.every((x) => JIT.test(baseName(x.proc)));
        const sev = allJit ? 'low' : meta.sev;
        const procs = [...new Set(list.filter((x) => x.proc).map((x) => `${baseName(x.proc)} (PID ${x.pid})`))];
        const where = !procs.length ? 'this image' : procs.length === 1 ? procs[0] : `${procs.length} process(es)`;
        note(sev, meta.cat,
          `FindEvil ${type} in ${where}${list.length > procs.length && procs.length ? `, ${list.length} hit(s)` : ''}`,
          meta.what + (allJit ? ' Every process here runs a just in time compiler, which allocates executable memory as part of normal work, so this is lowered unless something else points at the same process.' : ''),
          list.slice(0, 25).map((x) => `PID ${x.pid} ${x.proc} ${x.addr} ${x.desc}`).join('\n'),
          meta.mitre);
        // one execution entry per process, not one per detection type, so the path rules fire once
        for (const x of list) if (x.proc) { const k = `${x.pid}|${x.proc.toLowerCase()}`; const cur = seenProc.get(k); if (!cur || (!cur.flagged && (sev === 'critical' || sev === 'high'))) seenProc.set(k, { path: x.proc, flagged: sev === 'critical' || sev === 'high', types: [...(cur?.types || []), type] }); else cur.types.push(type); }
      }
      for (const p of seenProc.values()) ctx.exec_({ path: p.path, tool, file, source: `MemProcFS FindEvil (${[...new Set(p.types)].join(', ')})`, flagged: p.flagged });
      if (byType.size) {
        const worst = [...byType.keys()].filter((k) => (EVIL[k] || {}).sev === 'critical');
        tables.unshift(T('FindEvil summary', ['Type', 'Hits', 'Processes', 'Severity', 'Meaning'], [...byType].map(([k, v]) => [k, v.length, new Set(v.map((x) => x.pid)).size, (EVIL[k] || {}).sev || '?', (EVIL[k] || {}).what || ''])
          .sort((a, b) => ['critical', 'high', 'medium', 'low', 'info', '?'].indexOf(a[3]) - ['critical', 'high', 'medium', 'low', 'info', '?'].indexOf(b[3])),
          (worst.length ? `${worst.length} detection type(s) with no benign explanation: ${worst.join(', ')}. ` : 'No detection type here lacks a benign explanation; judge each by the process it appears in. ') + 'Severity here is the type\'s own; a finding can be lowered when every process it hit runs a just in time compiler.'));
      }
      break;
    }
    case 'process': {
      for (const r of rows) {
        const path = g(r, 'UserPath') || g(r, 'KernelPath') || g(r, 'Name');
        const cmd = g(r, 'CommandLine');
        const created = t(g(r, 'CreateTime'));
        if (!path) continue;
        ctx.exec_({ path, args: cmd, tool, file, time: created, source: 'MemProcFS process list' });
        if (created) ctx.event({ time: created, tool, file, type: 'Process running (memory)', desc: `${path}${cmd ? ' ' + cmd : ''} [PID ${g(r, 'PID')}, user ${g(r, 'User')}, ${g(r, 'IntegrityLevel')}]` });
        const cc = classifyCommand(cmd);
        if (cc.sev && cc.sev !== 'low') note(cc.sev, 'Execution', `${cc.reasons[0]}: ${baseName(path)}`, cc.reasons.join('; '), `PID ${g(r, 'PID')} (parent ${g(r, 'PPID')}) as ${g(r, 'User')}\n${cmd}`, cc.mitre || ['T1059'], created);
        const pc = classifyPath(path);
        if (pc.sev === 'critical' || pc.sev === 'high') note('high', 'Execution', `Process running from a suspicious location: ${baseName(path)}`, pc.reasons.join('; '), `PID ${g(r, 'PID')} ${path}\n${cmd}`, ['T1036'], created);
      }
      break;
    }
    case 'net': {
      const portSeen = new Set();
      for (const r of rows) {
        const dst = g(r, 'DstAddr'), proc = g(r, 'Process'), time = t(g(r, 'Time'));
        if (!dst || dst === '*' || dst === '0.0.0.0' || dst === '::') continue;
        const pub = /^\d+\.\d+\.\d+\.\d+$/.test(dst) && !isPrivateIp(dst);
        ctx.indicators.add(pub ? 'ipv4' : 'internal_ip', dst, file, `${proc} ${g(r, 'Proto')} ${g(r, 'State')} port ${g(r, 'DstPort')}`);
        if (time) ctx.event({ time, tool, file, type: 'Network connection (memory)', desc: `${proc} (PID ${g(r, 'PID')}) ${g(r, 'Proto')} -> ${dst}:${g(r, 'DstPort')} ${g(r, 'State')}` });
        if (pub && (isLolbin(baseName(proc)) || classifyPath(g(r, 'ProcessPath')).sev)) note('high', 'Command and Control', `${baseName(proc)} connected to ${dst}:${g(r, 'DstPort')}`, 'A living off the land binary or a program in a suspicious folder talking to a public address is worth pivoting on across every host.', `${g(r, 'ProcessPath') || proc}\n${g(r, 'Proto')} ${g(r, 'SrcAddr')}:${g(r, 'SrcPort')} -> ${dst}:${g(r, 'DstPort')} ${g(r, 'State')}`, ['T1071'], time);
        const pc = classifyPort(g(r, 'DstPort'), { proto: g(r, 'Proto'), owner: proc, path: g(r, 'ProcessPath'), peerPrivate: !pub, peerIsLoopback: /^127\./.test(dst) || dst === '::1' });
        const pk = pc && `${proc}|${pc.port}`;
        if (pc && pc.sev !== 'info' && pc.sev !== 'low' && !portSeen.has(pk)) { portSeen.add(pk); note(pc.sev, pc.cat, `${baseName(proc)} connected out on port ${pc.port} (${pc.name})`, `${pc.why ? pc.why + ' ' : ''}${pc.reasons.length ? `Here: ${pc.reasons.join('; ')}.` : ''}`.trim(), `${g(r, 'ProcessPath') || proc}\n${g(r, 'Proto')} -> ${dst}:${pc.port} ${g(r, 'State')}`, pc.mitre, time); }
      }
      for (const pt of portPatterns(rows.map((r) => ({ peer: g(r, 'DstAddr'), port: g(r, 'DstPort'), proto: g(r, 'Proto'), owner: g(r, 'Process'), time: t(g(r, 'Time')) })))) note(pt.sev, pt.cat, pt.title, pt.detail, pt.evidence, pt.mitre, pt.time);
      break;
    }
    case 'services': {
      for (const r of rows) {
        const img = g(r, 'ImagePath') || g(r, 'DriverpathOrCmdline');
        if (!img) continue;
        ctx.persist({ mechanism: 'Service (memory)', name: g(r, 'ServiceName'), command: img, tool, file, user: g(r, 'User'), mitre: ['T1543.003'] });
      }
      break;
    }
    case 'tasks': {
      for (const r of rows) {
        const cmd = [g(r, 'CommandLine'), g(r, 'Parameters')].filter(Boolean).join(' ');
        if (!cmd) continue;
        ctx.persist({ mechanism: 'Scheduled task (memory)', name: g(r, 'TaskPath') || g(r, 'TaskName'), command: cmd, tool, file, user: g(r, 'User'), mitre: ['T1053.005'] });
        const last = t(g(r, 'TimeLastRun'));
        if (last) ctx.event({ time: last, tool, file, type: 'Scheduled task last run (memory)', desc: `${g(r, 'TaskPath') || g(r, 'TaskName')} -> ${cmd}` });
      }
      break;
    }
    case 'drivers': {
      for (const r of rows) {
        const p = g(r, 'DriverPath');
        if (!p) continue;
        const pc = classifyPath(p.replace(/^\\SystemRoot/i, 'C:\\Windows').replace(/^\\\?\?\\/, ''));
        if (pc.sev && pc.sev !== 'low') note('high', 'Persistence', `Kernel driver loaded from ${p}`, `Drivers belong in System32\\drivers or the DriverStore. ${pc.reasons.join('; ')}`, `${g(r, 'Name')} service key ${g(r, 'ServiceKey')}`, ['T1014', 'T1543.003']);
      }
      break;
    }
    case 'modules': {
      for (const r of rows) {
        const p = g(r, 'Path');
        if (!p) continue;
        const pc = classifyPath(p);
        if (pc.sev === 'critical') note('medium', 'Defense Evasion', `Module loaded from a suspicious location: ${g(r, 'Name')}`, pc.reasons.join('; '), `PID ${g(r, 'PID')} ${g(r, 'Process')}\n${p}`, ['T1574']);
      }
      break;
    }
    case 'prefetch': {
      for (const r of rows) {
        const p = g(r, 'Process');
        if (!p) continue;
        const time = t(g(r, 'RunTime1'));
        ctx.exec_({ path: p, tool, file, time, source: 'MemProcFS prefetch (memory)' });
        if (time) ctx.event({ time, tool, file, type: 'Program executed (Prefetch in memory)', desc: `${p} (${g(r, 'RunCount')} runs)` });
      }
      break;
    }
    case 'yara': {
      const byRule = new Map();
      for (const r of rows) {
        const rule = g(r, 'Description') || g(r, 'Tags') || 'yara hit';
        if (!byRule.has(rule)) byRule.set(rule, []);
        byRule.get(rule).push(r);
      }
      for (const [rule, list] of byRule) note('critical', 'Defense Evasion', `YARA rule matched in memory: ${rule}`, `MemProcFS scanned process memory with its rule set and ${list.length} region(s) matched. A rule hit names the family; confirm it against the process and dump the region.`, list.slice(0, 20).map((r) => `PID ${g(r, 'PID')} ${g(r, 'ProcessName')} ${g(r, 'MemoryType')} ${g(r, 'MemoryBaseAddress')} ${g(r, 'Tags')}`).join('\n'), ['T1027']);
      break;
    }
    case 'timeline': {
      let n = 0;
      for (const r of rows) {
        const time = t(g(r, 'Time'));
        if (!time || n++ > 200000) continue;
        ctx.event({ time, tool, file, type: `${g(r, 'Type')} ${g(r, 'Action')}`.trim(), desc: `${g(r, 'Text')}${g(r, 'PID') && g(r, 'PID') !== '0' ? ` [PID ${g(r, 'PID')}]` : ''}` });
      }
      break;
    }
    default: break;
  }
  return { tool, artifact: `MemProcFS forensic ${kind}.csv`, summary: `${rows.length} row(s)`, tables, notes: [] };
}

/** Cross-check MemProcFS against Volatility once both are in. */
export function memProcFsFinal(shared, ctx) {
  const v = shared.vol, m = shared.mpfs;
  if (!v || !m) return;
  const evil = ctx.findings.filter((f) => /MemProcFS\): FindEvil/.test(f.title));
  const volInj = ctx.findings.filter((f) => f.tool === 'Volatility 3' && /injection|malfind|hollow|unlinked|masquerade/i.test(f.title));
  if (!evil.length || !volInj.length) return;
  const pidOf = (s) => [...String(s).matchAll(/PID (\d+)/g)].map((x) => x[1]);
  const evilPids = new Set(evil.flatMap((f) => pidOf(f.evidence || '')));
  const both = [...new Set(volInj.flatMap((f) => pidOf(`${f.title} ${f.evidence || ''}`)).filter((p) => evilPids.has(p)))];
  if (both.length) ctx.finding({
    sev: 'critical', category: 'Correlation', tool: 'Sudo-Z', file: '(multiple)',
    title: `Memory: ${both.length} process(es) flagged by both Volatility 3 and MemProcFS`,
    detail: 'Two memory forensics engines, written independently and parsing the structures differently, reached the same conclusion about these processes. That removes the most common doubt about a single memory finding, which is that one tool misread the image.',
    evidence: both.map((p) => `PID ${p}`).join(', '),
    mitre: ['T1055'],
  });
}
