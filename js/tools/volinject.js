// Code injection checks across Volatility 3 plugins. Single plugins each see a
// slice: ldrmodules sees loader lists and file mappings, malfind sees private
// executable memory, pstree sees the path the PEB claims. Injection shows up
// where those disagree, e.g. lsass.exe with a module in its loader lists whose
// MappedPath is N/A (nothing on disk behind it).
import { baseName } from '../ioc/heuristics.js';
import { wrongLocation } from '../ioc/baseline.js';

// processes where any injected code is serious: credential stores, session and service managers
export const SENSITIVE = /^(lsass|lsaiso|csrss|winlogon|wininit|services|smss|spoolsv|svchost|explorer|dwm|taskhostw|sihost|searchindexer|msmpeng)\.exe$/i;
const CRED = /^(lsass|lsaiso)\.exe$/i;
const JIT = /^(chrome|msedge|firefox|iexplore|msmpeng|teams|ms-teams|slack|discord|code|node|java|javaw|dotnet|powershell|pwsh|powershell_ise|onedrive|searchapp|smartscreen|devenv|w3wp|outlook|winword|excel|acrord32|acrobat)\.exe$/i;
const SYSDIR = /^([a-z]:)?\\(windows|winnt)\\(system32|syswow64|winsxs|systemapps|servicing|microsoft\.net|assembly)\\|\\systemroot\\system32\\/i;

const empty = (p) => p == null || /^(|n\/a|-|null|none)$/i.test(String(p).trim());
const yes = (v) => v === true || /^true$/i.test(String(v));
const norm = (p) => String(p || '').replace(/^\\\\\?\\|^\\\?\?\\/, '').replace(/^\\device\\harddiskvolume\d+/i, 'C:').replace(/^\\systemroot/i, 'C:\\Windows');
/** EPROCESS names are cut to 14 characters; compare on that. */
const sameName = (a, b) => { a = String(a || '').toLowerCase(); b = String(b || '').toLowerCase(); return a === b || (a.length >= 14 && b.startsWith(a.slice(0, 14))) || (b.length >= 14 && a.startsWith(b.slice(0, 14))); };

export function injectionChecks(v, shared, ctx) {
  const out = [];
  const add = (sev, title, detail, evidence, mitre, file, pid, proc) => { ctx.finding({ sev, category: 'Defense Evasion', tool: 'Volatility 3', file, title: `Memory: ${title}`, detail, evidence, mitre }); out.push([sev, pid, proc, title, detail]); };
  const procPath = new Map();
  for (const r of v.pstree || []) if (r.Path) procPath.set(String(r.PID), norm(r.Path));
  for (const r of v.dlllist || []) if (!procPath.has(String(r.PID)) && /\.exe$/i.test(r.Path || '')) procPath.set(String(r.PID), norm(r.Path));
  const injectedPids = new Map(); // pid -> [reasons]
  const mark = (pid, why) => { const k = String(pid); if (!injectedPids.has(k)) injectedPids.set(k, []); injectedPids.get(k).push(why); };

  // ------------------------------------------------------------- ldrmodules
  const byPid = new Map();
  for (const r of v.ldrmodules || []) { const k = String(r.Pid ?? r.PID); if (!byPid.has(k)) byPid.set(k, []); byPid.get(k).push(r); }
  const lf = shared.volFile.ldrmodules;
  for (const [pid, mods] of byPid) {
    const proc = String(mods[0].Process || ''); const sens = SENSITIVE.test(proc); const cred = CRED.test(proc);
    const noFile = mods.filter((m) => empty(m.MappedPath));
    // A. listed by the loader but nothing on disk behind it: reflective / manual mapping
    const listedNoFile = noFile.filter((m) => yes(m.InLoad) || yes(m.InInit) || yes(m.InMem));
    // B. image-type memory with no file and in no list
    const hiddenNoFile = noFile.filter((m) => !yes(m.InLoad) && !yes(m.InInit) && !yes(m.InMem));
    if (listedNoFile.length) {
      add(cred || sens ? 'critical' : 'high', `${proc} (PID ${pid}) has ${listedNoFile.length} loaded module(s) with no file behind them (MappedPath N/A)`, `A module in the PEB loader lists should map a file on disk. N/A means the image was written into memory by hand: reflective DLL injection, manual mapping or process hollowing.${cred ? ' In LSASS this is how credential theft tooling (e.g. injected SSPs, Mimikatz memssp) hides.' : ''}`, listedNoFile.map((m) => `Base ${m.Base}  InLoad=${m.InLoad} InInit=${m.InInit} InMem=${m.InMem}  MappedPath=${m.MappedPath ?? 'N/A'}`).join('\n'), ['T1055.001', 'T1620', ...(cred ? ['T1003.001'] : [])], lf, pid, proc);
      mark(pid, 'loader-listed module with no backing file');
    }
    if (hiddenNoFile.length) {
      add(sens ? 'critical' : 'high', `${proc} (PID ${pid}) has ${hiddenNoFile.length} image-mapped region(s) with no file and in no loader list`, 'Executable image memory that the loader does not know about and that is not backed by a file: injected or doppelganged code.', hiddenNoFile.map((m) => `Base ${m.Base}  MappedPath=${m.MappedPath ?? 'N/A'}`).join('\n'), ['T1055', 'T1620'], lf, pid, proc);
      mark(pid, 'image memory with no file and no loader entry');
    }
    // C. main image: the .exe in the load list should be the process itself, from where the PEB says
    const exes = mods.filter((m) => !empty(m.MappedPath) && /\.exe$/i.test(m.MappedPath) && yes(m.InLoad));
    const own = exes.find((m) => sameName(baseName(m.MappedPath), proc));
    if (exes.length && !own) {
      add(sens ? 'critical' : 'high', `${proc} (PID ${pid}) main module maps ${baseName(exes[0].MappedPath)}, not ${proc}`, 'The executable registered in the loader list is a different file from the process name: process hollowing or PEB masquerading.', exes.map((m) => `${m.Base} ${m.MappedPath}`).join('\n'), ['T1055.012', 'T1036.005'], lf, pid, proc);
      mark(pid, 'main image mismatch');
    } else if (own) {
      const peb = procPath.get(pid); const mp = norm(own.MappedPath);
      if (peb && !peb.toLowerCase().endsWith(mp.toLowerCase().replace(/^[a-z]:/, '')) && !mp.toLowerCase().endsWith(peb.toLowerCase().replace(/^[a-z]:/, ''))) {
        add('high', `${proc} (PID ${pid}): PEB path and mapped image differ`, `PEB says ${peb}, the mapped file is ${mp}. One of them was changed in memory.`, `${peb}\n${mp}`, ['T1036.005', 'T1055.012'], lf, pid, proc);
        mark(pid, 'PEB path differs from mapped image');
      }
      const wl = wrongLocation(mp);
      if (wl) { add('critical', `${proc} (PID ${pid}) runs from ${mp}`, `${wl.desc || wl.name} normally lives in ${wl.expected}.`, mp, ['T1036.005'], lf, pid, proc); mark(pid, 'system process image in wrong folder'); }
      if (!yes(own.InLoad) || !yes(own.InMem)) { add('medium', `${proc} (PID ${pid}) main module partly unlinked from the loader lists`, `InLoad=${own.InLoad} InMem=${own.InMem}`, mp, ['T1564', 'T1055'], lf, pid, proc); }
    }
    // D. DLLs the loader is half aware of (unlinking from one or two lists hides a DLL from tools that walk only that list)
    const partial = mods.filter((m) => !empty(m.MappedPath) && /\.dll$/i.test(m.MappedPath) && (yes(m.InLoad) || yes(m.InMem)) && yes(m.InLoad) !== yes(m.InMem) && !/\\(wow64|wow64win|wow64cpu|wow64base|wow64con|xtajit)\.dll$/i.test(m.MappedPath));
    if (partial.length) { add(sens ? 'high' : 'medium', `${proc} (PID ${pid}) has ${partial.length} DLL(s) unlinked from some loader lists`, 'A DLL present in one PEB list but missing from another was unlinked on purpose.', partial.slice(0, 20).map((m) => `${m.MappedPath} InLoad=${m.InLoad} InInit=${m.InInit} InMem=${m.InMem}`).join('\n'), ['T1055.001', 'T1564'], lf, pid, proc); mark(pid, 'partially unlinked DLL'); }
    // E. sensitive processes loading DLLs from outside the system folders (LSASS security packages, injected DLLs)
    const PF = /^([a-z]:)?\\program files( \(x86\))?\\/i;
    const foreign = mods.filter((m) => !empty(m.MappedPath) && /\.(dll|cpl|ocx|drv)$/i.test(m.MappedPath) && !SYSDIR.test(norm(m.MappedPath)));
    const outside = foreign.filter((m) => !PF.test(norm(m.MappedPath)));
    const vendor = foreign.filter((m) => PF.test(norm(m.MappedPath)));
    if (outside.length && sens) {
      add(cred ? 'critical' : 'high', `${proc} (PID ${pid}) loaded ${outside.length} DLL(s) from outside the Windows and Program Files folders`, cred ? 'LSASS only loads Microsoft and security vendor DLLs. A DLL from anywhere else is a candidate malicious security package, password filter or injected DLL.' : 'Core Windows processes do not load DLLs from user or temporary folders. Injected or sideloaded.', outside.slice(0, 20).map((m) => `${m.MappedPath} InLoad=${m.InLoad} InInit=${m.InInit} InMem=${m.InMem}`).join('\n'), cred ? ['T1547.005', 'T1556.002', 'T1055.001'] : ['T1055.001', 'T1574.002'], lf, pid, proc);
      mark(pid, 'DLL from outside system folders');
    }
    if (vendor.length && cred) add('medium', `${proc} (PID ${pid}) loaded ${vendor.length} third-party DLL(s) from Program Files`, 'Usually an AV/EDR or smart card vendor. Confirm each one is expected.', vendor.slice(0, 20).map((m) => m.MappedPath).join('\n'), ['T1547.005'], lf, pid, proc);
    // F. fully hidden DLLs with a path (kept, but resource-only image loads also look like this)
    const unlinked = mods.filter((m) => !empty(m.MappedPath) && /\.dll$/i.test(m.MappedPath) && !yes(m.InLoad) && !yes(m.InInit) && !yes(m.InMem));
    for (const m of unlinked.slice(0, 20)) {
      const odd = !SYSDIR.test(norm(m.MappedPath)); // System32 DLLs mapped as resources look the same, so only odd paths count
      if (odd) { add(sens ? 'critical' : 'high', `Unlinked DLL in ${proc} (PID ${pid}): ${baseName(m.MappedPath)}`, 'Mapped as an image but missing from all three loader lists: hidden or reflectively loaded. (DLLs loaded only as resources also look like this; they live in System32.)', m.MappedPath, ['T1055.001', 'T1620'], lf, pid, proc); mark(pid, 'DLL unlinked from all lists'); }
    }
  }

  // ------------------------------------------------------------- malfind, now with process context
  const mf = shared.volFile.malfind;
  const byPidM = new Map();
  for (const r of v.malfind || []) { const k = String(r.PID); if (!byPidM.has(k)) byPidM.set(k, []); byPidM.get(k).push(r); }
  for (const [pid, regs] of byPidM) {
    const proc = String(regs[0].Process || '');
    const hex = (r) => String(r.Hexdump || '').toLowerCase().replace(/[^0-9a-f ]/g, ' ');
    const erased = regs.filter((r) => !/^\s*4d 5a/.test(hex(r)) && /50 45 00 00/.test(hex(r)));
    if (erased.length) { add('critical', `${proc} (PID ${pid}): PE image with its MZ header wiped in private memory`, 'A "PE\\0\\0" signature without the MZ in front is a reflectively loaded DLL that erased its header to avoid scanners.', erased.map((r) => `${r['Start VPN']} ${r.Protection}\n${String(r.Hexdump || '').slice(0, 200)}`).join('\n'), ['T1620', 'T1027'], mf, pid, proc); mark(pid, 'erased PE header'); }
    if (CRED.test(proc) || (SENSITIVE.test(proc) && !JIT.test(proc))) { add(CRED.test(proc) ? 'critical' : 'high', `${proc} (PID ${pid}) has ${regs.length} private executable region(s) (malfind)`, 'This process has no reason to hold executable private memory. Expect injected code.', regs.slice(0, 10).map((r) => `${r['Start VPN']}-${r['End VPN']} ${r.Protection} ${r.Tag || ''}`).join('\n'), ['T1055', ...(CRED.test(proc) ? ['T1003.001'] : [])], mf, pid, proc); mark(pid, 'malfind region'); }
    else mark(pid, 'malfind region');
  }

  // ------------------------------------------------------------- suspicious threads / hollowing already flag; fold them into the picture
  for (const r of v.suspicious_threads || []) mark(r.PID, 'thread starting outside a module');
  for (const r of v.hollowprocesses || []) mark(r.PID, 'hollowprocesses');
  for (const [pid, what] of shared.volMarks || []) if (what !== 'suspended thread') mark(pid, what);

  // ------------------------------------------------------------- correlation: one process, several independent signals
  for (const [pid, why] of injectedPids) {
    const kinds = [...new Set(why)];
    if (kinds.length < 2) continue;
    const proc = (v.pstree || v.pslist || []).find((r) => String(r.PID) === pid)?.ImageFileName || byPid.get(pid)?.[0]?.Process || byPidM.get(pid)?.[0]?.Process || `PID ${pid}`;
    ctx.finding({ sev: 'critical', category: 'Correlation', tool: 'Volatility 3', file: lf || mf, title: `Memory: code injection in ${proc} (PID ${pid}) confirmed by ${kinds.length} independent signals`, detail: kinds.join('; '), evidence: kinds.join('\n'), mitre: ['T1055'] });
    out.push(['critical', pid, proc, 'injection confirmed by several plugins', kinds.join('; ')]);
  }
  return out;
}
