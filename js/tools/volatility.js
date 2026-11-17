// Volatility 3 output analysis. Accepts the JSON / JSON-lines output of
// `vol -r json -f <image> windows.<plugin>` (one file per plugin), either
// dropped into the browser or produced by the local runner. Each file is
// identified by its column set (or file name) and graded; a final pass
// correlates plugins (e.g. psscan vs pslist for hidden processes).
import { classifyPath, classifyCommand, baseName, isLolbin } from '../ioc/heuristics.js';
import { isPrivateIp } from '../ioc/indicators.js';
import { KEYWORD_RULES } from '../core/strings.js';
import { utf8 } from '../core/bytes.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });

// column signatures (Volatility 3.2x TreeGrid column names)
const SIGS = [
  ['windows.pstree', ['PID', 'PPID', 'ImageFileName', 'Audit', 'Cmd', 'Path']],
  ['windows.pslist', ['PID', 'PPID', 'ImageFileName', 'Threads', 'Handles', 'CreateTime']],
  ['windows.cmdline', ['PID', 'Process', 'Args']],
  ['windows.netscan', ['Proto', 'LocalAddr', 'ForeignAddr', 'State', 'Owner']],
  ['windows.malfind', ['Protection', 'Hexdump', 'Start VPN']],
  ['windows.psxview', ['pslist', 'psscan', 'thrdscan']],
  ['windows.ldrmodules', ['InLoad', 'InInit', 'InMem', 'MappedPath']],
  ['windows.processghosting', ['DeletePending', 'DeleteOnClose']],
  ['windows.suspicious_threads', ['TID', 'VAD Path', 'Note']],
  ['windows.hollowprocesses', ['PID', 'Process', 'Notes']],
  ['windows.svcscan', ['Binary', 'Name', 'Display', 'State']],
  ['windows.dlllist', ['Base', 'Size', 'Name', 'Path', 'LoadCount']],
  ['windows.handles', ['HandleValue', 'GrantedAccess', 'Type']],
  ['windows.getsids', ['PID', 'Process', 'SID', 'Name']],
  ['windows.privileges', ['Privilege', 'Attributes']],
  ['windows.cmdscan', ['ConsoleInfo', 'Property', 'Data']],
  ['windows.drivermodule', ['Known Exception', 'Driver Name']],
  ['windows.unhooked_system_calls', ['Function', 'Distinct Implementations']],
  ['windows.registry.userassist', ['Focus Count', 'Time Focused']],
  ['windows.info', ['Variable', 'Value']],
  ['windows.filescan', ['Offset', 'Name']],
];

export function parseVolJson(u8) {
  const txt = utf8(u8).trim();
  let rows;
  if (txt.startsWith('[')) rows = JSON.parse(txt);
  else rows = txt.split(/\r?\n/).filter((l) => l.trim().startsWith('{')).map((l) => JSON.parse(l));
  const flat = [];
  const walk = (list, depth, parent) => { for (const r of list || []) { const { __children, ...rest } = r; flat.push({ ...rest, _depth: depth, _parent: parent }); if (Array.isArray(__children) && __children.length) walk(__children, depth + 1, rest.PID ?? rest.Pid); } };
  walk(Array.isArray(rows) ? rows : [rows], 0, null);
  return flat;
}

export function looksLikeVol(u8, name = '') {
  if (u8.length < 2) return false;
  const c = u8[0] === 0xef ? u8[3] : u8[0];
  if (c !== 0x5b && c !== 0x7b && c !== 0x0a) return false; // [ or {
  const head = utf8(u8.subarray(0, 4096));
  return /"__children"\s*:/.test(head) || (/^(windows|linux|mac)\.[a-z_.]+/i.test(name.split(/[\\/]/).pop()) && /\.json/i.test(name));
}

export function identifyPlugin(name, rows) {
  const b = name.split(/[\\/]/).pop();
  // windows.malware.malfind.json, windows.pslist.PsList.json, windows.netscan.jsonl
  const m = b.match(/^((?:windows|linux|mac)(?:\.[a-z0-9_]+)+?)(?:\.[A-Z][A-Za-z0-9]*)?\.jsonl?$/);
  if (m) return m[1].replace(/^windows\.malware\./, 'windows.');
  const keys = new Set(Object.keys(rows[0] || {}));
  for (const [p, cols] of SIGS) if (cols.every((c) => keys.has(c))) return p;
  return 'volatility (unknown plugin)';
}

const SYSTEM_PARENTS = { 'smss.exe': ['system', 'smss.exe'], 'csrss.exe': ['smss.exe', null], 'wininit.exe': ['smss.exe', null], 'winlogon.exe': ['smss.exe', null], 'services.exe': ['wininit.exe'], 'lsass.exe': ['wininit.exe'], 'lsaiso.exe': ['wininit.exe'], 'svchost.exe': ['services.exe', 'msmpeng.exe', 'svchost.exe'], 'taskhostw.exe': ['svchost.exe'], 'runtimebroker.exe': ['svchost.exe'], 'userinit.exe': ['winlogon.exe', 'dwm.exe'] };
const SINGLETON = ['lsass.exe', 'services.exe', 'wininit.exe', 'lsaiso.exe'];

function procName(r) { return String(r.ImageFileName || r.Process || r.Name || '').toLowerCase(); }

export function runVol(u8, f, ctx, shared) {
  const rows = parseVolJson(u8);
  const plugin = identifyPlugin(f.name, rows);
  shared.vol = shared.vol || {};
  const key = plugin.replace(/^windows\./, '');
  shared.vol[key] = (shared.vol[key] || []).concat(rows);
  shared.volFile = shared.volFile || {}; shared.volFile[key] = f.name;
  const tables = [];
  const cols = Object.keys(rows[0] || {}).filter((c) => !c.startsWith('_'));
  const note = (sev, title, detail, evidence, mitre, category = 'Memory', time = null) => ctx.finding({ sev, category, tool: 'Volatility 3', file: f.name, time, title: `${plugin}: ${title}`, detail, evidence, mitre });

  switch (key) {
    case 'pslist': case 'psscan': case 'pstree': {
      // per-process rules run once in finalizeVol on the best available list
      tables.push(T(`Processes (${key})`, ['PID', 'PPID', 'Name', 'CreateTime', 'ExitTime', 'Threads', 'Handles', 'Session', 'Wow64', ...(key === 'pstree' ? ['Cmd', 'Path'] : [])], rows.map((r) => [r.PID, r.PPID, `${'  '.repeat(r._depth || 0)}${r.ImageFileName}`, r.CreateTime, r.ExitTime, r.Threads, r.Handles, r.SessionId, r.Wow64, ...(key === 'pstree' ? [r.Cmd, r.Path] : [])])));
      break;
    }
    case 'cmdline': {
      for (const r of rows) {
        const args = String(r.Args || '');
        if (!args || /^Required memory|unable to read/i.test(args)) continue;
        const exe = (args.match(/^"([^"]+)"/) || args.match(/^(\S+)/) || [])[1] || r.Process;
        ctx.exec_({ path: exe, args, tool: 'Volatility 3', file: f.name, source: 'Memory cmdline', extraDetail: `PID ${r.PID}` });
        const kw = KEYWORD_RULES.filter((k) => k.rx.test(args));
        if (kw.length) note(kw[0].sev, `${kw[0].title} in process command line`, `PID ${r.PID} ${r.Process}`, args, ['T1059']);
      }
      tables.push(T('Command lines', ['PID', 'Process', 'Args'], rows.map((r) => [r.PID, r.Process, r.Args])));
      break;
    }
    case 'netscan': case 'netstat': {
      for (const r of rows) {
        const fa = String(r.ForeignAddr || ''); const owner = String(r.Owner || '');
        if (fa && !/^(\*|0\.0\.0\.0|::|-)$/.test(fa) && /^\d+\.\d+\.\d+\.\d+$/.test(fa)) {
          ctx.indicators.add(isPrivateIp(fa) ? 'internal_ip' : 'ipv4', fa, f.name, `${owner} PID ${r.PID} ${r.Proto} ${r.LocalPort}->${r.ForeignPort} ${r.State || ''}`);
          if (!isPrivateIp(fa) && /^(powershell|pwsh|rundll32|regsvr32|mshta|certutil|bitsadmin|msbuild|installutil|wscript|cscript|notepad|calc|cmd|svchost32|dllhost|wmic)\.exe$/i.test(owner)) note('high', `${owner} (PID ${r.PID}) connected to ${fa}:${r.ForeignPort}`, `${r.State || ''} created ${r.Created || ''}`, '', ['T1071', 'T1218'], 'Command and Control', r.Created);
          if (/^(4444|1337|31337|8888|9001|9050|6667|5555|50050)$/.test(String(r.ForeignPort))) note('medium', `Connection to suspicious port ${r.ForeignPort} by ${owner}`, `${fa}`, '', ['T1571'], 'Command and Control', r.Created);
          if (String(r.ForeignPort) === '3389') ctx.indicators.add('rdp_target', fa, f.name, `memory netscan ${owner}`);
        }
        if (/LISTEN/i.test(r.State || '') && /^(4444|1337|31337|8888|9001|5555|50050|8080)$/.test(String(r.LocalPort)) && !/^(system|svchost\.exe|lsass\.exe|services\.exe|java\.exe|httpd\.exe|nginx\.exe|node\.exe)$/i.test(owner)) note('medium', `${owner} listening on port ${r.LocalPort}`, `PID ${r.PID}`, '', ['T1571'], 'Command and Control');
        if (r.Created && fa && !/^(\*|0\.0\.0\.0|::)$/.test(fa)) ctx.event({ time: r.Created, tool: 'Volatility 3', file: f.name, type: 'Network connection (memory)', desc: `${owner} ${r.LocalAddr}:${r.LocalPort} -> ${fa}:${r.ForeignPort} ${r.State || ''}` });
      }
      tables.push(T('Network connections', ['Proto', 'Local', 'Foreign', 'State', 'PID', 'Owner', 'Created'], rows.map((r) => [r.Proto, `${r.LocalAddr}:${r.LocalPort}`, `${r.ForeignAddr}:${r.ForeignPort}`, r.State, r.PID, r.Owner, r.Created])));
      break;
    }
    case 'malfind': {
      const per = new Map();
      for (const r of rows) {
        const mz = /^4d 5a/i.test(String(r.Hexdump || '').trim());
        const shell = /^(fc 48 83 e4|fc e8|e8 00 00 00 00|55 8b ec|48 89 5c 24|4c 8b dc|eb fe)/i.test(String(r.Hexdump || '').trim());
        const p = per.get(r.PID) || { proc: r.Process, n: 0, mz: 0, shell: 0, regions: [] };
        p.n++; if (mz) p.mz++; if (shell) p.shell++; p.regions.push(`${r['Start VPN']} ${r.Protection}${mz ? ' MZ' : ''}${shell ? ' shellcode-like' : ''}`); per.set(r.PID, p);
      }
      for (const [pid, p] of per) {
        const jit = /^(chrome|msedge|firefox|iexplore|msmpeng|teams|ms-teams|slack|discord|code|node|java|javaw|dotnet|powershell_ise|onedrive|searchapp|smartscreen|devenv)\.exe$/i.test(p.proc || '');
        const sev = p.mz ? 'critical' : p.shell ? 'high' : jit ? 'low' : 'medium';
        note(sev, `${p.n} injected/executable private region(s) in ${p.proc} (PID ${pid})${p.mz ? ', contains PE header' : ''}`, jit && !p.mz ? 'Process uses JIT; RWX memory is common, review the disassembly.' : 'PAGE_EXECUTE_READWRITE private memory not backed by a file.', p.regions.slice(0, 10).join('\n'), ['T1055'], 'Defense Evasion');
      }
      tables.push(T('Malfind regions', ['PID', 'Process', 'Start', 'End', 'Protection', 'Tag', 'Hexdump'], rows.map((r) => [r.PID, r.Process, r['Start VPN'], r['End VPN'], r.Protection, r.Tag, String(r.Hexdump || '').slice(0, 96)])));
      break;
    }
    case 'psxview': {
      for (const r of rows) if (r.psscan && !r.pslist && !r['Exit Time']) note('high', `Process hidden from the active process list: ${r.Name} (PID ${r.PID})`, `pslist=${r.pslist} psscan=${r.psscan} thrdscan=${r.thrdscan} csrss=${r.csrss}`, '', ['T1014', 'T1564'], 'Defense Evasion');
      tables.push(T('Cross-view process listing', ['Name', 'PID', 'pslist', 'psscan', 'thrdscan', 'csrss', 'ExitTime'], rows.map((r) => [r.Name, r.PID, r.pslist, r.psscan, r.thrdscan, r.csrss, r['Exit Time']])));
      break;
    }
    case 'ldrmodules': {
      for (const r of rows) {
        const mp = String(r.MappedPath || '');
        if (r.InLoad === false && r.InInit === false && r.InMem === false && mp && /\.dll$/i.test(mp)) note('high', `Unlinked DLL in ${r.Process} (PID ${r.Pid}): ${baseName(mp)}`, 'Module missing from all three loader lists (hidden / reflectively loaded).', mp, ['T1055.001', 'T1620'], 'Defense Evasion');
        else if (mp && classifyPath(mp).sev && /\.dll$/i.test(mp)) note('medium', `DLL loaded from suspicious path in ${r.Process}: ${baseName(mp)}`, classifyPath(mp).reasons.join('; '), mp, ['T1574.002'], 'Defense Evasion');
      }
      tables.push(T('Loader modules', ['Pid', 'Process', 'Base', 'InLoad', 'InInit', 'InMem', 'MappedPath'], rows.map((r) => [r.Pid, r.Process, r.Base, r.InLoad, r.InInit, r.InMem, r.MappedPath])));
      break;
    }
    case 'hollowprocesses': for (const r of rows) note('critical', `Process hollowing in ${r.Process} (PID ${r.PID})`, r.Notes, '', ['T1055.012'], 'Defense Evasion'); tables.push(T('Hollow processes', cols, rows.map((r) => cols.map((c) => r[c])))); break;
    case 'processghosting': for (const r of rows) note('critical', `Process ghosting / delete-pending image: ${r.Process} (PID ${r.PID})`, `DeletePending=${r.DeletePending} DeleteOnClose=${r.DeleteOnClose}`, r.Path, ['T1055.013'], 'Defense Evasion'); tables.push(T('Process ghosting', cols, rows.map((r) => cols.map((c) => r[c])))); break;
    case 'suspicious_threads': for (const r of rows) note('high', `Suspicious thread in ${r.Process} (PID ${r.PID}, TID ${r.TID})`, r.Note, `${r.Address} ${r['VAD Path'] || ''}`, ['T1055'], 'Defense Evasion'); tables.push(T('Suspicious threads', cols, rows.map((r) => cols.map((c) => r[c])))); break;
    case 'svcscan': {
      for (const r of rows) {
        const bin = String(r['Binary (Registry)'] || r.Binary || ''); if (!bin || bin === 'N/A') continue;
        ctx.persist({ mechanism: 'Service in memory (svcscan)', name: r.Name, command: bin + (r.Dll && r.Dll !== 'N/A' ? ` [${r.Dll}]` : ''), tool: 'Volatility 3', file: f.name, mitre: ['T1543.003'] });
      }
      tables.push(T('Services (memory)', ['Name', 'Display', 'State', 'Start', 'Type', 'PID', 'Binary', 'Dll'], rows.map((r) => [r.Name, r.Display, r.State, r.Start, r.Type, r.PID, r['Binary (Registry)'] || r.Binary, r.Dll])));
      break;
    }
    case 'dlllist': {
      const flagged = [];
      for (const r of rows) { const pc = classifyPath(String(r.Path || '')); if (pc.sev && /\.dll$/i.test(r.Path || '')) flagged.push([r.PID, r.Process, r.Path, pc.reasons.join('; ')]); }
      const uniq = [...new Map(flagged.map((x) => [String(x[2]).toLowerCase(), x])).values()];
      for (const x of uniq.slice(0, 50)) note('medium', `${x[1]} loaded ${baseName(x[2])} from a suspicious path`, x[3], x[2], ['T1574.002'], 'Defense Evasion');
      tables.push(T('Flagged DLLs', ['PID', 'Process', 'Path', 'Reasons'], uniq));
      tables.push(T('All loaded DLLs', ['PID', 'Process', 'Base', 'Size', 'Name', 'Path', 'LoadTime'], rows.map((r) => [r.PID, r.Process, r.Base, r.Size, r.Name, r.Path, r.LoadTime])));
      break;
    }
    case 'handles': {
      for (const r of rows) if (r.Type === 'Process' && /lsass\.exe/i.test(r.Name || '') && !/^(lsass|csrss|wininit|services|svchost|msmpeng|lsm|smss|system)\.exe$/i.test(r.Process || '')) note('high', `${r.Process} (PID ${r.PID}) holds a handle to lsass.exe`, `GrantedAccess ${r.GrantedAccess}`, '', ['T1003.001'], 'Credential Access');
      tables.push(T('Handles', ['PID', 'Process', 'Type', 'GrantedAccess', 'Name'], rows.slice(0, 200000).map((r) => [r.PID, r.Process, r.Type, r.GrantedAccess, r.Name])));
      break;
    }
    case 'privileges': {
      for (const r of rows) if (/SeDebugPrivilege/i.test(r.Privilege) && /Enabled/i.test(String(r.Attributes)) && !/^(system|smss|csrss|wininit|services|lsass|svchost|winlogon|msmpeng|mrt|taskmgr|procexp64?|vmtoolsd)\.exe$|^system$/i.test(r.Process)) note('medium', `${r.Process} (PID ${r.PID}) has SeDebugPrivilege enabled`, 'Commonly enabled by credential dumpers and injectors.', '', ['T1134'], 'Privilege Escalation');
      tables.push(T('Privileges', cols, rows.map((r) => cols.map((c) => r[c]))));
      break;
    }
    case 'cmdscan': case 'consoles': {
      const lines = rows.filter((r) => /Cmd|Command|History|Screen/i.test(String(r.Property)) && r.Data);
      for (const r of lines) {
        const d = String(r.Data);
        const cc = classifyCommand(d); const kw = KEYWORD_RULES.filter((k) => k.rx.test(d));
        ctx.text(d, f.name);
        const sev = kw.some((k) => k.sev === 'critical') ? 'critical' : kw.length ? 'high' : cc.sev;
        if (sev) note(sev, `Console command in ${r.Process} memory: ${kw[0]?.title || cc.reasons[0]}`, '', d.slice(0, 1500), ['T1059.003', ...cc.mitre], 'Execution');
      }
      tables.push(T('Console history / buffers', ['PID', 'Process', 'Property', 'Data'], rows.map((r) => [r.PID, r.Process, r.Property, r.Data])));
      break;
    }
    case 'drivermodule': for (const r of rows) if (r['Known Exception'] === false) note('high', `Driver object without a module (possible rootkit): ${r['Driver Name']}`, r['Service Key'] || '', '', ['T1014'], 'Defense Evasion'); tables.push(T('Driver module check', cols, rows.map((r) => cols.map((c) => r[c])))); break;
    case 'unhooked_system_calls': for (const r of rows) if ((r['Distinct Implementations'] || 0) > 1) note('high', `System call ${r.Function} has ${r['Distinct Implementations']} different implementations (hooking / EDR unhooking)`, '', '', ['T1562.001'], 'Defense Evasion'); tables.push(T('System call implementations', cols, rows.map((r) => cols.map((c) => r[c])))); break;
    case 'info': {
      const info = Object.fromEntries(rows.map((r) => [r.Variable, r.Value]));
      if (info.SystemTime) ctx.event({ time: String(info.SystemTime).replace(' ', 'T').replace(/(\+00:00)?$/, '').replace(/Z?$/, 'Z'), tool: 'Volatility 3', file: f.name, type: 'Memory image captured (SystemTime)', desc: `${info.NtSystemRoot || ''} ${info.NtBuildLab || ''}` });
      tables.push(T('Image information', ['Variable', 'Value'], rows.map((r) => [r.Variable, r.Value])));
      break;
    }
    case 'registry.userassist': for (const r of rows) if (r.Name && r['Last Updated']) { ctx.exec_({ path: String(r.Name), time: r['Last Updated'], tool: 'Volatility 3', file: f.name, source: 'UserAssist (memory)' }); } tables.push(T('UserAssist (memory)', cols, rows.map((r) => cols.map((c) => r[c])))); break;
    default: {
      for (const r of rows.slice(0, 50000)) for (const v of Object.values(r)) if (typeof v === 'string' && v.length > 6) ctx.text(v, f.name);
      tables.push(T(`${plugin} output`, cols, rows.map((r) => cols.map((c) => r[c]))));
    }
  }
  return { tool: 'Volatility 3', artifact: `Volatility 3 ${plugin}`, summary: `${rows.length} rows`, tables, notes: [] };
}

/** Cross-plugin checks once every Volatility file has been processed. */
function processRules(list, extra, file, ctx) {
  const note = (sev, title, detail, evidence, mitre, category = 'Memory', time = null) => ctx.finding({ sev, category, tool: 'Volatility 3', file, time, title: `Memory: ${title}`, detail, evidence, mitre });
  const all = [...list, ...extra];
  const byPid = new Map(all.map((r) => [r.PID, r]));
  const counts = {};
  const seenName = new Set();
  for (const r of all) {
    const n = procName(r);
    if (!r.ExitTime) counts[n] = (counts[n] || 0) + 1;
    if (r.CreateTime) ctx.event({ time: r.CreateTime, tool: 'Volatility 3', file, type: 'Process started (memory)', desc: `${r.ImageFileName} PID ${r.PID} PPID ${r.PPID}${r.Cmd ? ' :: ' + r.Cmd : ''}` });
    const path = r.Path || '';
    if (path || r.Cmd) ctx.exec_({ path: path || r.ImageFileName, args: r.Cmd && r.Cmd !== path ? r.Cmd : '', time: r.CreateTime, tool: 'Volatility 3', file, source: 'Memory process' });
    else if (!seenName.has(n)) { seenName.add(n); const pc = classifyPath(r.ImageFileName); if (pc.tool) note(pc.toolSev === 'critical' ? 'critical' : 'high', `${pc.tool} process: ${r.ImageFileName} (PID ${r.PID})`, '', r.ImageFileName, ['T1059'], 'Memory', r.CreateTime); }
    const parent = byPid.get(r.PPID); const pn = parent ? procName(parent) : null;
    const exp = SYSTEM_PARENTS[n];
    if (exp && parent && !exp.includes(pn) && !r.ExitTime) note(n === 'lsass.exe' || n === 'services.exe' ? 'critical' : 'high', `${r.ImageFileName} (PID ${r.PID}) has unexpected parent ${parent.ImageFileName} (PID ${r.PPID})`, `Expected parent: ${exp.filter(Boolean).join(' or ')}`, '', ['T1036.005', 'T1055'], 'Memory', r.CreateTime);
    if (pn && /^(winword|excel|powerpnt|outlook|msaccess|onenote|eqnedt32)\.exe$/.test(pn) && /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe$/.test(n)) note('high', `Office process ${parent.ImageFileName} spawned ${r.ImageFileName} (PID ${r.PID})`, '', r.Cmd || '', ['T1204.002', 'T1566.001'], 'Initial Access', r.CreateTime);
    if (pn && /^(w3wp|httpd|nginx|tomcat\d*|php-cgi|sqlservr|java)\.exe$/.test(pn) && /^(cmd|powershell|pwsh|whoami|net|net1|certutil)\.exe$/.test(n)) note('critical', `Server process ${parent.ImageFileName} spawned ${r.ImageFileName} (web shell?)`, `PID ${r.PID}`, r.Cmd || '', ['T1505.003'], 'Persistence', r.CreateTime);
    if (pn === 'wmiprvse.exe' && /^(cmd|powershell|pwsh|rundll32|mshta)\.exe$/.test(n)) note('high', `WmiPrvSE spawned ${r.ImageFileName} (remote WMI execution)`, `PID ${r.PID}`, r.Cmd || '', ['T1047'], 'Lateral Movement', r.CreateTime);
  }
  for (const s of SINGLETON) if ((counts[s] || 0) > 1) note('critical', `${counts[s]} running instances of ${s}`, 'Only one instance should exist. Extra copies are a masquerading indicator.', all.filter((r) => procName(r) === s).map((r) => `PID ${r.PID} PPID ${r.PPID} ${r.CreateTime || ''}`).join('\n'), ['T1036.005']);
}

export function finalizeVol(shared, ctx) {
  const v = shared.vol; if (!v) return;
  const chosen = v.pstree ? 'pstree' : v.pslist ? 'pslist' : v.psscan ? 'psscan' : null;
  if (chosen) {
    const ids = new Set(v[chosen].map((r) => `${r.PID}|${procName(r)}`));
    const extra = chosen !== 'psscan' && v.psscan ? v.psscan.filter((r) => !ids.has(`${r.PID}|${procName(r)}`)) : [];
    processRules(v[chosen], extra, shared.volFile[chosen], ctx);
  }
  if (v.pslist && v.psscan) {
    const live = new Set(v.pslist.map((r) => `${r.PID}|${String(r.ImageFileName).toLowerCase()}`));
    for (const r of v.psscan) {
      if (r.ExitTime || live.has(`${r.PID}|${String(r.ImageFileName).toLowerCase()}`)) continue;
      ctx.finding({ sev: 'high', category: 'Defense Evasion', tool: 'Volatility 3', file: shared.volFile.psscan, time: r.CreateTime, title: `Hidden process: ${r.ImageFileName} (PID ${r.PID}) found by psscan but not in pslist`, detail: 'An active EPROCESS unlinked from the process list is a DKOM rootkit indicator (or a process that exited without an exit time).', mitre: ['T1014', 'T1564'] });
    }
  }
  if (v.cmdline && (v.pslist || v.pstree)) {
    const names = new Map((v.pstree || v.pslist).map((r) => [r.PID, String(r.ImageFileName || '').toLowerCase()]));
    for (const r of v.cmdline) {
      const exe = baseName(String(r.Args || '').replace(/^"([^"]+)".*$/, '$1').split(' ')[0]).toLowerCase();
      const n = names.get(r.PID);
      const mismatch = n && exe && /\.exe$/.test(exe) && (n.length >= 14 ? !exe.startsWith(n.slice(0, 14)) : exe !== n);
      if (mismatch) {
        if (isLolbin(n) || /^(svchost|lsass|csrss|explorer)\.exe$/.test(n)) ctx.finding({ sev: 'medium', category: 'Defense Evasion', tool: 'Volatility 3', file: shared.volFile.cmdline, title: `Process name ${n} does not match its command line image ${exe} (PID ${r.PID})`, detail: 'PEB command line differs from the EPROCESS image name (PEB masquerading or hollowing).', evidence: String(r.Args), mitre: ['T1036'] });
      }
    }
  }
}
