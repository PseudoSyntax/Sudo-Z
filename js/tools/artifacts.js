// Tool wrappers for the non-registry, non-EVTX artifacts.
import { parsePrefetch } from '../parsers/prefetch.js';
import { parseLnk } from '../parsers/lnk.js';
import { parseAutomaticDest, parseCustomDest } from '../parsers/jumplist.js';
import { parseDollarI, parseInfo2, parseRecentFileCache, parseIisLog } from '../parsers/misc.js';
import { parseMft, siTimestomp, parseUsn, usnReasons, parseBoot } from '../parsers/ntfs.js';
import { SqliteDb } from '../parsers/sqlite.js';
import { filetimeToIso, unixToIso, webkitToIso, utf8 } from '../core/bytes.js';
import { classifyPath, classifyCommand, baseName, normPath } from '../ioc/heuristics.js';
import { isPrivateIp, decodePsB64 } from '../ioc/indicators.js';
import { runBstrings, KEYWORD_RULES } from '../core/strings.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });
export const MFT_ALL_COLS = ['Entry', 'Seq', 'InUse', 'Type', 'ParentPath', 'FileName', 'Size', 'SI Created', 'SI Modified', 'SI Accessed', 'SI RecordChange', 'FN Created', 'FN Modified', 'FN Accessed', 'FN RecordChange', 'Copied', 'ADS'];
const fmtPath = (p) => normPath(p).replace(/^<vol>/, 'C:');

// ---------------------------------------------------------------- PECmd
export function runPrefetch(u8, f, ctx) {
  const p = parsePrefetch(u8);
  const path = p.executablePath || p.executable;
  const res = ctx.exec_({ path: fmtPath(path), time: p.runTimes[0], tool: 'PECmd', file: f.name, source: 'Prefetch', extraDetail: `run count ${p.runCount}`, runCount: p.runCount });
  ctx.evidence({ artifact: 'Prefetch', path: fmtPath(path), time: p.runTimes[0], lastRuns: p.runTimes, runCount: p.runCount, file: f.name, pf: f.name.split(/[\\/]/).pop() });
  for (const t of p.runTimes) ctx.event({ time: t, tool: 'PECmd', file: f.name, type: 'Program execution (Prefetch)', desc: `${path} (run count ${p.runCount})` });
  for (const v of p.volumes) if (v.created) ctx.event({ time: v.created, tool: 'PECmd', file: f.name, type: 'Volume created (Prefetch)', desc: `${v.device} serial ${v.serial}` });
  // referenced files can reveal what the program touched
  const flaggedRefs = [];
  for (const ref of p.files) {
    const pc = classifyPath(fmtPath(ref));
    if (pc.sev && /\.(exe|dll|ps1|bat|vbs|js|hta|scr|sys)$/i.test(ref)) flaggedRefs.push([ref, pc.reasons.join('; ')]);
    if (/\\(lsass\.dmp|ntds\.dit)$/i.test(ref) || /\\(sam|security)$/i.test(ref) && /\\windows\\system32\\config\\/i.test(ref) === false) flaggedRefs.push([ref, 'credential material referenced']);
  }
  if (flaggedRefs.length) ctx.finding({ sev: 'medium', category: 'Execution', tool: 'PECmd', file: f.name, time: p.runTimes[0], title: `${p.executable} loaded/touched ${flaggedRefs.length} file(s) in suspicious locations`, evidence: flaggedRefs.slice(0, 15).map((x) => x[0]).join('\n'), mitre: ['T1574'] });
  if (/^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|psexec|psexesvc|schtasks|vssadmin|wevtutil|net|net1|whoami|nltest|bcdedit|ntdsutil|procdump|rar|7z|7za)\.exe$/i.test(p.executable) && !res?.sev)
    ctx.finding({ sev: 'info', category: 'Execution', tool: 'PECmd', file: f.name, time: p.runTimes[0], title: `LOLBin/admin tool executed: ${p.executable} (${p.runCount}x)`, detail: `Last runs: ${p.runTimes.slice(0, 3).join(', ')}` });
  return {
    tool: 'PECmd', artifact: `Prefetch v${p.version}${p.compressed ? ' (MAM compressed)' : ''}`,
    summary: `${p.executable} ran ${p.runCount}x, last ${p.runTimes[0] || 'n/a'}`,
    tables: [
      T('Prefetch summary', ['Field', 'Value'], [['Executable', p.executable], ['Full path', path], ['Hash', p.hash], ['Run count', p.runCount], ...p.runTimes.map((t, i) => [`Run time ${i}`, t]), ...p.volumes.map((v, i) => [`Volume ${i}`, `${v.device} serial ${v.serial} created ${v.created}`])]),
      T('Files referenced (first 10 seconds of execution)', ['#', 'Path', 'Flag'], p.files.map((x, i) => [i, x, flaggedRefs.find((y) => y[0] === x)?.[1] || ''])),
    ],
    notes: [],
    _prefetch: { name: p.executable, path, runCount: p.runCount, last: p.runTimes[0], runTimes: p.runTimes, file: f.name },
  };
}

// ---------------------------------------------------------------- LECmd / JLECmd
function gradeLnk(l, f, ctx, tool, extra = '') {
  const cmd = l.commandLine;
  const cc = classifyCommand(cmd);
  const pc = classifyPath(l.target);
  ctx.text(cmd, f.name); ctx.domains(l.arguments, f.name);
  if (l.tracker?.machineId) ctx.indicators.add('hostname', l.tracker.machineId, f.name, `LNK tracker ${extra}`);
  if (l.tracker && l.tracker.macAddress !== '00:00:00:00:00:00') ctx.indicators.add('mac_address', l.tracker.macAddress, f.name, `LNK tracker (${l.tracker.machineId})`);
  if (l.networkPath) ctx.indicators.add('unc', l.networkPath, f.name, tool);
  let sev = cc.sev && cc.score >= 4 ? (cc.score >= 6 ? 'high' : 'medium') : pc.sev;
  const reasons = [...cc.reasons, ...pc.reasons];
  if (l.arguments && /powershell|cmd(\.exe)?\s*\/c|mshta|wscript|cscript|rundll32|regsvr32|conhost.*--headless|forfiles|certutil|bitsadmin/i.test(l.target + ' ' + l.arguments) && (l.arguments.length > 120 || /http|\\\\|-e(nc)?\s|iex|frombase64|%[a-z]+%.{0,20}%/i.test(l.arguments))) { sev = 'high'; reasons.unshift('shortcut launches a script interpreter with suspicious arguments (malicious LNK)'); }
  if (l.arguments && l.arguments.length > 800) { sev = sev || 'medium'; reasons.push('very long arguments (padding to hide payload in Properties dialog)'); }
  if (l.volume?.driveType === 'Removable' && /\.(exe|bat|cmd|vbs|js|ps1|scr)$/i.test(l.target)) { sev = sev || 'low'; reasons.push('executable launched from removable media'); }
  if (sev) ctx.finding({ sev, category: 'Execution', tool, file: f.name, time: l.targetModified || l.targetCreated, title: `${tool === 'LECmd' ? 'Shortcut' : 'Jump list entry'}: ${reasons[0]}`, detail: reasons.join('; ') + (extra ? ` | ${extra}` : ''), evidence: cmd.slice(0, 1500), mitre: ['T1204.002', ...cc.mitre] });
  return sev;
}

/** The B/M/A of the target as the shortcut saw it, plus the $MFT entry/sequence from the shell item (MACB comparison). */
function lnkTimes(l, target, f, ctx, source) {
  if (!target || !/^[a-z]:\\/i.test(target) || !(l.targetCreated || l.targetModified)) return;
  const it = [...(l.idList || [])].reverse().find((x) => x && x.mft && x.mft.entry);
  ctx.fileTimes({ path: target, source, kind: 'recorded', file: f.name, B: l.targetCreated || '', M: l.targetModified || '', A: l.targetAccessed || '', entry: it ? it.mft.entry : null, seq: it ? it.mft.seq : null, size: l.fileSize });
}

export function runLnk(u8, f, ctx) {
  const l = parseLnk(u8);
  gradeLnk(l, f, ctx, 'LECmd');
  lnkTimes(l, l.localPath || l.target, f, ctx, 'LNK target times');
  for (const [t, k] of [[l.targetCreated, 'Target created'], [l.targetModified, 'Target modified'], [l.targetAccessed, 'Target accessed']]) ctx.event({ time: t, tool: 'LECmd', file: f.name, type: `LNK ${k}`, desc: l.target });
  const rows = [['Target', l.target], ['Arguments', l.arguments], ['Working dir', l.workingDir], ['Relative path', l.relativePath], ['Icon', l.iconLocation], ['Description', l.name], ['Target created', l.targetCreated], ['Target modified', l.targetModified], ['Target accessed', l.targetAccessed], ['File size', l.fileSize],
    ['Drive type', l.volume?.driveType || ''], ['Volume serial', l.volume?.serial || ''], ['Volume label', l.volume?.label || ''], ['Network path', l.networkPath], ['ID list path', l.idListPath || ''], ['Env var target', l.envTarget],
    ['Tracker machine ID', l.tracker?.machineId || ''], ['Tracker MAC', l.tracker?.macAddress || ''], ['Droid volume', l.tracker?.volumeDroid || ''], ['Droid file', l.tracker?.fileDroid || '']];
  return { tool: 'LECmd', artifact: 'Windows shortcut (LNK)', summary: `-> ${l.commandLine.slice(0, 160)}`, tables: [T('Shortcut details', ['Field', 'Value'], rows.filter((r) => r[1] !== '' && r[1] != null))], notes: [] };
}

export function runJumpList(u8, f, ctx, kind) {
  const j = kind === 'auto' ? parseAutomaticDest(u8, f.name) : parseCustomDest(u8, f.name);
  const rows = [];
  for (const e of j.entries) {
    const target = /\[URI\]/.test(e.target) && e.destPath ? e.destPath : e.target;
    rows.push([e.lastUsed || e.targetModified || '', target, e.arguments || '', e.accessCount ?? '', e.pinned ? 'Y' : '', e.hostname || e.tracker?.machineId || '', e.volume?.driveType || '', e.tracker?.macAddress || '']);
    gradeLnk({ ...e, target, commandLine: (target + ' ' + (e.arguments || '')).trim() }, f, ctx, 'JLECmd', `${j.appName || j.appId || 'unknown app'}`);
    lnkTimes(e, e.localPath || target, f, ctx, 'Jump list target times');
    if (e.lastUsed) ctx.event({ time: e.lastUsed, tool: 'JLECmd', file: f.name, type: `Jump list (${j.appName || j.appId})`, desc: target });
    if (j.appId === '1bc392b8e104a00e') ctx.indicators.add('rdp_target', target.replace(/^.*\\/, ''), f.name, 'mstsc jump list');
  }
  if (j.appId === '1bc392b8e104a00e' && rows.length) ctx.finding({ sev: 'low', category: 'Lateral Movement', tool: 'JLECmd', file: f.name, title: `Remote Desktop jump list: ${rows.length} recent connection(s)`, evidence: rows.map((r) => r[1]).join(', ').slice(0, 600), mitre: ['T1021.001'] });
  return { tool: 'JLECmd', artifact: `Jump list (${kind === 'auto' ? 'automatic' : 'custom'}) ${j.appName ? '- ' + j.appName : j.appId ? '- AppID ' + j.appId : ''}`, summary: `${j.entries.length} entries`, tables: [T('Jump list entries', ['LastUsed', 'Target', 'Arguments', 'AccessCount', 'Pinned', 'Host', 'DriveType', 'MAC'], rows)], notes: j.destListError ? ['DestList could not be fully decoded: ' + j.destListError] : [] };
}

// ---------------------------------------------------------------- RBCmd
function gradeDeleted(path, time, size, f, ctx) {
  ctx.event({ time, tool: 'RBCmd', file: f.name, type: 'File deleted (Recycle Bin)', desc: `${path} (${size} bytes)` });
  const pc = classifyPath(path);
  const ext = (path.match(/\.([a-z0-9]+)$/i) || [])[1]?.toLowerCase();
  let sev = pc.sev; const reasons = [...pc.reasons];
  if (!sev && /^(exe|dll|ps1|bat|vbs|js|hta|scr|msi|iso|img|lnk)$/.test(ext || '')) { sev = 'low'; reasons.push('executable/script deleted'); }
  if (/^(zip|7z|rar|tar|gz|cab)$/.test(ext || '') && size > 50 * 1024 * 1024) { sev = sev || 'medium'; reasons.push('large archive deleted (possible exfil staging clean-up)'); }
  if (/\.(dmp|kirbi|ccache|pcap|pcapng)$/i.test(path) || /lsass|ntds\.dit|\\sam$|\\system$/i.test(path)) { sev = 'high'; reasons.push('credential dump / capture artifact deleted'); }
  if (sev) ctx.finding({ sev, category: 'Defense Evasion', tool: 'RBCmd', file: f.name, time, title: `Deleted: ${baseName(path)}`, detail: reasons.join('; '), evidence: path, mitre: ['T1070.004'] });
}
export function runDollarI(u8, f, ctx) {
  const d = parseDollarI(u8);
  gradeDeleted(d.path, d.deleted, d.size, f, ctx);
  return { tool: 'RBCmd', artifact: `Recycle Bin $I (v${d.version})`, summary: `${d.path} deleted ${d.deleted}`, tables: [T('Deleted item', ['Field', 'Value'], [['Original path', d.path], ['Deleted', d.deleted], ['Size', d.size], ['Format', d.version === 2 ? 'Windows 10+' : 'Vista - 8.1']])], notes: [] };
}
export function runInfo2(u8, f, ctx) {
  const rows = parseInfo2(u8);
  for (const r of rows) gradeDeleted(r.path, r.deleted, r.size, f, ctx);
  return { tool: 'RBCmd', artifact: 'Recycle Bin INFO2 (XP)', summary: `${rows.length} deleted items`, tables: [T('Deleted items', ['Deleted', 'Path', 'Size', 'Index', 'Drive'], rows.map((r) => [r.deleted, r.path, r.size, r.index, String.fromCharCode(65 + r.drive)]))], notes: [] };
}

// ---------------------------------------------------------------- RecentFileCacheParser
export function runRecentFileCache(u8, f, ctx) {
  const list = parseRecentFileCache(u8);
  for (const p of list) ctx.exec_({ path: p, tool: 'RecentFileCacheParser', file: f.name, source: 'RecentFileCache' });
  return { tool: 'RecentFileCacheParser', artifact: 'RecentFileCache.bcf (Windows 7)', summary: `${list.length} programs`, tables: [T('Programs recently executed (no timestamps in this artifact)', ['#', 'Path'], list.map((p, i) => [i, p]))], notes: [] };
}

// ---------------------------------------------------------------- MFTECmd
const RANSOM_EXT = /\.(locked|encrypted|enc|crypt|crypted|cry|crypz|cerber\d?|locky|zepto|odin|thor|aesir|wallet|onion|wncry|wnry|wcry|ryk|ryuk|conti|lockbit|lockbit3|akira|blackcat|alphv|royal|play|hive|basta|clop|cl0p|phobos|eking|eight|devos|djvu|stop|makop|dharma|arena|java|cobra|nefilim|ragnar|sodinokibi|revil|maze|egregor|darkside|babyk|avoslocker|vice|quantum|rhysida|medusa|3am|trigona|cactus|hunters|8base|bianlian|mallox|lockfile|blackbasta|abcd|kraken|deadbolt|qlocker|7z\.encrypted|[a-z0-9]{8,10})$/i;
const RANSOM_NOTE = /^(readme.*decrypt.*|how_to_(decrypt|recover|restore).*|.*restore[-_]my[-_]files.*|.*_readme_?\.txt|!+.*read.*me.*!*\..*|decrypt[-_]instructions.*|recover[-_]files.*|.*ransom.*note.*|#?\s*how to back files.*|.*readme\.(hta|html|txt)$|.*-readme\.txt|restore_files_.*|info\.(hta|txt)|.*\.(hta)$)/i;

export function runMft(u8, f, ctx, shared) {
  const m = parseMft(u8);
  shared.mft = m;
  const flagged = [], zone = [], stomped = [];
  const noteDirs = new Map();
  const extCount = new Map();
  for (const r of m.rows) {
    if (r.isDir) continue;
    const full = `${r.parentPath}\\${r.name}`;
    const winPath = full.replace(/^\./, 'C:');
    const pc = classifyPath(winPath);
    if (pc.sev) flagged.push([r.si ? filetimeToIso(r.si.created) : '', winPath, r.inUse ? 'Yes' : 'Deleted', r.size, pc.sev, pc.reasons.join('; '), r.entry]);
    for (const ad of r.ads) if (ad.content) {
      const z = (ad.content.match(/ZoneId=(\d)/) || [])[1]; const host = (ad.content.match(/HostUrl=(\S+)/) || [])[1] || ''; const ref = (ad.content.match(/ReferrerUrl=(\S+)/) || [])[1] || '';
      zone.push([r.si ? filetimeToIso(r.si.created) : '', winPath, z, host, ref]);
      if (host && !/^about:/i.test(host)) ctx.indicators.add('url', host, f.name, `downloaded ${r.name}`);
      if (ref) ctx.indicators.add('url', ref, f.name, `referrer for ${r.name}`);
      ctx.event({ time: r.si && filetimeToIso(r.si.created), tool: 'MFTECmd', file: f.name, type: 'File downloaded (Zone.Identifier ADS)', desc: `${winPath} from ${host || 'zone ' + z}` });
      if (z === '3' || z === '4') {
        const exe = /\.(exe|dll|scr|msi|ps1|bat|cmd|vbs|js|jse|hta|lnk|iso|img|vhdx?|zip|7z|rar|one|docm|xlsm|jar)$/i.test(r.name);
        if (exe) ctx.finding({ sev: classifyPath(winPath).sev === 'high' || /\d+\.\d+\.\d+\.\d+|pastebin|transfer\.sh|anonfiles|mega\.nz|discord|ngrok|github\.io|raw\.githubusercontent/i.test(host) ? 'high' : 'medium', category: 'Initial Access', tool: 'MFTECmd', file: f.name, time: r.si && filetimeToIso(r.si.created), title: `Downloaded file with Mark-of-the-Web: ${r.name}`, detail: `ZoneId ${z}; HostUrl ${host || 'n/a'}; Referrer ${ref || 'n/a'}`, evidence: winPath, mitre: ['T1105', 'T1566'] });
      }
    }
    const ts = siTimestomp(r);
    if (ts && ts.length >= 2 && /\.(exe|dll|sys|ps1|bat|vbs|js|scr|hta|cmd)$/i.test(r.name) && (r.parentPath === '.' || /^\.\\(users|documents and settings|programdata|perflogs|temp|recycler|\$recycle\.bin)\\|\\temp(\\|$)|\\appdata\\|\\application data\\/i.test(r.parentPath))) {
      stomped.push([winPath, filetimeToIso(r.si.created), filetimeToIso(r.fn.created), ts.join('; ')]);
    }
    if (RANSOM_NOTE.test(r.name)) { const k = r.name.toLowerCase(); noteDirs.set(k, (noteDirs.get(k) || 0) + 1); }
    const ext = (r.name.match(/\.([^.\\]{2,12})$/) || [])[1]?.toLowerCase();
    if (ext) extCount.set(ext, (extCount.get(ext) || 0) + 1);
  }
  // findings: cap individual items
  flagged.sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 }[b[4]] - { critical: 4, high: 3, medium: 2, low: 1 }[a[4]]));
  const lows = flagged.filter((x) => x[4] === 'low');
  if (lows.length) ctx.finding({ sev: 'low', category: 'File System', tool: 'MFTECmd', file: f.name, title: `${lows.length} low-confidence files in user-writable/temporary locations (see MFT "Flagged files" table)`, evidence: lows.slice(0, 25).map((x) => x[1]).join('\n'), mitre: ['T1036'] });
  for (const x of flagged.filter((x) => x[4] !== 'low').slice(0, 150)) {
    ctx.finding({ sev: x[4], category: 'File System', tool: 'MFTECmd', file: f.name, time: x[0], title: `File ${x[2] === 'Deleted' ? '(deleted) ' : ''}in suspicious location: ${baseName(x[1])}`, detail: x[5], evidence: x[1], mitre: ['T1036', 'T1105'] });
    ctx.event({ time: x[0], tool: 'MFTECmd', file: f.name, type: 'Suspicious file created ($SI)', desc: x[1] });
    ctx.indicators.add('file_path', x[1], f.name, x[5]);
  }
  if (flagged.length - lows.length > 150) ctx.finding({ sev: 'info', category: 'File System', tool: 'MFTECmd', file: f.name, title: `${flagged.length - lows.length - 150} more suspicious-location files (see MFT table)`, detail: 'Individual findings capped at 150.' });
  if (stomped.length) ctx.finding({ sev: stomped.length > 20 ? 'medium' : 'high', category: 'Defense Evasion', tool: 'MFTECmd', file: f.name, title: `${stomped.length} executable(s) with timestomping indicators ($SI < $FN, zeroed fractions)`, evidence: stomped.slice(0, 20).map((s) => s[0]).join('\n'), mitre: ['T1070.006'] });
  for (const [n, c] of noteDirs) if (c >= 5) ctx.finding({ sev: 'critical', category: 'Impact', tool: 'MFTECmd', file: f.name, title: `Ransom note pattern: "${n}" present in ${c} directories`, mitre: ['T1486'] });
  const total = m.rows.length;
  for (const [e, c] of extCount) if (c > 300 && c / total > 0.05 && RANSOM_EXT.test('.' + e) && !/^(dll|exe|mui|png|jpg|xml|txt|manifest|cat|inf|pnf|js|htm|html|gif|ttf|nls|cab|mum|dat|log|etl|sys|ini|lnk|css|json|pf|ico|bin|tmp|db|config|resources|winmd|py|pyc|h|cpp|c|cs|java|class|go|rs|md|svg|ps1|psd1|psm1|xsd|xsl|properties|jar|so|a|o|pdb|lib|chm|hlp|ocx|ax|tlb|olb|cpl|scr|msi|msp|zip|7z|rar|wim|esd|vhd|vhdx|iso|mp3|mp4|wav|wma|wmv|avi|mov|doc|docx|xls|xlsx|ppt|pptx|pdf|csv)$/.test(e))
    ctx.finding({ sev: 'critical', category: 'Impact', tool: 'MFTECmd', file: f.name, title: `Mass file extension ".${e}" on ${c} files (${Math.round((c / total) * 100)}% of volume): possible ransomware encryption`, mitre: ['T1486'] });
  const ft = (v) => (v ? filetimeToIso(v) || '' : '');
  const all = m.rows.map((r) => [r.entry, r.seq, r.inUse ? 'Y' : 'N', r.isDir ? 'Dir' : 'File', r.parentPath, r.name, r.size, ft(r.si?.created), ft(r.si?.modified), ft(r.si?.accessed), ft(r.si?.recordChanged), ft(r.fn?.created), ft(r.fn?.modified), ft(r.fn?.accessed), ft(r.fn?.recordChanged), r.si && r.si.modified + 10000000n < r.si.created ? 'Y' : '', r.ads.map((a) => a.name).join(';')]);
  return {
    tool: 'MFTECmd', artifact: '$MFT', summary: `${m.rows.length} file records (${m.rows.filter((r) => !r.inUse).length} deleted), ${flagged.length} flagged, ${zone.length} Zone.Identifier streams`,
    tables: [
      T('Flagged files', ['$SI Created', 'Path', 'InUse', 'Size', 'Severity', 'Reasons', 'Entry'], flagged),
      T('Downloaded files (Zone.Identifier ADS)', ['$SI Created', 'Path', 'ZoneId', 'HostUrl', 'ReferrerUrl'], zone),
      T('Timestomping candidates', ['Path', '$SI Created', '$FN Created', 'Reasons'], stomped),
      T('All MFT entries', MFT_ALL_COLS, all, 'MACB: B = Created (born), M = Modified, A = Accessed, C = $MFT record change. Copied = M earlier than B (file copied or extracted with its M kept).'),
    ],
    notes: m.bad ? [`${m.bad} records failed fixup (torn or corrupt).`] : [],
  };
}

export function runUsn(u8, f, ctx, shared) {
  const rows = parseUsn(u8);
  const mft = shared.mft;
  const pathOf = (r) => (mft ? mft.pathOf(r.parent).replace(/^\./, 'C:') : `<parent ${r.parent}-${r.parentSeq}>`);
  const out = [];
  const renamedTo = new Map(); let deletes = 0;
  const flagged = [];
  for (const r of rows) {
    const reason = usnReasons(r.reason);
    out.push([r.time, r.name, reason, r.entry, r.seq, r.parent, mft ? pathOf(r) : '', r.usn]);
    if (r.reason & 0x200) deletes++;
    if (r.reason & 0x2000) { const ext = (r.name.match(/\.([^.]{2,12})$/) || [])[1]?.toLowerCase(); if (ext) renamedTo.set(ext, (renamedTo.get(ext) || 0) + 1); }
    if ((r.reason & 0x100) && /\.(exe|dll|ps1|bat|vbs|js|hta|scr|sys)$/i.test(r.name)) {
      const full = mft ? `${pathOf(r)}\\${r.name}` : r.name;
      const pc = classifyPath(full);
      if (pc.sev || (!mft && pc.tool)) flagged.push([r.time, full, pc.reasons.join('; '), pc.sev || 'low']);
    }
  }
  for (const x of flagged.slice(0, 100)) { ctx.finding({ sev: x[3], category: 'File System', tool: 'MFTECmd', file: f.name, time: x[0], title: `USN: executable created ${baseName(x[1])}`, detail: x[2], evidence: x[1], mitre: ['T1105'] }); ctx.event({ time: x[0], tool: 'MFTECmd ($J)', file: f.name, type: 'Executable created (USN)', desc: x[1] }); }
  for (const [e, c] of renamedTo) if (c > 200 && RANSOM_EXT.test('.' + e)) ctx.finding({ sev: 'critical', category: 'Impact', tool: 'MFTECmd', file: f.name, title: `USN: ${c} files renamed to .${e} (encryption pattern)`, mitre: ['T1486'] });
  if (deletes > 5000) ctx.finding({ sev: 'medium', category: 'Impact', tool: 'MFTECmd', file: f.name, title: `USN: ${deletes} file deletions recorded`, detail: 'High deletion volume can indicate wiping or ransomware.', mitre: ['T1485', 'T1070.004'] });
  for (const r of rows) if ((r.reason & 0x200) && /\.(evtx|pf|lnk|log|automaticdestinations-ms)$/i.test(r.name)) ctx.event({ time: r.time, tool: 'MFTECmd ($J)', file: f.name, type: 'Forensic artifact deleted (USN)', desc: r.name });
  const pfDel = rows.filter((r) => (r.reason & 0x200) && /\.pf$/i.test(r.name)).length;
  if (pfDel > 20) ctx.finding({ sev: 'high', category: 'Defense Evasion', tool: 'MFTECmd', file: f.name, title: `USN: ${pfDel} Prefetch files deleted`, detail: 'Bulk prefetch deletion is anti-forensics.', mitre: ['T1070.004'] });
  return { tool: 'MFTECmd', artifact: '$UsnJrnl:$J', summary: `${rows.length} USN records${mft ? ' (paths resolved via $MFT)' : ' (submit $MFT alongside to resolve paths)'}`, tables: [T('USN journal', ['Time', 'Name', 'Reasons', 'Entry', 'Seq', 'ParentEntry', 'ParentPath', 'USN'], out)], notes: mft ? [] : ['Parent paths are unresolved. Include the $MFT in the same submission for full paths.'] };
}

export function runBoot(u8, f) {
  const b = parseBoot(u8);
  return { tool: 'MFTECmd', artifact: '$Boot', summary: `NTFS volume serial ${b.serial}`, tables: [T('$Boot', ['Field', 'Value'], Object.entries(b))], notes: [] };
}

// ---------------------------------------------------------------- SQLECmd / WxTCmd
const SHARE_HOSTS = /(pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|temp\.sh|anonfiles|file\.io|gofile\.io|mega\.nz|mediafire|sendspace|wetransfer|dropmefiles|ufile\.io|catbox\.moe|filebin|ngrok|trycloudflare|workers\.dev|duckdns|no-ip|ddns\.net|discord(app)?\.com\/attachments|cdn\.discordapp|api\.telegram\.org|anydesk\.com\/download|rustdesk|ngrok\.com\/download|rclone\.org|mimikatz|gentilkiwi|github\.com\/(gentilkiwi|bloodhoundad|byt3bl33d3r|fortra|ParrotSec|SecureAuthCorp|GhostPack|PowerShellMafia|samratashok|rapid7|carlospolop|AlessandroZ|outflanknl|its-a-feature|BishopFox|HavocFramework))/i;

function gradeUrl(url, title, time, f, ctx, kind) {
  ctx.text(url, f.name);
  const host = url.replace(/^[a-z]+:\/\//i, '').split(/[/:?#]/)[0];
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) && !isPrivateIp(host)) return ctx.finding({ sev: 'medium', category: 'Command and Control', tool: 'SQLECmd', file: f.name, time, title: `Browser ${kind} raw-IP URL`, evidence: url, mitre: ['T1071.001'] });
  if (SHARE_HOSTS.test(url)) ctx.finding({ sev: /mimikatz|gentilkiwi|GhostPack|PowerShellMafia|BishopFox|HavocFramework|bloodhound/i.test(url) ? 'high' : 'low', category: 'Command and Control', tool: 'SQLECmd', file: f.name, time, title: `Browser ${kind} file-share / tunnelling / offensive-tool site`, evidence: url, detail: title || '', mitre: ['T1105', 'T1567'] });
}

function chromeHistory(db, f, ctx, tables) {
  const urls = db.table('urls') || [];
  const rows = urls.map((u) => [webkitToIso(u.last_visit_time), u.url, u.title, u.visit_count, u.typed_count]);
  tables.push(T('Browser history (urls)', ['LastVisit', 'URL', 'Title', 'Visits', 'Typed'], rows.sort((a, b) => (b[0] || '').localeCompare(a[0] || ''))));
  for (const r of rows) { ctx.event({ time: r[0], tool: 'SQLECmd', file: f.name, type: 'Web visit (Chromium)', desc: r[1] }); gradeUrl(r[1] || '', r[2], r[0], f, ctx, 'visited'); }
  const dl = db.table('downloads');
  if (dl) {
    const chains = new Map(); for (const c of db.table('downloads_url_chains') || []) { if (!chains.has(c.id)) chains.set(c.id, []); chains.get(c.id)[c.chain_index] = c.url; }
    const drows = dl.map((d) => [webkitToIso(d.start_time), d.target_path || d.current_path, (chains.get(d.id) || []).filter(Boolean).pop() || d.tab_url || '', d.referrer || d.tab_referrer_url || '', d.total_bytes, d.danger_type, d.mime_type || '']);
    tables.push(T('Downloads', ['Start', 'SavedTo', 'SourceURL', 'Referrer', 'Bytes', 'DangerType', 'MIME'], drows));
    for (const d of drows) {
      ctx.event({ time: d[0], tool: 'SQLECmd', file: f.name, type: 'File downloaded (Chromium)', desc: `${d[1]} <- ${d[2]}` });
      if (d[2]) ctx.indicators.add('url', d[2], f.name, `download -> ${d[1]}`);
      const risky = /\.(exe|dll|scr|msi|ps1|bat|cmd|vbs|js|jse|hta|lnk|iso|img|vhdx?|one|jar|zip|7z|rar|docm|xlsm)$/i.test(d[1] || '');
      if (risky || (d[5] && d[5] !== 0)) {
        const host = (d[2] || '').replace(/^[a-z]+:\/\//i, '').split(/[/:?#]/)[0];
        const sev = SHARE_HOSTS.test(d[2]) || /^\d+\.\d+\.\d+\.\d+$/.test(host) || (d[5] && ![0, 4].includes(d[5])) ? 'high' : classifyPath((d[1] || '').replace(/\//g, '\\')).tool ? 'high' : 'low';
        ctx.finding({ sev, category: 'Initial Access', tool: 'SQLECmd', file: f.name, time: d[0], title: `Browser downloaded ${baseName((d[1] || '').replace(/\//g, '\\'))}`, detail: `from ${d[2]}${d[5] ? ` (danger_type ${d[5]})` : ''}`, evidence: d[1], mitre: ['T1105', 'T1204.002'] });
      }
    }
  }
}

function firefoxHistory(db, f, ctx, tables) {
  const places = db.table('moz_places') || [];
  const byId = new Map(places.map((p) => [p.id, p]));
  const rows = places.filter((p) => p.last_visit_date).map((p) => [unixToIso(Number(p.last_visit_date) / 1e6), p.url, p.title, p.visit_count]);
  tables.push(T('Browser history (moz_places)', ['LastVisit', 'URL', 'Title', 'Visits'], rows.sort((a, b) => (b[0] || '').localeCompare(a[0] || ''))));
  for (const r of rows) { ctx.event({ time: r[0], tool: 'SQLECmd', file: f.name, type: 'Web visit (Firefox)', desc: r[1] }); gradeUrl(r[1] || '', r[2], r[0], f, ctx, 'visited'); }
  const attrs = new Map((db.table('moz_anno_attributes') || []).map((a) => [a.id, a.name]));
  const annos = (db.table('moz_annos') || []).filter((a) => attrs.get(a.anno_attribute_id) === 'downloads/destinationFileURI');
  if (annos.length) {
    const drows = annos.map((a) => [unixToIso(Number(a.dateAdded) / 1e6), decodeURIComponent(String(a.content).replace(/^file:\/\/\/?/, '')), byId.get(a.place_id)?.url || '']);
    tables.push(T('Downloads', ['Added', 'SavedTo', 'SourceURL'], drows));
    for (const d of drows) { ctx.event({ time: d[0], tool: 'SQLECmd', file: f.name, type: 'File downloaded (Firefox)', desc: `${d[1]} <- ${d[2]}` }); ctx.indicators.add('url', d[2], f.name, 'download'); if (/\.(exe|dll|scr|msi|ps1|bat|vbs|js|hta|lnk|iso|img|zip|7z|rar)$/i.test(d[1])) ctx.finding({ sev: SHARE_HOSTS.test(d[2]) ? 'high' : 'low', category: 'Initial Access', tool: 'SQLECmd', file: f.name, time: d[0], title: `Browser downloaded ${baseName(d[1].replace(/\//g, '\\'))}`, detail: `from ${d[2]}`, evidence: d[1], mitre: ['T1105'] }); }
  }
  const old = db.table('moz_downloads');
  if (old) tables.push(T('Downloads (legacy)', ['Start', 'Target', 'Source'], old.map((d) => [unixToIso(Number(d.startTime) / 1e6), d.target, d.source])));
}

function activitiesCache(db, f, ctx, tables) {
  const acts = db.table('Activity') || [];
  const rows = [];
  for (const a of acts) {
    let app = ''; let payload = {};
    try { const ids = JSON.parse(a.AppId); app = (ids.find((x) => /win32|x_exe_path/i.test(x.platform)) || ids[0] || {}).application || ''; } catch { }
    try { payload = JSON.parse(typeof a.Payload === 'string' ? a.Payload : new TextDecoder().decode(a.Payload || new Uint8Array())); } catch { }
    const start = unixToIso(a.StartTime), end = unixToIso(a.EndTime);
    rows.push([start, end, app, payload.displayText || '', payload.appDisplayName || '', payload.activationUri || payload.contentUri || '', a.ActivityType, unixToIso(a.LastModifiedTime)]);
    ctx.event({ time: start, tool: 'WxTCmd', file: f.name, type: `Windows Timeline (type ${a.ActivityType})`, desc: `${app} ${payload.displayText || ''}` });
    if (/^[a-z]:\\|^\{[0-9A-F-]+\}\\/i.test(app)) ctx.exec_({ path: app.replace(/^\{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7\}/i, 'C:\\Windows\\System32').replace(/^\{6D809377-6AF0-444B-8957-A3773F02200E\}/i, 'C:\\Program Files').replace(/^\{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E\}/i, 'C:\\Program Files (x86)'), time: start, tool: 'WxTCmd', file: f.name, source: 'Windows Timeline' });
  }
  tables.push(T('Windows 10/11 Timeline activities', ['Start', 'End', 'Application', 'DisplayText', 'AppDisplayName', 'ContentUri', 'Type', 'LastModified'], rows));
}

export function runSqlite(u8, f, ctx) {
  const db = new SqliteDb(u8);
  const names = db.tables().map((t) => t.toLowerCase());
  const tables = []; let tool = 'SQLECmd', artifact = 'SQLite database';
  const notes = [];
  if (names.includes('urls') && names.includes('visits')) { artifact = 'Chromium history (Chrome/Edge/Brave/Opera)'; chromeHistory(db, f, ctx, tables); }
  else if (names.includes('moz_places') || names.includes('moz_downloads')) { artifact = 'Firefox places'; firefoxHistory(db, f, ctx, tables); }
  else if (names.includes('activity') && names.includes('activityoperation')) { tool = 'WxTCmd'; artifact = 'ActivitiesCache.db (Windows Timeline)'; activitiesCache(db, f, ctx, tables); }
  else {
    // generic: table inventory + indicator sweep of text cells
    const inv = [];
    for (const t of db.tables()) {
      let n = 0;
      try { for (const row of db.rows(db.schema().find((s) => s.name === t).root)) { n++; if (n <= 20000) for (const v of row.values) if (typeof v === 'string' && v.length > 8) ctx.text(v, f.name); } } catch { }
      inv.push([t, n]);
    }
    tables.push(T('Tables', ['Table', 'Rows'], inv));
    notes.push('No SQLECmd map matched this database; table inventory and indicator sweep only.');
  }
  notes.push('Write-ahead log (-wal) contents are not merged. Submit the -wal file too and it will be string-scanned.');
  return { tool, artifact, summary: `${db.tables().length} tables`, tables, notes };
}

// ---------------------------------------------------------------- iisGeolocate (parse only)
const safeDecode = (s) => { try { return decodeURIComponent(s); } catch { return s.replace(/%([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))); } };
export function runIis(u8, f, ctx) {
  const { fields, rows } = parseIisLog(u8);
  const byIp = new Map(); const hits = [];
  const SQLI = /(union\s+(all\s+)?select|'\s*(or|and)\s+[\w'"@]+\s*(=|<|>|like)|@@version|sleep\(\s*\d+\s*\)|waitfor\s+delay|xp_cmdshell|information_schema|benchmark\(|convert\(\s*int|cast\(.{0,40}\s+as\s+(n?varchar|int)|char\(\d+\)\s*\+|;\s*(drop|insert|update|exec|declare|shutdown)\s|0x[0-9a-f]{16,}|80040e07|odbc_sql_server_driver|\[sql_server\]|ora-\d{5}|mysql_fetch|you have an error in your sql syntax)/i;
  const SHELL = /(cmd=|exec=|command=|c=whoami|whoami|powershell|cmd\.exe|\/bin\/sh|net(\s|%20|\+)user|ipconfig|systeminfo)/i;
  const EXPLOIT = /(\/autodiscover\/autodiscover\.json.{0,40}(powershell|@)|\/owa\/auth\/[^\/]+\.js|\/ecp\/(DDI|y\.js|[a-z]\.js)|\/aspnet_client\/[^\/]+\.aspx|\/owa\/auth\/[^\/]+\.aspx|\/mifs\/|\/vpn\/\.\.\/|\/cgi-bin\/.*\.\.%2f|\/\.env|\/wp-admin\/admin-ajax\.php\?action=revslider|\/telerik\.web\.ui\.dialoghandler|\/manager\/html|\/solr\/admin|\${jndi:)/i;
  const SCANNER = /(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|wpscan|nuclei|acunetix|nessus|openvas|burp|feroxbuster|ffuf|wfuzz|hydra|python-requests|go-http-client|curl\/|wget\/)/i;
  for (const r of rows) {
    const cip = r['c-ip'] || ''; const uri = `${r['cs-uri-stem'] || ''}${r['cs-uri-query'] && r['cs-uri-query'] !== '-' ? '?' + r['cs-uri-query'] : ''}`; const ua = r['cs(User-Agent)'] || ''; const st = r['sc-status'] || ''; const t = r.date && r.time ? `${r.date}T${r.time}Z` : null;
    const e = byIp.get(cip) || { n: 0, s404: 0, post: 0, first: t, last: t, uas: new Set() };
    e.n++; if (st === '404') e.s404++; if (r['cs-method'] === 'POST') e.post++; e.last = t; e.uas.add(ua); byIp.set(cip, e);
    let rule = null, sev = null;
    if (EXPLOIT.test(uri)) { rule = 'known exploitation path'; sev = 'critical'; }
    else if (/\.(aspx|ashx|asmx|asp|php|jsp|jspx)$/i.test(r['cs-uri-stem'] || '') && SHELL.test(r['cs-uri-query'] || '')) { rule = 'web shell command in query string'; sev = 'critical'; }
    else if (SQLI.test(safeDecode(uri).replace(/\+/g, ' '))) { rule = /80040e07|odbc|sql_server\]|ora-\d|sql syntax/i.test(uri) ? 'SQL injection with database error leaked' : 'SQL injection pattern'; sev = 'high'; }
    else if (SCANNER.test(ua)) { rule = `scanner user agent`; sev = 'low'; }
    if (rule) hits.push([t, sev, rule, cip, r['cs-method'] || '', uri, st, ua]);
  }
  const byRule = new Map();
  for (const h of hits) { const k = `${h[2]}|${h[3]}`; if (!byRule.has(k)) byRule.set(k, []); byRule.get(k).push(h); }
  for (const [k, hs] of byRule) { const [rule, cip] = k.split('|'); ctx.finding({ sev: hs[0][1], category: 'Initial Access', tool: 'iisGeolocate', file: f.name, time: hs[0][0], title: `IIS: ${rule} from ${cip} (${hs.length} request${hs.length > 1 ? 's' : ''})`, evidence: hs.slice(0, 5).map((h) => `${h[4]} ${h[5]} -> ${h[6]}`).join('\n'), mitre: [rule.includes('shell') ? 'T1505.003' : 'T1190'] }); }
  for (const [cip, e] of byIp) {
    if (cip && !isPrivateIp(cip) && /^\d/.test(cip)) ctx.indicators.add('ipv4', cip, f.name, `IIS client ${e.n} requests`);
    if (e.s404 > 300) ctx.finding({ sev: 'medium', category: 'Reconnaissance', tool: 'iisGeolocate', file: f.name, time: e.first, title: `IIS: ${cip} generated ${e.s404} 404s (content discovery / scanning)`, mitre: ['T1595.003'] });
  }
  for (const h of hits) if (h[1] !== 'low') ctx.event({ time: h[0], tool: 'iisGeolocate', file: f.name, type: `IIS ${h[2]}`, desc: `${h[3]} ${h[4]} ${h[5]}` });
  const ipRows = [...byIp].map(([ip, e]) => [ip, e.n, e.s404, e.post, e.first, e.last, [...e.uas].slice(0, 3).join(' || ')]).sort((a, b) => b[1] - a[1]);
  return { tool: 'iisGeolocate', artifact: 'IIS W3C log', summary: `${rows.length} requests from ${byIp.size} client IPs, ${hits.length} flagged`, tables: [T('Flagged requests', ['Time', 'Severity', 'Rule', 'ClientIP', 'Method', 'URI', 'Status', 'UserAgent'], hits), T('Client IPs (geolocation needs the MaxMind DB used by iisGeolocate; run offline)', ['ClientIP', 'Requests', '404s', 'POSTs', 'First', 'Last', 'UserAgents'], ipRows)], notes: ['Geolocation is not performed in-browser; use the IP list with your own GeoIP source.'] };
}

// ---------------------------------------------------------------- Sudo-Z extras: scripts, task XML, PS history
export function runText(u8, f, ctx, kind) {
  const text = /^\xff\xfe/.test(String.fromCharCode(u8[0], u8[1])) ? new TextDecoder('utf-16le').decode(u8) : utf8(u8);
  const tables = []; let artifact = 'Text';
  ctx.text(text.slice(0, 20 * 1024 * 1024), f.name); ctx.domains(text.slice(0, 2 * 1024 * 1024), f.name);
  if (kind === 'task') {
    artifact = 'Scheduled task XML (Windows\\System32\\Tasks)';
    const cmds = [...text.matchAll(/<Command>([^<]*)<\/Command>(?:\s*<Arguments>([^<]*)<\/Arguments>)?/g)].map((m) => `${m[1]} ${m[2] || ''}`.trim());
    const author = (text.match(/<Author>([^<]*)</) || [])[1] || ''; const date = (text.match(/<Date>([^<]*)</) || [])[1] || '';
    const hidden = /<Hidden>true<\/Hidden>/i.test(text); const com = (text.match(/<ClassId>([^<]*)</) || [])[1];
    if (hidden) ctx.finding({ sev: 'high', category: 'Persistence', tool: 'Sudo-Z', file: f.name, title: `Hidden scheduled task: ${f.name.split(/[\\/]/).pop()}`, detail: `Author ${author || 'n/a'}, registered ${date || 'n/a'}`, evidence: cmds.join('\n') || com || '', mitre: ['T1053.005', 'T1564'] });
    for (const c of cmds) ctx.persist({ mechanism: 'Scheduled task XML', name: f.name.split(/[\\/]/).pop(), command: c, time: date ? new Date(date).toISOString?.() : null, tool: 'Sudo-Z', file: f.name, alwaysReport: hidden ? 'medium' : null, mitre: ['T1053.005'] });
    tables.push(T('Task definition', ['Field', 'Value'], [['Author', author], ['Registered', date], ['Hidden', hidden], ['COM handler', com || ''], ...cmds.map((c, i) => [`Action ${i}`, c])]));
  } else if (kind === 'pshistory') {
    artifact = 'PowerShell PSReadLine history (ConsoleHost_history.txt)';
    const rows = [];
    text.split(/\r?\n/).forEach((line, i) => {
      if (!line.trim()) return;
      const cc = classifyCommand(line); const kw = KEYWORD_RULES.filter((k) => k.rx.test(line));
      const sev = kw.some((k) => k.sev === 'critical') ? 'critical' : kw.length ? 'high' : cc.sev;
      rows.push([i + 1, line, sev || '', [...kw.map((k) => k.title), ...cc.reasons].join('; ')]);
      if (sev) ctx.finding({ sev, category: 'Execution', tool: 'Sudo-Z', file: f.name, title: `PowerShell history line ${i + 1}: ${kw[0]?.title || cc.reasons[0]}`, evidence: line.slice(0, 1500), mitre: ['T1059.001', ...cc.mitre] });
    });
    tables.push(T('Commands typed in PowerShell', ['Line', 'Command', 'Severity', 'Reasons'], rows));
  } else {
    artifact = `Script / text (${(f.name.match(/\.([^.]+)$/) || [])[1] || 'txt'})`;
    const cc = classifyCommand(text.slice(0, 2 * 1024 * 1024));
    const kw = KEYWORD_RULES.filter((k) => k.rx.test(text.slice(0, 8 * 1024 * 1024)));
    const enc = [...text.matchAll(/[A-Za-z0-9+/]{200,}={0,2}/g)].slice(0, 3).map((m) => decodePsB64(m[0])).filter(Boolean);
    const sev = kw.some((k) => k.sev === 'critical') ? 'critical' : kw.length ? 'high' : cc.sev;
    if (sev) ctx.finding({ sev, category: 'Execution', tool: 'Sudo-Z', file: f.name, title: `Script content: ${kw[0]?.title || cc.reasons[0]}`, detail: [...kw.map((k) => k.title), ...cc.reasons].join('; '), evidence: text.slice(0, 1200), mitre: ['T1059', ...cc.mitre] });
    if (enc.length) { ctx.finding({ sev: 'medium', category: 'Defense Evasion', tool: 'Sudo-Z', file: f.name, title: 'Large base64 blob decodes to text', evidence: enc[0].slice(0, 800), mitre: ['T1027'] }); for (const e of enc) ctx.text(e, f.name + ' (decoded)'); }
    tables.push(T('Rule hits', ['Rule'], [...kw.map((k) => [k.title]), ...cc.reasons.map((r) => [r])]));
  }
  return { tool: 'Sudo-Z', artifact, summary: `${text.length} characters`, tables, notes: [] };
}

// ---------------------------------------------------------------- bstrings (generic fallback)
export function runGeneric(u8, f, ctx, reason) {
  const b = runBstrings(u8);
  ctx.text(b.text, f.name);
  for (const h of b.hits) ctx.finding({ sev: h.sev, category: 'Strings', tool: 'bstrings', file: f.name, title: `bstrings: ${h.title}`, evidence: h.text, mitre: [] });
  const pathHits = [];
  for (const m of b.text.matchAll(/[A-Za-z]:\\[^\r\n"<>|*?]{3,250}?\.(exe|dll|ps1|bat|vbs|js|hta|scr)\b/gi)) {
    const pc = classifyPath(m[0]); if (pc.sev) pathHits.push([m[0], pc.sev, pc.reasons.join('; ')]);
    if (pathHits.length > 500) break;
  }
  const uniq = [...new Map(pathHits.map((p) => [p[0].toLowerCase(), p])).values()];
  for (const p of uniq.slice(0, 40)) ctx.finding({ sev: p[1] === 'critical' ? 'high' : p[1] === 'high' ? 'medium' : 'low', category: 'Strings', tool: 'bstrings', file: f.name, title: `Executable path string: ${baseName(p[0])}`, detail: `${p[2]} (string evidence only, no timestamp)`, evidence: p[0] });
  return { tool: 'bstrings', artifact: reason || 'Unrecognised file', summary: `${b.count} strings${b.truncated ? ' (first 64 MB)' : ''}, ${b.hits.length} keyword hits, ${uniq.length} suspicious paths`, tables: [T('Keyword hits', ['Rule', 'Severity', 'String'], b.hits.map((h) => [h.title, h.sev, h.text])), T('Suspicious executable paths in strings', ['Path', 'Severity', 'Reasons'], uniq)], notes: [] };
}

// ---------------------------------------------------------------- Task Scheduler 1.0 (.job)
import { parseJob, parseEvt, parseIndx } from '../parsers/legacy.js';
export function runJob(u8, f, ctx) {
  const j = parseJob(u8);
  const name = f.name.split(/[\\/]/).pop();
  ctx.persist({ mechanism: 'Scheduled task (.job)', name, command: j.commandLine, tool: 'Sudo-Z', file: f.name, alwaysReport: /^at\d+\.job$/i.test(name) ? 'medium' : null, mitre: [/^at\d+\.job$/i.test(name) ? 'T1053.002' : 'T1053.005'] });
  if (j.lastRun) ctx.event({ time: j.lastRun.replace(' (local)', 'Z').replace(/Z+$/, 'Z'), tool: 'Sudo-Z', file: f.name, type: 'Scheduled task last run (.job, local time)', desc: `${name} -> ${j.commandLine}` });
  return { tool: 'Sudo-Z', artifact: 'Task Scheduler 1.0 job (.job)', summary: `${j.commandLine.slice(0, 140)} (${j.status})`, tables: [T('Job definition', ['Field', 'Value'], [['Application', j.application], ['Parameters', j.parameters], ['Working dir', j.workingDir], ['Author', j.author], ['Comment', j.comment], ['Status', j.status], ['Last run (local)', j.lastRun], ['Exit code', j.exitCode], ['Triggers', (j.triggers || []).map((t) => `${t.type} from ${t.begin}`).join('; ')], ['Job UUID', j.uuid]])], notes: [] };
}

// ---------------------------------------------------------------- legacy .evt (XP / 2003)
const XP_SEC = {
  517: ['critical', 'Security log cleared', 'T1070.001', 'Defense Evasion'], 624: ['medium', 'User account created', 'T1136', 'Persistence'], 626: ['low', 'User account enabled', 'T1098', 'Persistence'],
  628: ['low', 'Password set', 'T1098', 'Persistence'], 630: ['low', 'User account deleted', 'T1531', 'Impact'], 612: ['medium', 'Audit policy changed', 'T1562.002', 'Defense Evasion'],
  601: ['low', 'Service installed (Security)', 'T1543.003', 'Persistence'], 602: ['low', 'Scheduled task created', 'T1053.005', 'Persistence'],
};
export function runEvt(u8, f, ctx) {
  const recs = parseEvt(u8);
  const b = f.name.split(/[\\/]/).pop().toLowerCase();
  const channel = /secevent/.test(b) ? 'Security' : /sysevent/.test(b) ? 'System' : /appevent/.test(b) ? 'Application' : 'Unknown';
  const fails = new Map(); const notable = [];
  for (const r of recs) {
    const s = r.Strings || []; const blob = s.join(' | ');
    if (r.Computer) ctx.hosts.add(r.Computer);
    ctx.text(blob, f.name);
    const add = (sev, title, mitre, cat) => { ctx.finding({ sev, category: cat, tool: 'EvtxECmd (.evt)', file: f.name, time: r.TimeCreated, title: `${r.EventId} ${title}`, evidence: blob.slice(0, 1200), mitre: [mitre] }); notable.push([r.TimeCreated, sev, r.EventId, r.Provider, title, blob.slice(0, 300)]); };
    if (/security/i.test(r.Provider) || channel === 'Security') {
      if (XP_SEC[r.EventId]) { const [sev, t, m, c] = XP_SEC[r.EventId]; add(sev, `${t}: ${s[0] || ''}`, m, c); }
      if ([632, 636, 660].includes(r.EventId)) add(/administrators|domain admins|enterprise admins/i.test(blob) ? 'high' : 'low', `Member added to group ${s[2] || ''}`, 'T1098', 'Persistence');
      if (r.EventId >= 529 && r.EventId <= 539) { const src = s[11] || s[6] || '-'; const e = fails.get(src) || { n: 0, users: new Set(), first: r.TimeCreated }; e.n++; e.users.add(s[0]); fails.set(src, e); }
      if (r.EventId === 592) { ctx.exec_({ path: s[1] || '', tool: 'EvtxECmd (.evt)', file: f.name, time: r.TimeCreated, source: 'Security 592' }); ctx.event({ time: r.TimeCreated, tool: 'EvtxECmd (.evt)', file: f.name, type: '592 Process created', desc: s[1] || '' }); }
      if ((r.EventId === 528 || r.EventId === 540) && s[13] && /\d+\.\d+\.\d+\.\d+/.test(s[13])) { ctx.indicators.add(/^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(s[13]) ? 'internal_ip' : 'ipv4', s[13], f.name, `logon ${s[0]} type ${s[3]}`); if (s[3] === '10') ctx.event({ time: r.TimeCreated, tool: 'EvtxECmd (.evt)', file: f.name, type: 'RDP logon (528 type 10)', desc: `${s[0]} from ${s[13]}` }); }
    }
    if (r.Provider === 'Service Control Manager' && r.EventId === 7035 && /start/i.test(blob) && /psexesvc|remcom|paexec/i.test(blob)) add('high', `Remote execution service started: ${s[0]}`, 'T1569.002', 'Lateral Movement');
    if (r.Provider === 'Eventlog' && [6005, 6006, 6008].includes(r.EventId)) ctx.event({ time: r.TimeCreated, tool: 'EvtxECmd (.evt)', file: f.name, type: { 6005: 'Event log started (boot)', 6006: 'Clean shutdown', 6008: 'Unexpected shutdown' }[r.EventId], desc: r.Computer });
  }
  for (const [src, e] of fails) if (e.n >= 20 || (e.n >= 10 && e.users.size >= 5)) ctx.finding({ sev: 'high', category: 'Credential Access', tool: 'EvtxECmd (.evt)', file: f.name, time: e.first, title: `${e.n} failed logons from ${src} (${e.users.size} accounts)`, evidence: [...e.users].join(', '), mitre: ['T1110'] });
  return { tool: 'EvtxECmd (.evt)', artifact: `Legacy event log (.evt, ${channel})`, summary: `${recs.length} records`, tables: [T('Notable events', ['Time', 'Severity', 'EventId', 'Source', 'Rule', 'Strings'], notable), T('All events', ['TimeGenerated', 'EventId', 'Type', 'Source', 'Computer', 'User', 'Strings'], recs.map((r) => [r.TimeCreated, r.EventId, r.Type, r.Provider, r.Computer, r.UserId, (r.Strings || []).join(' | ').slice(0, 600)]))], notes: ['XP/2003 events have no message templates here; the inserted strings are shown raw.'] };
}

// ---------------------------------------------------------------- $I30
export function runIndx(u8, f, ctx, shared) {
  const rows = parseIndx(u8);
  const mft = shared.mft;
  const out = rows.map((r) => [r.slack ? 'SLACK (deleted)' : 'active', r.name, r.created, r.modified, r.recordChanged, r.accessed, r.size, r.entry, r.parent, mft ? mft.pathOf(r.parent).replace(/^\./, 'C:') : '']);
  for (const r of rows) {
    const full = mft ? `${mft.pathOf(r.parent).replace(/^\./, 'C:')}\\${r.name}` : r.name;
    const pc = classifyPath(full);
    if (r.slack) ctx.event({ time: r.created, tool: 'MFTECmd ($I30)', file: f.name, type: 'Deleted directory entry ($I30 slack)', desc: full });
    if (pc.sev || (r.slack && pc.tool)) ctx.finding({ sev: pc.sev || 'medium', category: 'File System', tool: 'MFTECmd', file: f.name, time: r.created, title: `$I30 ${r.slack ? 'slack (deleted) ' : ''}entry: ${r.name}`, detail: pc.reasons.join('; '), evidence: full, mitre: ['T1070.004'] });
  }
  return { tool: 'MFTECmd', artifact: '$I30 directory index', summary: `${rows.length} entries (${rows.filter((r) => r.slack).length} recovered from slack)`, tables: [T('$I30 entries', ['State', 'Name', 'Created', 'Modified', 'RecordChanged', 'Accessed', 'Size', 'Entry', 'ParentEntry', 'ParentPath'], out, 'Slack entries are names of files that were deleted or renamed out of this directory.')], notes: [] };
}
