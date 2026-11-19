// Timeline Explorer inputs: the CSVs written by the Eric Zimmerman tools (run by
// hand, by Sudo-Z's EZ runner, or by KAPE's !EZParser module), plus the other
// CSVs analysts open in Timeline Explorer (Autoruns, Sigcheck, Hayabusa).
// Each CSV is recognised by its header, mapped onto the same analysis context
// the binary parsers feed, and kept as a table for the GRID view.
import { gradeEvtx } from './evtx.js';
import { classifyPath, classifyCommand, baseName, maxSev } from '../ioc/heuristics.js';
import { utf8 } from '../core/bytes.js';
import { MFT_ALL_COLS } from './artifacts.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });
const MAX_ROWS = 500000;

/** Fast RFC 4180 parser. Returns {head: string[], rows: string[][]} */
export function parseCsv(text, max = MAX_ROWS) {
  const t = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const rows = []; let row = []; let i = 0; const n = t.length;
  while (i < n) {
    let cell;
    if (t[i] === '"') {
      let j = i + 1; let s = '';
      for (;;) {
        const q = t.indexOf('"', j);
        if (q < 0) { s += t.slice(j); j = n; break; }
        s += t.slice(j, q);
        if (t[q + 1] === '"') { s += '"'; j = q + 2; } else { j = q + 1; break; }
      }
      cell = s; i = j;
    } else {
      let j = i; while (j < n && t[j] !== ',' && t[j] !== '\n' && t[j] !== '\r') j++;
      cell = t.slice(i, j); i = j;
    }
    row.push(cell);
    if (t[i] === ',') { i++; continue; }
    if (t[i] === '\r') i++;
    if (t[i] === '\n') i++;
    if (row.length > 1 || row[0] !== '') rows.push(row);
    row = [];
    if (rows.length > max) break;
  }
  if (row.length) rows.push(row);
  const head = (rows.shift() || []).map((h) => h.trim());
  return { head, rows, truncated: rows.length >= max };
}

const KINDS = [
  { id: 'autoruns', tool: 'Autoruns', label: 'Autoruns CSV', need: ['entry location', 'signer'] },
  { id: 'sigcheck', tool: 'Sigcheck', label: 'Sigcheck CSV', need: ['path', 'verified', 'publisher'] },
  { id: 'evtxecmd', tool: 'EvtxECmd', label: 'EvtxECmd CSV', need: ['eventid', 'timecreated', 'payload'] },
  { id: 'hayabusa', tool: 'Hayabusa', label: 'Hayabusa timeline CSV', need: ['ruletitle', 'level'] },
  { id: 'chainsaw', tool: 'Chainsaw', label: 'Chainsaw hunt CSV', need: ['detections', 'timestamp'] },
  { id: 'pecmd', tool: 'PECmd', label: 'PECmd CSV', need: ['executablename', 'runcount'] },
  { id: 'pecmd-tl', tool: 'PECmd', label: 'PECmd timeline CSV', need: ['runtime', 'executablename'] },
  { id: 'amcache-drv', tool: 'AmcacheParser', label: 'Amcache driver binaries CSV', need: ['drivername', 'driversigned'] },
  { id: 'amcache', tool: 'AmcacheParser', label: 'Amcache file entries CSV', need: ['sha1'], any: ['fullpath', 'lowercaselongpath'] },
  { id: 'shimcache', tool: 'AppCompatCacheParser', label: 'AppCompatCacheParser CSV', need: ['cacheentryposition', 'path'] },
  { id: 'jlecmd', tool: 'JLECmd', label: 'JLECmd CSV', need: ['appid', 'sourcefile'], any: ['localpath', 'targetidabsolutepath', 'path'] },
  { id: 'lecmd', tool: 'LECmd', label: 'LECmd CSV', need: ['sourcefile', 'arguments'], any: ['localpath', 'targetidabsolutepath'] },
  { id: 'mft', tool: 'MFTECmd', label: 'MFTECmd $MFT CSV', need: ['entrynumber', 'parentpath', 'filename', 'isdirectory'] },
  { id: 'usn', tool: 'MFTECmd', label: 'MFTECmd $J CSV', need: ['updatereasons', 'updatetimestamp'] },
  { id: 'rbcmd', tool: 'RBCmd', label: 'RBCmd CSV', need: ['deletedon', 'filename'] },
  { id: 'sbecmd', tool: 'SBECmd', label: 'SBECmd CSV', need: ['absolutepath', 'shelltype'] },
  { id: 'recmd', tool: 'RECmd', label: 'RECmd batch CSV', need: ['hivepath', 'keypath', 'valuename', 'valuedata'] },
  { id: 'recmd-plugin', tool: 'RECmd', label: 'RECmd plugin CSV', need: ['batchkeypath'] },
  { id: 'browser-downloads', tool: 'SQLECmd', label: 'Browser downloads CSV', need: ['downloadurl', 'targetpath'] },
  { id: 'browser-history', tool: 'SQLECmd', label: 'Browser history CSV', need: ['url'], any: ['visittime (utc)', 'lastvisitedtime (utc)', 'visit_time', 'lastvisittime'] },
  { id: 'srum', tool: 'SrumECmd', label: 'SrumECmd CSV', need: ['exeinfo'] },
  { id: 'wxtcmd', tool: 'WxTCmd', label: 'WxTCmd activity CSV', need: ['activitytype', 'executable'] },
  { id: 'recentfilecache', tool: 'RecentFileCacheParser', label: 'RecentFileCacheParser CSV', need: ['sourcefile', 'filename'], only: 2 },
];

/** Which EZ/Timeline Explorer CSV is this? */
export function detectEzCsv(name, u8) {
  if (!/\.(csv|tsv)$/i.test(name)) return null;
  const first = utf8(u8.subarray(0, 8192)).replace(/^﻿/, '').split(/\r?\n/)[0];
  if (!first || !first.includes(',')) return null;
  const head = parseCsv(first + '\n', 1).head.map((h) => h.toLowerCase());
  const has = (c) => head.includes(c);
  for (const k of KINDS) if (k.need.every(has) && (!k.any || k.any.some(has)) && (!k.only || head.length <= k.only)) return k;
  // any other EZ tool output (SQLECmd maps, RECmd plugins, SumECmd ...): keep as a table
  if (/_(sqlecmd|recmd|sumecmd|srumecmd|evtxecmd|pecmd|lecmd|jlecmd|mftecmd|rbcmd|sbecmd|wxtcmd|amcache|appcompatcache)[^/\\]*\.csv$/i.test(name) || /^\d{14,}_/.test(baseName(name))) return { id: 'generic', tool: 'Timeline Explorer CSV', label: 'EZ tool CSV' };
  return null;
}

const iso = (s) => {
  if (!s) return null; s = String(s).trim();
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(s)) return s.replace(' ', 'T').replace(/(\.\d+)?$/, (m) => m) + (/[zZ]|[+-]\d{2}:?\d{2}$/.test(s) ? '' : 'Z');
  const d = Date.parse(s); return isNaN(d) ? null : new Date(d).toISOString();
};
const truthy = (v) => /^(true|1|yes|y)$/i.test(String(v || '').trim());

export function runEzCsv(u8, f, ctx, kind, shared) {
  const { head, rows, truncated } = parseCsv(utf8(u8));
  const H = head.map((h) => h.toLowerCase());
  const col = (...names) => { for (const n of names) { const i = H.indexOf(n.toLowerCase()); if (i >= 0) return i; } return -1; };
  const get = (r, i) => (i >= 0 ? r[i] ?? '' : '');
  const notes = []; if (truncated) notes.push(`Only the first ${MAX_ROWS} rows were analysed.`);
  const tables = []; let summary = `${rows.length} rows`;
  const keep = () => tables.push(T(`${kind.label} (${baseName(f.name)})`, head, rows, 'Full CSV as written by the tool. Open the GRID tab to sort, filter and group it like Timeline Explorer.'));
  const src = (r, i) => get(r, i) || f.name;

  switch (kind.id) {
    case 'evtxecmd': {
      const cId = col('EventId'), cT = col('TimeCreated'), cCh = col('Channel'), cPr = col('Provider'), cCo = col('Computer'), cRec = col('EventRecordId', 'RecordNumber'), cP = col('Payload'), cSrc = col('SourceFile'), cUid = col('UserId'), cLvl = col('Level');
      const groups = new Map();
      for (const r of rows) {
        const data = {}; const list = [];
        try {
          const p = JSON.parse(get(r, cP) || '{}');
          const ed = p.EventData || p.UserData || {};
          const flat = (o, pre = '') => { for (const [k, v] of Object.entries(o)) { if (v && typeof v === 'object' && !Array.isArray(v)) flat(v, pre + k + '.'); else data[pre + k] = String(v); } };
          const items = ed.Data != null ? (Array.isArray(ed.Data) ? ed.Data : [ed.Data]) : null;
          if (items) for (const d of items) { if (d && typeof d === 'object') { if (d['@Name']) data[d['@Name']] = d['#text'] ?? ''; else list.push(d['#text'] ?? ''); } else list.push(String(d)); }
          else flat(ed);
        } catch { }
        const rec = { EventId: +get(r, cId), TimeCreated: iso(get(r, cT)), Channel: get(r, cCh), Provider: get(r, cPr), Computer: get(r, cCo), RecordNumber: +get(r, cRec) || undefined, UserId: get(r, cUid), Level: get(r, cLvl), Data: data, DataList: list, Keywords: '' };
        const k = src(r, cSrc); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(rec);
      }
      let notable = 0;
      for (const [k, recs] of groups) {
        const res = gradeEvtx({ records: recs, errors: 0, chunks: 0 }, { name: `${f.name} :: ${baseName(k)}` }, ctx);
        for (const t of res.tables) if (/Notable/.test(t.title)) { notable += t.rows.length; tables.push({ ...t, title: `${t.title} (${baseName(k)})` }); }
      }
      summary = `${rows.length} events from ${groups.size} log(s), ${notable} notable`;
      keep(); break;
    }
    case 'hayabusa': case 'chainsaw': {
      const cT = col('Timestamp', 'timestamp'), cR = col('RuleTitle', 'detections'), cL = col('Level'), cC = col('Computer'), cD = col('Details', 'Event Data'), cE = col('EventID', 'Event ID'), cM = col('MitreTags', 'MitreTactics');
      const LV = { crit: 'critical', critical: 'critical', high: 'high', med: 'medium', medium: 'medium', low: 'low', info: 'info', informational: 'info' };
      let n = 0;
      for (const r of rows) {
        const sev = LV[String(get(r, cL)).toLowerCase()] || 'low';
        if (get(r, cC)) ctx.hosts.add(get(r, cC));
        ctx.event({ time: iso(get(r, cT)), tool: kind.tool, file: f.name, type: `${kind.tool}: ${get(r, cR)}`, desc: get(r, cD).slice(0, 400) });
        if (sev === 'info' && n > 2000) continue;
        ctx.finding({ sev, category: 'Sigma rule', tool: kind.tool, file: f.name, time: iso(get(r, cT)), title: `${kind.tool}: ${get(r, cR)}${get(r, cE) ? ` (${get(r, cE)})` : ''}`, evidence: get(r, cD).slice(0, 1500), mitre: (get(r, cM).match(/T\d{4}(\.\d{3})?/g) || []) });
        ctx.text(get(r, cD), f.name); n++;
      }
      summary = `${rows.length} detections`; keep(); break;
    }
    case 'pecmd': {
      ctx.sawArtifact('Prefetch', f.name);
      const cN = col('ExecutableName'), cRun = col('RunCount'), cLast = col('LastRun'), cFiles = col('FilesLoaded'), cSrc = col('SourceFilename'), cH = col('Hash'), cFull = col('FullPath');
      const prev = H.map((h, i) => (/^previousrun\d$/.test(h) ? i : -1)).filter((i) => i >= 0);
      for (const r of rows) {
        const exe = get(r, cN); if (!exe) continue;
        const full = (get(r, cFull) || get(r, cFiles).split(/,\s*/).find((p) => p.toLowerCase().endsWith('\\' + exe.toLowerCase())) || exe).replace(/^\\VOLUME\{[^}]+\}/i, 'C:');
        const times = [get(r, cLast), ...prev.map((i) => get(r, i))].map(iso).filter(Boolean);
        ctx.exec_({ path: full, time: times[0], tool: 'PECmd', file: f.name, source: 'Prefetch', extraDetail: `run count ${get(r, cRun)}`, runCount: get(r, cRun) });
        ctx.evidence({ artifact: 'Prefetch', path: full, time: times[0], lastRuns: times, runCount: +get(r, cRun) || null, file: f.name, pf: baseName(get(r, cSrc)) });
        for (const t of times) ctx.event({ time: t, tool: 'PECmd', file: f.name, type: 'Program executed (Prefetch)', desc: `${full} (${baseName(get(r, cSrc))} ${get(r, cH)})` });
      }
      keep(); break;
    }
    case 'pecmd-tl': {
      const cT = col('RunTime'), cN = col('ExecutableName');
      for (const r of rows) { const p = get(r, cN).replace(/^\\VOLUME\{[^}]+\}/i, 'C:'); ctx.event({ time: iso(get(r, cT)), tool: 'PECmd', file: f.name, type: 'Program executed (Prefetch)', desc: p }); }
      keep(); break;
    }
    case 'amcache': {
      ctx.sawArtifact('Amcache', f.name);
      const cP = col('FullPath', 'LowerCaseLongPath', 'Path'), cS = col('SHA1'), cT = col('FileKeyLastWriteTimestamp', 'FileIDLastWriteTimestamp', 'KeyLastWriteTimestamp', 'LastWriteTime'), cPub = col('Publisher', 'CompanyName'), cOs = col('IsOsComponent'), cProd = col('ProductName');
      for (const r of rows) {
        const p = get(r, cP); if (!p) continue;
        const sha1 = get(r, cS).replace(/^0000/, '').toLowerCase();
        const t = iso(get(r, cT));
        ctx.event({ time: t, tool: 'AmcacheParser', file: f.name, type: 'Amcache entry (program present/executed)', desc: `${p} SHA1 ${sha1}` });
        ctx.exec_({ path: p, time: t, tool: 'AmcacheParser', file: f.name, source: 'Amcache', sha1: sha1 || null });
        ctx.evidence({ artifact: 'Amcache', path: p, time: t, sha1: sha1 || null, publisher: get(r, cPub) || '', file: f.name });
        if (/\.(exe|dll|sys|scr|com)$/i.test(p)) ctx.sign({ path: p, sha1, publisher: get(r, cPub) || '', osComponent: truthy(get(r, cOs)), kind: /\.sys$/i.test(p) ? 'driver' : /\.dll$/i.test(p) ? 'dll' : 'exe', source: 'Amcache', file: f.name, time: t });
        if (sha1 && !truthy(get(r, cOs)) && !get(r, cPub) && /\.exe$/i.test(p) && !/\\(program files|windows)\\/i.test(p)) ctx.indicators.add('sha1_unsigned_review', sha1, f.name, p);
        void cProd;
      }
      keep(); break;
    }
    case 'amcache-drv': {
      const cN = col('DriverName'), cS = col('DriverSigned'), cC = col('DriverCompany'), cK = col('DriverIsKernelMode'), cId = col('DriverId'), cT = col('KeyLastWriteTimestamp', 'DriverLastWriteTime');
      for (const r of rows) {
        const p = get(r, cN); if (!p) continue; const signed = truthy(get(r, cS)); const sha1 = get(r, cId).replace(/^0000/, '');
        // AmcacheParser writes False for values that are absent, so only a True is trusted here
        ctx.sign({ path: p, sha1, signed: signed ? true : null, publisher: get(r, cC), kind: 'driver', source: 'Amcache drivers', file: f.name, time: iso(get(r, cT)) });
        if (false && !signed && (cK < 0 || truthy(get(r, cK)))) ctx.finding({ sev: 'high', category: 'Defense Evasion', tool: 'AmcacheParser', file: f.name, time: iso(get(r, cT)), title: `Unsigned driver loaded: ${baseName(p)}`, evidence: `${p} SHA1 ${sha1}`, mitre: ['T1014', 'T1068'] });
      }
      keep(); break;
    }
    case 'shimcache': {
      ctx.sawArtifact('ShimCache', f.name);
      const cP = col('Path'), cT = col('LastModifiedTimeUTC'), cX = col('Executed'), cCs = col('ControlSet');
      const first = rows.length ? [...new Set(rows.map((r) => get(r, cCs)))].sort()[0] : '';
      for (const r of rows) {
        if (cCs >= 0 && get(r, cCs) !== first) continue;
        const p = get(r, cP); const pc = classifyPath(p);
        ctx.evidence({ artifact: 'ShimCache', path: p, time: iso(get(r, cT)), executed: cX >= 0 && get(r, cX) ? truthy(get(r, cX)) : null, file: f.name });
        ctx.event({ time: iso(get(r, cT)), tool: 'AppCompatCacheParser', file: f.name, type: `ShimCache entry${truthy(get(r, cX)) ? ' (executed)' : ''}`, desc: p });
        if (pc.sev || truthy(get(r, cX))) ctx.exec_({ path: p, time: iso(get(r, cT)), tool: 'AppCompatCacheParser', file: f.name, source: 'ShimCache' });
      }
      keep(); break;
    }
    case 'lecmd': case 'jlecmd': {
      const cT = col('LocalPath', 'TargetIDAbsolutePath', 'Path'), cA = col('Arguments'), cS = col('SourceFile'), cC = col('TargetCreated', 'SourceCreated'), cMac = col('MachineID'), cMm = col('MachineMACAddress'), cApp = col('AppIdDescription'), cNet = col('NetworkPath');
      for (const r of rows) {
        const target = get(r, cT) || get(r, cNet); const args = get(r, cA);
        if (get(r, cMac)) ctx.indicators.add('hostname', get(r, cMac), f.name, 'LNK tracker machine ID');
        if (get(r, cMm)) ctx.indicators.add('mac_address', get(r, cMm), f.name, 'LNK tracker MAC');
        ctx.event({ time: iso(get(r, cC)), tool: kind.tool, file: f.name, type: kind.id === 'jlecmd' ? `Jump list entry${get(r, cApp) ? ' (' + get(r, cApp) + ')' : ''}` : 'Shortcut target', desc: `${target} ${args}`.trim() });
        const pc = classifyPath(target); const cc = classifyCommand(`${target} ${args}`);
        const sev = maxSev(pc.sev, cc.sev);
        if (sev) ctx.finding({ sev, category: cc.sev ? 'Execution' : 'User Activity', tool: kind.tool, file: f.name, time: iso(get(r, cC)), title: `${kind.tool}: shortcut to ${cc.reasons[0] || pc.reasons[0] || 'suspicious target'} (${baseName(target)})`, detail: [...pc.reasons, ...cc.reasons].join('; '), evidence: `${get(r, cS)}\n${target} ${args}`, mitre: cc.mitre });
        ctx.text(args, f.name); ctx.text(get(r, cNet), f.name);
      }
      keep(); break;
    }
    case 'mft': {
      const cE = col('EntryNumber'), cSeq = col('SequenceNumber'), cU = col('InUse'), cPP = col('ParentPath'), cN = col('FileName'), cD = col('IsDirectory'), cSz = col('FileSize'), cSi = col('SI<FN'), cUs = col('uSecZeros'), cCr = col('Created0x10'), cCrF = col('Created0x30'), cZ = col('ZoneIdContents'), cAds = col('IsAds');
      const cM = col('LastModified0x10'), cMF = col('LastModified0x30'), cC = col('LastRecordChange0x10'), cCF = col('LastRecordChange0x30'), cA = col('LastAccess0x10'), cAF = col('LastAccess0x30'), cCp = col('Copied');
      const all = [];
      const mrows = []; const flagged = []; const stomped = [];
      for (const r of rows) {
        if (truthy(get(r, cAds))) continue;
        const name = get(r, cN), pp = get(r, cPP), dir = truthy(get(r, cD));
        const si = { created: iso(get(r, cCr)) || '', modified: iso(get(r, cM)) || '', accessed: iso(get(r, cA)) || '', recordChanged: iso(get(r, cC)) || '' };
        const fn = { created: iso(get(r, cCrF)) || '', modified: iso(get(r, cMF)) || '', accessed: iso(get(r, cAF)) || '', recordChanged: iso(get(r, cCF)) || '' };
        mrows.push({ entry: +get(r, cE), seq: +get(r, cSeq), inUse: truthy(get(r, cU)), isDir: dir, parentPath: pp, name, size: +get(r, cSz) || 0, ads: [], si: si.created ? si : null, fn: fn.created ? fn : null });
        if (all.length < 3000000) all.push([+get(r, cE), +get(r, cSeq), truthy(get(r, cU)) ? 'Y' : 'N', dir ? 'Dir' : 'File', pp, name, +get(r, cSz) || 0, si.created, si.modified, si.accessed, si.recordChanged, fn.created, fn.modified, fn.accessed, fn.recordChanged, truthy(get(r, cCp)) ? 'Y' : '', '']);
        if (dir) continue;
        const wp = `${pp}\\${name}`.replace(/^\./, 'C:');
        const z = get(r, cZ);
        if (z && /HostUrl=/i.test(z)) { const host = (z.match(/HostUrl=(\S+)/i) || [])[1] || ''; if (host && !/^about:/i.test(host)) ctx.indicators.add('url', host, f.name, `downloaded ${name}`); ctx.event({ time: iso(get(r, cCr)), tool: 'MFTECmd', file: f.name, type: 'File downloaded (Zone.Identifier ADS)', desc: `${wp} from ${host}` }); }
        if (!/\.(exe|dll|sys|scr|ps1|bat|cmd|vbs|js|hta|com|cpl|msi|lnk|jar)$/i.test(name)) continue;
        const pc = classifyPath(wp);
        if (pc.sev && pc.sev !== 'low') flagged.push([iso(get(r, cCr)), wp, truthy(get(r, cU)) ? 'Yes' : 'Deleted', pc.sev, pc.reasons.join('; ')]);
        if (truthy(get(r, cSi)) && truthy(get(r, cUs)) && /\\(users|programdata|windows\\temp|perflogs)\\/i.test(wp)) stomped.push([wp, iso(get(r, cCr)), iso(get(r, cCrF))]);
      }
      shared.mft = shared.mft || { rows: [] }; for (const m of mrows) shared.mft.rows.push(m);
      for (const x of flagged.slice(0, 150)) { ctx.finding({ sev: x[3], category: 'File System', tool: 'MFTECmd', file: f.name, time: x[0], title: `File ${x[2] === 'Deleted' ? '(deleted) ' : ''}in suspicious location: ${baseName(x[1])}`, detail: x[4], evidence: x[1], mitre: ['T1036', 'T1105'] }); ctx.event({ time: x[0], tool: 'MFTECmd', file: f.name, type: 'Suspicious file created ($SI)', desc: x[1] }); }
      if (stomped.length) ctx.finding({ sev: stomped.length > 20 ? 'medium' : 'high', category: 'Defense Evasion', tool: 'MFTECmd', file: f.name, title: `${stomped.length} executable(s) with timestomping indicators ($SI < $FN, zeroed fractions)`, evidence: stomped.slice(0, 30).map((s) => s.join('  ')).join('\n'), mitre: ['T1070.006'] });
      tables.push(T('Flagged files', ['$SI Created', 'Path', 'InUse', 'Severity', 'Reasons'], flagged));
      tables.push(T('All MFT entries', MFT_ALL_COLS, all, 'MACB: B = Created (born), M = Modified, A = Accessed, C = $MFT record change.'));
      summary = `${mrows.length} records, ${flagged.length} flagged, ${stomped.length} timestomp candidates`;
      keep(); break;
    }
    case 'usn': {
      const cN = col('Name'), cPP = col('ParentPath'), cT = col('UpdateTimestamp'), cR = col('UpdateReasons'), cE = col('EntryNumber');
      const byEntry = shared.usn || (shared.usn = new Map());
      let n = 0;
      for (const r of rows) {
        const name = get(r, cN); const reasons = get(r, cR);
        const ent = +get(r, cE);
        if (ent && byEntry.size < 400000) {
          const t = iso(get(r, cT)) || '';
          let e = byEntry.get(ent);
          if (!e) { e = { first: t, last: t, data: '', create: '', basicOnly: '', name, reasons: 0 }; byEntry.set(ent, e); }
          if (t && (!e.first || t < e.first)) e.first = t;
          if (t && t > e.last) e.last = t;
          if (name && /\.[a-z0-9]{1,8}$/i.test(name)) e.name = name;
          if (/Data(Overwrite|Extend|Truncation)/i.test(reasons) && t > e.data) e.data = t;
          if (/FileCreate/i.test(reasons) && (!e.create || t < e.create)) e.create = t;
          if (/BasicInfoChange/i.test(reasons) && !/Data|Rename|SecurityChange|EaChange/i.test(reasons) && t > e.basicOnly) e.basicOnly = t;
        }
        if (!/\.(exe|dll|ps1|bat|vbs|js|hta|scr|sys|lnk|zip|7z|rar)$/i.test(name) || !/FileCreate|FileDelete|RenameNewName/i.test(reasons)) continue;
        const p = `${get(r, cPP) || ''}\\${name}`.replace(/^\./, 'C:');
        ctx.event({ time: iso(get(r, cT)), tool: 'MFTECmd', file: f.name, type: `USN ${reasons.match(/FileCreate|FileDelete|RenameNewName/i)[0]}`, desc: p });
        const pc = classifyPath(p); if (pc.sev && pc.sev !== 'low' && n++ < 100) ctx.finding({ sev: pc.sev, category: 'File System', tool: 'MFTECmd', file: f.name, time: iso(get(r, cT)), title: `$J: ${/FileDelete/i.test(reasons) ? 'deleted' : 'created'} ${baseName(p)} in suspicious location`, detail: pc.reasons.join('; '), evidence: `${p}\n${reasons}`, mitre: ['T1070.004'] });
      }
      keep(); break;
    }
    case 'rbcmd': {
      const cN = col('FileName'), cT = col('DeletedOn'), cS = col('FileSize');
      for (const r of rows) {
        const p = get(r, cN); ctx.event({ time: iso(get(r, cT)), tool: 'RBCmd', file: f.name, type: 'File deleted to Recycle Bin', desc: `${p} (${get(r, cS)} bytes)` });
        const pc = classifyPath(p); if (pc.sev && pc.sev !== 'low') ctx.finding({ sev: pc.sev, category: 'Defense Evasion', tool: 'RBCmd', file: f.name, time: iso(get(r, cT)), title: `Recycled: ${baseName(p)}`, detail: pc.reasons.join('; '), evidence: p, mitre: ['T1070.004'] });
      }
      keep(); break;
    }
    case 'sbecmd': {
      const cP = col('AbsolutePath'), cT = col('LastWriteTime', 'LastInteracted', 'ModifiedOn');
      for (const r of rows) { const p = get(r, cP); ctx.event({ time: iso(get(r, cT)), tool: 'SBECmd', file: f.name, type: 'Folder accessed (ShellBags)', desc: p }); if (/\\\\[^\\]+\\[a-z]\$|\\(c|admin)\$/i.test(p)) ctx.indicators.add('unc', p, f.name, 'ShellBags'); }
      keep(); break;
    }
    case 'recmd': {
      const cD = col('Description'), cC = col('Category'), cK = col('KeyPath'), cN = col('ValueName'), cV = col('ValueData'), cV2 = col('ValueData2'), cT = col('LastWriteTimestamp'), cH = col('HivePath');
      for (const r of rows) {
        const cat = get(r, cC), desc = get(r, cD), val = get(r, cV), t = iso(get(r, cT));
        ctx.text(`${val} ${get(r, cV2)}`, f.name);
        if (/autorun|asep|persist|run key|services|scheduled|startup|winlogon|image file execution/i.test(`${cat} ${desc}`) && val) ctx.persist({ mechanism: desc || cat, name: get(r, cN) || get(r, cK).split('\\').pop(), command: val, time: t, tool: 'RECmd', file: f.name, mitre: ['T1547.001'] });
        else if (/program execution|userassist|bam|dam|runmru/i.test(`${cat} ${desc}`) && /[a-z]:\\|\\device\\/i.test(val + get(r, cN))) ctx.exec_({ path: /[a-z]:\\|\\device\\/i.test(val) ? val : get(r, cN), time: iso(get(r, cV2)) || t, tool: 'RECmd', file: f.name, source: desc || 'RECmd' });
        void cH;
      }
      keep(); break;
    }
    case 'recmd-plugin': {
      // RECmd batch plugins write one CSV per plugin, each with its own columns
      const has = (c) => H.includes(c);
      const cBk = col('BatchKeyPath');
      if (has('imagepath') && has('startmode')) { // Services
        const cN = col('Name'), cI = col('ImagePath'), cD = col('ServiceDLL'), cT = col('NameKeyLastWrite'), cS = col('StartMode');
        for (const r of rows) { const cmd = get(r, cI); if (!cmd) continue; ctx.persist({ mechanism: `Service (${get(r, cS)})`, name: get(r, cN), command: get(r, cD) ? `${cmd} [ServiceDll ${get(r, cD)}]` : cmd, time: iso(get(r, cT)), tool: 'RECmd', file: f.name, mitre: ['T1543.003'] }); }
      } else if (has('command') && has('createdon')) { // TaskCache
        const cP = col('Path', 'KeyName'), cC = col('Command'), cA = col('Arguments'), cT = col('CreatedOn'), cL = col('LastStart');
        for (const r of rows) { const cmd = `${get(r, cC)} ${get(r, cA)}`.trim(); ctx.event({ time: iso(get(r, cT)), tool: 'RECmd', file: f.name, type: 'Scheduled task registered (TaskCache)', desc: `${get(r, cP)} -> ${cmd}` }); if (cmd) ctx.persist({ mechanism: 'Scheduled task (TaskCache)', name: get(r, cP), command: cmd, time: iso(get(r, cT)), tool: 'RECmd', file: f.name, mitre: ['T1053.005'] }); if (get(r, cL)) ctx.event({ time: iso(get(r, cL)), tool: 'RECmd', file: f.name, type: 'Scheduled task last ran', desc: get(r, cP) }); }
      } else if (has('programname') && has('runcounter')) { // UserAssist
        ctx.sawArtifact('UserAssist', f.name);
        const cP = col('ProgramName'), cR = col('RunCounter'), cT = col('LastExecuted');
        for (const r of rows) { const p = get(r, cP); if (!/\\|\.exe$/i.test(p)) continue; ctx.exec_({ path: p, time: iso(get(r, cT)), tool: 'RECmd', file: f.name, source: 'UserAssist', runCount: get(r, cR) }); ctx.evidence({ artifact: 'UserAssist', path: p, time: iso(get(r, cT)), runCount: +get(r, cR) || null, user: (get(r, col('HivePath')).match(/users[\\/]([^\\/]+)/i) || [])[1] || '', file: f.name }); }
      } else if (has('programname') && has('modifiedtime')) { // AppCompatCache via RECmd
        const cP = col('ProgramName'), cT = col('ModifiedTime'), cX = col('Executed');
        for (const r of rows) { const p = get(r, cP); ctx.evidence({ artifact: 'ShimCache', path: p, time: iso(get(r, cT)), executed: cX >= 0 && get(r, cX) ? truthy(get(r, cX)) : null, file: f.name }); if (classifyPath(p).sev || truthy(get(r, cX))) ctx.exec_({ path: p, time: iso(get(r, cT)), tool: 'RECmd', file: f.name, source: 'ShimCache' }); }
      } else if (has('executable') && has('openedon')) { // RunMRU, CIDSizeMRU, FirstFolder, LastVisitedPidlMRU
        const cE = col('Executable'), cT = col('OpenedOn'); const runMru = /runmru/i.test(rows[0] ? get(rows[0], cBk) : '');
        for (const r of rows) { const e = get(r, cE); if (!e) continue; if (runMru) { const cc = classifyCommand(e); ctx.event({ time: iso(get(r, cT)), tool: 'RECmd', file: f.name, type: 'Run dialog command (RunMRU)', desc: e }); ctx.exec_({ path: e.split(' ')[0], args: e, time: iso(get(r, cT)), tool: 'RECmd', file: f.name, source: 'RunMRU' }); void cc; } else ctx.exec_({ path: e, time: iso(get(r, cT)), tool: 'RECmd', file: f.name, source: 'MRU (program used a file dialog)' }); }
      } else if (has('filename') && has('lastdetectiontime')) { // RADAR
        const cF = col('Filename'), cT = col('LastDetectionTime'); for (const r of rows) ctx.exec_({ path: get(r, cF), time: iso(get(r, cT)), tool: 'RECmd', file: f.name, source: 'RADAR' });
      } else if (has('app') && has('action') && has('dir')) { // FirewallRules
        const cA = col('App'), cAc = col('Action'), cD = col('Dir'), cN = col('Name'), cAct = col('Active');
        for (const r of rows) { const app = get(r, cA); const pc = classifyPath(app); if (app && /allow/i.test(get(r, cAc)) && truthy(get(r, cAct) || 'true') && pc.sev && pc.sev !== 'low') ctx.finding({ sev: 'high', category: 'Defense Evasion', tool: 'RECmd', file: f.name, title: `Firewall allow rule for ${baseName(app)} (${get(r, cD)})`, detail: `${get(r, cN)} | ${pc.reasons.join('; ')}`, evidence: app, mitre: ['T1562.004'] }); }
      } else if (has('url')) { for (const r of rows) ctx.text(r.join(' '), f.name); }
      else if (has('displayname') && has('publisher')) { /* Uninstall / Products: kept as a table */ }
      else for (const r of rows.slice(0, 20000)) ctx.text(r.join(' '), f.name);
      keep(); break;
    }
    case 'browser-downloads': {
      const cT = col('TargetPath'), cU = col('DownloadURL'), cR = col('ReferrerURL'), cS = col('StartTime'), cD = col('DangerType');
      for (const r of rows) {
        const p = get(r, cT), u = get(r, cU);
        ctx.event({ time: iso(get(r, cS)), tool: 'SQLECmd', file: f.name, type: 'Browser download', desc: `${p} from ${u}` });
        if (u) ctx.indicators.add('url', u, f.name, `downloaded ${baseName(p)}`); if (get(r, cR)) ctx.text(get(r, cR), f.name);
        const pc = classifyPath(p); const risky = /\.(exe|dll|scr|msi|ps1|bat|cmd|vbs|js|jse|hta|lnk|iso|img|vhdx?|zip|7z|rar|one|docm|xlsm|jar)$/i.test(p);
        if (risky && (pc.sev || /\d+\.\d+\.\d+\.\d+|pastebin|transfer\.sh|anonfiles|mega\.nz|discord|ngrok|raw\.githubusercontent|dropbox/i.test(u) || +get(r, cD) > 0)) ctx.finding({ sev: pc.sev === 'high' || +get(r, cD) > 0 ? 'high' : 'medium', category: 'Initial Access', tool: 'SQLECmd', file: f.name, time: iso(get(r, cS)), title: `Browser downloaded ${baseName(p)}`, detail: [...pc.reasons, +get(r, cD) > 0 ? `browser danger type ${get(r, cD)}` : ''].filter(Boolean).join('; '), evidence: `${p}\n${u}`, mitre: ['T1105', 'T1204.002'] });
      }
      keep(); break;
    }
    case 'browser-history': {
      const cU = col('URL'); const cT = col('VisitTime (UTC)', 'LastVisitedTime (UTC)', 'visit_time', 'LastVisitTime');
      for (const r of rows) { ctx.text(get(r, cU), f.name); ctx.event({ time: iso(get(r, cT)), tool: 'SQLECmd', file: f.name, type: 'Browser visit', desc: get(r, cU).slice(0, 300) }); }
      keep(); break;
    }
    case 'srum': {
      ctx.sawArtifact('SRUM', f.name);
      const cE = col('ExeInfo'), cT = col('Timestamp'), cS = col('BytesSent'), cR = col('BytesReceived'), cU = col('UserName');
      const per = new Map();
      for (const r of rows) {
        const e = get(r, cE); if (!e) continue; const p = e.replace(/^\\device\\harddiskvolume\d+/i, 'C:');
        const t = iso(get(r, cT)); const x = per.get(p) || { sent: 0, recv: 0, first: t, last: t, user: get(r, cU) }; x.sent += +get(r, cS) || 0; x.recv += +get(r, cR) || 0; if (t && t < x.first) x.first = t; if (t && t > x.last) x.last = t; per.set(p, x);
      }
      for (const [p, x] of per) {
        if (/^[a-z]:\\/i.test(p)) { ctx.exec_({ path: p, time: x.first, tool: 'SrumECmd', file: f.name, source: 'SRUM' }); ctx.evidence({ artifact: 'SRUM', path: p, time: x.first, first: x.first, last: x.last, sent: x.sent, recv: x.recv, user: x.user, file: f.name }); }
        const pc = classifyPath(p);
        if (cS >= 0 && x.sent > 50 * 1024 ** 2 && !/\\(chrome|msedge|firefox|onedrive|teams|zoom|outlook|svchost|backgroundtransferhost)\.exe$/i.test(p)) ctx.finding({ sev: pc.sev ? 'high' : 'medium', category: 'Exfiltration', tool: 'SrumECmd', file: f.name, time: x.first, title: `${baseName(p)} sent ${(x.sent / 1024 ** 2).toFixed(0)} MB (SRUM)`, evidence: `${p}\nsent ${x.sent} received ${x.recv} user ${x.user}`, mitre: ['T1041'] });
      }
      keep(); break;
    }
    case 'wxtcmd': {
      const cX = col('Executable'), cT = col('StartTime'), cD = col('DisplayText');
      for (const r of rows) { const p = get(r, cX); if (!p) continue; ctx.event({ time: iso(get(r, cT)), tool: 'WxTCmd', file: f.name, type: 'Windows Timeline activity', desc: `${p} ${get(r, cD)}` }); if (/^[a-z]:\\/i.test(p)) ctx.exec_({ path: p, time: iso(get(r, cT)), tool: 'WxTCmd', file: f.name, source: 'Windows Timeline' }); }
      keep(); break;
    }
    case 'autoruns': {
      const cL = col('Entry Location'), cE = col('Entry'), cEn = col('Enabled'), cCat = col('Category'), cS = col('Signer'), cCo = col('Company'), cI = col('Image Path'), cLs = col('Launch String'), cT = col('Time'), cH = col('SHA-1');
      let unsigned = 0;
      for (const r of rows) {
        const img = get(r, cI); const signer = get(r, cS); if (!get(r, cE) || !get(r, cL)) continue;
        const verified = /^\(verified\)/i.test(signer); const notVerified = /^\(not verified\)/i.test(signer) || (!signer && img && img !== 'File not found');
        ctx.persist({ mechanism: `Autoruns ${get(r, cCat)}: ${get(r, cL)}`, name: get(r, cE), command: get(r, cLs) || img, time: iso(get(r, cT)), tool: 'Autoruns', file: f.name, mitre: ['T1547'] });
        if (img && img !== 'File not found') ctx.sign({ path: img, sha1: get(r, cH), signed: verified ? true : notVerified ? false : null, verified: verified ? true : notVerified ? false : null, signer: signer.replace(/^\((not )?verified\)\s*/i, ''), publisher: get(r, cCo), kind: 'autorun', source: 'Autoruns', file: f.name });
        if (notVerified && img && /enabled/i.test(get(r, cEn) || 'enabled')) {
          const pc = classifyPath(img); unsigned++;
          ctx.finding({ sev: pc.sev && pc.sev !== 'low' ? 'high' : /\\windows\\system32\\/i.test(img) ? 'low' : 'medium', category: 'Persistence', tool: 'Autoruns', file: f.name, time: iso(get(r, cT)), title: `Unsigned autorun: ${get(r, cE)} (${baseName(img)})`, detail: `${get(r, cL)} | signer: ${signer || 'none'}${pc.reasons.length ? ' | ' + pc.reasons.join('; ') : ''}`, evidence: `${get(r, cLs) || img}\nSHA1 ${get(r, cH)}`, mitre: ['T1547', 'T1553.002'] });
        }
        if (/file not found/i.test(img)) ctx.finding({ sev: 'low', category: 'Persistence', tool: 'Autoruns', file: f.name, title: `Autorun points at a missing file: ${get(r, cE)}`, detail: get(r, cL), evidence: get(r, cLs) });
      }
      summary = `${rows.length} autostart entries, ${unsigned} enabled and not verified`; keep(); break;
    }
    case 'sigcheck': {
      const cP = col('Path'), cV = col('Verified'), cPub = col('Publisher'), cCo = col('Company'), cS = col('SHA1');
      let n = 0;
      for (const r of rows) {
        const p = get(r, cP); const v = get(r, cV); const signed = /^signed$/i.test(v); const unsigned = /^unsigned$/i.test(v);
        ctx.sign({ path: p, sha1: get(r, cS), signed: signed ? true : unsigned ? false : null, verified: signed ? true : v ? false : null, signer: get(r, cPub), publisher: get(r, cCo), status: v, kind: /\.sys$/i.test(p) ? 'driver' : /\.dll$/i.test(p) ? 'dll' : 'exe', source: 'Sigcheck', file: f.name });
        if (!signed && v) { const pc = classifyPath(p); if (n++ < 200) ctx.finding({ sev: pc.sev && pc.sev !== 'low' ? 'high' : /\\(windows|program files)/i.test(p) ? 'low' : 'medium', category: 'Unsigned Binary', tool: 'Sigcheck', file: f.name, title: `${unsigned ? 'Unsigned' : 'Signature not valid (' + v + ')'}: ${baseName(p)}`, detail: pc.reasons.join('; '), evidence: `${p}\nSHA1 ${get(r, cS)}`, mitre: ['T1553.002'] }); }
      }
      keep(); break;
    }
    case 'recentfilecache': {
      const cN = col('FileName'); for (const r of rows) ctx.exec_({ path: get(r, cN), tool: 'RecentFileCacheParser', file: f.name, source: 'RecentFileCache' });
      keep(); break;
    }
    default: {
      for (const r of rows.slice(0, 50000)) ctx.text(r.join(' '), f.name);
      keep();
    }
  }
  return { tool: kind.tool, artifact: kind.label, summary, tables, notes };
}
