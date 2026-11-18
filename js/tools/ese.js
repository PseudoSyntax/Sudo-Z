// SrumECmd / WebCache / generic ESE analysis.
import { EseDb } from '../parsers/ese.js';
import { classifyPath, baseName, isLolbin } from '../ioc/heuristics.js';
import { filetimeToIso } from '../core/bytes.js';

const T = (title, columns, rows, note) => ({ title, columns, rows, note });
const sid = (b) => {
  if (!(b instanceof Uint8Array) || b.length < 8) return '';
  let a = 0; for (let i = 2; i < 8; i++) a = a * 256 + b[i];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let s = `S-${b[0]}-${a}`; for (let i = 0; i < b[1] && 8 + i * 4 + 4 <= b.length; i++) s += '-' + dv.getUint32(8 + i * 4, true);
  return s;
};
const fmtBytes = (n) => (n >= 1 << 30 ? (n / (1 << 30)).toFixed(2) + ' GB' : n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B');
const BROWSER_OR_SYSTEM = /\\(chrome|msedge|firefox|iexplore|brave|opera|onedrive|teams|ms-teams|outlook|svchost|system|backgroundtaskhost|wuauclt|musnotification|mousocoreworker|msmpeng|searchapp|microsoftedgeupdate|googleupdate|dropbox|steam|spotify|zoom|slack|discord|winstore\.app|explorer)\.exe$|^system$|^svc\.|windows defender|microsoft\.windowsstore|msedge/i;

const SRUM_TABLES = {
  network: '{973F5D5C-1D90-4944-BE8E-24B94231A174}',
  app: '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}',
  connect: '{DD6636C4-8929-4683-974E-22C046A43763}',
  timeline: '{5C8CF1C7-7257-4F13-B223-970EF5939312}',
  push: '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}',
};

function srum(db, f, ctx, tables) {
  const ids = new Map();
  for (const r of db.rows('SruDbIdMapTable')) {
    const b = r.IdBlob;
    let v = '';
    if (b instanceof Uint8Array) v = r.IdType === 3 ? sid(b) : new TextDecoder('utf-16le').decode(b).replace(/\0+$/, '');
    else if (typeof b === 'string') v = b;
    ids.set(r.IdIndex, { type: r.IdType, value: v });
  }
  const app = (id) => ids.get(id)?.value || `#${id}`;
  // network usage per app
  ctx.sawArtifact('SRUM', f.name);
  const net = db.table(SRUM_TABLES.network) || [];
  const per = new Map();
  for (const r of net) {
    const k = r.AppId; const e = per.get(k) || { sent: 0, recv: 0, first: r.TimeStamp, last: r.TimeStamp, users: new Set() };
    e.sent += r.BytesSent || 0; e.recv += r.BytesRecvd || 0; if (r.TimeStamp < e.first) e.first = r.TimeStamp; if (r.TimeStamp > e.last) e.last = r.TimeStamp; e.users.add(app(r.UserId)); per.set(k, e);
  }
  const perRows = [...per].map(([id, e]) => [app(id), e.sent, e.recv, fmtBytes(e.sent), fmtBytes(e.recv), e.first, e.last, [...e.users].join(', ')]).sort((a, b) => b[1] - a[1]);
  tables.push(T('SRUM network usage by application (NetworkUsages)', ['Application', 'BytesSent', 'BytesRecvd', 'Sent', 'Received', 'First', 'Last', 'Users'], perRows, 'Hourly totals summed per application. Large uploads from unexpected programs are a classic exfiltration indicator.'));
  tables.push(T('SRUM network usage records', ['Time', 'Application', 'User', 'BytesSent', 'BytesRecvd', 'InterfaceLuid', 'L2ProfileId'], net.map((r) => [r.TimeStamp, app(r.AppId), app(r.UserId), r.BytesSent, r.BytesRecvd, r.InterfaceLuid, r.L2ProfileId])));
  for (const [path, sent, recv, , , first, last, users] of perRows) {
    const pc = classifyPath(path);
    const lol = isLolbin(path) && /\\(powershell|pwsh|certutil|bitsadmin|rundll32|regsvr32|mshta|wscript|cscript|curl|msbuild|installutil)\.exe$/i.test(path);
    let sev = null; const why = [];
    if (pc.sev && sent + recv > 0) { sev = pc.sev === 'critical' ? 'critical' : 'high'; why.push(...pc.reasons); }
    if (lol && sent > 1 << 20) { sev = 'high'; why.push(`${baseName(path)} sent ${fmtBytes(sent)}`); }
    if (sent > 500 * (1 << 20) && !BROWSER_OR_SYSTEM.test(path)) { sev = sev || 'high'; why.push(`uploaded ${fmtBytes(sent)} (possible exfiltration)`); }
    else if (sent > 100 * (1 << 20) && !BROWSER_OR_SYSTEM.test(path) && sent > recv * 2) { sev = sev || 'medium'; why.push(`upload-heavy traffic: sent ${fmtBytes(sent)}, received ${fmtBytes(recv)}`); }
    if (sev) ctx.finding({ sev, category: 'Exfiltration', tool: 'SrumECmd', file: f.name, time: first, title: `SRUM: ${baseName(path) || path} network activity (${fmtBytes(sent)} sent)`, detail: why.join('; ') + ` | ${first} to ${last} | ${users}`, evidence: path, mitre: ['T1041', 'T1567'] });
    if (/^[a-z]:\\|\\device\\harddiskvolume/i.test(path)) ctx.exec_({ path: path.replace(/^\\device\\harddiskvolume\d+/i, 'C:'), time: first, tool: 'SrumECmd', file: f.name, source: 'SRUM' });
    if (/^[a-z]:\\|\\device\\harddiskvolume/i.test(path)) ctx.evidence({ artifact: 'SRUM', path: path.replace(/^\\device\\harddiskvolume\d+/i, 'C:'), time: first, first, last, sent, recv, user: users, file: f.name });
  }
  for (const r of net) if ((r.BytesSent || 0) > 50 * (1 << 20)) ctx.event({ time: r.TimeStamp, tool: 'SrumECmd', file: f.name, type: 'SRUM large upload hour', desc: `${app(r.AppId)} sent ${fmtBytes(r.BytesSent)}` });
  // app resource usage
  const au = db.table(SRUM_TABLES.app) || [];
  if (au.length) {
    tables.push(T('SRUM application resource usage (AppResourceUseInfo)', ['Time', 'Application', 'User', 'ForegroundCycleTime', 'BackgroundCycleTime', 'FgBytesWritten', 'BgBytesWritten'], au.map((r) => [r.TimeStamp, app(r.AppId), app(r.UserId), r.ForegroundCycleTime, r.BackgroundCycleTime, r.ForegroundBytesWritten, r.BackgroundBytesWritten])));
    const seen = new Set();
    for (const r of au) { const p = app(r.AppId); if (seen.has(p)) continue; seen.add(p); ctx.event({ time: r.TimeStamp, tool: 'SrumECmd', file: f.name, type: 'SRUM app activity (first record)', desc: p }); if (/^[a-z]:\\|\\device\\/i.test(p)) ctx.exec_({ path: p.replace(/^\\device\\harddiskvolume\d+/i, 'C:'), time: r.TimeStamp, tool: 'SrumECmd', file: f.name, source: 'SRUM' }); }
  }
  const cn = db.table(SRUM_TABLES.connect) || [];
  if (cn.length) tables.push(T('SRUM network connections (NetworkConnections)', ['Time', 'Application', 'User', 'ConnectedTime(s)', 'ConnectStartTime', 'InterfaceLuid', 'L2ProfileId'], cn.map((r) => [r.TimeStamp, app(r.AppId), app(r.UserId), r.ConnectedTime, typeof r.ConnectStartTime === 'number' ? filetimeToIso(BigInt(Math.max(0, r.ConnectStartTime))) : r.ConnectStartTime, r.InterfaceLuid, r.L2ProfileId])));
  tables.push(T('SRUM ID map (applications, services, users)', ['IdIndex', 'IdType', 'Value'], [...ids].map(([k, v]) => [k, { 0: 'App', 1: 'Service', 2: 'Package', 3: 'User SID' }[v.type] ?? v.type, v.value])));
  return `SRUM: ${ids.size} IDs, ${net.length} network usage records, ${au.length} app usage records, ${cn.length} connection records`;
}

const SHARE = /(pastebin|transfer\.sh|temp\.sh|anonfiles|file\.io|gofile|mega\.nz|mediafire|sendspace|wetransfer|ngrok|trycloudflare|duckdns|no-ip|discord(app)?\.com\/attachments|cdn\.discordapp|api\.telegram|mimikatz|gentilkiwi|githubusercontent)/i;
function webcache(db, f, ctx, tables) {
  const containers = db.table('Containers') || [];
  const all = [];
  for (const c of containers) {
    if (!/^(history|mshist|iedownload|content|cookies)/i.test(c.Name || '')) continue;
    for (const r of db.rows(`Container_${c.ContainerId}`)) {
      const url = String(r.Url || ''); if (!url) continue;
      const acc = typeof r.AccessedTime === 'number' ? filetimeToIso(BigInt(r.AccessedTime)) : null;
      const mod = typeof r.ModifiedTime === 'number' ? filetimeToIso(BigInt(r.ModifiedTime)) : null;
      all.push([acc, c.Name, url, r.AccessCount, mod, r.Filename || '', c.Directory || '']);
    }
  }
  all.sort((a, b) => (b[0] || '').localeCompare(a[0] || ''));
  tables.push(T('WebCache entries (IE / legacy Edge / Explorer)', ['Accessed', 'Container', 'URL', 'AccessCount', 'Modified', 'Filename', 'Directory'], all, 'History containers include "Visited: user@URL" records and local file access ("file:///"), so this also shows files opened through Explorer.'));
  for (const r of all) {
    const url = r[2];
    if (/^(history|mshist)/i.test(r[1])) ctx.event({ time: r[0], tool: 'SQLECmd (WebCache)', file: f.name, type: 'Web/file access (WebCache)', desc: url });
    if (/^iedownload/i.test(r[1])) { ctx.event({ time: r[0], tool: 'SQLECmd (WebCache)', file: f.name, type: 'IE download', desc: url }); ctx.indicators.add('url', url.replace(/^[^@]*@/, ''), f.name, 'IE download'); }
    const clean = url.replace(/^Visited:\s*[^@]*@/i, '');
    if (/^https?:\/\/\d+\.\d+\.\d+\.\d+/i.test(clean) && !/^https?:\/\/(10|127|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(clean)) ctx.finding({ sev: 'medium', category: 'Command and Control', tool: 'SQLECmd', file: f.name, time: r[0], title: 'WebCache: raw-IP URL', evidence: clean, mitre: ['T1071.001'] });
    else if (SHARE.test(clean)) ctx.finding({ sev: /mimikatz|gentilkiwi/i.test(clean) ? 'high' : 'low', category: 'Command and Control', tool: 'SQLECmd', file: f.name, time: r[0], title: 'WebCache: file-share / tunnelling / offensive-tool site', evidence: clean, mitre: ['T1105'] });
    if (/^file:\/\/\//i.test(clean)) { const p = decodeURIComponent(clean.replace(/^file:\/\/\//i, '')).replace(/\//g, '\\'); const pc = classifyPath(p); if (pc.sev) ctx.finding({ sev: pc.sev, category: 'Execution', tool: 'SQLECmd', file: f.name, time: r[0], title: `WebCache: file opened from suspicious location (${baseName(p)})`, detail: pc.reasons.join('; '), evidence: p, mitre: ['T1204'] }); }
    if (/^https?:/i.test(clean)) ctx.text(clean, f.name);
  }
  return `WebCache: ${containers.length} containers, ${all.length} entries`;
}

export function runEse(u8, f, ctx) {
  const db = new EseDb(u8);
  const names = db.tables();
  const tables = []; const notes = [];
  let tool = 'ESE', artifact = 'ESE database', summary;
  if (names.includes('SruDbIdMapTable')) { tool = 'SrumECmd'; artifact = 'SRUM (SRUDB.dat)'; summary = srum(db, f, ctx, tables); }
  else if (names.includes('Containers') && names.some((n) => /^Container_\d+$/.test(n))) { tool = 'SQLECmd (WebCache)'; artifact = 'WebCacheV01.dat (IE / Edge legacy / Explorer)'; summary = webcache(db, f, ctx, tables); }
  else {
    if (names.some((n) => /^(CLIENTS|ROLE_ACCESS|DNS|VIRTUALMACHINES)$/i.test(n))) { tool = 'SumECmd'; artifact = 'User Access Logging (SUM)'; }
    const inv = [];
    for (const t of db.catalog()) {
      if (/^MSys/.test(t.name)) continue;
      let n = 0;
      try { for (const row of db.rows(t.name, 200000)) { n++; if (n <= 20000) for (const v of Object.values(row)) if (typeof v === 'string' && v.length > 6) { ctx.text(v, f.name); if (tool === 'SumECmd') ctx.domains(v, f.name); } } } catch { }
      inv.push([t.name, n, t.columns.map((c) => c.name).join(', ').slice(0, 300)]);
    }
    tables.push(T('Tables', ['Table', 'Rows', 'Columns'], inv));
    if (tool === 'SumECmd') {
      const clients = db.table('CLIENTS') || [];
      if (clients.length) {
        const rows = clients.map((c) => [c.InsertDate, c.LastAccess, c.AuthenticatedUserName, c.Address instanceof Uint8Array ? Array.from(c.Address.subarray(0, 4)).join('.') : c.Address, c.TotalAccesses, c.RoleGuid]);
        tables.unshift(T('UAL clients (who accessed which server role)', ['InsertDate', 'LastAccess', 'User', 'Address', 'TotalAccesses', 'RoleGuid'], rows));
        for (const r of rows) { if (r[3]) ctx.indicators.add(/^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(r[3]) ? 'internal_ip' : 'ipv4', r[3], f.name, `UAL ${r[2]}`); ctx.event({ time: r[1], tool: 'SumECmd', file: f.name, type: 'UAL last access', desc: `${r[2]} from ${r[3]}` }); }
      }
    }
    summary = `${names.length} tables (generic ESE inventory)`;
    notes.push('No specific ESE map matched; table inventory and indicator sweep only.');
  }
  notes.push(`ESE format 0x${db.formatVersion.toString(16)} rev 0x${db.formatRevision.toString(16)}, ${db.pageSize} byte pages, state: ${db.state}.${db.state === 'Dirty shutdown' ? ' Uncommitted transactions in .log files are not replayed (esentutl /r on Windows does that).' : ''}`);
  return { tool, artifact, summary, tables, notes };
}
