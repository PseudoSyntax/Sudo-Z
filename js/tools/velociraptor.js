// Velociraptor offline collection support. Velociraptor (Rapid7) collects
// raw files and VQL artifact results into a zip. Sudo-Z decodes the upload
// paths so raw files route to the normal parsers, and grades the artifact
// results (JSON lines in results/*.json).
import { utf8 } from '../core/bytes.js';
import { classifyPath, classifyCommand, baseName } from '../ioc/heuristics.js';
import { isPrivateIp } from '../ioc/indicators.js';

export function isVeloCollection(names) {
  return names.some((n) => /(^|\/)collection_context\.json$/i.test(n)) || (names.some((n) => /^uploads\//i.test(n)) && names.some((n) => /^results\/.+\.json$/i.test(n)));
}

const dec = (s) => { try { return decodeURIComponent(s); } catch { return s.replace(/%([0-9a-f]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))); } };

/** uploads/ntfs/%5C%5C.%5CC%3A/%24MFT -> uploads/C/$MFT */
export function veloName(p) {
  const parts = p.split('/').map(dec);
  let s = parts.join('/');
  s = s.replace(/^uploads\/(auto|ntfs|file|lazy_ntfs|mft|ntfs_vss)\//i, 'uploads/')
    .replace(/\\\\[.?]\\([A-Za-z]):\\?/g, '$1/').replace(/\\\\[.?]\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy(\d+)\\?/gi, 'VSS$1/')
    .replace(/(^|\/)([A-Za-z]):(\/|$)/g, '$1$2$3').replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  return s;
}

const SEV_MAP = { critical: 'critical', crit: 'critical', high: 'high', medium: 'medium', med: 'medium', low: 'low', informational: 'info', info: 'info' };
const flat = (v) => (v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v));
const pick = (o, keys) => { for (const k of keys) { const hit = Object.keys(o).find((x) => x.toLowerCase() === k.toLowerCase()); if (hit && o[hit] != null && o[hit] !== '') return o[hit]; } return undefined; };

export function runVelo(u8, f, ctx) {
  const artifact = (f.name.match(/\/results\/(.+)\.json$/i)?.[1] || f.name.split('/').pop().replace(/\.json$/i, '')).replace(/\//g, ' / ');
  const rows = utf8(u8).split(/\r?\n/).filter((l) => l.trim().startsWith('{')).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const cols = [...new Set(rows.slice(0, 200).flatMap((r) => Object.keys(r)))].slice(0, 30);
  const persistArt = /autoruns|persistence|services|scheduledtasks|startup|runkeys|wmi|bits/i.test(artifact);
  let flagged = 0;
  for (const r of rows.slice(0, 200000)) {
    const time = pick(r, ['Timestamp', 'EventTime', 'CreateTime', 'Time', 'Mtime', 'LastWriteTime', 'Created', 'StartTime']);
    // detection engines run inside Velociraptor (Hayabusa / Sigma / YARA / Chainsaw)
    const level = pick(r, ['Level', 'Severity', 'level', 'RuleLevel']);
    const rule = pick(r, ['RuleTitle', 'Title', 'Rule', 'Detection', 'RuleName']);
    if (rule && level && SEV_MAP[String(level).toLowerCase()]) {
      const sev = SEV_MAP[String(level).toLowerCase()];
      if (sev !== 'info') { ctx.finding({ sev, category: 'Velociraptor detection', tool: 'Velociraptor', file: f.name, time: time ? String(time) : null, title: `${artifact}: ${rule}`, evidence: flat(pick(r, ['Details', 'ExtraFieldInfo', 'Message', 'Event']) || r).slice(0, 1500), mitre: String(pick(r, ['MitreTactics', 'MitreTags', 'Tags']) || '').match(/T\d{4}(\.\d{3})?/g) || [] }); flagged++; }
      continue;
    }
    if (/yara/i.test(artifact) && pick(r, ['Rule', 'RuleName'])) { ctx.finding({ sev: 'high', category: 'Velociraptor detection', tool: 'Velociraptor', file: f.name, title: `${artifact}: YARA ${pick(r, ['Rule', 'RuleName'])}`, evidence: flat(pick(r, ['OSPath', 'FullPath', 'Path', 'ProcessName', 'Name']) || r).slice(0, 800) }); flagged++; continue; }
    const cmd = pick(r, ['CommandLine', 'Commandline', 'CmdLine', 'Command', 'Launch String', 'LaunchString', 'Action', 'Arguments']);
    const exe = pick(r, ['Exe', 'ImagePath', 'Image', 'Path', 'FullPath', 'OSPath', 'PathName', 'Image Path', 'Binary', 'Name']);
    if (persistArt && (cmd || exe)) {
      const name = flat(pick(r, ['Entry', 'Name', 'ServiceName', 'TaskName', 'Key', 'Location']) || baseName(flat(exe)));
      if (ctx.persist({ mechanism: `Velociraptor ${artifact}`, name, command: flat(cmd || exe), time: time ? String(time) : null, tool: 'Velociraptor', file: f.name, mitre: ['T1547'] })) flagged++;
    } else if (cmd) {
      const res = ctx.exec_({ path: flat(exe || flat(cmd).split(' ')[0]), args: flat(cmd), time: time ? String(time) : null, tool: 'Velociraptor', file: f.name, source: artifact });
      if (res?.sev) flagged++;
    }
    const ra = pick(r, ['Raddr', 'RemoteAddr', 'RemoteAddress', 'DestinationIp', 'DstIP']);
    const rip = typeof ra === 'object' && ra ? ra.IP || ra.ip : ra;
    if (rip && /^\d+\.\d+\.\d+\.\d+$/.test(rip) && rip !== '0.0.0.0') ctx.indicators.add(isPrivateIp(rip) ? 'internal_ip' : 'ipv4', rip, f.name, `${artifact} ${flat(pick(r, ['Name', 'Pid', 'Process']))}`);
    for (const v of Object.values(r)) if (typeof v === 'string' && v.length > 8 && /https?:|\\\\|\d+\.\d+\.\d+\.\d+/.test(v)) ctx.text(v, f.name);
    if (time && (cmd || rule)) ctx.event({ time: String(time), tool: 'Velociraptor', file: f.name, type: artifact, desc: flat(cmd || rule || exe).slice(0, 300) });
  }
  return { tool: 'Velociraptor', artifact: `Velociraptor results: ${artifact}`, summary: `${rows.length} rows, ${flagged} flagged`, tables: [{ title: artifact, columns: cols, rows: rows.slice(0, 100000).map((r) => cols.map((c) => flat(r[c]).slice(0, 2000))) }], notes: [] };
}
