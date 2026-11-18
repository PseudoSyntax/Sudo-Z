// Report exporters: Markdown IOC report, CSV helpers, defanging.
import { CATALOG } from './catalog.js';

export const defang = (s) => String(s).replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/:\/\//, '[://]');
// Defang only network indicators inside free text (paths like EVIL.EXE stay readable).
export const defangText = (s) => String(s)
  .replace(/\b(?:https?|ftp):\/\/[^\s"'<>`]+/gi, (u) => defang(u))
  .replace(/(?<![\d.\[])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])/g, '$1[.]$2[.]$3[.]$4');

export function csv(columns, rows) {
  const esc = (v) => {
    if (v == null) return '';
    if (v instanceof Uint8Array) v = Array.from(v.subarray(0, 256), (b) => b.toString(16).padStart(2, '0')).join('');
    v = Array.isArray(v) ? v.join(' | ') : String(v);
    return /[",\r\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  };
  return [columns.map(esc).join(','), ...rows.map((r) => r.map(esc).join(','))].join('\r\n');
}

export const timelineCsv = (rep) => csv(['TimeUTC', 'Tool', 'EventType', 'Description', 'SourceFile'], rep.timeline.map((e) => [e.time, e.tool, e.type, e.desc, e.file]));
export const findingsCsv = (rep) => csv(['Severity', 'Category', 'Title', 'TimeUTC', 'Tool', 'SourceFile', 'MITRE', 'Detail', 'Evidence'], rep.findings.map((f) => [f.sev, f.category, f.title, f.time || '', f.tool, f.file, (f.mitre || []).join(' '), f.detail || '', f.evidence || '']));
export const indicatorsCsv = (rep) => csv(['Type', 'Value', 'Count', 'Sources', 'Context'], rep.indicators.map((i) => [i.type, i.value, i.count, i.sources.join(' | '), i.context || '']));

export const leadsCsv = (rep) => csv(['Severity', 'Kind', 'Category', 'Title', 'Why', 'Next', 'MITRE', 'Entities', 'Evidence'], (rep.leads || []).map((l) => [l.sev, l.kind, l.category || '', l.title, l.why || '', l.next || '', (l.mitre || []).join(' '), (l.entities || []).join(' | '), l.evidence || '']));

const PCOLS = [['risk', 'Risk'], ['level', 'Level'], ['name', 'Program'], ['signature', 'Signature'], ['location', 'Location'], ['path', 'Path'], ['firstSeen', 'FirstSeen'], ['lastSeen', 'LastSeen'], ['runs', 'Runs'], ['sources', 'SeenBy'], ['persistence', 'Persistence'], ['findings', 'Findings'], ['topFinding', 'TopFinding'], ['reasons', 'Why'], ['executed', 'Executed'], ['firstRun', 'FirstRun'], ['lastRun', 'LastRun'], ['Prefetch', 'Prefetch'], ['ShimCache', 'ShimCache'], ['Amcache', 'Amcache'], ['UserAssist', 'UserAssist'], ['SRUM', 'SRUM'], ['sha1', 'SHA1'], ['signer', 'SignerOrPublisher'], ['args', 'CommandLines']];
export const programsCsv = (rep) => csv(PCOLS.map((c) => c[1]), (rep.programs || []).map((p) => PCOLS.map((c) => p[c[0]] ?? '')));

export function mitreSummary(rep) {
  const m = new Map();
  for (const f of rep.findings) for (const t of f.mitre || []) { if (!t) continue; const e = m.get(t) || { id: t, count: 0, worst: 'info' }; e.count++; if (rank(f.sev) > rank(e.worst)) e.worst = f.sev; m.set(t, e); }
  return [...m.values()].sort((a, b) => rank(b.worst) - rank(a.worst) || b.count - a.count);
}
const rank = (s) => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0);

const INDICATOR_LABEL = { ipv4: 'External IPv4', internal_ip: 'Internal IP (lateral movement)', domain: 'Domain', url: 'URL', email: 'Email', unc: 'UNC / network path', file_path: 'Suspicious file path', command_line: 'Suspicious command line', sha1: 'SHA1 (from artifacts)', sha256: 'SHA256', md5: 'MD5', imphash: 'Import hash', sha256_submitted: 'SHA256 of submitted files', sha1_unsigned_review: 'SHA1 for review (no publisher, outside Program Files/Windows)', persistence: 'Persistence entry', rdp_target: 'RDP target', ssh_target: 'SSH target', hostname: 'Hostname (LNK tracker)', mac_address: 'MAC address (LNK tracker)', av_detection: 'AV detection name', encoded_powershell: 'Encoded PowerShell', btc_wallet: 'Crypto wallet', named_pipe: 'Named pipe', bitlocker_key: 'BitLocker recovery key' };
export const indicatorLabel = (t) => INDICATOR_LABEL[t] || t;

export function markdown(rep, { defanged = true } = {}) {
  const L = [];
  const d = (v) => (defanged ? defangText(v) : v);
  const di = (i) => (defanged && /^(ipv4|domain|url|email)$/.test(i.type) ? defang(i.value) : defanged ? defangText(i.value) : i.value);
  L.push(`# Sudo-Z IOC Report`, '');
  L.push(`Generated ${rep.meta.generated} by Sudo-Z ${rep.meta.version}. All analysis ran locally in the browser.`, '');
  L.push(`## Verdict: ${rep.verdict}`, '');
  L.push(`| Critical | High | Medium | Low | Info |`, `|---|---|---|---|---|`, `| ${rep.severity.critical || 0} | ${rep.severity.high || 0} | ${rep.severity.medium || 0} | ${rep.severity.low || 0} | ${rep.severity.info || 0} |`, '');
  L.push(`- Files: ${rep.counts.files} (${rep.counts.parsed} parsed, ${rep.counts.partial} partial, ${rep.counts.rejected} not accepted, ${rep.counts.errors} errors)`);
  if (rep.window.attackFirst) L.push(`- High/critical activity window: ${rep.window.attackFirst} to ${rep.window.attackLast}`);
  if (rep.window.first) L.push(`- Evidence spans: ${rep.window.first} to ${rep.window.last}`);
  if (rep.hosts.length) L.push(`- Hosts seen: ${rep.hosts.join(', ')}`);
  if (rep.users.length) L.push(`- Accounts seen: ${rep.users.slice(0, 40).join(', ')}`);
  L.push('');
  const mitre = mitreSummary(rep);
  if (mitre.length) { L.push('## MITRE ATT&CK techniques observed', '', '| Technique | Findings | Worst severity |', '|---|---|---|'); for (const m of mitre.slice(0, 40)) L.push(`| ${m.id} | ${m.count} | ${m.worst} |`); L.push(''); }
  if ((rep.leads || []).length) {
    L.push('## Leads to investigate', '', 'Each lead ties together evidence from more than one artifact, or points at something a single tool would not flag on its own.', '');
    rep.leads.forEach((l, i) => {
      L.push(`### ${i + 1}. [${l.sev.toUpperCase()}] ${l.kind}: ${d(l.title)}`, '');
      if (l.why) L.push(`- Why it matters: ${l.why}`);
      if (l.next) L.push(`- Next: ${d(l.next)}`);
      if (l.mitre?.length) L.push(`- ATT&CK: ${l.mitre.join(', ')}`);
      if (l.evidence) L.push('', '```', d(l.evidence).slice(0, 2500), '```');
      if (l.related?.length) { L.push('', `Related events (${l.related.length}, first 20):`, ''); for (const e of l.related.slice(0, 20)) L.push(`- ${e.time} ${e.tool} ${e.type}: ${d(String(e.desc || '').slice(0, 200))}`); }
      L.push('');
    });
  }
  if (rep.execution?.coverage?.length) {
    L.push('## Execution evidence', '', 'The five core execution artifacts, what was collected, and what each one proves.', '');
    L.push('| Artifact | Status | Entries | Range | Expected file | Proves | Note |', '|---|---|---|---|---|---|---|');
    for (const c of rep.execution.coverage) L.push(`| ${c.artifact} | ${c.state} | ${c.entries} | ${c.first ? c.first.slice(0, 10) + ' to ' + c.last.slice(0, 10) : ''} | ${c.expected.replace(/\\/g, '\\\\')} | ${c.proves} | ${c.note} |`);
    L.push('');
  }
  const progs = (rep.programs || []).filter((p) => p.risk >= 25);
  if (progs.length) {
    L.push('## Programs to review', '', 'Every program seen in any artifact, scored on location, signature, persistence, name tricks and linked findings. Full list in programs.csv / the GRID tab.', '');
    L.push('| Risk | Program | Executed? | First run | Signature | Location | Prefetch | ShimCache | Amcache | UserAssist | SRUM | Why |', '|---|---|---|---|---|---|---|---|---|---|---|---|');
    for (const p of progs.slice(0, 60)) L.push(`| ${p.risk} | ${p.name} | ${p.executed} | ${p.firstRun} | ${p.signature} | ${p.location} | ${p.Prefetch} | ${p.ShimCache} | ${p.Amcache} | ${p.UserAssist} | ${p.SRUM} | ${d(p.reasons).replace(/\|/g, '/')} |`);
    L.push('');
  }
  L.push('## Findings', '');
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const fs = rep.findings.filter((f) => f.sev === sev);
    if (!fs.length) continue;
    L.push(`### ${sev.toUpperCase()} (${fs.length})`, '');
    for (const f of fs.slice(0, sev === 'low' ? 100 : 500)) {
      L.push(`**${f.title}**`, '');
      L.push(`- When: ${f.time || 'n/a'} | Tool: ${f.tool} | Category: ${f.category}${f.mitre?.length ? ' | ATT&CK: ' + f.mitre.join(', ') : ''}`);
      L.push(`- Source: \`${f.file}\``);
      if (f.detail) L.push(`- Why: ${f.detail}`);
      if (f.next) L.push(`- Next: ${d(f.next)}`);
      if (f.evidence) L.push('', '```', d(f.evidence).slice(0, 1500), '```');
      L.push('');
    }
    if (sev === 'low' && fs.length > 100) L.push(`_${fs.length - 100} more low severity findings in the JSON/CSV export._`, '');
  }
  L.push('## Indicators of compromise', '');
  const groups = new Map();
  for (const i of rep.indicators) { if (!groups.has(i.type)) groups.set(i.type, []); groups.get(i.type).push(i); }
  for (const [t, list] of groups) {
    L.push(`### ${indicatorLabel(t)} (${list.length})`, '');
    for (const i of list.slice(0, 300)) L.push(`- \`${di(i).slice(0, 400)}\`${i.count > 1 ? ` (x${i.count})` : ''}`);
    L.push('');
  }
  L.push('## Files analysed', '', '| Status | Tool | Artifact | File | Summary |', '|---|---|---|---|---|');
  for (const f of rep.files) L.push(`| ${f.status} | ${f.tool} | ${f.artifact || ''} | \`${f.name}\` | ${(f.summary || f.reason || '').replace(/\|/g, '/')} |`);
  L.push('');
  const rej = rep.files.filter((f) => f.status === 'rejected' || f.status === 'partial');
  if (rej.length) { L.push('## Not accepted / partially analysed', '', '| File | Reason |', '|---|---|'); for (const f of rej) L.push(`| \`${f.name}\` | ${(f.reason || f.notes?.[0] || f.artifact || '').replace(/\|/g, '/')} |`); L.push(''); }
  L.push('## Tool coverage', '', '| EZ tool | Sudo-Z coverage |', '|---|---|');
  for (const c of CATALOG) L.push(`| ${c.tool} | ${c.status} |`);
  L.push('', '---', 'Heuristic findings need analyst validation. Timestamps are UTC.');
  return L.join('\n');
}
