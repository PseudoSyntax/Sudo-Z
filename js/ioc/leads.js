// Investigation leads: cross-artifact reasoning that single-artifact rules
// miss. Runs after every file is parsed.
//   * attack chains (downloaded -> executed -> persisted -> connected/cleaned up)
//   * programs executed then deleted (execution evidence vs $MFT)
//   * the same binary under different names (Amcache SHA1)
//   * process-name lookalikes and known names in the wrong folder
//   * activity around high/critical findings that nothing flagged
//   * new programs in user-writable folders during the incident window
//   * newly created accounts that were then used
import { classifyPath, baseName, isLolbin, SEV_RANK, TOOL_NAMES } from './heuristics.js';
import { BASELINE } from './baseline.js';
import { nextStep } from './playbook.js';

const EXE_RX = /[^\s\\/"'|<>:*?]+\.(exe|dll|scr|ps1|bat|cmd|vbs|js|jse|hta|msi|com|pif|cpl|sys)\b/gi;
const USER_WRITABLE = /\\(users|documents and settings)\\|\\programdata\\|\\windows\\temp\\|\\perflogs\\|\\\$recycle\.bin\\|\\recycler\\|^[a-z]:\\[^\\]+\.(exe|dll|scr|ps1|bat)$/i;
const ROUTINE = /Volume created|Event log started|Clean shutdown|Unexpected shutdown|Shutdown initiated|Web visit|ShimCache \(file mtime\)|SRUM app activity|Local account last logon/i;
const names = (text) => [...new Set((String(text || '').match(EXE_RX) || []).map((n) => n.toLowerCase()))];
const toMs = (t) => (t ? Date.parse(t) : NaN);
const winPath = (p) => String(p || '').replace(/\//g, '\\').replace(/^\\\?\?\\/, '').replace(/^\\device\\harddiskvolume\d+/i, 'C:').replace(/^<vol>/i, 'C:').replace(/^%systemroot%/i, 'C:\\Windows').toLowerCase();

export function buildLeads(ctx, shared, window) {
  const leads = [];
  const lead = (l) => leads.push({ entities: [], related: [], evidence: '', ...l, next: l.next || nextStep({ mitre: l.mitre || [], category: l.category || '' }) });
  const findings = ctx.findings;
  const tl = ctx.timeline;

  // ------------------------------------------------------------ attack chains per file name
  const ent = new Map();
  const touch = (n, stage, info) => {
    if (!n || BASELINE[n] || isLolbin(n)) return;
    const e = ent.get(n) || { stages: new Map(), findings: new Set() };
    if (!e.stages.has(stage)) e.stages.set(stage, []);
    e.stages.get(stage).push(info); ent.set(n, e);
  };
  for (const ev of tl) {
    if (/download|zone\.identifier|ie download|bits/i.test(ev.type)) for (const n of names(ev.desc)) touch(n, 'Delivered', { time: ev.time, src: `${ev.tool}: ${ev.desc}`.slice(0, 300) });
    if (/deleted|recycle bin/i.test(ev.type)) for (const n of names(ev.desc)) touch(n, 'Deleted', { time: ev.time, src: `${ev.tool}: ${ev.desc}`.slice(0, 300) });
  }
  for (const [key, list] of ctx.exec) for (const x of list) touch(baseName(x.path).toLowerCase(), 'Executed', { time: x.time, src: `${x.source}: ${x.path}` });
  for (const p of ctx.persistAll || []) for (const n of names(p.command)) touch(n, 'Persisted', { time: p.time, src: `${p.mechanism}: ${p.name} -> ${p.command}`.slice(0, 300) });
  for (const f of findings) {
    const ns = names(`${f.title} ${f.evidence || ''}`);
    const stage = f.category === 'Persistence' ? 'Persisted' : f.category === 'Command and Control' || f.category === 'Exfiltration' ? 'Network' : /Defense Evasion|File System/.test(f.category) && /delet|timestomp|wipe/i.test(f.title) ? 'Deleted' : null;
    for (const n of ns) { if (stage) touch(n, stage, { time: f.time, src: `${f.tool}: ${f.title}` }); const e = ent.get(n); if (e) e.findings.add(f); }
  }
  const ORDER = ['Delivered', 'Executed', 'Persisted', 'Network', 'Deleted'];
  for (const [n, e] of ent) {
    const stages = ORDER.filter((s) => e.stages.has(s));
    const worst = [...e.findings].reduce((m, f) => Math.max(m, SEV_RANK[f.sev] || 0), 0);
    if (stages.length < 2 || (stages.length < 3 && worst < 2)) continue;
    const execPaths = (e.stages.get('Executed') || []).map((x) => x.src.toLowerCase());
    const vendorOnly = execPaths.length && execPaths.every((x) => /:\\(program files( \(x86\))?|windows)\\/.test(x));
    if (vendorOnly && !e.stages.has('Delivered') && worst < 3) continue;
    const sev = stages.includes('Persisted') && stages.includes('Executed') && (stages.includes('Delivered') || stages.includes('Network')) ? 'critical' : stages.length >= 3 || worst >= 3 ? 'high' : 'medium';
    const steps = stages.map((s) => { const xs = e.stages.get(s).filter((x) => x.time).sort((a, b) => a.time.localeCompare(b.time)); const x = xs[0] || e.stages.get(s)[0]; return `${s.padEnd(9)} ${x.time || '(no time)'}  ${x.src}`; });
    lead({ kind: 'Attack chain', sev, category: 'Correlation', title: `Attack chain for ${n}: ${stages.join(' > ')}`, why: `${n} appears across ${stages.length} stages of an intrusion in independent artifacts. Single artifacts rarely show the whole story; together they do.`, evidence: steps.join('\n'), entities: [n], mitre: ['T1204.002', ...(stages.includes('Persisted') ? ['T1547.001'] : [])], next: `Collect ${n} (or recover it from the $MFT / Recycle Bin if deleted), hash it, and scope the same name / hash on other hosts. Follow each stage in the timeline.` });
  }

  // ------------------------------------------------------------ executed then deleted (needs $MFT)
  if (shared.mft) {
    const byPath = new Map();
    for (const r of shared.mft.rows) if (!r.isDir) byPath.set(winPath(`${r.parentPath}\\${r.name}`.replace(/^\./, 'C:')), r);
    const dirs = new Set([...byPath.keys()].map((p) => p.slice(0, p.lastIndexOf('\\'))));
    const gone = [];
    for (const [, list] of ctx.exec) for (const x of list) {
      const p = winPath(x.path); if (!/^[a-z]:\\/.test(p) || !USER_WRITABLE.test(p)) continue;
      const r = byPath.get(p);
      if (r && !r.inUse) gone.push({ p, state: 'deleted ($MFT record not in use)', x });
      else if (!r && dirs.has(p.slice(0, p.lastIndexOf('\\')))) gone.push({ p, state: 'missing from its folder', x });
    }
    const uniq = [...new Map(gone.map((g) => [g.p, g])).values()];
    if (uniq.length) lead({ kind: 'Executed then deleted', sev: uniq.some((g) => g.x.flagged) ? 'high' : 'medium', category: 'Defense Evasion', title: `${uniq.length} program(s) ran from user-writable folders and are no longer on disk`, why: 'Attackers delete tools after use. Execution artifacts (Prefetch, Amcache, BAM, ShimCache) outlive the file, so comparing them with the $MFT shows what was cleaned up.', evidence: uniq.slice(0, 30).map((g) => `${g.p}  [${g.state}; seen by ${g.x.source}${g.x.time ? ' ' + g.x.time : ''}]`).join('\n'), entities: uniq.slice(0, 10).map((g) => baseName(g.p)), mitre: ['T1070.004'] });
  }

  // ------------------------------------------------------------ same binary, different names
  const bySha = new Map();
  for (const [, list] of ctx.exec) for (const x of list) if (x.sha1) { const s = bySha.get(x.sha1) || new Map(); s.set(baseName(x.path).toLowerCase(), x.path); bySha.set(x.sha1, s); }
  for (const [sha, m] of bySha) {
    if (m.size < 2) continue;
    const list = [...m.keys()];
    // installers (Inno/NSIS .tmp, unins000) and DLL-only pairs are normal duplicates
    if (list.every((n) => /\.(dll|sys|ocx|cpl|tmp)$/.test(n) || /^unins\d+\.exe$|setup|install/.test(n))) continue;
    if (list.some((n) => /\.tmp$|^unins\d+\.exe$/.test(n))) continue;
    const known = list.find((n) => isLolbin(n) || TOOL_NAMES.some((t) => t.rx.test(n)) || BASELINE[n]);
    lead({ kind: 'Renamed binary', sev: known ? 'high' : 'medium', category: 'Defense Evasion', title: `Same file (SHA1 ${sha.slice(0, 12)}…) seen under ${m.size} names: ${list.join(', ')}`, why: known ? `${known} renamed to evade name-based detection is a common attacker trick (e.g. renamed PsExec, rclone or a LOLBin).` : 'One binary under several names is worth explaining (renamed tools hide from name-based rules).', evidence: [...m.values()].join('\n'), entities: [sha, ...list], mitre: ['T1036.003'] });
  }

  // ------------------------------------------------------------ lookalikes / wrong folder (aggregate)
  const looks = findings.filter((f) => /lookalike of|outside its normal folder/.test(f.detail || ''));
  if (looks.length) {
    const items = [...new Map(looks.map((f) => [(f.evidence || f.title).toLowerCase(), f])).values()];
    lead({ kind: 'Masquerading', sev: looks.some((f) => /non-Latin/.test(f.detail)) ? 'critical' : 'high', category: 'Defense Evasion', title: `${items.length} executable(s) imitate Windows or common application names`, why: 'Misspelled names (scvhost.exe), lookalike characters, extra digits, and genuine names in the wrong folder are easy to miss when scanning a process or file list by eye.', evidence: items.slice(0, 30).map((f) => `${f.evidence || f.title}\n    ${(f.detail || '').split('; ').filter((d) => /lookalike|normal folder/.test(d)).join('; ')}  [${f.tool}]`).join('\n'), entities: items.slice(0, 10).map((f) => baseName(f.evidence || '')).filter(Boolean), mitre: ['T1036.005'] });
  }

  // ------------------------------------------------------------ activity around high/critical findings
  const hot = findings.filter((f) => SEV_RANK[f.sev] >= 3 && !isNaN(toMs(f.time))).sort((a, b) => toMs(a.time) - toMs(b.time));
  const W = 15 * 60 * 1000;
  const clusters = [];
  for (const f of hot) { const t = toMs(f.time); const c = clusters[clusters.length - 1]; if (c && t - c.end <= W) { c.end = t; c.items.push(f); } else clusters.push({ start: t, end: t, items: [f] }); }
  const flaggedText = new Set(findings.map((f) => (f.evidence || '').toLowerCase().slice(0, 120)));
  for (const c of clusters.slice(0, 12)) {
    const around = tl.filter((e) => { const t = toMs(e.time); return t >= c.start - W && t <= c.end + W && !ROUTINE.test(e.type); });
    const unflagged = around.filter((e) => !flaggedText.has(String(e.desc || '').toLowerCase().slice(0, 120)));
    if (unflagged.length < 3) continue;
    lead({ kind: 'Activity window', sev: 'medium', category: 'Correlation', title: `${unflagged.length} unflagged event(s) within 15 min of: ${c.items[0].title.slice(0, 90)}${c.items.length > 1 ? ` (+${c.items.length - 1} more)` : ''}`, why: 'What happened just before and after a confirmed bad event is where analysts find the next step of the intrusion: the dropper, the logon that preceded it, the tool run next. These events did not trip a rule on their own.', evidence: c.items.map((f) => `[${f.sev}] ${f.time} ${f.title}`).join('\n'), related: unflagged.slice(0, 60), entities: names(c.items.map((f) => f.evidence).join(' ')).slice(0, 5), mitre: [], next: 'Read the related events in order. Anything executed, created or logged on in this window that you cannot explain belongs in scope.' });
  }

  // ------------------------------------------------------------ new programs in user-writable folders during the incident
  if (window.attackFirst) {
    const a = toMs(window.attackFirst) - 7200000, b = toMs(window.attackLast) + 7200000;
    const fresh = [];
    for (const [, list] of ctx.exec) for (const x of list) {
      const t = toMs(x.time); const p = winPath(x.path);
      if (isNaN(t) || t < a || t > b || x.flagged || !USER_WRITABLE.test(p) || BASELINE[baseName(p)]) continue;
      if (!/\.(exe|scr|com|pif|bat|cmd|ps1|vbs|js|hta)$/i.test(p)) continue;
      if (/\\programdata\\(chocolatey|package cache)\\|\\appdata\\local\\(apps\\2\.0|jetbrains|programs\\(microsoft vs code|python))\\/i.test(p)) continue;
      if (/(^|\\)(unins\d+|.*setup.*|.*install.*|.*update.*)\.exe$|\.tmp$/i.test(p)) continue;
      if (/\\appdata\\local\\(microsoft\\(onedrive|teams|edgeupdate)|google\\update|temp\\[^\\]*\\(is-|~nsu|nsx|chocolatey))/i.test(p)) continue;
      fresh.push(x);
    }
    // one entry per folder so a single installer does not flood the list
    const uniq = [...new Map(fresh.map((x) => [winPath(x.path).replace(/\\[^\\]+$/, '').toLowerCase(), x])).values()].sort((x, y) => (x.time || '').localeCompare(y.time || ''));
    if (uniq.length) lead({ kind: 'Unflagged new programs', sev: uniq.length > 25 ? 'low' : 'medium', category: 'Execution', title: `${uniq.length} program(s) in user-writable folders ran within 2 hours of the high/critical activity and were not flagged`, why: 'Custom or renamed attacker tools often have harmless-looking names and sit in user folders. Rules miss them; timing does not.', evidence: uniq.slice(0, 40).map((x) => `${x.time}  ${x.path}  [${x.source}]`).join('\n'), entities: uniq.slice(0, 10).map((x) => baseName(x.path)), mitre: ['T1204'], next: 'Hash each program (Amcache SHA1 is often available), check it in threat intel, and confirm with the user whether it is expected.' });
  }

  // ------------------------------------------------------------ new account then used
  for (const f of findings.filter((x) => /User account created|Local account name ends with \$|account created:/i.test(x.title))) {
    const user = (f.title.match(/created:\s*(?:[^\\\s]+\\)?(\S+)/i) || f.title.match(/ends with \$:\s*(\S+)/) || [])[1];
    if (!user || user === '-') continue;
    const uses = tl.filter((e) => /logon|RDP|session|Explicit credential/i.test(e.type) && new RegExp(`(^|[^\\w$])${user.replace(/[$.*+?^{}()|[\]\\]/g, '\\$&')}($|[^\\w$])`, 'i').test(e.desc) && (!f.time || e.time >= f.time));
    if (uses.length) lead({ kind: 'New account used', sev: 'high', category: 'Persistence', title: `Account ${user} was created and then used ${uses.length} time(s)`, why: 'A freshly created account that is immediately used for logons or RDP is a backdoor pattern.', evidence: `${f.time || ''} ${f.title}\n` + uses.slice(0, 15).map((e) => `${e.time} ${e.type}: ${e.desc}`).join('\n'), related: uses.slice(0, 40), entities: [user], mitre: ['T1136', 'T1078'] });
  }

  // ------------------------------------------------------------ event log tampering summary
  const gaps = findings.filter((f) => /record\(s\) missing|records missing|clock moved backwards/i.test(f.title));
  const cleared = findings.filter((f) => /log cleared/i.test(f.title));
  if (gaps.length || cleared.length) lead({ kind: 'Log tampering', sev: cleared.length || gaps.some((g) => g.sev === 'high') ? 'high' : 'medium', category: 'Defense Evasion', title: `Event logs show signs of tampering (${cleared.length} clear event(s), ${gaps.length} record gap(s))`, why: 'Cleared logs are obvious; selectively deleted records (gaps in EventRecordID) are not, and are only visible when record numbers are checked.', evidence: [...cleared, ...gaps].slice(0, 20).map((f) => `${f.time || ''} ${f.title} [${f.file.split('/').pop()}]`).join('\n'), mitre: ['T1070.001'] });

  return leads.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev]);
}

export function attachNextSteps(findings) { for (const f of findings) if (!f.next) f.next = nextStep(f); }
