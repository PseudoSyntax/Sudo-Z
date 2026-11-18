// One row per program seen anywhere in the evidence: where it lives, who signed
// it, when it ran, how it persists, what it touched, and a risk score. This is
// the "top view" the GRID tab opens on.
import { classifyPath, baseName, SEV_RANK, isLolbin, expandPath } from './heuristics.js';
import { normKey } from './context.js';
import { lookalike } from './baseline.js';

const LOC = [
  [/^[a-z]:\\windows\\temp\\/i, 'User-writable'],
  [/^[a-z]:\\windows\\(system32|syswow64|winsxs|servicing)\\/i, 'System'],
  [/^[a-z]:\\windows\\/i, 'Windows'],
  [/^[a-z]:\\program files( \(x86\))?\\/i, 'Program Files'],
  [/^[a-z]:\\(users|documents and settings)\\[^\\]+\\appdata\\local\\(microsoft\\(onedrive|teams|edgeupdate|windowsapps)|programs\\)/i, 'User apps'],
  [/^[a-z]:\\(users|documents and settings|programdata|perflogs|recycler|\$recycle\.bin)\\|\\temp\\|^[a-z]:\\[^\\]+\.(exe|dll|scr)$/i, 'User-writable'],
  [/^\\\\/, 'Network share'],
  [/^[d-z]:\\/i, 'Other drive'],
];
export const location = (p) => { for (const [rx, n] of LOC) if (rx.test(p)) return n; return /\\/.test(p) ? 'Other' : 'Name only'; };

export function signatureLabel(s) {
  if (!s) return ['unknown', 'No signature data'];
  if (s.signed === true && s.verified === false) return ['invalid', `Signature not valid${s.status ? ' (' + s.status + ')' : ''}${s.signer ? ': ' + s.signer : ''}`];
  if (s.signed === true) return ['signed', `Signed${s.verified ? ' (verified)' : ''}${s.signer ? ': ' + s.signer : ''}`];
  if (s.signed === false) return ['unsigned', 'Unsigned'];
  if (s.os) return ['os', 'Windows component (Amcache)'];
  if (s.publisher) return ['publisher', `Publisher ${s.publisher} (version info, not a signature)`];
  return ['unknown', 'No signature data'];
}

/** Findings from signature data that no single artifact raises on its own. */
export function gradeSignatures(ctx) {
  let n = 0;
  for (const s of ctx.signs.values()) {
    if (n > 200) break;
    if (s.signed === true && s.verified === false && s.status && !/^valid$/i.test(s.status)) {
      const revoked = /revoked|distrust|untrusted|bad/i.test(s.status);
      if (/expired/i.test(s.status) && !s.kinds.has('driver')) continue; // expired code-signing certs are common and still valid with a timestamp
      ctx.finding({ sev: revoked ? 'high' : 'medium', category: 'Defense Evasion', tool: [...s.sources][0] || 'Sudo-Z', file: s.file, time: s.time, title: `Signature not valid (${s.status}): ${baseName(s.path)}`, detail: `signer ${s.signer || '?'}; sources ${[...s.sources].join(', ')}`, evidence: `${s.path}${s.sha1 ? '\nSHA1 ' + s.sha1 : ''}`, mitre: ['T1553.002'] }); n++;
    }
  }
}

export function buildPrograms(ctx, findings) {
  const rows = new Map();
  const clean = (p) => expandPath(String(p || '')).replace(/^\\\?\?\\|^\\\\\?\\/, '').replace(/^\\(device\\harddiskvolume\d+|volume\{[^}]+\})/i, 'C:');
  const row = (key, path) => {
    path = clean(path);
    let r = rows.get(key);
    if (!r) { r = { key, path, name: baseName(path), sha1: new Set(), sources: new Set(), times: [], persist: new Set(), persistFlagged: false, findings: [], args: new Set(), sign: null }; rows.set(key, r); }
    if (path && path.length > r.path.length) r.path = path;
    return r;
  };
  for (const [key, list] of ctx.exec) for (const x of list) {
    const r = row(key, x.path); r.sources.add(x.source); if (x.time) r.times.push(x.time); if (x.sha1) r.sha1.add(x.sha1); if (x.args && r.args.size < 5) r.args.add(x.args.slice(0, 300));
  }
  for (const [key, s] of ctx.signs) {
    if (key.startsWith('sha1:')) continue;
    // DLL and driver loads are only rows of their own when the signature is a problem
    const only = !rows.has(key);
    if (only && (s.kinds.has('dll') || s.kinds.has('driver')) && s.signed !== false && s.verified !== false && !s.sources.has('Amcache drivers')) continue;
    const r = row(key, s.path); r.sign = s; for (const src of s.sources) r.sources.add(src); if (s.sha1) r.sha1.add(s.sha1); if (s.time) r.times.push(s.time);
  }
  for (const p of ctx.persistAll) {
    const cmd = p.command || '';
    const exe = (cmd.match(/^"([^"]+)"/) || cmd.match(/^(.+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|com|scr))\b/i) || [])[1];
    if (!exe) continue;
    if (!/\\/.test(exe) && !p.flagged) continue; // bare names (cmd.exe) only when the entry itself was flagged
    const r = row(normKey(exe), exe); r.persist.add(p.mechanism); if (p.flagged) r.persistFlagged = true; if (p.time) r.times.push(p.time);
  }
  // fold name-only rows into the single full-path row with the same name
  const byBase = new Map();
  for (const r of rows.values()) if (/\\/.test(r.path)) { const k = r.name.toLowerCase(); byBase.set(k, byBase.has(k) ? null : r); }
  for (const [key, r] of [...rows]) {
    if (/\\/.test(r.path)) continue;
    const target = byBase.get(r.name.toLowerCase()); if (!target) continue;
    for (const x of r.sources) target.sources.add(x); for (const x of r.sha1) target.sha1.add(x); target.times.push(...r.times); for (const x of r.persist) target.persist.add(x);
    target.persistFlagged ||= r.persistFlagged; for (const x of r.args) target.args.add(x); target.sign ||= r.sign;
    rows.delete(key);
  }
  // findings that name a program
  const byName = new Map();
  for (const r of rows.values()) if (r.name.length >= 5 && /\.[a-z]{2,4}$/i.test(r.name)) { const k = r.name.toLowerCase(); if (!byName.has(k)) byName.set(k, []); byName.get(k).push(r); }
  // a finding belongs to a program when it names its full path, or (for names that are not
  // common Windows binaries) when the name is the finding's subject "(name.exe)"
  for (const f of findings) {
    if (f.sev === 'info') continue;
    const text = `${f.title}\n${f.evidence || ''}`.toLowerCase().replace(/\\\?\?\\/g, '');
    for (const m of text.matchAll(/[\w$.~\-]+\.(exe|dll|sys|scr|com|ps1|bat|cmd|vbs|js|hta|cpl|msi)\b/g)) {
      for (const r of byName.get(m[0]) || []) {
        if (r.findings.includes(f)) continue;
        const common = isLolbin(r.name) || /^(svchost|explorer|services|lsass|csrss|winlogon|smss|wininit|taskhostw?|conhost|dllhost|spoolsv|searchindexer|msmpeng)\.exe$/i.test(r.name);
        const full = /\\/.test(r.path) && text.includes(r.path.toLowerCase());
        const subject = f.title.toLowerCase().includes(`(${r.name.toLowerCase()})`) || f.title.toLowerCase().endsWith(r.name.toLowerCase());
        if (full || (!common && subject) || (subject && !/\\/.test(r.path))) r.findings.push(f);
      }
    }
  }
  const out = [];
  for (const r of rows.values()) {
    if (!r.name || /^[{(]/.test(r.name)) continue;
    const loc = location(clean(r.path));
    const pc = classifyPath(r.path);
    const [state, sigText] = signatureLabel(r.sign);
    const worst = r.findings.reduce((m, f) => Math.max(m, SEV_RANK[f.sev] || 0), 0);
    const reasons = [...pc.reasons];
    let risk = Math.min(40, (pc.score || 0) * 8);
    const userish = loc === 'User-writable' || loc === 'Network share' || loc === 'Other drive';
    if (state === 'unsigned') { risk += userish ? 25 : loc === 'System' || loc === 'Windows' ? 15 : 10; reasons.push('unsigned'); }
    if (state === 'invalid') { risk += 30; reasons.push('signature not valid'); }
    if ((state === 'unknown' || state === 'publisher') && userish && /\.exe$/i.test(r.name) && !r.sign?.publisher) { risk += 8; reasons.push('no publisher recorded'); }
    if (r.persist.size && (r.persistFlagged || !['System', 'Windows', 'Program Files'].includes(loc))) { risk += r.persistFlagged ? 20 : 15; reasons.push('persists: ' + [...r.persist].slice(0, 2).join(', ')); }
    if (worst) risk += [0, 0, 10, 25, 40][worst];
    const look = lookalike(r.name); if (look && !reasons.some((x) => /lookalike/.test(x))) { risk += 15; reasons.push(look.detail); }
    if (r.sources.size >= 3 && userish) { risk += 5; reasons.push(`seen by ${r.sources.size} artifacts`); }
    risk = Math.min(100, risk);
    const t = r.times.filter(Boolean).sort();
    out.push({
      risk, level: risk >= 70 ? 'critical' : risk >= 45 ? 'high' : risk >= 25 ? 'medium' : risk >= 10 ? 'low' : 'info',
      name: r.name, path: r.path, location: loc, signature: sigText, signState: state,
      signer: r.sign?.signer || r.sign?.publisher || '', sha1: [...r.sha1].slice(0, 3).join(' '),
      firstSeen: t[0] || '', lastSeen: t[t.length - 1] || '', runs: ctx.runCounts.get(r.key) || '',
      sources: [...r.sources].join(', '), persistence: [...r.persist].join('; '), lolbin: isLolbin(r.name),
      findings: r.findings.length, topFinding: r.findings.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev])[0]?.title || '',
      reasons: [...new Set(reasons)].join('; '), args: [...r.args].join(' | '),
    });
  }
  return out.sort((a, b) => b.risk - a.risk || a.name.localeCompare(b.name)).slice(0, 25000);
}

export const PROGRAM_COLUMNS = [
  ['risk', 'Risk'], ['level', 'Level'], ['name', 'Program'], ['signature', 'Signature'], ['location', 'Location'], ['path', 'Path'],
  ['firstSeen', 'First seen'], ['lastSeen', 'Last seen'], ['runs', 'Runs'], ['sources', 'Seen by'], ['persistence', 'Persistence'],
  ['findings', 'Findings'], ['topFinding', 'Top finding'], ['reasons', 'Why'], ['sha1', 'SHA1'], ['signer', 'Signer / publisher'], ['args', 'Command lines'],
];
