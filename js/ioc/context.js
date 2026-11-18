// Analysis context shared by every tool module.
import { IndicatorStore, extractFromText, extractDomains } from './indicators.js';
import { classifyPath, classifyCommand, maxSev, SEV_RANK, baseName, isLolbin, expandPath } from './heuristics.js';

/** Normalised key for a Windows path (drive letter for volume/device prefixes, lower case). */
export const normKey = (p) => (/\\/.test(p) ? expandPath(String(p)).replace(/^\\\\\?\\/, '').replace(/^\\(volume\{[^}]+\}|device\\harddiskvolume\d+)/i, 'C:').toLowerCase() : baseName(p).toLowerCase());

export class Context {
  constructor() {
    this.findings = [];
    this.timeline = [];
    this.indicators = new IndicatorStore();
    this.exec = new Map(); // lowercase exe name -> [{source, path, time, file}]
    this.hosts = new Set();
    this.users = new Set();
    this.persistAll = []; // every persistence entry, flagged or not (attack chains use it)
    this.signs = new Map(); // path or sha1 -> what any artifact said about its code signature
    this.runCounts = new Map(); // exe path -> run count (Prefetch)
    this._dedupe = new Set();
  }

  finding(f) {
    // f: {sev, title, detail, tool, file, time, mitre[], category, evidence}
    const key = `${f.sev}|${f.title}|${f.file}|${(f.evidence || f.detail || '').slice(0, 200)}`;
    if (this._dedupe.has(key)) return;
    this._dedupe.add(key);
    this.findings.push({ mitre: [], category: 'General', ...f, mitre: [...new Set(f.mitre || [])] });
  }

  event(e) {
    // e: {time, tool, file, type, desc, sev?}
    if (!e.time) return;
    if (this.timeline.length < 400000) this.timeline.push(e);
  }

  text(t, file, opts) { extractFromText(t, this.indicators, file, opts); }
  domains(t, file) { extractDomains(t, this.indicators, file); }

  /** Record evidence that a program ran and grade it. */
  exec_(o) {
    // o: {path, args, time, tool, file, source, user, sha1, extraDetail, baseSev}
    const name = baseName(o.path).toLowerCase();
    if (!name) return null;
    const pc = classifyPath(o.path);
    const key = normKey(o.path);
    if (!this.exec.has(key)) this.exec.set(key, []);
    this.exec.get(key).push({ source: o.source || o.tool, path: o.path, time: o.time, file: o.file, flagged: !!pc.sev, sha1: o.sha1 ? String(o.sha1).toLowerCase() : null, args: o.args || '' });
    if (o.runCount) this.runCounts.set(key, Math.max(this.runCounts.get(key) || 0, +o.runCount || 0));
    const cc = classifyCommand([o.path, o.args].filter(Boolean).join(' '));
    if (o.args || /\s/.test(o.path)) { this.text(o.args || '', o.file); this.domains(o.args || '', o.file); }
    const sev = maxSev(pc.sev, cc.sev, o.baseSev);
    if (sev) {
      const reasons = [...pc.reasons, ...cc.reasons];
      this.finding({
        sev, category: 'Execution', tool: o.tool, file: o.file, time: o.time,
        title: `${o.source || o.tool}: ${cc.reasons[0] || pc.tool || pc.reasons[0] || 'suspicious execution'} (${baseName(o.path)})`,
        detail: reasons.join('; ') + (o.extraDetail ? ` | ${o.extraDetail}` : ''),
        evidence: [o.path, o.args].filter(Boolean).join(' ').slice(0, 1500),
        mitre: [...cc.mitre, ...(pc.score ? ['T1204'] : [])],
      });
      if (pc.score >= 3) this.indicators.add('file_path', o.path, o.file, reasons.join('; '));
      if (o.sha1) this.indicators.add('sha1', o.sha1, o.file, o.path);
      if (cc.score >= 4 && o.args) this.indicators.add('command_line', [o.path, o.args].join(' ').slice(0, 1000), o.file, cc.reasons.join('; '));
    }
    return { pc, cc, sev };
  }

  /**
   * Record what an artifact says about a binary's code signature.
   * o: {path, sha1, signed: true|false|null, verified: true|false|null, signer, publisher, status, kind: 'exe'|'dll'|'driver'|'autorun', source, file, time, host}
   * signed=true/false is an actual signature statement (Sysmon, Autoruns, Sigcheck, PE header, Amcache drivers);
   * publisher alone (Amcache) only says the version resource names a company.
   */
  sign(o) {
    if (!o.path && !o.sha1) return;
    const key = o.path ? normKey(o.path) : `sha1:${String(o.sha1).toLowerCase()}`;
    const e = this.signs.get(key) || { path: o.path || '', sha1: '', signed: null, verified: null, signer: '', publisher: '', status: '', kinds: new Set(), sources: new Set(), file: o.file, time: o.time || '', hosts: new Set() };
    if (o.sha1 && !e.sha1) e.sha1 = String(o.sha1).toLowerCase();
    if (o.signed === false) e.signed = false; else if (o.signed === true && e.signed !== false) e.signed = true;
    if (o.verified === false) e.verified = false; else if (o.verified === true && e.verified !== false) e.verified = true;
    if (o.signer && !e.signer) e.signer = String(o.signer).trim();
    if (o.publisher && !e.publisher) e.publisher = String(o.publisher).trim();
    if (o.status && (!e.status || /valid/i.test(e.status))) e.status = String(o.status);
    if (o.kind) e.kinds.add(o.kind);
    if (o.osComponent) e.os = true;
    if (o.source) e.sources.add(o.source);
    if (o.host) e.hosts.add(o.host);
    if (o.time && (!e.time || o.time < e.time)) e.time = o.time;
    this.signs.set(key, e);
  }

  /** Persistence mechanisms are graded one level higher than plain execution. */
  persist(o) {
    // o: {mechanism, name, command, time, tool, file, mitre, alwaysReport}
    const cmd = o.command || '';
    const pentry = { mechanism: o.mechanism, name: o.name, command: cmd, time: o.time, file: o.file, flagged: false };
    if (this.persistAll.length < 50000) this.persistAll.push(pentry);
    const exe = (cmd.match(/^"([^"]+)"/) || cmd.match(/^(\S+\.(?:exe|dll|bat|cmd|ps1|vbs|js|com|scr))/i) || cmd.match(/^(.+?\.(?:exe|dll|bat|cmd|ps1|vbs|js|com|scr))\b/i) || [null, cmd.split(' ')[0]])[1] || '';
    const pc = classifyPath(exe);
    const cc = classifyCommand(cmd);
    this.text(cmd, o.file); this.domains(cmd, o.file);
    let sev = maxSev(pc.sev, cc.sev);
    if (sev) sev = { low: 'medium', medium: 'high', high: 'critical', critical: 'critical' }[sev];
    const lol = /^(powershell|pwsh|mshta|wscript|cscript|cmd|certutil|bitsadmin|forfiles|msbuild|installutil|regasm|regsvcs|cmstp|msxsl|wmic)\.exe$/i.test(baseName(exe)) || (/^(rundll32|regsvr32)\.exe$/i.test(baseName(exe)) && /\\(users|programdata|temp|perflogs)\\|https?:|scrobj|javascript:/i.test(cmd));
    if (!sev && lol && !/^(svchost|services|lsass)\.exe$/i.test(baseName(exe))) sev = 'medium';
    if (!sev && o.alwaysReport) sev = o.alwaysReport;
    if (sev) {
      pentry.flagged = true;
      this.finding({
        sev, category: 'Persistence', tool: o.tool, file: o.file, time: o.time,
        title: `${o.mechanism}: ${o.name}`,
        detail: [...pc.reasons, ...cc.reasons, lol ? `launches ${baseName(exe)} (LOLBin)` : ''].filter(Boolean).join('; ') || 'review entry',
        evidence: cmd.slice(0, 1500),
        mitre: [...(o.mitre || []), ...cc.mitre],
      });
      this.indicators.add('persistence', `${o.mechanism}: ${o.name} -> ${cmd}`.slice(0, 600), o.file);
    }
    return sev;
  }

  summary() {
    const by = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) by[f.sev] = (by[f.sev] || 0) + 1;
    return by;
  }

  sortedFindings() {
    return [...this.findings].sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || (a.time || '').localeCompare(b.time || ''));
  }
}
