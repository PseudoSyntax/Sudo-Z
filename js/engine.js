// Sudo-Z engine: intake -> route each file to the right tool -> build report.
import { isZip, unzip } from './core/zip.js';
import { hashAll } from './core/hash.js';
import { Reader, utf8 } from './core/bytes.js';
import { Context } from './ioc/context.js';
import { SEV_RANK } from './ioc/heuristics.js';
import { isEvtx } from './parsers/evtx.js';
import { isPrefetch } from './parsers/prefetch.js';
import { isLnk } from './parsers/lnk.js';
import { isCfb } from './core/cfb.js';
import { isRegf } from './parsers/regf.js';
import { isMft, isBoot, looksLikeUsn } from './parsers/ntfs.js';
import { isDollarI, isInfo2, isRecentFileCache, isIisLog } from './parsers/misc.js';
import { isSqlite } from './parsers/sqlite.js';
import { runEvtx } from './tools/evtx.js';
import { runRegistry } from './tools/registry.js';
import * as A from './tools/artifacts.js';

export const VERSION = '1.0.0';
const MAX_ZIP_DEPTH = 3;
const MAX_FILE = 1.5 * 1024 ** 3;

const base = (n) => n.split(/[\\/]/).pop();
const ext = (n) => (base(n).match(/\.([^.]+)$/) || [])[1]?.toLowerCase() || '';

/** Decide what a file is. Returns {id, tool, label} | {reject, reason} */
export function detect(name, u8) {
  const b = base(name), lb = b.toLowerCase();
  if (u8.length === 0) return { reject: true, reason: 'Empty file (0 bytes).' };
  if (isEvtx(u8)) return { id: 'evtx', tool: 'EvtxECmd', label: 'Windows event log' };
  if (/\.evt$/i.test(b) && new Reader(u8).magic(4, 'LfLe')) return { reject: true, reason: 'Legacy XP/2003 .evt format. EvtxECmd does not read .evt either; convert with wevtutil epl /lf:true.', strings: true };
  if (isPrefetch(u8)) return { id: 'prefetch', tool: 'PECmd', label: 'Prefetch' };
  if (isLnk(u8)) return { id: 'lnk', tool: 'LECmd', label: 'Shortcut' };
  if (/\.automaticdestinations-ms$/i.test(b) && isCfb(u8)) return { id: 'jl-auto', tool: 'JLECmd', label: 'Jump list (automatic)' };
  if (/\.customdestinations-ms$/i.test(b)) return { id: 'jl-custom', tool: 'JLECmd', label: 'Jump list (custom)' };
  if (isRegf(u8)) return { id: 'reg', tool: 'RECmd', label: 'Registry hive' };
  if (/\.(log1|log2)$/i.test(b) || (/\.log$/i.test(b) && new Reader(u8).magic(0, 'regf')) || (/\.log\d?$/i.test(b) && new Reader(u8).magic(0, 'HvLE'))) return { reject: true, reason: 'Registry transaction log. Needs RLA (Registry Log Replayer) on Windows to merge into the hive.' };
  if (isMft(u8) && (/mft/i.test(b) || u8.length >= 16 * 1024)) return { id: 'mft', tool: 'MFTECmd', label: '$MFT' };
  if (isBoot(u8) && /boot/i.test(b)) return { id: 'boot', tool: 'MFTECmd', label: '$Boot' };
  if (/^(\$j|\$usnjrnl.*|usnjrnl.*|.*\$j)$/i.test(b) || (/usn/i.test(b) && looksLikeUsn(u8))) return { id: 'usn', tool: 'MFTECmd', label: '$UsnJrnl:$J' };
  if (/^\$(logfile|sds|secure.*sds|i30)$/i.test(b)) return { id: 'strings', tool: 'bstrings', label: `${b} (MFTECmd input not decoded in-browser)`, partial: true };
  if (isDollarI(u8, b)) return { id: 'dollar-i', tool: 'RBCmd', label: 'Recycle Bin $I' };
  if (isInfo2(u8, b)) return { id: 'info2', tool: 'RBCmd', label: 'Recycle Bin INFO2' };
  if (/^\$R[A-Z0-9]{6}/i.test(b)) return { id: 'strings', tool: 'bstrings', label: 'Recycle Bin $R (deleted file content)', partial: true };
  if (isRecentFileCache(u8, b)) return { id: 'rfc', tool: 'RecentFileCacheParser', label: 'RecentFileCache.bcf' };
  if (isSqlite(u8)) return { id: 'sqlite', tool: /activitiescache/i.test(b) ? 'WxTCmd' : 'SQLECmd', label: 'SQLite database' };
  if (u8.length > 8 && new Reader(u8).u32(4) === 0x89abcdef) {
    const which = /srudb/i.test(b) ? 'SrumECmd' : /\.mdb$/i.test(b) ? 'SumECmd' : 'ESE';
    return { id: 'strings', tool: 'bstrings', label: `ESE database (${which} input; string-scanned only)`, partial: true, eseFor: which };
  }
  const head = utf8(u8.subarray(0, 4096));
  if (isIisLog(u8, b)) return { id: 'iis', tool: 'iisGeolocate', label: 'IIS log' };
  if (/consolehost_history\.txt$/i.test(b)) return { id: 'pshistory', tool: 'Sudo-Z', label: 'PowerShell history' };
  if (/<Task\s[^>]*xmlns=["']http:\/\/schemas\.microsoft\.com\/windows\/2004\/02\/mit\/task/i.test(head) || /^﻿?<\?xml[^>]*\?>\s*<Task/i.test(head) || (/\x00<\x00T\x00a\x00s\x00k\x00/.test(String.fromCharCode(...u8.subarray(0, 400))))) return { id: 'task', tool: 'Sudo-Z', label: 'Scheduled task XML' };
  if (/\.(ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|hta|sh|py|txt|log|xml|ini|inf|reg|url|csv|json|html?|aspx?|ashx|php|jsp)$/i.test(b) && !/[\x00-\x08\x0e-\x1f]/.test(head.replace(/\x00/g, '').slice(0, 1000))) return { id: 'text', tool: 'Sudo-Z', label: 'Script / text file' };
  if (u8[0] === 0x4d && u8[1] === 0x5a) return { reject: true, reason: 'Windows PE executable/DLL. Not an Eric Zimmerman tool input; hashed and string-scanned only.', strings: true, pe: true };
  if (/\.sdb$/i.test(b)) return { id: 'strings', tool: 'bstrings', label: 'Shim database (.sdb, SDB Explorer input)', partial: true, sdb: true };
  if (/^(e01|ex01|s01|l01|aff4?|vmdk|vhdx?|vdi|qcow2?|dd|raw|img|iso|dmg|mem|vmem|dmp|hiberfil\.sys|pagefile\.sys|swapfile\.sys)$/i.test(ext(b)) || /^(hiberfil|pagefile|swapfile)\.sys$/i.test(b)) return { reject: true, reason: 'Disk/memory image or system page file. Not accepted: extract artifacts with KAPE/FTK Imager first.' };
  if (/^(rar|7z|gz|tgz|tar|bz2|xz|cab|wim)$/i.test(ext(b))) return { reject: true, reason: `.${ext(b)} archives are not opened in-browser. Re-pack as a standard .zip.` };
  if (/^(jpe?g|png|gif|bmp|ico|mp3|mp4|avi|mov|wav|ttf|otf|woff2?)$/i.test(ext(b))) return { reject: true, reason: 'Media/font file. No EZ tool parses this; hashed and string-scanned only.', strings: true };
  if (/^(docx?|xlsx?|pptx?|pdf|rtf|one|msg|eml)$/i.test(ext(b))) return { reject: true, reason: 'Office/PDF/mail document. Only EZViewer (a viewer) opens these; hashed and string-scanned for indicators.', strings: true };
  return { reject: true, reason: 'No Eric Zimmerman tool accepts this file type. Hashed and string-scanned only.', strings: true };
}

/** Expand inputs (zips may be nested). inputs: [{name, data:Uint8Array}] */
async function expand(inputs, log) {
  const out = []; const rejected = [];
  const walk = async (name, data, depth, parent) => {
    if (isZip(data) && /\.zip$|^[^.]*$/i.test(base(name)) || (isZip(data) && depth === 0)) {
      if (depth >= MAX_ZIP_DEPTH) { rejected.push({ name, size: data.length, reason: `Nested zip deeper than ${MAX_ZIP_DEPTH} levels.`, parent }); return; }
      log(`unzipping ${name}`);
      let z;
      try { z = await unzip(data); } catch (e) { rejected.push({ name, size: data.length, reason: `Zip could not be read: ${e.message}`, parent }); return; }
      for (const ent of z.entries) {
        const full = `${name}/${ent.name}`;
        if (ent.error) { rejected.push({ name: full, size: ent.size, reason: ent.error, parent: name }); continue; }
        await walk(full, ent.data, depth + 1, name);
      }
      return;
    }
    out.push({ name, data, parent });
  };
  for (const i of inputs) await walk(i.name, i.data, 0, null);
  return { files: out, rejected };
}

export async function analyze(inputs, { onProgress = () => {}, log = () => {} } = {}) {
  const t0 = Date.now();
  const ctx = new Context();
  const shared = {};
  onProgress(0, 'Expanding archives');
  const { files, rejected } = await expand(inputs, log);
  const results = [];
  // routing; MFT first so $J can resolve paths
  const routed = files.map((f) => ({ ...f, det: f.data.length > MAX_FILE ? { reject: true, reason: 'File larger than 1.5 GB browser limit.' } : detect(f.name, f.data) }));
  routed.sort((a, b) => (a.det.id === 'mft' ? -1 : 0) - (b.det.id === 'mft' ? -1 : 0));
  let i = 0;
  for (const f of routed) {
    i++;
    onProgress(i / (routed.length + 1), `${f.det.tool || 'Hasher'} :: ${base(f.name)}`);
    await new Promise((r) => setTimeout(r, 0));
    const rec = { name: f.name, size: f.data.length, parent: f.parent, hashes: null, status: 'parsed', tool: f.det.tool || 'Hasher + bstrings', artifact: f.det.label || '', summary: '', tables: [], notes: [], ms: 0 };
    const t = Date.now();
    try { rec.hashes = await hashAll(f.data); } catch (e) { rec.notes.push('hashing failed: ' + e.message); }
    const ff = { name: f.name };
    try {
      let r;
      switch (f.det.id) {
        case 'evtx': r = runEvtx(f.data, ff, ctx); break;
        case 'prefetch': r = A.runPrefetch(f.data, ff, ctx); break;
        case 'lnk': r = A.runLnk(f.data, ff, ctx); break;
        case 'jl-auto': r = A.runJumpList(f.data, ff, ctx, 'auto'); break;
        case 'jl-custom': r = A.runJumpList(f.data, ff, ctx, 'custom'); break;
        case 'reg': r = runRegistry(f.data, ff, ctx); break;
        case 'mft': r = A.runMft(f.data, ff, ctx, shared); break;
        case 'usn': r = A.runUsn(f.data, ff, ctx, shared); break;
        case 'boot': r = A.runBoot(f.data, ff, ctx); break;
        case 'dollar-i': r = A.runDollarI(f.data, ff, ctx); break;
        case 'info2': r = A.runInfo2(f.data, ff, ctx); break;
        case 'rfc': r = A.runRecentFileCache(f.data, ff, ctx); break;
        case 'sqlite': r = A.runSqlite(f.data, ff, ctx); break;
        case 'iis': r = A.runIis(f.data, ff, ctx); break;
        case 'pshistory': r = A.runText(f.data, ff, ctx, 'pshistory'); break;
        case 'task': r = A.runText(f.data, ff, ctx, 'task'); break;
        case 'text': r = A.runText(f.data, ff, ctx, 'text'); break;
        case 'strings': r = A.runGeneric(f.data, ff, ctx, f.det.label); rec.status = 'partial'; break;
        default:
          rec.status = 'rejected'; rec.reason = f.det.reason;
          if (f.det.strings) { r = A.runGeneric(f.data, ff, ctx, 'Not accepted (strings + hash only)'); }
          if (f.det.pe) ctx.finding({ sev: 'info', category: 'Submitted Binary', tool: 'Hasher', file: f.name, title: `Executable submitted: ${base(f.name)}`, detail: 'Pivot on the hashes in your threat intel / sandbox.', evidence: rec.hashes ? `SHA256 ${rec.hashes.sha256}` : '' });
      }
      if (f.det.sdb) ctx.finding({ sev: /apppatch\\custom/i.test(f.name.replace(/\//g, '\\')) ? 'high' : 'medium', category: 'Persistence', tool: 'SDB Explorer', file: f.name, title: `Application shim database present: ${base(f.name)}`, detail: 'Custom shims can inject DLLs into processes (shim persistence).', mitre: ['T1546.011'] });
      if (r) Object.assign(rec, { tool: r.tool || rec.tool, artifact: r.artifact || rec.artifact, summary: r.summary || '', tables: r.tables || [], notes: [...rec.notes, ...(r.notes || [])] });
      if (f.det.partial && f.det.eseFor) rec.notes.push(`${f.det.eseFor} would fully parse this ESE database; Sudo-Z extracted strings only.`);
    } catch (e) {
      rec.notes.push(`${f.det.tool} failed: ${e.message}. Falling back to bstrings.`);
      rec.status = 'error';
      try { const g = A.runGeneric(f.data, ff, ctx, 'Parser error, strings only'); rec.tables = g.tables; rec.summary = g.summary; } catch { }
    }
    if (rec.hashes) ctx.indicators.add('sha256_submitted', rec.hashes.sha256, f.name, base(f.name));
    rec.ms = Date.now() - t;
    results.push(rec);
  }
  for (const r of rejected) results.push({ name: r.name, size: r.size, parent: r.parent, status: 'rejected', reason: r.reason, tool: '-', artifact: '', summary: '', tables: [], notes: [] });

  onProgress(0.99, 'Building report');
  // correlation: same suspicious program seen by multiple execution artifacts
  for (const [name, list] of ctx.exec) {
    const sources = [...new Set(list.map((l) => l.source))];
    const susp = list.some((l) => l.flagged);
    if (susp && sources.length >= 2) ctx.finding({ sev: 'high', category: 'Correlation', tool: 'Sudo-Z', file: '(multiple)', time: list.map((l) => l.time).filter(Boolean).sort()[0], title: `${name.split('\\').pop()} confirmed by ${sources.length} independent execution artifacts`, detail: sources.join(', '), evidence: [...new Set(list.map((l) => l.path))].slice(0, 5).join('\n') });
  }
  const timeline = ctx.timeline.filter((e) => e.time).sort((a, b) => a.time.localeCompare(b.time));
  const findings = ctx.sortedFindings();
  const indicators = ctx.indicators.list();
  const counts = { files: results.length, parsed: results.filter((r) => r.status === 'parsed').length, partial: results.filter((r) => r.status === 'partial').length, rejected: results.filter((r) => r.status === 'rejected').length, errors: results.filter((r) => r.status === 'error').length };
  const sev = ctx.summary();
  const verdict = sev.critical ? 'COMPROMISE LIKELY' : sev.high ? 'SUSPICIOUS ACTIVITY' : sev.medium ? 'REVIEW RECOMMENDED' : 'NO STRONG INDICATORS';
  const first = timeline[0]?.time, last = timeline[timeline.length - 1]?.time;
  // attack window = span of high/critical findings
  const hot = findings.filter((x) => SEV_RANK[x.sev] >= 3 && x.time).map((x) => x.time).sort();
  return {
    meta: { tool: 'Sudo-Z', version: VERSION, generated: new Date().toISOString(), durationMs: Date.now() - t0, inputs: inputs.map((i) => ({ name: i.name, size: i.data.length })) },
    verdict, severity: sev, counts,
    hosts: [...ctx.hosts].filter(Boolean), users: [...ctx.users].filter((u) => u && !/^(-|system|local service|network service|anonymous logon|dwm-\d+|umfd-\d+)$/i.test(u) && !/\$$/.test(u)),
    window: { first, last, attackFirst: hot[0], attackLast: hot[hot.length - 1] },
    findings, indicators, timeline, files: results,
  };
}
