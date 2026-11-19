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
import { runEse } from './tools/ese.js';
import { runVol, finalizeVol, looksLikeVol } from './tools/volatility.js';
import { runVelo, isVeloCollection, veloName } from './tools/velociraptor.js';
import { isEse } from './parsers/ese.js';
import { isJob, isEvt, isIndx, isWal, mergeWal } from './parsers/legacy.js';
import { isRegLog, replayHive } from './parsers/reglog.js';
import { buildLeads, attachNextSteps } from './ioc/leads.js';
import { probeImage, extractImage, groupSegments, IMAGE_EXT } from './image/index.js';
import { fromBytes } from './image/source.js';
import { isPe } from './parsers/pe.js';
import { runPe } from './tools/binaries.js';
import { buildPrograms, gradeSignatures } from './ioc/programs.js';
import { analyseExecution } from './ioc/execution.js';
import { analyseMacb } from './ioc/macb.js';
import { OOXML_EXT, OLE_EXT, isPdf } from './parsers/docmeta.js';
import { runDoc } from './tools/documents.js';
import { detectEzCsv, runEzCsv } from './tools/ezcsv.js';

export const VERSION = '1.10.0';
const MAX_ZIP_DEPTH = 3;
const MAX_FILE = 1.5 * 1024 ** 3;

const base = (n) => n.split(/[\\/]/).pop();
const ext = (n) => (base(n).match(/\.([^.]+)$/) || [])[1]?.toLowerCase() || '';

/** Decide what a file is. Returns {id, tool, label} | {reject, reason} */
export function detect(name, u8) {
  const b = base(name), lb = b.toLowerCase();
  if (u8.length === 0) return { reject: true, reason: 'Empty file (0 bytes).' };
  if (isEvtx(u8)) return { id: 'evtx', tool: 'EvtxECmd', label: 'Windows event log' };
  if (isEvt(u8)) return { id: 'evt', tool: 'EvtxECmd (.evt)', label: 'Legacy event log (.evt)' };
  if (isPrefetch(u8)) return { id: 'prefetch', tool: 'PECmd', label: 'Prefetch' };
  if (isLnk(u8)) return { id: 'lnk', tool: 'LECmd', label: 'Shortcut' };
  if (/\.automaticdestinations-ms$/i.test(b) && isCfb(u8)) return { id: 'jl-auto', tool: 'JLECmd', label: 'Jump list (automatic)' };
  if (/\.customdestinations-ms$/i.test(b)) return { id: 'jl-custom', tool: 'JLECmd', label: 'Jump list (custom)' };
  if (isRegf(u8) && !isRegLog(u8)) return { id: 'reg', tool: 'RECmd', label: 'Registry hive' };
  if (/\.log\d?$/i.test(b) && (isRegLog(u8) || new Reader(u8).magic(0, 'HvLE'))) return { id: 'reglog', tool: 'RLA', label: 'Registry transaction log' };
  if (/\.(log1|log2)$/i.test(b) && u8.every((x) => x === 0)) return { reject: true, reason: 'Empty (zeroed) registry transaction log; nothing to replay.' };
  if (isMft(u8) && (/mft/i.test(b) || u8.length >= 16 * 1024)) return { id: 'mft', tool: 'MFTECmd', label: '$MFT' };
  if (isBoot(u8) && /boot/i.test(b)) return { id: 'boot', tool: 'MFTECmd', label: '$Boot' };
  if (/^(\$j|\$usnjrnl.*|usnjrnl.*|.*\$j)$/i.test(b) || (/usn/i.test(b) && looksLikeUsn(u8))) return { id: 'usn', tool: 'MFTECmd', label: '$UsnJrnl:$J' };
  if (isIndx(u8)) return { id: 'indx', tool: 'MFTECmd', label: '$I30 directory index' };
  if (/^\$(logfile|sds|secure.*sds)$/i.test(b)) return { id: 'strings', tool: 'bstrings', label: `${b} (MFTECmd input not decoded in-browser)`, partial: true };
  if (isDollarI(u8, b)) return { id: 'dollar-i', tool: 'RBCmd', label: 'Recycle Bin $I' };
  if (isInfo2(u8, b)) return { id: 'info2', tool: 'RBCmd', label: 'Recycle Bin INFO2' };
  if (/^\$R[A-Z0-9]{6}/i.test(b)) return { id: 'strings', tool: 'bstrings', label: 'Recycle Bin $R (deleted file content)', partial: true };
  if (isRecentFileCache(u8, b)) return { id: 'rfc', tool: 'RecentFileCacheParser', label: 'RecentFileCache.bcf' };
  if (isSqlite(u8)) return { id: 'sqlite', tool: /activitiescache/i.test(b) ? 'WxTCmd' : 'SQLECmd', label: 'SQLite database' };
  if (isEse(u8)) return { id: 'ese', tool: /srudb/i.test(b) ? 'SrumECmd' : /\.mdb$/i.test(b) ? 'SumECmd' : 'ESE', label: 'ESE database' };
  if (isWal(u8)) return { id: 'wal', tool: 'SQLECmd', label: 'SQLite write-ahead log' };
  if (isJob(u8, b)) return { id: 'job', tool: 'Sudo-Z', label: 'Task Scheduler 1.0 job' };
  if (OOXML_EXT.test(b) && isZip(u8)) return { id: 'doc', kind: 'ooxml', tool: 'Sudo-Z docmeta', label: 'Office document (OOXML)' };
  if (OLE_EXT.test(b) && isCfb(u8)) return { id: 'doc', kind: 'ole', tool: 'Sudo-Z docmeta', label: 'Office document (OLE, 97-2003)' };
  if (/\.pdf$/i.test(b) && isPdf(u8)) return { id: 'doc', kind: 'pdf', tool: 'Sudo-Z docmeta', label: 'PDF document' };
  const ez = detectEzCsv(b, u8);
  if (ez) return { id: 'ezcsv', tool: ez.tool, label: ez.label, ez };
  const head = utf8(u8.subarray(0, 4096));
  if (/\.jsonl?$/i.test(b) && looksLikeVol(u8, b)) return { id: 'vol', tool: 'Volatility 3', label: 'Volatility 3 output' };
  const mem = memoryImage(u8, b);
  if (mem) return { reject: true, reason: `${mem}. Volatility 3 cannot run in a browser. Use the local install (run "sudo-z", then the MEMORY panel) or run "vol -r json -f <image> windows.pslist" etc. yourself and drop the .json files here.`, memory: true };
  if (isIisLog(u8, b)) return { id: 'iis', tool: 'iisGeolocate', label: 'IIS log' };
  if (/consolehost_history\.txt$/i.test(b)) return { id: 'pshistory', tool: 'Sudo-Z', label: 'PowerShell history' };
  if (/<Task\s[^>]*xmlns=["']http:\/\/schemas\.microsoft\.com\/windows\/2004\/02\/mit\/task/i.test(head) || /^﻿?<\?xml[^>]*\?>\s*<Task/i.test(head) || (/\x00<\x00T\x00a\x00s\x00k\x00/.test(String.fromCharCode(...u8.subarray(0, 400))))) return { id: 'task', tool: 'Sudo-Z', label: 'Scheduled task XML' };
  if (/\.(ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|hta|sh|py|txt|log|xml|ini|inf|reg|url|csv|json|html?|aspx?|ashx|php|jsp)$/i.test(b) && !/[\x00-\x08\x0e-\x1f]/.test(head.replace(/\x00/g, '').slice(0, 1000))) return { id: 'text', tool: 'Sudo-Z', label: 'Script / text file' };
  if (isPe(u8)) return { id: 'pe', tool: 'Hasher + Sigcheck', label: 'Windows executable' };
  if (u8[0] === 0x4d && u8[1] === 0x5a) return { reject: true, reason: 'Windows PE executable/DLL. Not an Eric Zimmerman tool input; hashed and string-scanned only.', strings: true, pe: true };
  if (/\.sdb$/i.test(b)) return { id: 'strings', tool: 'bstrings', label: 'Shim database (.sdb, SDB Explorer input)', partial: true, sdb: true };
  if (/^(e01|ex01|s01|l01|aff4?|vmdk|vhdx?|vdi|qcow2?|dd|img|iso|dmg)$/i.test(ext(b)) || /^(hiberfil|pagefile|swapfile)\.sys$/i.test(b)) return { reject: true, reason: /^(hiberfil|pagefile|swapfile)\.sys$/i.test(b) ? 'Hibernation or page file (memory). Use Volatility 3 through the home install.' : 'Disk image Sudo-Z could not open (no NTFS volume found, or an unsupported container such as VMDK, VDI, AFF4 or DMG). Supported: raw/dd, split raw, E01, VHD, VHDX, QCOW2.' };
  if (/^(rar|7z|gz|tgz|tar|bz2|xz|cab|wim)$/i.test(ext(b))) return { reject: true, reason: `.${ext(b)} archives are not opened in-browser. Re-pack as a standard .zip.` };
  if (/^(jpe?g|png|gif|bmp|ico|mp3|mp4|avi|mov|wav|ttf|otf|woff2?)$/i.test(ext(b))) return { reject: true, reason: 'Media/font file. No EZ tool parses this; hashed and string-scanned only.', strings: true };
  if (/^(docx?|xlsx?|pptx?|pdf|rtf|one|msg|eml)$/i.test(ext(b))) return { reject: true, reason: 'RTF, OneNote or mail file. Only EZViewer (a viewer) opens these; hashed and string-scanned for indicators.', strings: true };
  return { reject: true, reason: 'No Eric Zimmerman tool accepts this file type. Hashed and string-scanned only.', strings: true };
}

function memoryImage(u8, b) {
  const r = new Reader(u8);
  if (r.magic(0, 'PAGEDU64') || r.magic(0, 'PAGEDUMP')) return 'Windows crash dump (memory)';
  if (/^(hibr|wake|rstr)$/i.test(r.ascii(0, 4)) && /hiberfil/i.test(b)) return 'Hibernation file (memory)';
  if (r.magic(0, 'EMiL')) return 'LiME memory image';
  if (/\.(mem|vmem|raw|lime|dmp|vmsn|vmss|bin)$/i.test(b) && u8.length >= 64 * 1024 * 1024) return 'Memory image';
  if (/^(pagefile|swapfile)\.sys$/i.test(b)) return 'Page file (memory)';
  return null;
}

/**
 * Pull disk images out of the inputs and replace them with the triage files found inside.
 * An input is {name, data} or {name, src} (a lazy random-access source for big files).
 */
async function openImages(inputs, onProgress, log) {
  const plain = []; const cands = []; const recs = [];
  for (const i of inputs) {
    const src = i.src || (i.data && i.data.length >= 1024 * 1024 && (IMAGE_EXT.test(i.name) || (i.data[0] === 0x45 && i.data[1] === 0x56 && i.data[2] === 0x46)) ? fromBytes(i.data, i.name) : null);
    let k = null;
    if (src) { try { k = await probeImage(i.name, src); } catch (e) { log(`image probe failed for ${i.name}: ${e.message}`); } }
    if (k) { cands.push({ name: i.name, src, kind: k.kind, unsupported: k.unsupported }); continue; }
    if (i.data) { plain.push(i); continue; }
    // a lazy input that is not a disk image: load it if it fits
    if (i.src.size > MAX_FILE) { recs.push({ name: i.name, size: i.src.size, parent: null, status: 'rejected', reason: memoryImage(await i.src.read(0, 4096), base(i.name)) ? 'Memory image. Volatility 3 cannot run in a browser: use the home install (MEMORY panel) or drop vol -r json output.' : 'File larger than the 1.5 GB browser limit and not a disk image Sudo-Z can open.', tool: '-', artifact: '', summary: '', tables: [], notes: [] }); continue; }
    plain.push({ name: i.name, data: await i.src.read(0, i.src.size) });
  }
  const groups = groupSegments(cands);
  let gi = 0;
  for (const g of groups) {
    const t = Date.now();
    if (g[0].unsupported) { recs.push({ name: g[0].name, size: g[0].src.size, parent: null, status: 'rejected', reason: g[0].unsupported, tool: 'Disk image (Sudo-Z)', artifact: g[0].kind, summary: '', tables: [], notes: [] }); continue; }
    try {
      const { files, record } = await extractImage(g, { kind: g[0].kind, log, onProgress: (p, l) => onProgress(((gi + p) / groups.length) * 0.4, l) });
      record.ms = Date.now() - t;
      record.notes.unshift('Image itself is not hashed (too large to hash in-browser); every extracted file is.');
      recs.push(record);
      plain.push(...files);
    } catch (e) {
      recs.push({ name: g[0].name, size: g.reduce((n, s) => n + s.src.size, 0), parent: null, status: 'error', reason: e.message, tool: 'Disk image (Sudo-Z)', artifact: g[0].kind, summary: '', tables: [], notes: [`Image could not be opened: ${e.message}`] });
    }
    gi++;
  }
  return { plain, recs, images: groups.length };
}

/** Expand inputs (zips may be nested). inputs: [{name, data:Uint8Array}] */
async function expand(inputs, log) {
  const out = []; const rejected = [];
  const walk = async (name, data, depth, parent, meta = {}) => {
    if (isZip(data) && /\.zip$|^[^.]*$/i.test(base(name)) || (isZip(data) && depth === 0 && !OOXML_EXT.test(base(name)))) {
      if (depth >= MAX_ZIP_DEPTH) { rejected.push({ name, size: data.length, reason: `Nested zip deeper than ${MAX_ZIP_DEPTH} levels.`, parent }); return; }
      log(`unzipping ${name}`);
      let z;
      try { z = await unzip(data); } catch (e) { rejected.push({ name, size: data.length, reason: `Zip could not be read: ${e.message}`, parent }); return; }
      const velo = isVeloCollection(z.entries.map((e) => e.name));
      if (velo) log(`Velociraptor collection detected in ${name}`);
      for (const ent of z.entries) {
        const full = `${name}/${velo ? veloName(ent.name) : ent.name}`;
        if (velo && /^results\/.+\.json$/i.test(ent.name) && !ent.error) { out.push({ name: full, data: ent.data, parent: name, velo: true }); continue; }
        if (velo && !/^uploads\//i.test(ent.name) && /\.json$/i.test(ent.name) && !ent.error) { out.push({ name: full, data: ent.data, parent: name, veloMeta: true }); continue; }
        if (ent.error) { rejected.push({ name: full, size: ent.size, reason: ent.error, parent: name }); continue; }
        await walk(full, ent.data, depth + 1, name, ent.times ? { zipTimes: ent.times } : {});
      }
      return;
    }
    out.push({ ...meta, name, data, parent });
  };
  for (const i of inputs) { const { name, data, parent, ...meta } = i; await walk(name, data, 0, parent || null, meta); }
  return { files: out, rejected };
}

export async function analyze(inputs, opts = {}) {
  const { onProgress = () => {}, log = () => {} } = opts;
  const t0 = Date.now();
  const ctx = new Context();
  const shared = {};
  onProgress(0, 'Opening inputs');
  const img = await openImages(inputs, onProgress, log);
  const pstart = img.images ? 0.4 : 0;
  const prog = (p, l) => onProgress(pstart + p * (1 - pstart), l);
  onProgress(pstart, 'Expanding archives');
  const { files, rejected } = await expand(img.plain, log);
  // keep the bytes around for the STRINGS search (bstrings) after the report is built
  try { opts.onFiles?.({ files: files.map((f) => ({ name: f.name, data: f.data })), raw: inputs.filter((i) => i.src).map((i) => ({ name: i.name, src: i.src })) }); } catch { }
  const results = [...img.recs];
  // routing; MFT first so $J can resolve paths
  const routed = files.map((f) => ({ ...f, det: f.data.length > MAX_FILE ? { reject: true, reason: 'File larger than 1.5 GB browser limit.' } : f.velo ? { id: 'velo', tool: 'Velociraptor', label: 'Velociraptor artifact results' } : f.veloMeta ? { id: 'velo-meta', tool: 'Velociraptor', label: 'Velociraptor collection metadata' } : detect(f.name, f.data) }));
  // pair hives with their transaction logs and SQLite databases with their -wal files
  const byPath = new Map(routed.map((f) => [f.name.toLowerCase(), f]));
  for (const f of routed) {
    if (f.det.id === 'reglog') {
      const h = byPath.get(f.name.toLowerCase().replace(/\.log\d?$/, ''));
      if (h && h.det.id === 'reg') { (h.logs = h.logs || []).push({ name: f.name, data: f.data }); f.pairedWith = h.name; }
    }
    if (f.det.id === 'wal') {
      const d = byPath.get(f.name.toLowerCase().replace(/-wal$/, ''));
      if (d && d.det.id === 'sqlite') { d.wal = { name: f.name, data: f.data }; f.pairedWith = d.name; }
    }
  }
  routed.sort((a, b) => (a.det.id === 'mft' ? -1 : 0) - (b.det.id === 'mft' ? -1 : 0));
  const preNotes = new Map();
  for (const f of routed) {
    if (f.logs?.length) { try { const rr = replayHive(f.data, f.logs); f.data = rr.data; preNotes.set(f.name, rr.notes); } catch (e) { preNotes.set(f.name, ['Transaction log replay failed: ' + e.message]); } }
    if (f.wal) { try { const m = mergeWal(f.data, f.wal.data); f.data = m.data; preNotes.set(f.name, [`Merged ${m.pages} page(s) from ${m.commits} committed transaction(s) in ${f.wal.name.split('/').pop()} (${m.frames} frames).`]); } catch (e) { preNotes.set(f.name, ['WAL merge failed: ' + e.message]); } }
  }
  let i = 0;
  for (const f of routed) {
    i++;
    prog(i / (routed.length + 1), `${f.det.tool || 'Hasher'} :: ${base(f.name)}`);
    await new Promise((r) => setTimeout(r, 0));
    const rec = { name: f.name, size: f.data.length, parent: f.parent, hashes: null, status: 'parsed', tool: f.det.tool || 'Hasher + bstrings', artifact: f.det.label || '', summary: '', tables: [], notes: [], ms: 0 };
    const t = Date.now();
    try { rec.hashes = await hashAll(f.data); } catch (e) { rec.notes.push('hashing failed: ' + e.message); }
    const ff = { name: f.name };
    if (preNotes.has(f.name)) rec.notes.push(...preNotes.get(f.name));
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
        case 'ese': r = runEse(f.data, ff, ctx); break;
        case 'evt': r = A.runEvt(f.data, ff, ctx); break;
        case 'job': r = A.runJob(f.data, ff, ctx); break;
        case 'indx': r = A.runIndx(f.data, ff, ctx, shared); break;
        case 'vol': r = runVol(f.data, ff, ctx, shared); break;
        case 'velo': r = runVelo(f.data, ff, ctx); break;
        case 'pe': r = runPe(f.data, ff, ctx, { winPath: f.winPath, fromImage: f.fromImage, si: f.si, sha1: rec.hashes?.sha1 }); break;
        case 'ezcsv': r = runEzCsv(f.data, ff, ctx, f.det.ez, shared); break;
        case 'doc': r = await runDoc(f.data, ff, ctx, f.det.kind, { winPath: f.winPath, si: f.si }); break;
        case 'velo-meta': { const t = utf8(f.data); for (const m of t.matchAll(/"(?:Hostname|Fqdn|hostname|fqdn)"\s*:\s*"([^"]+)"/g)) ctx.hosts.add(m[1]); r = { tool: 'Velociraptor', artifact: f.det.label, summary: `${f.data.length} bytes`, tables: [], notes: [] }; break; }
        case 'reglog': case 'wal':
          if (f.pairedWith) r = { tool: f.det.id === 'wal' ? 'SQLECmd' : 'RLA', artifact: f.det.label, summary: `${f.det.id === 'wal' ? 'merged into' : 'replayed into'} ${f.pairedWith.split('/').pop()}`, tables: [], notes: [] };
          else { rec.status = 'rejected'; rec.reason = f.det.id === 'wal' ? 'SQLite -wal file without its database. Submit both files together (same folder) and the WAL is merged automatically.' : 'Registry transaction log without its hive. Submit the hive and its .LOG1/.LOG2 together (same folder) and they are replayed automatically.'; r = A.runGeneric(f.data, ff, ctx, 'Unpaired log (strings only)'); }
          break;
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
    // file system times that came with the file (disk image $SI, archive entry) for the MACB analysis
    if (f.si && f.winPath) ctx.fileTimes({ path: f.winPath, source: '$SI (disk image)', kind: 'fs', file: f.name, B: f.si.created || '', M: f.si.modified || '', A: f.si.accessed || '', C: f.si.mftModified || '' });
    if (f.zipTimes && (f.zipTimes.mtime || f.zipTimes.dos)) { const z = f.zipTimes; ctx.fileTimes({ path: f.name, source: z.zone ? `ZIP entry (${z.zone})` : 'ZIP entry (DOS time, local, no zone)', kind: 'container', utc: !!z.zone, file: f.name, B: z.ctime || '', M: z.mtime || z.dos, A: z.atime || '' }); }
    if (rec.hashes) ctx.indicators.add('sha256_submitted', rec.hashes.sha256, f.name, base(f.name));
    rec.ms = Date.now() - t;
    results.push(rec);
  }
  for (const r of rejected) results.push({ name: r.name, size: r.size, parent: r.parent, status: 'rejected', reason: r.reason, tool: '-', artifact: '', summary: '', tables: [], notes: [] });

  onProgress(0.99, 'Building report');
  try {
    finalizeVol(shared, ctx);
    for (const t of shared.volTables || []) { // cross-view tables built from several plugin outputs
      const host = results.find((r) => r.name === (shared.volFile?.psxview || shared.volFile?.pspcid)) || results.find((r) => r.tool === 'Volatility 3');
      if (host) host.tables.push(t);
    }
  } catch (e) { log('volatility correlation failed: ' + e.message); }
  // correlation: same suspicious program seen by multiple execution artifacts
  for (const [name, list] of ctx.exec) {
    const sources = [...new Set(list.map((l) => l.source))];
    const susp = list.some((l) => l.flagged);
    if (susp && sources.length >= 2) ctx.finding({ sev: 'high', category: 'Correlation', tool: 'Sudo-Z', file: '(multiple)', time: list.map((l) => l.time).filter(Boolean).sort()[0], title: `${name.split('\\').pop()} confirmed by ${sources.length} independent execution artifacts`, detail: sources.join(', '), evidence: [...new Set(list.map((l) => l.path))].slice(0, 5).join('\n') });
  }
  const timeline = ctx.timeline.filter((e) => e.time).sort((a, b) => a.time.localeCompare(b.time));
  let execution = { coverage: [] };
  try { const pre = ctx.findings.filter((x) => SEV_RANK[x.sev] >= 3 && x.time).map((x) => x.time).sort(); execution = analyseExecution(ctx, results, { attackFirst: pre[0] }); } catch (e) { log('execution evidence analysis failed: ' + e.message); }
  let macb = null;
  try { const pre = ctx.findings.filter((x) => SEV_RANK[x.sev] >= 3 && x.time).map((x) => x.time).sort(); macb = analyseMacb(ctx, shared, { attackFirst: pre[0], attackLast: pre[pre.length - 1] }); } catch (e) { log('MACB analysis failed: ' + e.message); }
  try { gradeSignatures(ctx); } catch (e) { log('signature grading failed: ' + e.message); }
  attachNextSteps(ctx.findings);
  const findings = ctx.sortedFindings();
  const indicators = ctx.indicators.list();
  const counts = { files: results.length, parsed: results.filter((r) => r.status === 'parsed').length, partial: results.filter((r) => r.status === 'partial').length, rejected: results.filter((r) => r.status === 'rejected').length, errors: results.filter((r) => r.status === 'error').length };
  const sev = ctx.summary();
  const verdict = sev.critical ? 'COMPROMISE LIKELY' : sev.high ? 'SUSPICIOUS ACTIVITY' : sev.medium ? 'REVIEW RECOMMENDED' : 'NO STRONG INDICATORS';
  const first = timeline[0]?.time, last = timeline[timeline.length - 1]?.time;
  // attack window = span of high/critical findings
  const hot = findings.filter((x) => SEV_RANK[x.sev] >= 3 && x.time).map((x) => x.time).sort();
  let programs = [];
  try { programs = buildPrograms(ctx, findings); } catch (e) { log('program view failed: ' + e.message); }
  let leads = [];
  try { ctx.timeline = timeline; leads = buildLeads(ctx, shared, { attackFirst: hot[0], attackLast: hot[hot.length - 1] }); } catch (e) { log('lead generation failed: ' + e.message); }
  return {
    meta: { tool: 'Sudo-Z', version: VERSION, generated: new Date().toISOString(), durationMs: Date.now() - t0, inputs: inputs.map((i) => ({ name: i.name, size: i.src ? i.src.size : i.data.length })) },
    verdict, severity: sev, counts,
    hosts: [...ctx.hosts].filter(Boolean), users: [...ctx.users].filter((u) => u && !/^(-|system|local service|network service|anonymous logon|dwm-\d+|umfd-\d+)$/i.test(u) && !/\$$/.test(u)),
    window: { first, last, attackFirst: hot[0], attackLast: hot[hot.length - 1] },
    leads, programs, execution, macb, findings, indicators, timeline, files: results,
  };
}
