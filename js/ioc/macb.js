// MACB analysis: Modified, Accessed, Changed ($MFT record change) and Born times for files.
// Two kinds of evidence are compared:
//   * the file system's own times ($STANDARD_INFORMATION and $FILE_NAME in the $MFT, disk image metadata, archive entries)
//   * times stored somewhere else: inside the file (document metadata, PE compile time) or by another artifact
//     that took a copy when it last saw the file (LNK and jump list target times, Amcache LinkDate).
// A file system time that disagrees with the file's own content or with an older copy of itself is the
// classic sign of timestomping (T1070.006), file replacement or a planted file.
import { filetimeToIso } from '../core/bytes.js';
import { normKey } from './context.js';
import { baseName, SEV_RANK } from './heuristics.js';

const DAY = 86400000, SLACK = 2000;
const ROOT_SYSTEM = /^[a-z]:\\(ntdetect\.com|ntldr|boot\.ini|bootmgr|bootsect\.bak|io\.sys|msdos\.sys|config\.sys|autoexec\.bat|pagefile\.sys|hiberfil\.sys|swapfile\.sys|dumpstack\.log(\.tmp)?)$/i;
const WEB_CACHE = /\\(temporary internet files|inetcache|webcache|cache2?|code cache|gpucache|service worker)\\/i;
const MFT_RULES = new Set(['siBeforeFn', 'bornAfterChange', 'modAfterChange', 'allSame', 'preVolume', 'future', 'mixedPrecision']);
const EXEC = /\.(exe|dll|sys|scr|com|cpl|ocx|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|msi|lnk|jar)$/i;
const DOCS = /\.(docx?|docm|xlsx?|xlsm|xlsb|pptx?|pptm|pdf|rtf|one)$/i;
export const USER_WRITABLE = /^[a-z]:\\(users|documents and settings)\\(?!default\\|default user\\|all users\\)|^[a-z]:\\programdata\\|\\windows\\temp\\|^[a-z]:\\perflogs\\|\\\$recycle\.bin\\|\\recycler\\|^[a-z]:\\temp\\|^[a-z]:\\[^\\]+\.[a-z0-9]{2,4}$/i;

/** time value (BigInt FILETIME or ISO string) to epoch ms */
const tms = (v) => { if (v == null || v === '') return NaN; if (typeof v === 'bigint') return v === 0n ? NaN : Number(v / 10000n) - 11644473600000; const t = Date.parse(v); return t; };
const zeroFrac = (v) => (typeof v === 'bigint' ? v !== 0n && v % 10000000n === 0n : /:\d\d(\.0+)?Z?$/.test(String(v || '')));
const isoOf = (v) => (v == null || v === '' ? '' : typeof v === 'bigint' ? filetimeToIso(v) || '' : String(v));
const isoMs = (t) => (isFinite(t) ? new Date(t).toISOString() : '');

/** Best guess of the original Windows path for a submitted file ("triage.zip/C/Users/bob/x.docx" -> "C:\Users\bob\x.docx"). */
export function winPathOf(name, winPath) {
  if (winPath) return winPath;
  const s = String(name).replace(/\\/g, '/');
  const m = s.match(/(?:^|\/)([A-Za-z])(?:%3A|:|\$)?\/((?:Users|Windows|ProgramData|Program Files[^/]*|Documents and Settings|PerfLogs|\$Recycle\.Bin|RECYCLER|Temp|inetpub|Recovery)\/.*)$/i);
  return m ? `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, '\\')}` : '';
}

const RULES = {
  siBeforeFn: { title: '$SI born before $FN born', why: 'The $FILE_NAME born time is set by the kernel when the name is created and is hard to change. A $STANDARD_INFORMATION born time earlier than it means the visible born time was moved back.', mitre: ['T1070.006'] },
  bornAfterChange: { title: 'Born later than its $MFT record change (B > C)', why: 'Every change to a file updates C. A born time later than C cannot happen naturally; SetFileTime style tools change B but leave C alone.', mitre: ['T1070.006'] },
  modAfterChange: { title: 'Modified later than its $MFT record change (M > C)', why: 'Writing data updates M and C together. M later than C means M was set forward by a tool.', mitre: ['T1070.006'] },
  allSame: { title: 'All four $SI times identical with no sub-second part', why: 'Windows records 100 ns precision. Four identical whole-second times are what a timestomp tool writes when given one value.', mitre: ['T1070.006'] },
  preVolume: { title: 'Born before the volume was formatted', why: 'A file in a user folder cannot be created before the file system existed ($MFT record 0 born time). The born time was set back or copied from another system with a tool that keeps B.', mitre: ['T1070.006'] },
  future: { title: 'Time in the future', why: 'A time after the analysis date comes from a forged time, a wrong clock or a reproducible build hash.', mitre: ['T1070.006'] },
  compiledAfterFs: { title: 'Compiled after the file system says the file was born and last modified', why: 'A program cannot be on disk before the linker wrote it. The PE header compile time is later than the file system B and M, so the file system times were set back.', mitre: ['T1070.006', 'T1036'] },
  docModAfterFs: { title: 'Document last saved after its file system modified time', why: 'Saving a document writes the save time into its metadata and updates M at the same moment. A metadata save time later than M means M was set back.', mitre: ['T1070.006'] },
  docBornAfterFs: { title: 'Document authored after the file system says it was born', why: 'The file cannot exist on disk before its content was created. The file system born time was set back.', mitre: ['T1070.006'] },
  docInconsistent: { title: 'Document metadata created after modified', why: 'Created later than last saved does not happen when an office suite saves a file. Common in documents built by scripts and maldoc kits.', mitre: ['T1204.002'] },
  lnkBornBack: { title: 'Born time moved back since a shortcut recorded it', why: 'LNK files and jump lists keep a copy of the target\'s B, M and A from when it was opened. The current $MFT born time is earlier than that copy, for the same file record.', mitre: ['T1070.006'] },
  lnkModBack: { title: 'Modified time moved back since a shortcut recorded it', why: 'M only moves forward on a normal write. The current M is earlier than the copy a shortcut took, so M was set back or the file was swapped for an older copy.', mitre: ['T1070.006'] },
  replaced: { title: 'File replaced since a shortcut recorded it', why: 'The shortcut points to an older file record (different $MFT entry or sequence) or an earlier born time. The file at that path was deleted and recreated, for example a document swapped for a payload with the same name.', mitre: ['T1036'] },
  usnBasicOnly: { title: 'Timestamps rewritten, recorded in the USN journal', why: 'The change journal holds a BasicInfoChange record with no data, rename or security change beside it. That combination is what SetFileTime produces, which is to say the file\'s timestamps were edited and nothing else about it was. The journal is append only, so the edit is recorded even though the times it wrote are not.', mitre: ['T1070.006'] },
  usnAfterMod: { title: 'Data written after the file says it was last modified', why: 'The change journal records a data write at a time later than the modified time the file now shows. Writing data updates M, so M was moved back afterwards.', mitre: ['T1070.006'] },
  usnBeforeBorn: { title: 'Journal records predate the file\'s born time', why: 'The change journal mentions this file record before the file claims to have been created. The journal is written as things happen, so the born time was moved forward or the file is older than it says.', mitre: ['T1070.006'] },
  ranBeforeBorn: { title: 'Program ran before the file says it was created', why: 'Prefetch, Amcache, ShimCache or UserAssist recorded this program running at a time earlier than its born time on disk. Execution artifacts are written by the system as the program runs and are awkward to edit, so the file system time is the one to doubt.', mitre: ['T1070.006', 'T1036'] },
  mixedPrecision: { title: 'Some times have 100 ns precision and others are whole seconds', why: 'Windows writes all four times with 100 ns precision. A time that lands exactly on a second, next to others that do not, was written from a formatted string by a tool rather than by the file system.', mitre: ['T1070.006'] },
  burstBorn: { title: 'Mass file creation in one minute', why: 'Many files born in the same minute in user-writable folders: an archive extraction, installer or dropper unpacking.', mitre: ['T1105'] },
  burstMod: { title: 'Mass file modification in one minute', why: 'Many user files modified in the same minute. Ransomware encrypting in place produces exactly this pattern.', mitre: ['T1486'] },
};

/**
 * @param ctx analysis context (ctx.ftimes holds every non-$MFT source)
 * @param shared shared.mft.rows from MFTECmd (native or CSV)
 * @param window {attackFirst, attackLast}
 */
export function analyseMacb(ctx, shared, window = {}, now = Date.now()) {
  const anomalies = []; const counts = {}; const clusters = [];
  const future = now + DAY;
  const add = (rule, sev, path, detail, times = {}, extra = {}) => {
    counts[rule] = (counts[rule] || 0) + 1;
    if (anomalies.length < 60000) anomalies.push({ sev, rule, title: RULES[rule].title, path, detail, ...times, ...extra });
  };
  // files outside user-writable folders (Windows setup copies keep old $SI times) only count for programs, and then low
  const sevFor = (p, strong) => { const exe = EXEC.test(p), uw = USER_WRITABLE.test(p) && !ROOT_SYSTEM.test(p); return strong ? (exe && uw ? 'high' : uw && DOCS.test(p) ? 'medium' : uw ? 'low' : exe ? 'low' : 'info') : (exe && uw ? 'medium' : uw ? 'low' : 'info'); };

  // keys the other sources need from the $MFT
  const needKey = new Set(), needEntry = new Set();
  for (const r of ctx.ftimes) { if (r.kind === 'fs') continue; const p = winPathOf(r.path); if (p) needKey.add(normKey(p)); if (r.entry != null) needEntry.add(r.entry); }
  for (const k of ctx.exec.keys()) needKey.add(k); // so "ran before it was born" can find the record
  const idx = new Map(), byEntry = new Map();
  const rows = shared.mft?.rows || [];
  const volBorn = tms(rows.find((r) => r.entry === 0)?.si?.created);
  const bornB = new Map(), modB = new Map();
  let fsFiles = 0;
  const win0 = tms(window.attackFirst) - 3600000, win1 = tms(window.attackLast || window.attackFirst) + 3600000;

  for (const r of rows) {
    if (r.isDir || !r.si) continue;
    if (r.parentPath === '.' && /^\$/.test(r.name)) continue;
    fsFiles++;
    const path = `${r.parentPath}\\${r.name}`.replace(/^\./, 'C:');
    const B = tms(r.si.created), M = tms(r.si.modified), A = tms(r.si.accessed), C = tms(r.si.recordChanged);
    const fB = tms(r.fn?.created);
    const rec = { path, entry: r.entry, seq: r.seq, inUse: r.inUse, B, M, A, C, fB, fM: tms(r.fn?.modified), src: '$MFT' };
    if (needEntry.has(r.entry)) byEntry.set(r.entry, rec);
    const key = normKey(path); if (needKey.has(key) && (!idx.has(key) || r.inUse)) idx.set(key, rec);
    const T = { siB: isoOf(r.si.created), siM: isoOf(r.si.modified), siA: isoOf(r.si.accessed), siC: isoOf(r.si.recordChanged), fnB: isoOf(r.fn?.created), entry: `${r.entry}-${r.seq}` };
    if (isFinite(B) && isFinite(fB) && B + SLACK < fB) add('siBeforeFn', sevFor(path, true), path, `$SI B ${T.siB} is ${dur(fB - B)} before $FN B ${T.fnB}`, T);
    if (isFinite(B) && isFinite(C) && B > C + SLACK) add('bornAfterChange', sevFor(path, true), path, `B ${T.siB} is ${dur(B - C)} after C ${T.siC}`, T);
    if (isFinite(M) && isFinite(C) && M > C + SLACK) add('modAfterChange', sevFor(path, true), path, `M ${T.siM} is ${dur(M - C)} after C ${T.siC}`, T);
    if (isFinite(B) && B === M && M === A && A === C && zeroFrac(r.si.created)) add('allSame', sevFor(path, true), path, `B = M = A = C = ${T.siB}`, T);
    const uw = USER_WRITABLE.test(path);
    if (uw && isFinite(volBorn) && isFinite(B) && B < volBorn - DAY && !/^c:\\[^\\]+$/i.test(path)) add('preVolume', sevFor(path, false), path, `B ${T.siB}, volume formatted ${isoMs(volBorn)}`, T);
    const fut = [['B', B], ['M', M], ['A', A], ['C', C], ['$FN B', fB]].filter(([, t]) => t > future);
    if (fut.length) add('future', sevFor(path, false), path, fut.map(([k, t]) => `${k} ${isoMs(t)}`).join(', '), T);
    // one-minute buckets for bursts
    if (uw && isFinite(B) && !WEB_CACHE.test(path)) { const k = Math.floor(B / 60000); const b = bornB.get(k) || { n: 0, exe: 0, dirs: new Map() }; b.n++; if (EXEC.test(r.name)) b.exe++; b.dirs.set(r.parentPath, (b.dirs.get(r.parentPath) || 0) + 1); bornB.set(k, b); }
    if (r.inUse && isFinite(M) && /^[a-z]:\\users\\[^\\]+\\(?!appdata\\)/i.test(path)) { const k = Math.floor(M / 60000); const b = modB.get(k) || { n: 0, ext: new Map(), dirs: new Set() }; b.n++; const e = (r.name.match(/\.([^.]{1,12})$/) || [])[1]?.toLowerCase() || ''; b.ext.set(e, (b.ext.get(e) || 0) + 1); if (b.dirs.size < 2000) b.dirs.add(r.parentPath); modB.set(k, b); }
  }
  // a targeted timestomp touches a few files; the same anomaly on many files in one folder is an installer,
  // an archive extraction that kept the archive's times, or a clock change. Keep them, but low.
  const grp = new Map();
  for (const a of anomalies) if (MFT_RULES.has(a.rule)) { const k = `${a.rule}|${a.path.slice(0, a.path.lastIndexOf('\\')).toLowerCase()}`; grp.set(k, (grp.get(k) || 0) + 1); }
  for (const a of anomalies) {
    if (!MFT_RULES.has(a.rule)) continue;
    const n = grp.get(`${a.rule}|${a.path.slice(0, a.path.lastIndexOf('\\')).toLowerCase()}`);
    if (n >= 10) { a.bulk = n; a.detail += ` [bulk: ${n} files in this folder]`; if (SEV_RANK[a.sev] > SEV_RANK.low) a.sev = 'low'; }
  }
  for (const [k, b] of bornB) if (b.n >= 50) {
    const top = [...b.dirs].sort((x, y) => y[1] - x[1])[0];
    const inWin = k * 60000 >= win0 && k * 60000 <= win1;
    clusters.push({ kind: 'Born', minute: isoMs(k * 60000).slice(0, 16), files: b.n, executables: b.exe, folders: b.dirs.size, topFolder: top ? top[0].replace(/^\./, 'C:') : '', topExt: '', inWindow: inWin });
    if (b.exe >= 5) add('burstBorn', inWin ? 'medium' : 'low', top ? top[0].replace(/^\./, 'C:') : '', `${b.n} files (${b.exe} executable) born ${isoMs(k * 60000).slice(0, 16)} across ${b.dirs.size} folder(s)${inWin ? ', inside the attack window' : ''}`, { siB: isoMs(k * 60000) });
  }
  for (const [k, b] of modB) if (b.n >= 200) {
    const [ext, en] = [...b.ext].sort((x, y) => y[1] - x[1])[0];
    const share = en / b.n; const odd = share >= 0.8 && !/^(docx?|xlsx?|pptx?|pdf|jpe?g|png|txt|tmp|log|dat|db|ini|lnk|json|xml|html?|js|css|mp3|mp4|zip)$/.test(ext);
    clusters.push({ kind: 'Modified', minute: isoMs(k * 60000).slice(0, 16), files: b.n, executables: 0, folders: b.dirs.size, topFolder: '', topExt: `.${ext} (${Math.round(share * 100)}%)`, inWindow: k * 60000 >= win0 && k * 60000 <= win1 });
    add('burstMod', odd ? 'high' : b.dirs.size >= 20 ? 'medium' : 'low', `${b.dirs.size} folder(s) under C:\\Users`, `${b.n} user files modified ${isoMs(k * 60000).slice(0, 16)}; most common extension .${ext} (${Math.round(share * 100)}%)`, { siM: isoMs(k * 60000) });
  }
  clusters.sort((a, b) => b.files - a.files);

  // ---------------------------------------------------------------- the change journal as a witness
  // $SI can be rewritten in one call; the USN journal cannot, so where they disagree the journal wins.
  const usn = shared.usn;
  if (usn && usn.size) {
    const seen = new Set();
    for (const r of rows) {
      if (r.isDir || !r.si) continue;
      const u = usn.get(r.entry);
      if (!u) continue;
      const path = `${r.parentPath}\\${r.name}`.replace(/^\./, 'C:');
      if (u.name && r.name && u.name.toLowerCase() !== r.name.toLowerCase()) continue; // the record was reused
      const key = `${r.entry}|${path.toLowerCase()}`;
      if (seen.has(key)) continue; seen.add(key);
      const B = tms(r.si.created), M = tms(r.si.modified);
      const T = { siB: isoOf(r.si.created), siM: isoOf(r.si.modified), siA: isoOf(r.si.accessed), siC: isoOf(r.si.recordChanged), fnB: isoOf(r.fn?.created), entry: `${r.entry}-${r.seq}`, source: 'USN journal' };
      const bo = tms(u.basicOnly), dw = tms(u.data), first = tms(u.first);
      if (isFinite(bo)) {
        const stale = isFinite(M) && M < bo - DAY;
        add('usnBasicOnly', stale ? sevFor(path, true) : sevFor(path, false), path,
          `BasicInfoChange only, recorded ${isoMs(bo)}${stale ? `; the file now says it was last modified ${T.siM}, ${dur(bo - M)} earlier` : ''}`, T);
      }
      if (isFinite(dw) && isFinite(M) && M < dw - DAY) add('usnAfterMod', sevFor(path, true), path, `data written ${isoMs(dw)} but M says ${T.siM} (${dur(dw - M)} earlier)`, T);
      if (isFinite(first) && isFinite(B) && first < B - DAY && !isFinite(tms(u.create))) add('usnBeforeBorn', sevFor(path, true), path, `journal first mentions this record ${isoMs(first)}, B says ${T.siB} (${dur(B - first)} later)`, T);
      // mixed precision across the four $SI times
      const parts = [['B', r.si.created], ['M', r.si.modified], ['A', r.si.accessed], ['C', r.si.recordChanged]].filter(([, v]) => tms(v) > 0);
      const whole = parts.filter(([, v]) => zeroFrac(v)), frac = parts.filter(([, v]) => !zeroFrac(v));
      if (whole.length && frac.length && USER_WRITABLE.test(path) && EXEC.test(path)) add('mixedPrecision', 'medium', path, `${whole.map(([k]) => k).join(', ')} land exactly on a second; ${frac.map(([k]) => k).join(', ')} do not`, T);
    }
  }

  // ---------------------------------------------------------------- execution evidence as a witness
  // a program cannot run before it exists
  for (const [key, runs] of ctx.exec) {
    const rec = idx.get(key);
    if (!rec || !isFinite(rec.B)) continue;
    const earliest = runs.map((x) => tms(x.time)).filter((t) => isFinite(t) && t > Date.UTC(2000, 0, 1)).sort((a, b) => a - b)[0];
    if (!isFinite(earliest) || earliest >= rec.B - DAY) continue;
    const who = [...new Set(runs.filter((x) => isFinite(tms(x.time)) && tms(x.time) === earliest).map((x) => x.source))].join(', ');
    add('ranBeforeBorn', EXEC.test(rec.path) ? 'high' : 'medium', rec.path,
      `${who || 'execution evidence'} says it ran ${isoMs(earliest)}, ${dur(rec.B - earliest)} before the born time ${isoMs(rec.B)}`,
      { siB: isoMs(rec.B), siM: isoMs(rec.M), entry: `${rec.entry}-${rec.seq}`, source: who });
  }

  // file system times from disk image metadata (when no $MFT was parsed) and archive entries
  const imgFs = new Map(), zipFs = new Map();
  for (const r of ctx.ftimes) {
    const p = winPathOf(r.path); if (!p) continue; const k = normKey(p);
    if (r.kind === 'fs' && !idx.has(k)) imgFs.set(k, { path: p, B: tms(r.B), M: tms(r.M), A: tms(r.A), C: tms(r.C), src: r.source });
    if (r.kind === 'container' && r.utc) zipFs.set(k, { path: p, B: tms(r.B), M: tms(r.M), A: tms(r.A), C: NaN, src: r.source });
  }
  const fsOf = (p, entry) => { const k = normKey(p); return idx.get(k) || imgFs.get(k) || (entry != null && byEntry.get(entry)) || zipFs.get(k) || null; };

  const embedded = [];
  for (const r of ctx.ftimes) {
    if (r.kind === 'fs') continue;
    const p = winPathOf(r.path);
    const fs = p ? fsOf(p, r.entry) : null;
    const x = r.extra || {}; const verdict = [];
    const B = tms(r.B), M = tms(r.M), comp = tms(x.compiled);
    const T = { siB: fs ? isoMs(fs.B) : '', siM: fs ? isoMs(fs.M) : '', embB: r.B || '', embM: r.M || '', source: r.source, file: r.file };
    const path = p || r.path;
    if (r.kind === 'embedded' && isFinite(comp)) {
      const signer = ctx.signs.get(normKey(path))?.signer || x.signer || '';
      if (fs && comp > Date.UTC(2000, 0, 1) && comp < future && !/\\windows\\/i.test(path) && !/microsoft/i.test(signer) && comp > fs.B + DAY && (!isFinite(fs.M) || comp > fs.M + DAY)) {
        add('compiledAfterFs', USER_WRITABLE.test(path) ? 'high' : 'medium', path, `compiled ${x.compiled}; file system B ${isoMs(fs.B)}, M ${isoMs(fs.M)} (${fs.src})`, T); verdict.push('compiled after B/M');
      }
      if (comp > future) verdict.push('compile time in the future (reproducible build hash or forged)');
    }
    if (r.kind === 'recorded' && isFinite(comp) && fs && USER_WRITABLE.test(path) && comp > fs.B + DAY && (!isFinite(fs.M) || comp > fs.M + DAY) && comp < future) {
      add('compiledAfterFs', 'high', path, `${r.source} says compiled ${x.compiled}; file system B ${isoMs(fs.B)}, M ${isoMs(fs.M)}`, T); verdict.push('compiled after B/M');
    }
    if (r.kind === 'embedded' && x.doc) {
      if (fs && isFinite(M) && isFinite(fs.M) && M > fs.M + DAY) { add('docModAfterFs', sevFor(path, true) === 'info' ? 'low' : sevFor(path, true), path, `metadata last saved ${r.M}; file system M ${isoMs(fs.M)} (${fs.src})`, T); verdict.push('saved after file system M'); }
      if (fs && isFinite(B) && isFinite(fs.B) && fs.src !== r.source && B > fs.B + DAY && !/container|zip/i.test(fs.src)) { add('docBornAfterFs', sevFor(path, true) === 'info' ? 'low' : sevFor(path, true), path, `metadata created ${r.B}; file system B ${isoMs(fs.B)} (${fs.src})`, T); verdict.push('authored after file system B'); }
      if (isFinite(B) && isFinite(M) && B > M + 60000) { add('docInconsistent', 'low', path, `created ${r.B} after last saved ${r.M}`, T); verdict.push('created after modified'); }
      for (const [k, t] of [['created', B], ['modified', M], ['printed', tms(x.printed)]]) if (t > future) { add('future', 'low', path, `document ${k} ${isoMs(t)}`, T); verdict.push(`${k} in the future`); }
    }
    if (r.kind === 'recorded' && /LNK|jump list/i.test(r.source) && fs && fs.src === '$MFT' && isFinite(B)) {
      const sameRec = r.entry == null || (fs.entry === r.entry && (r.seq == null || fs.seq === r.seq));
      const moved = r.entry != null && fs.entry === r.entry && normKey(fs.path) !== normKey(path);
      if (r.entry != null && !sameRec) { add('replaced', sevFor(path, false), path, `shortcut recorded $MFT ${r.entry}-${r.seq ?? '?'}, now ${fs.entry}-${fs.seq}; recorded B ${r.B}, now ${isoMs(fs.B)}`, T); verdict.push('replaced (new $MFT record)'); }
      else if (fs.B + SLACK < B) { add('lnkBornBack', sevFor(path, true), path, `shortcut recorded B ${r.B}; $MFT now says ${isoMs(fs.B)} (${dur(B - fs.B)} earlier)${moved ? `; file moved to ${fs.path}` : ''}`, T); verdict.push('B moved back'); }
      else if (fs.B > B + SLACK) { if (r.entry == null) { add('replaced', 'info', path, `shortcut recorded B ${r.B}; $MFT now says ${isoMs(fs.B)}`, T); verdict.push('recreated or copied over since'); } else { add('lnkBornBack', sevFor(path, false), path, `same $MFT record but B moved forward: recorded ${r.B}, now ${isoMs(fs.B)}`, T); verdict.push('B changed'); } }
      if (sameRec && isFinite(M) && isFinite(fs.M) && fs.M + SLACK < M) { add('lnkModBack', sevFor(path, true), path, `shortcut recorded M ${r.M}; $MFT now says ${isoMs(fs.M)} (${dur(M - fs.M)} earlier)`, T); verdict.push('M moved back'); }
    }
    if (x.flags?.length) verdict.push(...x.flags);
    if (embedded.length < 50000) embedded.push({ path, source: r.source, kind: r.kind, B: r.B || '', M: r.M || '', A: r.A || '', other: x.compiled ? `compiled ${x.compiled}` : x.printed ? `printed ${x.printed}` : '', author: x.author || '', lastBy: x.lastBy || '', app: x.app || '', fsSource: fs?.src || '', fsB: fs ? isoMs(fs.B) : '', fsM: fs ? isoMs(fs.M) : '', fsEntry: fs?.entry != null ? `${fs.entry}-${fs.seq}` : '', recEntry: r.entry != null ? `${r.entry}-${r.seq ?? ''}` : '', verdict: verdict.join('; '), file: r.file || '' });
  }

  // findings: one per rule, worst first
  const byRule = new Map();
  for (const a of anomalies) { if (!byRule.has(a.rule)) byRule.set(a.rule, []); byRule.get(a.rule).push(a); }
  for (const [rule, list] of byRule) {
    const real = list.filter((a) => a.sev !== 'info'); if (!real.length) continue;
    real.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || (a.bulk || 0) - (b.bulk || 0));
    const R = RULES[rule]; const n = counts[rule];
    // widespread across the volume: a clock change or bulk tool is more likely than targeted stomping
    const wide = MFT_RULES.has(rule) && n >= 200 && n / Math.max(1, fsFiles) > 0.02;
    const worst = wide && SEV_RANK[real[0].sev] > SEV_RANK.medium ? 'medium' : real[0].sev;
    const bulk = real.filter((a) => a.bulk).length;
    const lead = real[0].path ? baseName(real[0].path) : '';
    ctx.finding({ sev: worst, category: rule.startsWith('burst') ? (rule === 'burstMod' ? 'Impact' : 'File System') : 'Defense Evasion', tool: 'Sudo-Z MACB', file: list[0].file || '$MFT', time: real[0].siB || real[0].siM || real[0].embM || '', title: `MACB: ${R.title}${n > 1 ? ` (${n} files)` : lead ? `: ${lead}` : ''}`, detail: R.why + (wide ? ` Seen on ${n} of ${fsFiles} files: check for a system clock change or a bulk copy tool before calling it timestomping; the files listed first stand out most.` : bulk ? ` ${bulk} of the listed files sit in folders where many files share the anomaly (installer or archive extraction).` : ''), evidence: real.slice(0, 20).map((a) => `${a.path}  ${a.detail}`).join('\n'), mitre: R.mitre });
  }

  // tools and one-liners that set timestamps, from anything that carries a command line
  const TOOLS = [
    [/\btimestomp(\.exe)?\b/i, 'timestomp (Metasploit / MAFIA)'],
    [/\bsetmace(\.exe)?\b/i, 'SetMace'],
    [/\bnewfiletime(\.exe)?\b|\battributemagic\b|\bbulkfilechanger\b|\bnirsoft.{0,20}filetime\b/i, 'a file time editor'],
    [/\b(creationtime|lastwritetime|lastaccesstime)\s*=/i, 'a PowerShell timestamp assignment'],
    [/Set-ItemProperty[^\r\n]{0,120}\b(CreationTime|LastWriteTime|LastAccessTime)\b/i, 'Set-ItemProperty on a timestamp'],
    [/\[IO\.File\]::Set(Creation|LastWrite|LastAccess)Time/i, 'the .NET SetCreationTime API from PowerShell'],
    [/\bSetFileTime\b/, 'the SetFileTime API'],
  ];
  const toolHits = [];
  for (const e of ctx.timeline) {
    const text = `${e.desc || ''} ${e.type || ''}`;
    for (const [rx, what] of TOOLS) if (rx.test(text)) { toolHits.push({ time: e.time, what, text: text.slice(0, 300), file: e.file }); break; }
    if (toolHits.length > 200) break;
  }
  if (toolHits.length) {
    const byWhat = new Map();
    for (const h of toolHits) { if (!byWhat.has(h.what)) byWhat.set(h.what, []); byWhat.get(h.what).push(h); }
    for (const [what, list] of byWhat) ctx.finding({
      sev: /timestomp|SetMace/i.test(what) ? 'critical' : 'high', category: 'Defense Evasion', tool: 'Sudo-Z MACB', file: list[0].file || '', time: list[0].time,
      title: `Timestamp editing: ${what} seen${list.length > 1 ? ` ${list.length} times` : ''}`,
      detail: 'Something on this host ran a command whose job is to change file timestamps. Compare the time this ran with the MACB anomalies: files whose times were set are usually the ones named on the command line.',
      evidence: list.slice(0, 10).map((h) => `${h.time || ''}  ${h.text}`).join('\n'), mitre: ['T1070.006'],
    });
  }

  const sl = ctx.settings.lastAccess;
  const accessNote = sl ? `NtfsDisableLastAccessUpdate = 0x${(sl.value >>> 0).toString(16)} (${lastAccessText(sl.value)}). ${/disabled/.test(lastAccessText(sl.value)) ? 'A (accessed) times are not updated on this system: do not read them as access.' : 'A times are updated, but lazily (up to an hour late) and also by antivirus and indexing.'}` : 'NtfsDisableLastAccessUpdate not seen (no SYSTEM hive). Windows 10 1803+ only updates A on small system volumes by default, and lazily: treat A (accessed) as weak evidence.';
  const sources = new Map(); if (fsFiles) sources.set('$MFT ($SI + $FN)', fsFiles);
  if (usn && usn.size) sources.set('USN journal ($J)', usn.size);
  if (ctx.exec.size) sources.set('execution artifacts (run times)', ctx.exec.size);
  for (const r of ctx.ftimes) sources.set(r.source, (sources.get(r.source) || 0) + 1);
  return { fsFiles, volumeBorn: isoMs(volBorn), counts, anomalies: anomalies.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev] || (a.bulk || 0) - (b.bulk || 0)).slice(0, 5000), anomaliesTotal: anomalies.length, clusters: clusters.slice(0, 200), embedded, sources: [...sources].map(([source, n]) => ({ source, n })), accessNote, rules: Object.fromEntries(Object.entries(RULES).map(([k, v]) => [k, v.title])) };
}

export function lastAccessText(v) {
  v = v >>> 0;
  return { 0: 'enabled', 1: 'disabled', 0x80000000: 'user managed, enabled', 0x80000001: 'user managed, disabled', 0x80000002: 'system managed, enabled', 0x80000003: 'system managed, disabled' }[v] || 'unknown value';
}
function dur(ms) { const s = Math.abs(ms) / 1000; return s < 120 ? `${Math.round(s)}s` : s < 7200 ? `${Math.round(s / 60)} min` : s < 172800 ? `${Math.round(s / 3600)} h` : `${Math.round(s / 86400)} days`; }

/** mactime style rows from an "All MFT entries" table: [time, macb, attr, size, entry-seq, inUse, path] */
export const MFT_COLS = { entry: 0, seq: 1, inUse: 2, type: 3, parent: 4, name: 5, size: 6, si: [7, 8, 9, 10], fn: [11, 12, 13, 14] };
export function macbRows(table, cap = 1500000) {
  const out = []; let truncated = false;
  for (const r of table.rows) {
    const path = `${r[MFT_COLS.parent]}\\${r[MFT_COLS.name]}`.replace(/^\./, 'C:');
    for (const [attr, ix] of [['$SI', MFT_COLS.si], ['$FN', MFT_COLS.fn]]) {
      const ts = ix.map((i) => r[i] || ''); // B, M, A, C order in the table
      const seen = new Map();
      ts.forEach((t, i) => { if (!t) return; const f = seen.get(t) || ['.', '.', '.', '.']; f[i] = 'bmac'[i]; seen.set(t, f); });
      for (const [t, f] of seen) {
        if (out.length >= cap) { truncated = true; break; }
        out.push([t, `${f[1] === '.' ? '.' : 'm'}${f[2] === '.' ? '.' : 'a'}${f[3] === '.' ? '.' : 'c'}${f[0] === '.' ? '.' : 'b'}`, attr, r[MFT_COLS.size], `${r[MFT_COLS.entry]}-${r[MFT_COLS.seq]}`, r[MFT_COLS.inUse], r[MFT_COLS.type], path]);
      }
    }
  }
  out.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return { rows: out, truncated };
}

/** The Sleuth Kit body file (mactime input): MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime, epoch seconds. */
export function bodyfile(tables) {
  const sec = (t) => { const v = Date.parse(t); return isFinite(v) ? Math.floor(v / 1000) : 0; };
  const L = [];
  for (const t of tables) for (const r of t.rows) {
    const path = `${r[MFT_COLS.parent]}\\${r[MFT_COLS.name]}`.replace(/^\./, 'C:').replace(/\\/g, '/');
    const mode = r[MFT_COLS.type] === 'Dir' ? 'd/drwxrwxrwx' : 'r/rrwxrwxrwx';
    const del = r[MFT_COLS.inUse] === 'N' ? ' (deleted)' : '';
    const [sB, sM, sA, sC] = MFT_COLS.si.map((i) => sec(r[i])); const [fB, fM, fA, fC] = MFT_COLS.fn.map((i) => sec(r[i]));
    L.push(`0|${path}${del}|${r[MFT_COLS.entry]}-128-${r[MFT_COLS.seq]}|${mode}|0|0|${r[MFT_COLS.size]}|${sA}|${sM}|${sC}|${sB}`);
    if (fB || fM || fA || fC) L.push(`0|${path} ($FILE_NAME)${del}|${r[MFT_COLS.entry]}-48-${r[MFT_COLS.seq]}|${mode}|0|0|${r[MFT_COLS.size]}|${fA}|${fM}|${fC}|${fB}`);
  }
  return L.join('\n') + '\n';
}
