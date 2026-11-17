// Legacy and NTFS index formats:
//  * Task Scheduler 1.0 .job files (MS-TSCH)
//  * Windows XP/2003 .evt event logs (EVENTLOGRECORD)
//  * NTFS $I30 directory index (INDX records, including slack entries)
//  * SQLite write-ahead log merge
import { Reader, filetimeToIso, unixToIso, guidStr } from '../core/bytes.js';

// ---------------------------------------------------------------- .job
const JOB_STATUS = { 0x41300: 'Ready', 0x41301: 'Running', 0x41302: 'Disabled', 0x41303: 'Has not run', 0x41304: 'No more runs', 0x41305: 'Not scheduled', 0x41306: 'Terminated', 0x41307: 'No valid triggers', 0x41308: 'Event trigger' };
export const isJob = (u8, name = '') => /\.job$/i.test(name) && u8.length >= 70 && [0x400, 0x500, 0x501, 0x502, 0x600, 0x601, 0x602, 0x603, 0x0a00].includes(new Reader(u8).u16(0)) === true || (/\.job$/i.test(name) && u8.length >= 70 && new Reader(u8).u16(2) === 1);

export function parseJob(u8) {
  const r = new Reader(u8);
  const st = (o) => { const y = r.u16(o); if (!y) return null; const d = Date.UTC(y, r.u16(o + 2) - 1, r.u16(o + 6), r.u16(o + 8), r.u16(o + 10), r.u16(o + 12), r.u16(o + 14)); return isNaN(d) ? null : new Date(d).toISOString().replace('Z', ' (local)'); };
  const out = { productVersion: '0x' + r.u16(0).toString(16), uuid: guidStr(r.bytes(4, 16)), priority: r.u32(32), maxRunMs: r.u32(36), exitCode: r.u32(40), status: JOB_STATUS[r.u32(44)] || '0x' + r.u32(44).toString(16), flags: r.u32(48), lastRun: st(52) };
  let p = 68;
  out.instances = r.u16(p); p += 2;
  const str = () => { const n = r.u16(p); p += 2; const s = n ? r.utf16(p, n).replace(/\0+$/, '') : ''; p += n * 2; return s; };
  out.application = str(); out.parameters = str(); out.workingDir = str(); out.author = str(); out.comment = str();
  try {
    const ud = r.u16(p); p += 2 + ud;
    const rd = r.u16(p); p += 2 + rd;
    const nt = r.u16(p); p += 2;
    out.triggers = [];
    for (let i = 0; i < nt && p + 48 <= r.length; i++) {
      const t = p; const type = r.u32(t + 36);
      out.triggers.push({ begin: `${r.u16(t + 4)}-${String(r.u16(t + 6)).padStart(2, '0')}-${String(r.u16(t + 8)).padStart(2, '0')} ${String(r.u16(t + 16)).padStart(2, '0')}:${String(r.u16(t + 18)).padStart(2, '0')}`, type: ['Once', 'Daily', 'Weekly', 'Monthly date', 'Monthly DOW', 'On idle', 'At startup', 'At logon'][type] || type });
      p += r.u16(t) || 48;
    }
  } catch { }
  out.commandLine = `${out.application} ${out.parameters}`.trim();
  return out;
}

// ---------------------------------------------------------------- .evt
export const isEvt = (u8) => u8.length >= 48 && new Reader(u8).u32(0) === 0x30 && new Reader(u8).magic(4, 'LfLe');
const EVT_TYPES = { 0: 'Success', 1: 'Error', 2: 'Warning', 4: 'Information', 8: 'Audit Success', 16: 'Audit Failure' };

export function parseEvt(u8, max = 500000) {
  const r = new Reader(u8);
  const out = [];
  const seen = new Set();
  // circular buffer: scan for record signatures rather than trusting header offsets
  for (let p = 48; p + 56 <= u8.length && out.length < max; p += 4) {
    if (!(u8[p + 4] === 0x4c && u8[p + 5] === 0x66 && u8[p + 6] === 0x4c && u8[p + 7] === 0x65)) continue;
    const len = r.u32(p);
    if (len < 56 || len > 0x10000 || p + len > u8.length || r.u32(p + len - 4) !== len) continue;
    const num = r.u32(p + 8);
    if (seen.has(num)) continue; seen.add(num);
    const nStr = r.u16(p + 26), sOff = r.u32(p + 36), sidLen = r.u32(p + 40), sidOff = r.u32(p + 44), dLen = r.u32(p + 48), dOff = r.u32(p + 52);
    const source = r.utf16z(p + 56, 256);
    const computer = r.utf16z(p + 56 + (source.length + 1) * 2, 256);
    let strings = [];
    if (nStr && sOff < len) strings = r.utf16(p + sOff, Math.max(0, ((dOff && dOff > sOff ? dOff : len - 4) - sOff) >> 1)).split('\0').slice(0, nStr);
    let sid = '';
    if (sidLen >= 8 && sidOff + sidLen <= len) { const b = r.bytes(p + sidOff, sidLen); let a = 0; for (let i = 2; i < 8; i++) a = a * 256 + b[i]; sid = `S-${b[0]}-${a}`; for (let i = 0; i < b[1]; i++) sid += '-' + new DataView(b.buffer, b.byteOffset).getUint32(8 + i * 4, true); }
    out.push({ RecordNumber: num, TimeCreated: unixToIso(r.u32(p + 12)), TimeWritten: unixToIso(r.u32(p + 16)), EventId: r.u32(p + 20) & 0xffff, Type: EVT_TYPES[r.u16(p + 24)] || r.u16(p + 24), Category: r.u16(p + 28), Provider: source, Computer: computer, UserId: sid, Strings: strings, DataLen: dLen });
    p += len - 4;
  }
  out.sort((a, b) => (a.TimeCreated || '').localeCompare(b.TimeCreated || '') || a.RecordNumber - b.RecordNumber);
  return out;
}

// ---------------------------------------------------------------- $I30 (INDX)
export const isIndx = (u8) => u8.length >= 4096 && u8[0] === 0x49 && u8[1] === 0x4e && u8[2] === 0x44 && u8[3] === 0x58;

function fixupIndx(rec) {
  const r = new Reader(rec); const usaOff = r.u16(4), usaCnt = r.u16(6);
  if (usaOff + usaCnt * 2 > rec.length) return;
  for (let i = 1; i < usaCnt; i++) { const end = i * 512 - 2; if (end + 1 >= rec.length) break; rec[end] = rec[usaOff + i * 2]; rec[end + 1] = rec[usaOff + i * 2 + 1]; }
}

function fnAt(r, o, end) {
  // $FILE_NAME structure at o; returns null when it does not look valid
  if (o + 66 > end) return null;
  const nl = r.u8at(o + 64), ns = r.u8at(o + 65);
  if (!nl || ns > 3 || o + 66 + nl * 2 > end) return null;
  const times = [8, 16, 24, 32].map((k) => r.u64(o + k));
  const lo = 116444736000000000n - 315537897600000000n, hi = 116444736000000000n + 32503680000000000n; // ~1600..3000
  if (times.some((t) => t < 116444736000000000n - 3155378975999999999n / 10n || t > hi)) return null;
  if (times.some((t) => t === 0n)) return null;
  const name = r.utf16(o + 66, nl);
  if (/[\x00-\x1f]/.test(name)) return null;
  return { parent: Number(r.u64(o) & 0xffffffffffffn), created: filetimeToIso(times[0]), modified: filetimeToIso(times[1]), recordChanged: filetimeToIso(times[2]), accessed: filetimeToIso(times[3]), size: r.u64n(o + 48), flags: r.u32(o + 56), ns, name };
}

export function parseIndx(u8) {
  const rows = [];
  for (let off = 0; off + 4096 <= u8.length; off += 4096) {
    if (!(u8[off] === 0x49 && u8[off + 1] === 0x4e && u8[off + 2] === 0x44 && u8[off + 3] === 0x58)) continue;
    const rec = u8.slice(off, off + 4096); fixupIndx(rec);
    const r = new Reader(rec);
    const vcn = r.u64n(16);
    const h = 0x18, eStart = h + r.u32(h), used = h + r.u32(h + 4);
    let p = eStart;
    while (p + 16 <= used) {
      const elen = r.u16(p + 8), slen = r.u16(p + 10), fl = r.u8at(p + 12);
      if (fl & 2) break;
      if (elen < 16 || p + elen > 4096) break;
      const fn = slen >= 66 ? fnAt(r, p + 16, p + 16 + slen) : null;
      if (fn) rows.push({ vcn, slack: false, entry: Number(r.u64(p) & 0xffffffffffffn), ...fn });
      p += elen;
    }
    // slack: scan remaining bytes for $FILE_NAME structures (deleted entries)
    for (let s = Math.max(used, eStart); s + 82 <= 4096; s += 2) {
      const fn = fnAt(r, s + 16, 4096);
      if (fn && fn.ns <= 3 && r.u16(s + 8) >= 82 && r.u16(s + 8) < 600) { rows.push({ vcn, slack: true, entry: Number(r.u64(s) & 0xffffffffffffn), ...fn }); s += 80; }
    }
  }
  return rows;
}

// ---------------------------------------------------------------- SQLite WAL
export const isWal = (u8) => u8.length >= 32 && (new Reader(u8).u32be(0) & 0xfffffffe) === 0x377f0682;

/** Apply committed WAL frames to a copy of the database. */
export function mergeWal(db, wal) {
  const w = new Reader(wal);
  const pageSize = w.u32be(8) || 65536;
  const salt1 = w.u32be(16), salt2 = w.u32be(20);
  const frames = new Map(); let committed = new Map(); let dbPages = 0; let nFrames = 0, nCommits = 0;
  for (let p = 32; p + 24 + pageSize <= wal.length; p += 24 + pageSize) {
    if (w.u32be(p + 8) !== salt1 || w.u32be(p + 12) !== salt2) break;
    const pg = w.u32be(p), commit = w.u32be(p + 4);
    frames.set(pg, p + 24); nFrames++;
    if (commit) { committed = new Map(frames); dbPages = commit; nCommits++; }
  }
  if (!committed.size) return { data: db, frames: nFrames, commits: 0, pages: 0 };
  const size = Math.max(dbPages * pageSize, 0) || db.length;
  const out = new Uint8Array(size);
  out.set(db.subarray(0, Math.min(db.length, size)));
  for (const [pg, off] of committed) if ((pg - 1) * pageSize + pageSize <= size) out.set(wal.subarray(off, off + pageSize), (pg - 1) * pageSize);
  return { data: out, frames: nFrames, commits: nCommits, pages: committed.size };
}
