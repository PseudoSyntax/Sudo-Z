// MFTECmd equivalent: $MFT records, $J (USN journal) and $Boot.
import { Reader, filetimeToIso, filetimeHasZeroFraction, utf16, latin1 } from '../core/bytes.js';

export const isMft = (u8) => u8.length >= 1024 && u8[0] === 0x46 && u8[1] === 0x49 && u8[2] === 0x4c && u8[3] === 0x45; // FILE
export const isBoot = (u8) => u8.length >= 512 && latin1(u8.subarray(3, 11)) === 'NTFS    ';

function fixup(rec, sector = 512) {
  const r = new Reader(rec);
  const usaOff = r.u16(4), usaCnt = r.u16(6);
  if (usaOff + usaCnt * 2 > rec.length) return false;
  const usn0 = rec[usaOff], usn1 = rec[usaOff + 1];
  for (let i = 1; i < usaCnt; i++) {
    const end = i * sector - 2;
    if (end + 1 >= rec.length) break;
    if (rec[end] !== usn0 || rec[end + 1] !== usn1) return false;
    rec[end] = rec[usaOff + i * 2]; rec[end + 1] = rec[usaOff + i * 2 + 1];
  }
  return true;
}

export function parseMft(u8, { onProgress } = {}) {
  const r0 = new Reader(u8);
  // record size: FILE records are 1024 (most) or 4096 bytes
  let recSize = 1024;
  if (u8.length >= 0x20) { const alloc = r0.u32(0x1c); if (alloc === 4096 || alloc === 1024) recSize = alloc; }
  const n = Math.floor(u8.length / recSize);
  const entries = new Array(n);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const off = i * recSize;
    if (!(u8[off] === 0x46 && u8[off + 1] === 0x49 && u8[off + 2] === 0x4c && u8[off + 3] === 0x45)) { continue; }
    const rec = u8.slice(off, off + recSize);
    if (!fixup(rec)) { bad++; }
    const r = new Reader(rec);
    try {
      const flags = r.u16(22);
      const e = { entry: i, seq: r.u16(16), inUse: !!(flags & 1), isDir: !!(flags & 2), baseRef: Number(r.u64(32) & 0xffffffffffffn), names: [], ads: [], si: null, fn: null, size: 0, zone: null, resident: false };
      let p = r.u16(20);
      while (p + 16 <= recSize) {
        const type = r.u32(p); if (type === 0xffffffff || type === 0) break;
        const len = r.u32(p + 4); if (len < 16 || p + len > recSize) break;
        const nonRes = r.u8at(p + 8), nameLen = r.u8at(p + 9), nameOff = r.u16(p + 10);
        const aname = nameLen ? r.utf16(p + nameOff, nameLen) : '';
        if (!nonRes) {
          const cs = r.u32(p + 16), co = p + r.u16(p + 20);
          if (type === 0x10 && cs >= 48) {
            e.si = { created: r.u64(co), modified: r.u64(co + 8), recordChanged: r.u64(co + 16), accessed: r.u64(co + 24), attrs: r.u32(co + 32) };
          } else if (type === 0x30 && cs >= 66) {
            const nl = r.u8at(co + 64), ns = r.u8at(co + 65);
            const fn = { parent: Number(r.u64(co) & 0xffffffffffffn), parentSeq: Number(r.u64(co) >> 48n), created: r.u64(co + 8), modified: r.u64(co + 16), recordChanged: r.u64(co + 24), accessed: r.u64(co + 32), realSize: r.u64n(co + 48), ns, name: r.utf16(co + 66, nl) };
            e.names.push(fn);
          } else if (type === 0x80) {
            if (aname) {
              const ad = { name: aname, size: cs };
              if (/^Zone\.Identifier$/i.test(aname) && cs < 4096) ad.content = latin1(r.bytes(co, cs));
              e.ads.push(ad);
            } else { e.size = cs; e.resident = true; }
          }
        } else if (type === 0x80) {
          const real = r.u64n(p + 48);
          if (aname) e.ads.push({ name: aname, size: real }); else e.size = real;
        }
        p += len;
      }
      // prefer Win32 (1) or Win32&DOS (3) names over DOS (2)
      e.fn = e.names.find((x) => x.ns === 1 || x.ns === 3) || e.names.find((x) => x.ns === 0) || e.names[0] || null;
      entries[i] = e;
    } catch { bad++; }
    if (onProgress && i % 20000 === 0) onProgress(i / n);
  }
  // resolve paths
  const cache = new Map();
  const pathOf = (i, depth = 0) => {
    if (i === 5) return '.';
    if (cache.has(i)) return cache.get(i);
    const e = entries[i];
    if (!e || !e.fn || depth > 64) return `.\\[orphan ${i}]`;
    const parent = e.fn.parent;
    const pe = entries[parent];
    let pp;
    if (parent === i) pp = '.';
    else if (!pe || pe.seq !== e.fn.parentSeq && pe.seq !== e.fn.parentSeq + 1) pp = `.\\PathUnknown\\Directory with ID 0x${parent.toString(16)}-${e.fn.parentSeq}`;
    else pp = pathOf(parent, depth + 1);
    const full = `${pp}\\${e.fn.name}`;
    cache.set(i, full);
    return full;
  };
  const rows = [];
  for (const e of entries) {
    if (!e || !e.fn) continue;
    if (e.baseRef && e.baseRef !== e.entry) continue; // extension record
    const parentPath = pathOf(e.fn.parent === e.entry ? 5 : e.fn.parent);
    rows.push({
      entry: e.entry, seq: e.seq, inUse: e.inUse, isDir: e.isDir,
      parentPath: e.fn.parent === 5 ? '.' : parentPath, name: e.fn.name, size: e.size || e.fn.realSize,
      si: e.si, fn: e.fn, ads: e.ads, resident: e.resident,
    });
  }
  return { rows, recSize, total: n, bad, pathOf };
}

export function siTimestomp(row) {
  // Returns reasons if $STANDARD_INFORMATION looks backdated relative to $FILE_NAME.
  if (!row.si || !row.fn) return null;
  const reasons = [];
  const siC = row.si.created, fnC = row.fn.created;
  if (siC && fnC && siC + 10000000n < fnC) reasons.push('$SI created earlier than $FN created');
  if (filetimeHasZeroFraction(siC) && !filetimeHasZeroFraction(fnC)) reasons.push('$SI created has zero sub-second precision');
  if (row.si.modified && row.si.modified + 10000000n < fnC && filetimeHasZeroFraction(row.si.modified)) reasons.push('$SI modified predates $FN created with zeroed fraction');
  return reasons.length ? reasons : null;
}

// ---------------------------------------------------------------- $J
const USN_REASONS = [[0x1, 'DataOverwrite'], [0x2, 'DataExtend'], [0x4, 'DataTruncation'], [0x10, 'NamedDataOverwrite'], [0x20, 'NamedDataExtend'], [0x40, 'NamedDataTruncation'], [0x100, 'FileCreate'], [0x200, 'FileDelete'], [0x400, 'EaChange'], [0x800, 'SecurityChange'], [0x1000, 'RenameOldName'], [0x2000, 'RenameNewName'], [0x4000, 'IndexableChange'], [0x8000, 'BasicInfoChange'], [0x10000, 'HardLinkChange'], [0x20000, 'CompressionChange'], [0x40000, 'EncryptionChange'], [0x80000, 'ObjectIdChange'], [0x100000, 'ReparsePointChange'], [0x200000, 'StreamChange'], [0x80000000, 'Close']];
export const usnReasons = (v) => USN_REASONS.filter(([b]) => (v & b) >>> 0).map(([, n]) => n).join('|');

export function looksLikeUsn(u8) {
  // find the first non-zero 8-byte aligned qword and test a V2/V3 record header
  let p = 0;
  const lim = Math.min(u8.length, 64 * 1024 * 1024);
  while (p < lim && u8[p] === 0 && u8[p + 1] === 0 && u8[p + 2] === 0 && u8[p + 3] === 0) p += 8;
  if (p + 60 > u8.length) return false;
  const r = new Reader(u8);
  const len = r.u32(p), maj = r.u16(p + 4);
  return len >= 60 && len < 1024 && (maj === 2 || maj === 3) && r.u16(p + 58) === (maj === 2 ? 60 : 76);
}

export function parseUsn(u8, { max = 2000000 } = {}) {
  const r = new Reader(u8);
  const rows = [];
  let p = 0;
  while (p + 60 <= u8.length && rows.length < max) {
    const len = r.u32(p);
    if (len === 0) { p += 8; continue; }
    const maj = r.u16(p + 4);
    if (len < 60 || len > 4096 || (maj !== 2 && maj !== 3) || p + len > u8.length) { p += 8; continue; }
    try {
      if (maj === 2) {
        const nl = r.u16(p + 56), no = r.u16(p + 58);
        rows.push({ entry: Number(r.u64(p + 8) & 0xffffffffffffn), seq: Number(r.u64(p + 8) >> 48n), parent: Number(r.u64(p + 16) & 0xffffffffffffn), parentSeq: Number(r.u64(p + 16) >> 48n), usn: Number(r.u64(p + 24)), time: r.filetime(p + 32), reason: r.u32(p + 40), attrs: r.u32(p + 52), name: r.utf16(p + no, nl / 2) });
      } else {
        const nl = r.u16(p + 72), no = r.u16(p + 74);
        rows.push({ entry: r.u32(p + 8), seq: 0, parent: r.u32(p + 24), parentSeq: 0, usn: Number(r.u64(p + 40)), time: r.filetime(p + 48), reason: r.u32(p + 56), attrs: r.u32(p + 68), name: r.utf16(p + no, nl / 2) });
      }
    } catch { }
    p += (len + 7) & ~7;
  }
  return rows;
}

export function parseBoot(u8) {
  const r = new Reader(u8);
  const bps = r.u16(11), spc = r.u8at(13);
  const clusterSize = spc <= 0x80 ? bps * spc : 2 ** (256 - spc);
  const mftRecRaw = r.i8(0x40);
  return {
    oem: r.ascii(3, 8), bytesPerSector: bps, clusterSize, totalSectors: r.u64n(0x28),
    mftCluster: r.u64n(0x30), mftMirrCluster: r.u64n(0x38),
    mftRecordSize: mftRecRaw > 0 ? mftRecRaw * clusterSize : 2 ** -mftRecRaw,
    serial: r.u64(0x48).toString(16).toUpperCase().padStart(16, '0'),
  };
}
