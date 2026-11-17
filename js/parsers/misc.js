// RBCmd ($I / INFO2), RecentFileCacheParser, iisGeolocate (parsing only).
import { Reader, filetimeToIso, utf8 } from '../core/bytes.js';

export function isDollarI(u8, name = '') {
  if (u8.length < 24) return false;
  const v = new Reader(u8).u64n(0);
  return (v === 1 || v === 2) && (/^\$I[A-Z0-9]{6}/i.test(name.split(/[\\/]/).pop()) || (u8.length === 544 && v === 1));
}

export function parseDollarI(u8) {
  const r = new Reader(u8);
  const ver = r.u64n(0);
  const size = r.u64n(8), deleted = r.filetime(16);
  const path = ver === 2 ? r.utf16(28, Math.min(r.u32(24), (u8.length - 28) >> 1)) : r.utf16z(24, 260);
  return { version: ver, size, deleted, path: path.replace(/\0.*$/, '') };
}

export function isInfo2(u8, name = '') {
  if (!/^info2$/i.test(name.split(/[\\/]/).pop()) || u8.length < 20) return false;
  const r = new Reader(u8); return r.u32(12) === 800 || r.u32(12) === 280;
}

export function parseInfo2(u8) {
  const r = new Reader(u8);
  const recSize = r.u32(12);
  const rows = [];
  for (let p = 20; p + recSize <= u8.length; p += recSize) {
    rows.push({ path: recSize === 800 ? r.utf16z(p + 280, 260) || r.asciiz(p, 260) : r.asciiz(p, 260), index: r.u32(p + 260), drive: r.u32(p + 264), deleted: r.filetime(p + 268), size: r.u32(p + 276) });
  }
  return rows;
}

export const isRecentFileCache = (u8, name = '') => /recentfilecache\.bcf$/i.test(name) && u8.length >= 20;

export function parseRecentFileCache(u8) {
  const r = new Reader(u8);
  const out = [];
  let p = 0x14;
  while (p + 4 <= u8.length) {
    const n = r.u32(p); if (!n || n > 1024 || p + 4 + n * 2 > u8.length) break;
    out.push(r.utf16(p + 4, n)); p += 4 + n * 2 + 2;
  }
  return out;
}

// --- IIS W3C logs (iisGeolocate parses these to geolocate c-ip; we parse and analyse) --
export function isIisLog(u8, name = '') {
  const head = utf8(u8.subarray(0, 2048));
  return /^#Software: Microsoft Internet Information Services/m.test(head) || (/^#Fields:.*\bc-ip\b/m.test(head) && /\b(cs-uri-stem|s-ip)\b/.test(head)) || /^u_ex\d+.*\.log$/i.test(name.split(/[\\/]/).pop());
}

export function parseIisLog(u8, { max = 2000000 } = {}) {
  const text = utf8(u8);
  let fields = null;
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    if (line[0] === '#') { if (line.startsWith('#Fields:')) fields = line.slice(8).trim().split(/\s+/); continue; }
    if (!fields) continue;
    const parts = line.split(' ');
    const o = {}; fields.forEach((f, i) => { o[f] = parts[i]; });
    rows.push(o);
    if (rows.length >= max) break;
  }
  return { fields: fields || [], rows };
}
