// Read-only ESE (JET Blue / .edb / .dat) database reader: catalog, table
// b-trees, fixed / variable / tagged columns, 7-bit and Xpress compressed
// values, and inline long values. Powers the SrumECmd / SumECmd equivalents
// and WebCacheV01 history.
import { Reader, guidStr, filetimeToIso } from '../core/bytes.js';
import { lzxpressPlainDecompress } from '../core/lzxpress.js';

export const isEse = (u8) => u8.length > 8192 && new Reader(u8).u32(4) === 0x89abcdef;

const FIXED_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 4, 7: 8, 8: 8, 14: 4, 15: 8, 16: 16, 17: 2 };
export const COLTYP = { 1: 'Bit', 2: 'UnsignedByte', 3: 'Short', 4: 'Long', 5: 'Currency', 6: 'IEEESingle', 7: 'IEEEDouble', 8: 'DateTime', 9: 'Binary', 10: 'Text', 11: 'LongBinary', 12: 'LongText', 13: 'SLV', 14: 'UnsignedLong', 15: 'LongLong', 16: 'GUID', 17: 'UnsignedShort' };

function sevenBit(b, start) {
  let out = '', acc = 0, bits = 0;
  for (let i = start; i < b.length; i++) {
    acc |= b[i] << bits; bits += 8;
    while (bits >= 7) { out += String.fromCharCode(acc & 0x7f); acc >>= 7; bits -= 7; }
  }
  return out;
}

export function decompressValue(b) {
  if (!b.length) return b;
  const t = b[0] >> 3;
  if (t === 1 || t === 2) { const s = sevenBit(b, 1); return { text: t === 2 ? s : s }; }
  if (t === 3) { const n = b[1] | (b[2] << 8); return lzxpressPlainDecompress(b.subarray(3), n); }
  return b;
}

export class EseDb {
  constructor(u8) {
    this.u8 = u8; this.r = new Reader(u8);
    if (!isEse(u8)) throw new Error('not an ESE database');
    this.formatVersion = this.r.u32(8);
    this.formatRevision = this.r.u32(0xd8);
    this.pageSize = this.r.u32(0xec) || 4096;
    this.state = { 1: 'Just created', 2: 'Dirty shutdown', 3: 'Clean shutdown', 4: 'Being converted', 5: 'Force detach' }[this.r.u32(0x34)] || String(this.r.u32(0x34));
    this.large = this.pageSize >= 16384;
    this.hdr = this.large ? 80 : 40;
    this.pages = Math.floor(u8.length / this.pageSize) - 1;
    this.lvCache = new Map();
    this._catalog = null;
  }
  pageOff(n) { return (n + 1) * this.pageSize; }
  page(n) {
    const o = this.pageOff(n);
    if (n < 0 || o + this.pageSize > this.u8.length) throw new Error(`page ${n} out of range`);
    const r = this.r;
    const nTags = r.u16(o + 34), flags = r.u32(o + 36);
    const tags = [];
    for (let i = 0; i < nTags; i++) {
      const t = o + this.pageSize - 4 * (i + 1);
      const a = r.u16(t), b = r.u16(t + 2);
      let size, off, tf;
      if (this.large) { size = a & 0x7fff; off = b & 0x7fff; const s = o + this.hdr + off; tf = size >= 2 ? (r.u16(s) >> 13) : 0; }
      else { size = a & 0x1fff; off = b & 0x1fff; tf = b >> 13; }
      tags.push({ start: o + this.hdr + off, size, flags: tf });
    }
    return { o, prev: r.u32(o + 16), next: r.u32(o + 20), fdp: r.u32(o + 24), flags, tags };
  }
  // Yield {key, data} for every leaf entry under the tree rooted at page `root`
  *leaves(root, seen = new Set()) {
    if (seen.has(root) || seen.size > 2000000) return;
    seen.add(root);
    let p;
    try { p = this.page(root); } catch { return; }
    if (p.flags & 0x08) return; // empty
    const isLeaf = !!(p.flags & 0x02), isParent = !!(p.flags & 0x04);
    if (p.flags & 0x20) return; // space tree
    const common = p.tags[0] ? this.u8.subarray(p.tags[0].start, p.tags[0].start + p.tags[0].size) : new Uint8Array();
    for (let i = 1; i < p.tags.length; i++) {
      const t = p.tags[i];
      if (t.size === 0 || (t.flags & 0x2)) continue; // defunct / deleted
      let q = t.start; const end = t.start + t.size;
      const mask = this.large ? 0x1fff : 0xffff;
      let commonSize = 0;
      if (t.flags & 0x4) { commonSize = this.r.u16(q) & mask; q += 2; }
      const localSize = (this.r.u16(q) & (t.flags & 0x4 ? 0xffff : mask)); q += 2;
      const key = new Uint8Array(commonSize + localSize);
      key.set(common.subarray(0, commonSize)); key.set(this.u8.subarray(q, q + localSize), commonSize);
      q += localSize;
      if (isParent && !isLeaf) {
        if (end - 4 < q) continue;
        yield* this.leaves(this.r.u32(end - 4), seen);
      } else if (isLeaf) {
        yield { key, data: this.u8.subarray(q, end) };
      }
    }
  }
  // Decode a data record using a column list
  record(data, columns, lvFdp) {
    const r = new Reader(data);
    const out = {};
    if (data.length < 4) return out;
    const lastFixed = data[0], lastVar = data[1], varOff = r.u16(2);
    // fixed
    let p = 4;
    const fixed = columns.filter((c) => c.id <= 127).sort((a, b) => a.id - b.id);
    const nullMapOff = (() => { let q = 4; for (const c of fixed) { if (c.id > lastFixed) break; q += c.fixedSize; } return q; })();
    for (const c of fixed) {
      if (c.id > lastFixed) break;
      const isNull = nullMapOff + ((c.id - 1) >> 3) < data.length && (data[nullMapOff + ((c.id - 1) >> 3)] >> ((c.id - 1) & 7)) & 1;
      if (!isNull && p + c.fixedSize <= data.length) out[c.name] = this.value(c, data.subarray(p, p + c.fixedSize));
      p += c.fixedSize;
    }
    // variable
    const vars = columns.filter((c) => c.id >= 128 && c.id <= 255);
    const nVar = lastVar >= 128 ? lastVar - 127 : 0;
    const varData = varOff + nVar * 2;
    let prevEnd = 0, lastEnd = 0;
    for (let i = 0; i < nVar; i++) {
      if (varOff + i * 2 + 2 > data.length) break;
      const raw = r.u16(varOff + i * 2); const end = raw & 0x7fff;
      const col = vars.find((c) => c.id === 128 + i);
      if (!(raw & 0x8000) && col && varData + end <= data.length) out[col.name] = this.value(col, data.subarray(varData + prevEnd, varData + end));
      if (!(raw & 0x8000)) prevEnd = end;
      lastEnd = Math.max(lastEnd, end);
    }
    // tagged
    const tStart = nVar ? varData + prevEnd : varOff;
    if (tStart + 4 <= data.length) {
      const tagged = [];
      const first = r.u16(tStart + 2);
      const offMask = this.large ? 0x7fff : 0x3fff;
      const count = Math.min(((first & offMask) / 4) | 0, 256);
      for (let i = 0; i < count; i++) {
        const id = r.u16(tStart + i * 4), raw = r.u16(tStart + i * 4 + 2);
        tagged.push({ id, off: raw & offMask, hasFlags: this.large ? true : !!(raw & 0x4000) || this.formatRevision >= 0x11 });
      }
      for (let i = 0; i < tagged.length; i++) {
        const t = tagged[i];
        const s = tStart + t.off, e = i + 1 < tagged.length ? tStart + tagged[i + 1].off : data.length;
        if (s >= e || e > data.length) continue;
        const col = columns.find((c) => c.id === t.id);
        if (!col) continue;
        let v = data.subarray(s, e); let fl = 0;
        if (t.hasFlags) { fl = v[0]; v = v.subarray(1); }
        try {
          if (fl & 0x04) { // long value reference
            const lv = this.longValue(lvFdp, v);
            out[col.name] = lv ? this.value(col, lv) : '[long value]';
          } else {
            if (fl & 0x02) { const d = decompressValue(v); if (d.text !== undefined) { out[col.name] = d.text; continue; } v = d; }
            if (fl & 0x08 && !(fl & 0x10)) { out[col.name] = this.value(col, v); continue; } // multi value: first only
            out[col.name] = this.value(col, v);
          }
        } catch { out[col.name] = '[undecodable]'; }
      }
    }
    return out;
  }
  longValue(lvFdp, ref) {
    if (!lvFdp || ref.length < 4) return null;
    let map = this.lvCache.get(lvFdp);
    if (!map) {
      map = new Map();
      try {
        for (const { key, data } of this.leaves(lvFdp)) {
          if (key.length === 4) continue; // LV root (refcount/size)
          if (key.length < 8) continue;
          const id = ((key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3]) >>> 0;
          const off = ((key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7]) >>> 0;
          if (!map.has(id)) map.set(id, []);
          map.get(id).push({ off, data });
        }
      } catch { }
      this.lvCache.set(lvFdp, map);
    }
    const idLE = new Reader(ref).u32(0);
    const idBE = ((ref[0] << 24) | (ref[1] << 16) | (ref[2] << 8) | ref[3]) >>> 0;
    const parts = map.get(idBE) || map.get(idLE);
    if (!parts) return null;
    parts.sort((a, b) => a.off - b.off);
    const total = parts.reduce((n, x) => Math.max(n, x.off + x.data.length), 0);
    if (total > 16 * 1024 * 1024) return null;
    const out = new Uint8Array(total);
    for (const x of parts) out.set(x.data, x.off);
    return out;
  }
  value(col, b) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    switch (col.type) {
      case 1: return b[0] ? true : false;
      case 2: return b[0];
      case 3: return b.length >= 2 ? dv.getInt16(0, true) : null;
      case 4: return b.length >= 4 ? dv.getInt32(0, true) : null;
      case 14: return b.length >= 4 ? dv.getUint32(0, true) : null;
      case 17: return b.length >= 2 ? dv.getUint16(0, true) : null;
      case 15: case 5: return b.length >= 8 ? Number(dv.getBigInt64(0, true)) : null;
      case 6: return b.length >= 4 ? dv.getFloat32(0, true) : null;
      case 7: return b.length >= 8 ? dv.getFloat64(0, true) : null;
      case 8: { if (b.length < 8) return null; const d = dv.getFloat64(0, true); const ms = (d - 25569) * 86400000; return isFinite(ms) && d > 0 ? new Date(ms).toISOString() : null; }
      case 16: return b.length >= 16 ? `{${guidStr(b)}}` : null;
      case 10: case 12: {
        if (col.codepage === 1200 || (b.length >= 2 && b[1] === 0 && b.length % 2 === 0)) return new TextDecoder('utf-16le').decode(b).replace(/\0+$/, '');
        return new TextDecoder('latin1').decode(b).replace(/\0+$/, '');
      }
      default: return b;
    }
  }
  catalog() {
    if (this._catalog) return this._catalog;
    const catCols = [
      { id: 1, name: 'ObjidTable', type: 4, fixedSize: 4 }, { id: 2, name: 'Type', type: 3, fixedSize: 2 }, { id: 3, name: 'Id', type: 4, fixedSize: 4 },
      { id: 4, name: 'ColtypOrPgnoFDP', type: 4, fixedSize: 4 }, { id: 5, name: 'SpaceUsage', type: 4, fixedSize: 4 }, { id: 6, name: 'Flags', type: 4, fixedSize: 4 },
      { id: 7, name: 'PagesOrLocale', type: 4, fixedSize: 4 }, { id: 8, name: 'RootFlag', type: 1, fixedSize: 1 }, { id: 9, name: 'RecordOffset', type: 3, fixedSize: 2 },
      { id: 10, name: 'LCMapFlags', type: 4, fixedSize: 4 }, { id: 11, name: 'KeyMost', type: 3, fixedSize: 2 }, { id: 128, name: 'Name', type: 10 },
    ];
    const tables = new Map();
    for (const { data } of this.leaves(4)) {
      const rec = this.record(data, catCols);
      if (rec.Type === 1) tables.set(rec.ObjidTable, { name: rec.Name, fdp: rec.ColtypOrPgnoFDP, columns: [], lv: null });
      else if (rec.Type === 2) { const t = tables.get(rec.ObjidTable); if (t) t.columns.push({ id: rec.Id, name: rec.Name, type: rec.ColtypOrPgnoFDP, fixedSize: FIXED_SIZE[rec.ColtypOrPgnoFDP] || rec.SpaceUsage || 0, codepage: rec.PagesOrLocale }); }
      else if (rec.Type === 4) { const t = tables.get(rec.ObjidTable); if (t) t.lv = rec.ColtypOrPgnoFDP; }
    }
    this._catalog = [...tables.values()].filter((t) => t.name);
    return this._catalog;
  }
  tables() { return this.catalog().map((t) => t.name); }
  *rows(name, max = 1000000) {
    const t = this.catalog().find((x) => x.name.toLowerCase() === name.toLowerCase());
    if (!t) return;
    let n = 0;
    for (const { data } of this.leaves(t.fdp)) {
      yield this.record(data, t.columns, t.lv);
      if (++n >= max) return;
    }
  }
  table(name, max) { return [...this.rows(name, max)]; }
}
