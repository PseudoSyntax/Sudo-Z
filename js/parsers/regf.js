// Registry hive (regf) reader: the base that RECmd, AppCompatCacheParser,
// AmcacheParser and SBECmd plugins are built on.
import { Reader, filetimeToIso, utf16, latin1 } from '../core/bytes.js';

export const isRegf = (u8) => u8.length > 4096 && u8[0] === 0x72 && u8[1] === 0x65 && u8[2] === 0x67 && u8[3] === 0x66;

const REG_TYPES = { 0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD', 5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 8: 'REG_RESOURCE_LIST', 11: 'REG_QWORD' };

export class Hive {
  constructor(u8) {
    this.r = new Reader(u8);
    if (!isRegf(u8)) throw new Error('not a registry hive (missing regf signature)');
    const r = this.r;
    this.primarySeq = r.u32(4); this.secondarySeq = r.u32(8);
    this.dirty = this.primarySeq !== this.secondarySeq;
    this.lastWritten = r.filetime(12);
    this.minor = r.u32(0x18);
    this.rootOff = r.u32(0x24);
    this.embeddedName = r.utf16z(0x30, 32);
    this.cache = new Map();
  }
  cell(off) { return 0x1000 + off + 4; } // absolute offset of cell data
  key(off = this.rootOff) {
    let k = this.cache.get(off);
    if (k) return k;
    const r = this.r, p = this.cell(off);
    if (!r.magic(p, 'nk')) throw new Error(`expected nk @${off}`);
    const flags = r.u16(p + 2), nameLen = r.u16(p + 0x48);
    k = new Key(this, off, {
      flags,
      lastWritten: r.filetime(p + 4),
      nSub: r.u32(p + 0x14), subOff: r.u32(p + 0x1c),
      nVal: r.u32(p + 0x24), valOff: r.u32(p + 0x28),
      classOff: r.u32(p + 0x30), classLen: r.u16(p + 0x4a),
      name: (flags & 0x20) ? latin1(r.bytes(p + 0x4c, nameLen)) : utf16(r.bytes(p + 0x4c, nameLen)),
    });
    this.cache.set(off, k);
    return k;
  }
  subkeyOffsets(listOff, out = [], depth = 0) {
    if (listOff === 0xffffffff || depth > 4) return out;
    const r = this.r, p = this.cell(listOff);
    const sig = r.ascii(p, 2), n = r.u16(p + 2);
    if (sig === 'lf' || sig === 'lh') for (let i = 0; i < n; i++) out.push(r.u32(p + 4 + i * 8));
    else if (sig === 'li') for (let i = 0; i < n; i++) out.push(r.u32(p + 4 + i * 4));
    else if (sig === 'ri') for (let i = 0; i < n; i++) this.subkeyOffsets(r.u32(p + 4 + i * 4), out, depth + 1);
    return out;
  }
  valueData(size, off) {
    const r = this.r;
    if (size & 0x80000000) {
      const n = size & 0x7fffffff; const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, off, true); return b.subarray(0, Math.min(n, 4));
    }
    if (size === 0 || off === 0xffffffff) return new Uint8Array();
    const p = this.cell(off);
    if (size > 16344 && this.minor >= 4 && r.magic(p, 'db')) {
      const n = r.u16(p + 2), list = this.cell(r.u32(p + 4));
      const out = new Uint8Array(size); let w = 0;
      for (let i = 0; i < n && w < size; i++) {
        const seg = this.cell(r.u32(list + i * 4));
        const segSize = Math.abs(r.i32(seg - 4)) - 4;
        const take = Math.min(16344, segSize, size - w);
        out.set(r.bytes(seg, take), w); w += take;
      }
      return out.subarray(0, w);
    }
    const avail = Math.abs(r.i32(p - 4)) - 4;
    return r.bytes(p, Math.min(size, Math.max(0, avail)));
  }
}

function decodeValue(type, b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  switch (type) {
    case 1: case 2: case 6: return utf16(b).replace(/\0.*$/s, '');
    case 7: return utf16(b).split('\0').filter(Boolean);
    case 4: return b.length >= 4 ? dv.getUint32(0, true) : null;
    case 5: return b.length >= 4 ? dv.getUint32(0, false) : null;
    case 11: return b.length >= 8 ? Number(dv.getBigUint64(0, true)) : null;
    default: return b;
  }
}

export class Value {
  constructor(hive, name, type, size, dataOff) { Object.assign(this, { hive, name, type, size, dataOff }); }
  get raw() { return this._raw || (this._raw = this.hive.valueData(this.size, this.dataOff)); }
  get data() { return decodeValue(this.type, this.raw); }
  get typeName() { return REG_TYPES[this.type] || `0x${this.type.toString(16)}`; }
  get text() {
    const d = this.data;
    if (d instanceof Uint8Array) {
      // binary that is really a UTF-16 string is common (e.g. Run values)
      return Array.from(d.subarray(0, 64), (x) => x.toString(16).padStart(2, '0')).join(' ') + (d.length > 64 ? ' …' : '');
    }
    return Array.isArray(d) ? d.join(' | ') : String(d);
  }
}

export class Key {
  constructor(hive, off, f) { this.hive = hive; this.off = off; Object.assign(this, f); }
  subkeys() {
    if (!this._subs) {
      this._subs = [];
      if (this.nSub && this.subOff !== 0xffffffff) {
        for (const o of this.hive.subkeyOffsets(this.subOff)) { try { this._subs.push(this.hive.key(o)); } catch { } }
      }
    }
    return this._subs;
  }
  values() {
    if (!this._vals) {
      this._vals = [];
      const r = this.hive.r;
      if (this.nVal && this.valOff !== 0xffffffff) {
        const lp = this.hive.cell(this.valOff);
        for (let i = 0; i < this.nVal; i++) {
          try {
            const vp = this.hive.cell(r.u32(lp + i * 4));
            if (!r.magic(vp, 'vk')) continue;
            const nl = r.u16(vp + 2), flags = r.u16(vp + 16);
            const name = nl ? ((flags & 1) ? latin1(r.bytes(vp + 20, nl)) : utf16(r.bytes(vp + 20, nl))) : '(default)';
            this._vals.push(new Value(this.hive, name, r.u32(vp + 12), r.u32(vp + 4), r.u32(vp + 8)));
          } catch { }
        }
      }
    }
    return this._vals;
  }
  value(name) { const n = name.toLowerCase(); return this.values().find((v) => v.name.toLowerCase() === n) || null; }
  get(name) { const v = this.value(name); return v ? v.data : undefined; }
  sub(name) { const n = name.toLowerCase(); return this.subkeys().find((k) => k.name.toLowerCase() === n) || null; }
  path(p) {
    let k = this;
    for (const part of p.split('\\').filter(Boolean)) { k = k.sub(part); if (!k) return null; }
    return k;
  }
  get className() {
    if (!this.classLen || this.classOff === 0xffffffff) return '';
    try { return utf16(this.hive.r.bytes(this.hive.cell(this.classOff), this.classLen)); } catch { return ''; }
  }
}

export function guessHiveType(hive, filename = '') {
  const fn = filename.toLowerCase().split(/[\\/]/).pop();
  const root = hive.key();
  const names = new Set(root.subkeys().map((k) => k.name.toLowerCase()));
  if (/amcache/.test(fn) || names.has('inventoryapplicationfile') || (root.sub('Root') && root.sub('Root').sub('InventoryApplicationFile'))) return 'AMCACHE';
  if (root.sub('Root') && (root.path('Root\\File') || root.path('Root\\Programs'))) return 'AMCACHE';
  if (/usrclass/.test(fn) || (names.has('local settings') && !names.has('software'))) return 'USRCLASS';
  if (/ntuser/.test(fn) || (names.has('software') && (names.has('environment') || names.has('control panel')))) return 'NTUSER';
  if (/^sam(\.|$)/.test(fn) || names.has('sam')) return 'SAM';
  if (/^security(\.|$)/.test(fn) || names.has('policy')) return 'SECURITY';
  if (/^system(\.|$)/.test(fn) || names.has('select') || [...names].some((n) => /^controlset00\d$/.test(n))) return 'SYSTEM';
  if (/^software(\.|$)/.test(fn) || (names.has('microsoft') && names.has('classes'))) return 'SOFTWARE';
  if (/^default(\.|$)/.test(fn)) return 'NTUSER';
  return 'UNKNOWN';
}
