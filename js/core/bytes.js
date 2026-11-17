// Sudo-Z byte helpers. Every parser reads through these so bounds errors
// surface as clean exceptions instead of silent garbage.

const TD_U16 = new TextDecoder('utf-16le', { fatal: false });
const TD_U8 = new TextDecoder('utf-8', { fatal: false });
const TD_LATIN1 = new TextDecoder('latin1');

export class Reader {
  constructor(u8, base = 0) {
    this.u8 = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
    this.dv = new DataView(this.u8.buffer, this.u8.byteOffset, this.u8.byteLength);
    this.base = base;
    this.length = this.u8.length;
  }
  check(o, n) {
    if (o < 0 || o + n > this.length) throw new RangeError(`read out of bounds @${o}+${n} (len ${this.length})`);
  }
  u8at(o) { this.check(o, 1); return this.u8[o]; }
  i8(o) { this.check(o, 1); return this.dv.getInt8(o); }
  u16(o) { this.check(o, 2); return this.dv.getUint16(o, true); }
  i16(o) { this.check(o, 2); return this.dv.getInt16(o, true); }
  u16be(o) { this.check(o, 2); return this.dv.getUint16(o, false); }
  u32(o) { this.check(o, 4); return this.dv.getUint32(o, true); }
  i32(o) { this.check(o, 4); return this.dv.getInt32(o, true); }
  u32be(o) { this.check(o, 4); return this.dv.getUint32(o, false); }
  u64(o) { this.check(o, 8); return this.dv.getBigUint64(o, true); }
  i64(o) { this.check(o, 8); return this.dv.getBigInt64(o, true); }
  u64n(o) { return Number(this.u64(o)); }
  f32(o) { this.check(o, 4); return this.dv.getFloat32(o, true); }
  f64(o) { this.check(o, 8); return this.dv.getFloat64(o, true); }
  bytes(o, n) { this.check(o, n); return this.u8.subarray(o, o + n); }
  sub(o, n) { return new Reader(this.bytes(o, n === undefined ? this.length - o : n), this.base + o); }
  ascii(o, n) { return latin1(this.bytes(o, n)); }
  asciiz(o, max = 4096) {
    let e = o; const lim = Math.min(this.length, o + max);
    while (e < lim && this.u8[e] !== 0) e++;
    return latin1(this.u8.subarray(o, e));
  }
  utf16(o, nChars) { return utf16(this.bytes(o, nChars * 2)); }
  utf16z(o, maxChars = 4096) {
    let e = o; const lim = Math.min(this.length - 1, o + maxChars * 2);
    while (e < lim && (this.u8[e] | this.u8[e + 1]) !== 0) e += 2;
    return utf16(this.u8.subarray(o, e));
  }
  filetime(o) { return filetimeToIso(this.u64(o)); }
  guid(o) { return guidStr(this.bytes(o, 16)); }
  magic(o, str) {
    if (o + str.length > this.length) return false;
    for (let i = 0; i < str.length; i++) if (this.u8[o + i] !== str.charCodeAt(i)) return false;
    return true;
  }
}

export const utf16 = (b) => TD_U16.decode(b).replace(/\0+$/, '');
export const utf8 = (b) => TD_U8.decode(b);
export const latin1 = (b) => TD_LATIN1.decode(b);

const EPOCH_DIFF = 116444736000000000n; // 1601 -> 1970 in 100ns ticks

export function filetimeToIso(ft) {
  if (typeof ft !== 'bigint') ft = BigInt(ft);
  if (ft === 0n || ft === 0xFFFFFFFFFFFFFFFFn) return null;
  const ms = Number((ft - EPOCH_DIFF) / 10000n);
  if (!isFinite(ms) || ms < -11644473600000 || ms > 32503680000000) return null; // 1601..3000
  const frac = Number((ft - EPOCH_DIFF) % 10000000n);
  const d = new Date(ms);
  if (isNaN(d)) return null;
  // keep 7 digit precision like the EZ tools do
  const f = String(frac < 0 ? frac + 10000000 : frac).padStart(7, '0');
  return d.toISOString().replace(/\.\d{3}Z$/, `.${f}Z`);
}

export function filetimeHasZeroFraction(ft) {
  if (typeof ft !== 'bigint') ft = BigInt(ft);
  return ft !== 0n && ft % 10000000n === 0n;
}

export function unixToIso(sec) {
  if (!sec || !isFinite(sec)) return null;
  const d = new Date(sec * 1000);
  return isNaN(d) ? null : d.toISOString();
}

export function webkitToIso(us) {
  // Chrome: microseconds since 1601
  if (!us) return null;
  const ms = Number(us) / 1000 - 11644473600000;
  const d = new Date(ms);
  return isNaN(d) || ms < 0 ? null : d.toISOString();
}

export function dosDateTime(date, time) {
  if (!date) return null;
  const y = ((date >> 9) & 0x7f) + 1980, m = (date >> 5) & 0xf, d = date & 0x1f;
  const hh = (time >> 11) & 0x1f, mm = (time >> 5) & 0x3f, ss = (time & 0x1f) * 2;
  if (m < 1 || m > 12 || d < 1) return null;
  const t = Date.UTC(y, m - 1, d, hh, mm, ss);
  return isNaN(t) ? null : new Date(t).toISOString();
}

export function guidStr(b) {
  const h = (i) => b[i].toString(16).padStart(2, '0');
  return `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`.toUpperCase();
}

export function hex(b, max = Infinity) {
  let s = '';
  const n = Math.min(b.length, max);
  for (let i = 0; i < n; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

export function startsWith(u8, arr, off = 0) {
  if (u8.length < off + arr.length) return false;
  for (let i = 0; i < arr.length; i++) if (u8[off + i] !== arr[i]) return false;
  return true;
}

export function indexOfBytes(u8, pat, from = 0) {
  const n = pat.length, first = pat[0];
  outer: for (let i = u8.indexOf(first, from); i !== -1 && i <= u8.length - n; i = u8.indexOf(first, i + 1)) {
    for (let j = 1; j < n; j++) if (u8[i + j] !== pat[j]) continue outer;
    return i;
  }
  return -1;
}

export const basename = (p) => (p || '').split(/[\\/]/).pop();
export const lc = (s) => (s || '').toLowerCase();
