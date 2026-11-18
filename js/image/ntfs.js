// Read-only NTFS volume reader: boot sector -> $MFT -> every record -> paths ->
// file content (resident, non-resident, sparse, LZNT1 compressed, named streams).
// Built for pulling triage artifacts out of an image, not for writing.

const le16 = (b, o) => b[o] | (b[o + 1] << 8);
const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const le64 = (b, o) => le32(b, o) + le32(b, o + 4) * 2 ** 32;
const ref48 = (b, o) => le32(b, o) + (le16(b, o + 4)) * 2 ** 32;
const U16 = new TextDecoder('utf-16le');
const ftIso = (b, o) => { const v = le64(b, o); if (!v) return ''; const ms = v / 10000 - 11644473600000; return ms > 0 && ms < 4102444800000 ? new Date(ms).toISOString() : ''; };

/** LZNT1 (NTFS compression) for one compression unit. */
export function lznt1(src, outLen) {
  const out = new Uint8Array(outLen); let o = 0, i = 0;
  while (i + 2 <= src.length && o < outLen) {
    const h = le16(src, i); i += 2;
    if (!h) break;
    const size = (h & 0xfff) + 1; const end = Math.min(i + size, src.length);
    const chunkStart = o;
    if (!(h & 0x8000)) { const n = Math.min(size, outLen - o, end - i); out.set(src.subarray(i, i + n), o); o += n; i = end; continue; }
    while (i < end && o < outLen) {
      const flags = src[i++];
      for (let bit = 0; bit < 8 && i < end && o < outLen; bit++) {
        if (!(flags & (1 << bit))) { out[o++] = src[i++]; continue; }
        if (i + 2 > end) { i = end; break; }
        const t = le16(src, i); i += 2;
        let lenMask = 0xfff, shift = 12;
        for (let p = o - chunkStart - 1; p >= 0x10; p >>= 1) { lenMask >>= 1; shift--; }
        const disp = (t >> shift) + 1; let len = (t & lenMask) + 3;
        let from = o - disp; if (from < chunkStart) return out.subarray(0, o); // corrupt
        while (len-- > 0 && o < outLen) out[o++] = out[from++];
      }
    }
    i = end;
  }
  return out;
}

function fixup(rec, bps) {
  const usaOff = le16(rec, 4), usaCnt = le16(rec, 6);
  if (usaOff + usaCnt * 2 > rec.length) return false;
  const usn0 = rec[usaOff], usn1 = rec[usaOff + 1];
  for (let i = 1; i < usaCnt; i++) {
    const end = i * bps - 2; if (end + 1 >= rec.length) break;
    if (rec[end] !== usn0 || rec[end + 1] !== usn1) return false;
    rec[end] = rec[usaOff + i * 2]; rec[end + 1] = rec[usaOff + i * 2 + 1];
  }
  return true;
}

function decodeRuns(b, off, end, vcn = 0) {
  const runs = []; let lcn = 0;
  while (off < end && b[off]) {
    const h = b[off++]; const ls = h & 15, os = h >> 4;
    if (!ls || off + ls + os > end) break;
    let len = 0; for (let i = ls - 1; i >= 0; i--) len = len * 256 + b[off + i];
    off += ls;
    if (os) {
      let d = 0; for (let i = os - 1; i >= 0; i--) d = d * 256 + b[off + i];
      if (b[off + os - 1] & 0x80) d -= 2 ** (8 * os);
      lcn += d; runs.push({ vcn, lcn, len });
    } else runs.push({ vcn, lcn: null, len }); // sparse
    off += os; vcn += len;
  }
  return runs;
}

/** Parse one fixed-up MFT record into {flags, base, names[], si, streams{}} */
function parseRecord(rec) {
  const flags = le16(rec, 22); const base = ref48(rec, 32); const baseRaw = le64(rec, 32);
  const r = { flags, base, baseRaw, names: [], si: null, streams: {} };
  let off = le16(rec, 20); const used = Math.min(le32(rec, 24) || rec.length, rec.length);
  while (off + 16 <= used) {
    const type = le32(rec, off); if (type === 0xffffffff || !type) break;
    const len = le32(rec, off + 4); if (len < 16 || off + len > rec.length) break;
    const nonres = rec[off + 8]; const nlen = rec[off + 9]; const noff = le16(rec, off + 10); const aflags = le16(rec, off + 12);
    const name = nlen ? U16.decode(rec.subarray(off + noff, off + noff + nlen * 2)) : '';
    if (!nonres) {
      const cl = le32(rec, off + 16), co = le16(rec, off + 20); const c = rec.subarray(off + co, off + co + cl);
      if (type === 0x10 && c.length >= 32) r.si = { created: ftIso(c, 0), modified: ftIso(c, 8), mftModified: ftIso(c, 16), accessed: ftIso(c, 24) };
      else if (type === 0x30 && c.length >= 66) {
        const fl = c[64]; r.names.push({ parent: ref48(c, 0), ns: c[65], name: U16.decode(c.subarray(66, 66 + fl * 2)), created: ftIso(c, 8), modified: ftIso(c, 16), size: le64(c, 48) });
      } else if (type === 0x80) r.streams[name] = { resident: c.slice(), size: c.length, flags: aflags };
    } else if (type === 0x80) {
      const startVcn = le64(rec, off + 16); const runOff = le16(rec, off + 32); const cu = le16(rec, off + 34);
      const st = r.streams[name] || (r.streams[name] = { runs: [], size: 0, init: 0, alloc: 0, flags: aflags, cu });
      if (!startVcn) { st.alloc = le64(rec, off + 40); st.size = le64(rec, off + 48); st.init = le64(rec, off + 56); st.flags = aflags; st.cu = cu; }
      st.runs = st.runs || []; st.runs.push(...decodeRuns(rec, off + runOff, off + len, startVcn));
    }
    off += len;
  }
  return r;
}

export class Ntfs {
  /** @param vol Source-like ({size, read}) positioned at the volume start */
  constructor(vol) { this.vol = vol; }

  async open({ onProgress = () => {} } = {}) {
    const b = await this.vol.read(0, 512);
    this.bps = le16(b, 11) || 512;
    const spc = b[13]; this.cluster = this.bps * (spc > 128 ? 2 ** (256 - spc) : spc);
    const cpr = b[64] > 127 ? b[64] - 256 : b[64];
    this.recSize = cpr < 0 ? 2 ** -cpr : cpr * this.cluster;
    this.mftLcn = le64(b, 48);
    this.serial = le64(b, 72).toString(16).toUpperCase();
    // record 0 describes $MFT itself
    const r0 = await this.vol.read(this.mftLcn * this.cluster, this.recSize);
    if (String.fromCharCode(...r0.subarray(0, 4)) !== 'FILE' || !fixup(r0, this.bps)) throw new Error('$MFT record 0 is not readable (encrypted or damaged volume?)');
    const p0 = parseRecord(r0);
    let mftStream = p0.streams[''];
    if (!mftStream?.runs) throw new Error('$MFT has no data runs');
    // a heavily fragmented $MFT keeps more extents in extension records (listed in $ATTRIBUTE_LIST);
    // those records sit inside the first extent, so read what is mapped, fold them in, read again
    const isRec = (rec) => rec[0] === 0x46 && rec[1] === 0x49 && rec[2] === 0x4c && rec[3] === 0x45;
    let bytes = await this.readStream(mftStream, { max: 4 * 1024 ** 3 });
    let extra = 0;
    for (let i = 1; i < Math.min(Math.floor(bytes.length / this.recSize), 4096); i++) {
      const rec = bytes.slice(i * this.recSize, (i + 1) * this.recSize);
      if (!isRec(rec) || !fixup(rec, this.bps)) continue;
      const p = parseRecord(rec);
      if (p.baseRaw && p.base === 0 && p.streams['']?.runs) { mftStream.runs.push(...p.streams[''].runs); extra++; }
    }
    if (extra) { mftStream.runs.sort((a, b) => a.vcn - b.vcn); bytes = await this.readStream(mftStream, { max: 4 * 1024 ** 3 }); }
    this.mftBytes = bytes;
    const n = Math.floor(bytes.length / this.recSize);
    // parse every record
    this.recs = new Array(n);
    const ext = [];
    for (let i = 0; i < n; i++) {
      if (i % 20000 === 0) { onProgress(i / n); await new Promise((r) => setTimeout(r, 0)); }
      const rec = this.mftBytes.slice(i * this.recSize, (i + 1) * this.recSize);
      if (rec[0] !== 0x46 || rec[1] !== 0x49 || rec[2] !== 0x4c || rec[3] !== 0x45 || !fixup(rec, this.bps)) continue;
      const p = parseRecord(rec);
      if (p.baseRaw) { ext.push(p); continue; }
      this.recs[i] = p;
    }
    // merge extension records into their base record
    for (const p of ext) {
      const base = this.recs[Number(p.base % 2 ** 48)]; if (!base) continue;
      base.names.push(...p.names);
      for (const [k, s] of Object.entries(p.streams)) {
        const t = base.streams[k];
        if (!t) base.streams[k] = s;
        else if (s.runs && t.runs) { t.runs.push(...s.runs); if (!t.size && s.size) Object.assign(t, { size: s.size, init: s.init, alloc: s.alloc }); }
      }
    }
    for (const r of this.recs) if (r) for (const s of Object.values(r.streams)) if (s.runs) s.runs.sort((a, b) => a.vcn - b.vcn);
    this._paths = new Map();
    return this;
  }

  bestName(r) {
    return r.names.find((n) => n.ns === 1 || n.ns === 3) || r.names.find((n) => n.ns === 0) || r.names[0] || null;
  }

  /** Full path of record i ('' for root). */
  path(i, depth = 0) {
    if (i === 5) return '';
    if (this._paths.has(i)) return this._paths.get(i);
    const r = this.recs[i]; const n = r && this.bestName(r);
    if (!n || depth > 64) return null;
    const parent = Number(n.parent % 2 ** 48);
    const pp = parent === i ? null : this.path(parent, depth + 1);
    const p = pp == null ? `$OrphanFiles/${n.name}` : pp ? `${pp}/${n.name}` : n.name;
    this._paths.set(i, p);
    return p;
  }

  /** Iterate in-use records: {id, path, dir, size, si, streams} */
  *files() {
    for (let i = 0; i < this.recs.length; i++) {
      const r = this.recs[i]; if (!r || !(r.flags & 1)) continue;
      const p = this.path(i); if (p == null) continue;
      yield { id: i, path: p, dir: !!(r.flags & 2), size: r.streams['']?.size || 0, si: r.si, streams: r.streams };
    }
  }

  /** Read a stream. opts.max caps the bytes returned; opts.dropSparse removes sparse runs (for $UsnJrnl:$J). */
  async readStream(st, { max = Infinity, dropSparse = false } = {}) {
    if (st.resident) return st.resident.subarray(0, Math.min(st.resident.length, max));
    const cs = this.cluster; const size = Math.min(st.size, max);
    if (st.flags & 0x4000) throw new Error('EFS encrypted file');
    if (st.flags & 0x0001 && st.cu) return this._readCompressed(st, size);
    if (dropSparse) {
      const parts = []; let total = 0;
      for (const r of st.runs) {
        if (r.lcn == null) continue;
        const start = r.vcn * cs; if (start >= st.size) break;
        const n = Math.min(r.len * cs, st.size - start);
        parts.push(await this.vol.read(r.lcn * cs, n)); total += n;
        if (total >= max) break;
      }
      const out = new Uint8Array(Math.min(total, max)); let o = 0;
      for (const p of parts) { const n = Math.min(p.length, out.length - o); out.set(p.subarray(0, n), o); o += n; }
      return out;
    }
    const out = new Uint8Array(size);
    const initEnd = Math.min(st.init || st.size, size);
    for (const r of st.runs) {
      const start = r.vcn * cs; if (start >= initEnd) break;
      if (r.lcn == null) continue;
      const n = Math.min(r.len * cs, initEnd - start);
      out.set(await this.vol.read(r.lcn * cs, n), start);
    }
    return out;
  }

  async _readCompressed(st, size) {
    const cs = this.cluster; const unit = 2 ** st.cu; const ub = unit * cs;
    const out = new Uint8Array(size);
    // vcn -> lcn map
    const lcnAt = (v) => { for (const r of st.runs) if (v >= r.vcn && v < r.vcn + r.len) return r.lcn == null ? null : r.lcn + (v - r.vcn); return null; };
    for (let u = 0; u * ub < size; u++) {
      const v0 = u * unit; const allocated = [];
      for (let k = 0; k < unit; k++) { const l = lcnAt(v0 + k); if (l == null) break; allocated.push(l); }
      const want = Math.min(ub, size - u * ub);
      if (!allocated.length) continue; // all sparse = zeros
      const raw = new Uint8Array(allocated.length * cs);
      for (let k = 0; k < allocated.length;) { // read contiguous clusters together
        let j = k; while (j + 1 < allocated.length && allocated[j + 1] === allocated[j] + 1) j++;
        raw.set(await this.vol.read(allocated[k] * cs, (j - k + 1) * cs), k * cs); k = j + 1;
      }
      out.set(allocated.length === unit ? raw.subarray(0, want) : lznt1(raw, ub).subarray(0, want), u * ub);
    }
    return out;
  }
}
