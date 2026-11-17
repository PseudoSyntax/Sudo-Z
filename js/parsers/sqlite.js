// Minimal read-only SQLite reader (table b-trees, overflow pages, record
// decoding). Powers the SQLECmd and WxTCmd equivalents with no WASM dependency.
import { Reader, utf8 } from '../core/bytes.js';

export const isSqlite = (u8) => u8.length >= 100 && new Reader(u8).magic(0, 'SQLite format 3\0');

function varint(u8, p) {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    const b = u8[p + i];
    v = (v << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) return [v, p + i + 1];
  }
  v = (v << 8n) | BigInt(u8[p + 8]);
  return [v, p + 9];
}
const vnum = (u8, p) => { const [v, q] = varint(u8, p); return [Number(v), q]; };

export class SqliteDb {
  constructor(u8) {
    this.u8 = u8; this.r = new Reader(u8);
    let ps = this.r.u16be(16); if (ps === 1) ps = 65536;
    this.pageSize = ps;
    this.usable = ps - u8[20];
    this.enc = this.r.u32be(56) || 1;
    this.td = this.enc === 1 ? new TextDecoder('utf-8') : new TextDecoder(this.enc === 2 ? 'utf-16le' : 'utf-16be');
    this.pageCount = Math.floor(u8.length / ps);
  }
  page(n) { const off = (n - 1) * this.pageSize; if (n < 1 || off + this.pageSize > this.u8.length) throw new Error(`page ${n} out of range`); return off; }

  // Iterate all rows of a table b-tree rooted at page `root`.
  *rows(root, depth = 0, seen = new Set()) {
    if (depth > 30 || seen.has(root)) return;
    seen.add(root);
    const u8 = this.u8, r = this.r;
    const base = this.page(root);
    const hdr = base + (root === 1 ? 100 : 0);
    const type = u8[hdr];
    const nCells = r.u16be(hdr + 3);
    if (type === 0x05) {
      for (let i = 0; i < nCells; i++) {
        const cp = base + r.u16be(hdr + 12 + i * 2);
        yield* this.rows(r.u32be(cp), depth + 1, seen);
      }
      yield* this.rows(r.u32be(hdr + 8), depth + 1, seen);
    } else if (type === 0x0d) {
      for (let i = 0; i < nCells; i++) {
        try {
          let cp = base + r.u16be(hdr + 8 + i * 2);
          let plen, rowid; [plen, cp] = vnum(u8, cp); [rowid, cp] = varint(u8, cp);
          yield { rowid: Number(rowid), values: this.record(this.payload(cp, plen)) };
        } catch { /* corrupt cell */ }
      }
    }
  }
  payload(p, P) {
    const U = this.usable, X = U - 35;
    if (P <= X) return this.u8.subarray(p, p + P);
    const M = Math.floor(((U - 12) * 32) / 255) - 23;
    const K = M + ((P - M) % (U - 4));
    const local = K <= X ? K : M;
    const out = new Uint8Array(P);
    out.set(this.u8.subarray(p, p + local));
    let w = local, ov = this.r.u32be(p + local);
    const seen = new Set();
    while (ov && w < P && !seen.has(ov)) {
      seen.add(ov);
      const o = this.page(ov);
      const take = Math.min(U - 4, P - w);
      out.set(this.u8.subarray(o + 4, o + 4 + take), w); w += take;
      ov = this.r.u32be(o);
    }
    return out;
  }
  record(b) {
    let [hl, p] = vnum(b, 0);
    const types = [];
    while (p < hl) { let t; [t, p] = vnum(b, p); types.push(t); }
    const vals = []; let q = hl;
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    for (const t of types) {
      if (t === 0) vals.push(null);
      else if (t >= 1 && t <= 6) {
        const n = [0, 1, 2, 3, 4, 6, 8][t];
        let v = 0n; for (let i = 0; i < n; i++) v = (v << 8n) | BigInt(b[q + i]);
        if (b[q] & 0x80) v -= 1n << BigInt(n * 8);
        vals.push(n > 6 ? (v > BigInt(Number.MAX_SAFE_INTEGER) || v < -BigInt(Number.MAX_SAFE_INTEGER) ? v.toString() : Number(v)) : Number(v));
        q += n;
      } else if (t === 7) { vals.push(dv.getFloat64(q, false)); q += 8; }
      else if (t === 8) vals.push(0);
      else if (t === 9) vals.push(1);
      else if (t >= 12 && t % 2 === 0) { const n = (t - 12) / 2; vals.push(b.subarray(q, q + n)); q += n; }
      else if (t >= 13) { const n = (t - 13) / 2; vals.push(this.td.decode(b.subarray(q, q + n))); q += n; }
      else vals.push(null);
    }
    return vals;
  }
  schema() {
    if (this._schema) return this._schema;
    const out = [];
    for (const row of this.rows(1)) {
      const [type, name, tbl, root, sql] = row.values;
      out.push({ type, name, tbl, root, sql: sql || '' });
    }
    return (this._schema = out);
  }
  columns(table) {
    const t = this.schema().find((s) => s.type === 'table' && s.name.toLowerCase() === table.toLowerCase());
    if (!t) return null;
    const body = t.sql.slice(t.sql.indexOf('(') + 1, t.sql.lastIndexOf(')'));
    const cols = []; let depth = 0, cur = '';
    for (const ch of body) {
      if (ch === '(') depth++; else if (ch === ')') depth--;
      if (ch === ',' && depth === 0) { cols.push(cur); cur = ''; } else cur += ch;
    }
    cols.push(cur);
    return cols.map((c) => c.trim()).filter((c) => c && !/^(primary|unique|check|foreign|constraint)\b/i.test(c))
      .map((c) => { const name = c.match(/^["`[]?([^"`\]\s]+)/)[1]; return { name, ipk: /integer\s+primary\s+key/i.test(c) }; });
  }
  /** Read a table as array of objects. */
  table(name, max = 500000) {
    const t = this.schema().find((s) => s.type === 'table' && s.name.toLowerCase() === name.toLowerCase());
    if (!t) return null;
    const cols = this.columns(name) || [];
    const out = [];
    for (const row of this.rows(t.root)) {
      const o = {};
      cols.forEach((c, i) => { o[c.name] = c.ipk && row.values[i] == null ? row.rowid : row.values[i]; });
      o._rowid = row.rowid;
      out.push(o);
      if (out.length >= max) break;
    }
    return out;
  }
  tables() { return this.schema().filter((s) => s.type === 'table').map((s) => s.name); }
}
