// EvtxECmd equivalent: full EVTX chunk + Binary XML decoder with template
// caching. Output is a flat record object similar to EvtxECmd's CSV/JSON
// (EventId, Provider, Channel, Computer, TimeCreated, UserId, PayloadData).
import { Reader, filetimeToIso, guidStr, hex } from '../core/bytes.js';

const CHUNK = 0x10000;

export function isEvtx(u8) { return u8.length >= 8 && new Reader(u8).magic(0, 'ElfFile\0'); }

function sidStr(b) {
  if (b.length < 8) return hex(b);
  const rev = b[0], cnt = b[1];
  let auth = 0; for (let i = 2; i < 8; i++) auth = auth * 256 + b[i];
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let s = `S-${rev}-${auth}`;
  for (let i = 0; i < cnt && 8 + i * 4 + 4 <= b.length; i++) s += '-' + dv.getUint32(8 + i * 4, true);
  return s;
}

class ChunkParser {
  constructor(c) {
    this.c = c; // Reader over the 64KB chunk
    this.templates = new Map();
    this.names = new Map();
  }

  name(off) {
    let n = this.names.get(off);
    if (n === undefined) {
      const len = this.c.u16(off + 6);
      n = this.c.utf16(off + 8, len);
      this.names.set(off, n);
    }
    return n;
  }
  nameSize(off) { return 8 + this.c.u16(off + 6) * 2 + 2; }

  // Parse a token stream starting at p. Returns { nodes, p }.
  // Stops at EndElement (0x04, consumed by caller) or EOF (0x00) or end.
  content(p, end) {
    const c = this.c; const nodes = [];
    while (p < end) {
      const tok = c.u8at(p); const t = tok & 0x0f; // strip the 0x40 more-data flag
      if (tok === 0x00) { p += 1; break; }
      if (t === 0x04) break; // end element, caller consumes
      switch (t) {
        case 0x0f: p += 4; break; // fragment header
        case 0x01: { const r = this.element(p, end); nodes.push(r.node); p = r.p; break; }
        case 0x05: { const r = this.valueText(p); nodes.push(r.node); p = r.p; break; }
        case 0x0d: case 0x0e: nodes.push({ t: 'sub', id: c.u16(p + 1), type: c.u8at(p + 3), opt: t === 0x0e }); p += 4; break;
        case 0x08: nodes.push({ t: 'txt', v: String.fromCharCode(c.u16(p + 1)) }); p += 3; break;
        case 0x09: { const off = c.u32(p + 1); p += 5; if (off === p) p += this.nameSize(off); nodes.push({ t: 'txt', v: `&${this.name(off)};` }); break; }
        case 0x07: { const n = c.u16(p + 1); nodes.push({ t: 'txt', v: c.utf16(p + 3, n) }); p += 3 + n * 2; break; }
        case 0x0a: { const off = c.u32(p + 1); p += 5; if (off === p) p += this.nameSize(off); break; }
        case 0x0b: { const n = c.u16(p + 1); p += 3 + n * 2; break; }
        case 0x0c: { const r = this.templateInstance(p); nodes.push(r.node); p = r.p; break; }
        case 0x02: case 0x03: p += 1; break; // stray close tokens
        default: throw new Error(`unknown binxml token 0x${tok.toString(16)} @${p}`);
      }
    }
    return { nodes, p };
  }

  valueText(p) {
    const c = this.c; const type = c.u8at(p + 1); const n = c.u16(p + 2);
    if (type !== 1) throw new Error('non string value text');
    return { node: { t: 'txt', v: c.utf16(p + 4, n) }, p: p + 4 + n * 2 };
  }

  element(p, end) {
    const c = this.c; const tok = c.u8at(p);
    const nameOff = c.u32(p + 7);
    let q = p + 11;
    if (nameOff === q) q += this.nameSize(nameOff); // inline name
    if (tok & 0x40) q += 4; // attribute list size follows the name
    const node = { t: 'el', name: this.name(nameOff), attrs: [], kids: [] };
    if (tok & 0x40) {
      while (q < end && (c.u8at(q) & 0x0f) === 0x06) {
        const aOff = c.u32(q + 1); q += 5;
        if (aOff === q) q += this.nameSize(aOff);
        const val = [];
        while (q < end) {
          const vt = c.u8at(q) & 0x0f;
          if (vt === 0x05) { const r = this.valueText(q); val.push(r.node); q = r.p; }
          else if (vt === 0x0d || vt === 0x0e) { val.push({ t: 'sub', id: c.u16(q + 1), type: c.u8at(q + 3), opt: vt === 0x0e }); q += 4; }
          else if (vt === 0x08) { val.push({ t: 'txt', v: String.fromCharCode(c.u16(q + 1)) }); q += 3; }
          else if (vt === 0x09) { const off = c.u32(q + 1); q += 5; if (off === q) q += this.nameSize(off); val.push({ t: 'txt', v: `&${this.name(off)};` }); }
          else break;
        }
        node.attrs.push({ name: this.name(aOff), val });
      }
    }
    const close = c.u8at(q);
    if (close === 0x03) return { node, p: q + 1 };
    if (close !== 0x02) throw new Error(`expected close start element @${q}, got 0x${close.toString(16)}`);
    const r = this.content(q + 1, end);
    node.kids = r.nodes;
    q = r.p;
    if (q < end && (c.u8at(q) & 0x0f) === 0x04) q += 1;
    return { node, p: q };
  }

  templateDef(off) {
    let t = this.templates.get(off);
    if (!t) {
      const size = this.c.u32(off + 20);
      const start = off + 24;
      t = { nodes: this.content(start, start + size).nodes, size, guid: guidStr(this.c.bytes(off + 4, 16)) };
      this.templates.set(off, t);
    }
    return t;
  }

  templateInstance(p) {
    const c = this.c;
    const defOff = c.u32(p + 6);
    let q = p + 10;
    let tpl;
    if (defOff === q) { tpl = this.templateDef(defOff); q = defOff + 24 + tpl.size; }
    else tpl = this.templateDef(defOff);
    const n = c.u32(q); q += 4;
    const desc = [];
    for (let i = 0; i < n; i++) { desc.push({ size: c.u16(q), type: c.u8at(q + 2) }); q += 4; }
    const values = [];
    for (const d of desc) { values.push(this.value(q, d.size, d.type)); q += d.size; }
    return { node: { t: 'inst', tpl, values }, p: q };
  }

  value(p, size, type) {
    const c = this.c;
    if (size === 0) return { type, v: null };
    try {
      switch (type) {
        case 0x00: return { type, v: null };
        case 0x01: return { type, v: c.utf16(p, size >> 1).replace(/\0+$/, '') };
        case 0x02: return { type, v: c.ascii(p, size).replace(/\0+$/, '') };
        case 0x03: return { type, v: String(c.i8(p)) };
        case 0x04: return { type, v: String(c.u8at(p)) };
        case 0x05: return { type, v: String(c.i16(p)) };
        case 0x06: return { type, v: String(c.u16(p)) };
        case 0x07: return { type, v: String(c.i32(p)) };
        case 0x08: return { type, v: String(c.u32(p)) };
        case 0x09: return { type, v: String(c.i64(p)) };
        case 0x0a: return { type, v: String(c.u64(p)) };
        case 0x0b: return { type, v: String(c.f32(p)) };
        case 0x0c: return { type, v: String(c.f64(p)) };
        case 0x0d: return { type, v: c.u32(p) ? 'true' : 'false' };
        case 0x0e: return { type, v: hex(c.bytes(p, size)).toUpperCase() };
        case 0x0f: return { type, v: `{${guidStr(c.bytes(p, 16))}}` };
        case 0x10: return { type, v: '0x' + (size === 8 ? c.u64(p).toString(16) : c.u32(p).toString(16)).padStart(size * 2, '0') };
        case 0x11: return { type, v: filetimeToIso(c.u64(p)) };
        case 0x12: { const y = c.u16(p), mo = c.u16(p + 2), d = c.u16(p + 6), h = c.u16(p + 8), mi = c.u16(p + 10), s = c.u16(p + 12), ms = c.u16(p + 14); return { type, v: new Date(Date.UTC(y, mo - 1, d, h, mi, s, ms)).toISOString() }; }
        case 0x13: return { type, v: sidStr(c.bytes(p, size)) };
        case 0x14: return { type, v: '0x' + c.u32(p).toString(16).padStart(8, '0') };
        case 0x15: return { type, v: '0x' + c.u64(p).toString(16).padStart(16, '0') };
        case 0x21: return { type, v: null, nodes: this.content(p, p + size).nodes };
        case 0x81: return { type, v: c.utf16(p, size >> 1).split('\0').filter(Boolean).join(', ') };
        default:
          if (type & 0x80) {
            const base = type & 0x7f; const w = { 3: 1, 4: 1, 5: 2, 6: 2, 7: 4, 8: 4, 9: 8, 10: 8, 0x0f: 16, 0x14: 4, 0x15: 8, 0x11: 8 }[base];
            if (w) { const arr = []; for (let o = 0; o + w <= size; o += w) arr.push(this.value(p + o, w, base).v); return { type, v: arr.join(', ') }; }
          }
          return { type, v: hex(c.bytes(p, Math.min(size, 256))) };
      }
    } catch (e) { return { type, v: `<bad value: ${e.message}>` }; }
  }
}

// Render node tree (with substitutions) into plain {name, attrs:{}, kids:[...], text}
function render(nodes, values) {
  const out = [];
  for (const n of nodes) {
    if (n.t === 'txt') out.push(n.v);
    else if (n.t === 'sub') {
      const v = values && values[n.id];
      if (!v) continue;
      if (v.nodes) out.push(...render(v.nodes, null));
      else if (v.v !== null && v.v !== undefined) out.push(String(v.v));
    } else if (n.t === 'inst') out.push(...render(n.tpl.nodes, n.values));
    else if (n.t === 'el') {
      const attrs = {};
      for (const a of n.attrs) {
        const parts = render(a.val, values);
        if (parts.length || !a.val.some((x) => x.opt)) attrs[a.name] = parts.map((x) => (typeof x === 'string' ? x : '')).join('');
      }
      const el = { name: n.name, attrs, kids: render(n.kids, values) };
      // Optional substitution elements with no value are dropped (matches Windows rendering)
      const onlyOptSub = n.kids.length === 1 && n.kids[0].t === 'sub' && n.kids[0].opt && n.attrs.length === 0;
      if (onlyOptSub && el.kids.length === 0) continue;
      out.push(el);
    }
  }
  return out;
}

const textOf = (el) => el.kids.map((k) => (typeof k === 'string' ? k : textOf(k))).join('');
const child = (el, name) => el && el.kids.find((k) => typeof k !== 'string' && k.name === name);

function toRecord(root) {
  const ev = root.find((k) => typeof k !== 'string' && k.name === 'Event') || root.find((k) => typeof k !== 'string');
  if (!ev) return null;
  const sys = child(ev, 'System');
  const rec = { EventId: null, Provider: '', Channel: '', Computer: '', TimeCreated: null, Level: null, UserId: '', ProcessId: null, ThreadId: null, Data: {}, DataList: [], Keywords: '', Task: null };
  if (sys) {
    for (const k of sys.kids) {
      if (typeof k === 'string') continue;
      switch (k.name) {
        case 'Provider': rec.Provider = k.attrs.Name || k.attrs.EventSourceName || ''; break;
        case 'EventID': rec.EventId = parseInt(textOf(k), 10); break;
        case 'Level': rec.Level = parseInt(textOf(k), 10); break;
        case 'Task': rec.Task = parseInt(textOf(k), 10); break;
        case 'Keywords': rec.Keywords = textOf(k); break;
        case 'TimeCreated': rec.TimeCreated = k.attrs.SystemTime || null; break;
        case 'EventRecordID': rec.EventRecordId = textOf(k); break;
        case 'Execution': rec.ProcessId = k.attrs.ProcessID; rec.ThreadId = k.attrs.ThreadID; break;
        case 'Channel': rec.Channel = textOf(k); break;
        case 'Computer': rec.Computer = textOf(k); break;
        case 'Security': rec.UserId = k.attrs.UserID || ''; break;
      }
    }
  }
  const ed = child(ev, 'EventData');
  if (ed) {
    for (const d of ed.kids) {
      if (typeof d === 'string') continue;
      const v = textOf(d);
      if (d.attrs.Name) rec.Data[d.attrs.Name] = v; else rec.DataList.push(v);
    }
  }
  const ud = child(ev, 'UserData');
  if (ud) {
    const top = ud.kids.find((k) => typeof k !== 'string');
    if (top) {
      rec.UserDataName = top.name;
      const walk = (el, prefix) => {
        for (const k of el.kids) {
          if (typeof k === 'string') continue;
          if (k.kids.some((x) => typeof x !== 'string')) walk(k, prefix + k.name + '.');
          else rec.Data[prefix + k.name] = textOf(k);
        }
      };
      walk(top, '');
    }
  }
  return rec;
}

export function parseEvtx(u8, { maxRecords = 500000, onProgress } = {}) {
  const r = new Reader(u8);
  if (!isEvtx(u8)) throw new Error('not an EVTX file (missing ElfFile signature)');
  const hdrFlags = r.u32(0x78);
  const out = { records: [], errors: 0, errorSamples: [], chunks: 0, dirty: !!(hdrFlags & 1), full: !!(hdrFlags & 2) };
  for (let off = 0x1000; off + 0x200 <= u8.length; off += CHUNK) {
    if (!r.magic(off, 'ElfChnk\0')) continue;
    out.chunks++;
    const c = new Reader(u8.subarray(off, Math.min(off + CHUNK, u8.length)));
    const free = Math.min(c.u32(0x30), c.length);
    const cp = new ChunkParser(c);
    let p = 0x200;
    while (p + 24 < free) {
      if (c.u32(p) !== 0x00002a2a) break;
      const size = c.u32(p + 4);
      if (size < 28 || p + size > c.length) break;
      try {
        const nodes = cp.content(p + 24, p + size - 4).nodes;
        const rec = toRecord(render(nodes, null));
        if (rec) {
          rec.RecordNumber = Number(c.u64(p + 8));
          if (!rec.TimeCreated) rec.TimeCreated = filetimeToIso(c.u64(p + 16));
          out.records.push(rec);
        }
      } catch (e) {
        out.errors++;
        if (out.errorSamples.length < 5) out.errorSamples.push(`chunk@${off} rec@${p}: ${e.message}`);
      }
      p += size;
      if (out.records.length >= maxRecords) { out.truncated = true; return out; }
    }
    if (onProgress && out.chunks % 16 === 0) onProgress(off / u8.length);
  }
  return out;
}

/** One line payload like EvtxECmd's PayloadData columns. */
export function payloadString(rec, max = 600) {
  const parts = Object.entries(rec.Data).filter(([, v]) => v !== '' && v !== '-' && v != null).map(([k, v]) => `${k}: ${v}`);
  if (rec.DataList.length) parts.push(...rec.DataList.filter(Boolean));
  const s = parts.join(' | ');
  return s.length > max ? s.slice(0, max) + '…' : s;
}
