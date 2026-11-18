// Timestamps and risky features stored inside documents (ExifTool style).
// OOXML (docx/xlsx/pptx and macro variants), legacy OLE Office (doc/xls/ppt) and PDF.
import { Reader, latin1, utf8, filetimeToIso } from '../core/bytes.js';
import { unzip } from '../core/zip.js';
import { readCfb, isCfb } from '../core/cfb.js';

export const OOXML_EXT = /\.(docx|docm|dotx|dotm|xlsx|xlsm|xltx|xltm|xlsb|pptx|pptm|potx|potm|ppsx|ppsm)$/i;
export const OLE_EXT = /\.(doc|dot|xls|xlt|ppt|pps|pot)$/i;
export const isPdf = (u8) => { for (let i = 0; i < Math.min(1024, u8.length - 5); i++) if (u8[i] === 0x25 && u8[i + 1] === 0x50 && u8[i + 2] === 0x44 && u8[i + 3] === 0x46 && u8[i + 4] === 0x2d) return true; return false; };
export { isCfb };

const xmlText = (xml, tag) => { const m = xml.match(new RegExp(`<(?:[a-zA-Z]+:)?${tag}\\b[^>]*>([^<]*)</(?:[a-zA-Z]+:)?${tag}>`)); return m ? m[1].trim().replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'") : ''; };
const isoOrEmpty = (s) => { if (!s) return ''; const d = Date.parse(s); return isNaN(d) ? '' : new Date(d).toISOString(); };

/** OOXML: docProps/core.xml + app.xml, macros, external relationships (remote templates, linked objects). */
export async function parseOoxml(u8) {
  const { entries } = await unzip(u8, { maxEntryBytes: 64 * 1024 * 1024 });
  const get = (rx) => entries.find((e) => rx.test(e.name) && e.data);
  const core = get(/^docProps\/core\.xml$/i), app = get(/^docProps\/app\.xml$/i);
  const c = core ? utf8(core.data) : '', a = app ? utf8(app.data) : '';
  const out = {
    format: 'OOXML',
    created: isoOrEmpty(xmlText(c, 'created')), modified: isoOrEmpty(xmlText(c, 'modified')), printed: isoOrEmpty(xmlText(c, 'lastPrinted')),
    author: xmlText(c, 'creator'), lastBy: xmlText(c, 'lastModifiedBy'), title: xmlText(c, 'title'), revision: xmlText(c, 'revision'),
    app: [xmlText(a, 'Application'), xmlText(a, 'AppVersion')].filter(Boolean).join(' '), company: xmlText(a, 'Company'), template: xmlText(a, 'Template'), editMinutes: xmlText(a, 'TotalTime'),
    macros: entries.some((e) => /vbaProject\.bin$/i.test(e.name)), activeX: entries.some((e) => /activeX\d*\.(xml|bin)$/i.test(e.name)),
    oleObjects: entries.filter((e) => /\/embeddings\/oleObject\d*\.bin$/i.test(e.name)).length,
    external: [], entryTimes: [],
  };
  for (const e of entries) {
    if (e.mtime) out.entryTimes.push(e.mtime);
    if (!/\.rels$/i.test(e.name) || !e.data) continue;
    const x = utf8(e.data);
    for (const m of x.matchAll(/<Relationship\b[^>]*>/gi)) {
      const tag = m[0]; if (!/TargetMode\s*=\s*"External"/i.test(tag)) continue;
      const target = (tag.match(/Target\s*=\s*"([^"]*)"/i) || [])[1] || ''; const type = ((tag.match(/Type\s*=\s*"([^"]*)"/i) || [])[1] || '').split('/').pop();
      if (/^hyperlink$/i.test(type)) continue; // ordinary links
      out.external.push({ type, target: target.replace(/&amp;/g, '&'), part: e.name });
    }
  }
  return out;
}

// OLE property sets (\x05SummaryInformation): PIDs 4 author, 8 last author, 11 last printed, 12 created, 13 last saved, 18 application, 7 template, 10 edit time
function propSet(u8) {
  const r = new Reader(u8); const props = new Map();
  if (u8.length < 48 || r.u16(0) !== 0xfffe) return props;
  const off = r.u32(44); if (off + 8 > u8.length) return props;
  const n = Math.min(r.u32(off + 4), 256);
  for (let i = 0; i < n; i++) {
    const pid = r.u32(off + 8 + i * 8), po = off + r.u32(off + 12 + i * 8); if (po + 8 > u8.length) continue;
    const type = r.u32(po);
    if (type === 0x40) props.set(pid, r.u64(po + 4));
    else if (type === 0x1e) { const len = r.u32(po + 4); props.set(pid, latin1(u8.subarray(po + 8, Math.min(po + 8 + len, u8.length))).replace(/\0+$/, '')); }
    else if (type === 0x1f) { const len = r.u32(po + 4); props.set(pid, r.utf16(po + 8, Math.min(len, (u8.length - po - 8) >> 1)).replace(/\0+$/, '')); }
    else if (type === 3) props.set(pid, r.u32(po + 4));
  }
  return props;
}
export function parseOleDoc(u8) {
  const streams = readCfb(u8);
  const si = streams.get('\x05SummaryInformation');
  const p = si ? propSet(si) : new Map();
  const ft = (v) => (typeof v === 'bigint' ? filetimeToIso(v) || '' : '');
  const edit = p.get(10); const names = [...streams.keys()];
  return {
    format: 'OLE',
    created: ft(p.get(12)), modified: ft(p.get(13)), printed: ft(p.get(11)),
    author: p.get(4) || '', lastBy: p.get(8) || '', title: p.get(2) || '', revision: String(p.get(9) || ''), app: p.get(18) || '', template: p.get(7) || '', company: '',
    editMinutes: typeof edit === 'bigint' ? String(Number(edit / 600000000n)) : '',
    macros: names.some((n) => /^(_VBA_PROJECT|dir|PROJECT|VBA)$/i.test(n)) && names.some((n) => /^_VBA_PROJECT$/i.test(n)),
    activeX: names.some((n) => /^\x03OCXNAME$/i.test(n)), oleObjects: names.filter((n) => /^\x01Ole10Native$/i.test(n)).length,
    external: [], entryTimes: [],
  };
}

// PDF date: D:YYYYMMDDHHmmSSOHH'mm'
export function pdfDate(s) {
  const m = String(s).match(/^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?\s*([Zz+\-])?\s*(\d{2})?'?(\d{2})?'?/);
  if (!m) return '';
  const [, y, mo = '01', d = '01', h = '00', mi = '00', se = '00', z, oh = '00', om = '00'] = m;
  let t = Date.UTC(+y, +mo - 1, +d, +h, +mi, +se);
  if (z === '+' || z === '-') t -= (z === '+' ? 1 : -1) * ((+oh) * 60 + (+om)) * 60000;
  return isNaN(t) ? '' : new Date(t).toISOString();
}
const pdfStr = (s) => {
  if (!s) return '';
  if (s[0] === '<') { const hex = s.slice(1, -1).replace(/\s/g, ''); const b = (hex.match(/../g) || []).map((x) => parseInt(x, 16)); if (b[0] === 0xfe && b[1] === 0xff) { let o = ''; for (let i = 2; i + 1 < b.length; i += 2) o += String.fromCharCode((b[i] << 8) | b[i + 1]); return o; } return String.fromCharCode(...b); }
  let t = s.slice(1, -1).replace(/\\([()\\])/g, '$1');
  if (t.charCodeAt(0) === 0xfe && t.charCodeAt(1) === 0xff) { let o = ''; for (let i = 2; i + 1 < t.length; i += 2) o += String.fromCharCode((t.charCodeAt(i) << 8) | t.charCodeAt(i + 1)); return o; }
  return t;
};
export function parsePdfMeta(u8) {
  const cap = 16 * 1024 * 1024;
  const t = u8.length <= 2 * cap ? latin1(u8) : latin1(u8.subarray(0, cap)) + latin1(u8.subarray(u8.length - cap));
  const last = (key) => { const rx = new RegExp(`/${key}\\s*(\\((?:\\\\.|[^\\\\)])*\\)|<[0-9A-Fa-f\\s]*>)`, 'g'); let v = ''; for (const m of t.matchAll(rx)) v = m[1]; return pdfStr(v); };
  const first = (key) => { const m = t.match(new RegExp(`/${key}\\s*(\\((?:\\\\.|[^\\\\)])*\\)|<[0-9A-Fa-f\\s]*>)`)); return m ? pdfStr(m[1]) : ''; };
  const xmp = (tag) => { const m = t.match(new RegExp(`<xmp:${tag}>([^<]+)</xmp:${tag}>`)) || t.match(new RegExp(`xmp:${tag}="([^"]+)"`)); return m ? isoOrEmpty(m[1]) : ''; };
  const count = (rx) => (t.match(rx) || []).length;
  return {
    format: 'PDF',
    created: pdfDate(first('CreationDate')) || xmp('CreateDate'), modified: pdfDate(last('ModDate')) || xmp('ModifyDate'), printed: '',
    xmpCreated: xmp('CreateDate'), xmpModified: xmp('ModifyDate'),
    author: last('Author'), lastBy: '', title: last('Title'), revision: String(Math.max(0, count(/%%EOF/g) - 1)), app: [last('Creator'), last('Producer')].filter(Boolean).join(' / '), template: '', company: '', editMinutes: '',
    macros: false, activeX: false, oleObjects: 0,
    javascript: count(/\/(JavaScript|JS)\b/g), openAction: count(/\/(OpenAction|AA)\b/g), launch: count(/\/Launch\b/g), embedded: count(/\/EmbeddedFiles?\b/g), uris: count(/\/URI\b/g), objStm: count(/\/ObjStm\b/g),
    encrypted: /\/Encrypt\b/.test(t), external: [], entryTimes: [],
  };
}
