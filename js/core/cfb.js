// Minimal OLE Compound File Binary reader (used for automaticDestinations-ms).
import { Reader } from './bytes.js';

const SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
export const isCfb = (u8) => u8.length > 512 && SIG.every((b, i) => u8[i] === b);

export function readCfb(u8) {
  const r = new Reader(u8);
  const secSize = 1 << r.u16(0x1e), miniSize = 1 << r.u16(0x20);
  const nFat = r.u32(0x2c), dirStart = r.u32(0x30), cutoff = r.u32(0x38);
  const miniFatStart = r.u32(0x3c), nMiniFat = r.u32(0x40);
  let difatStart = r.u32(0x44); const nDifat = r.u32(0x48);
  const secOff = (s) => (s + 1) * secSize;
  const fatSecs = [];
  for (let i = 0; i < 109 && fatSecs.length < nFat; i++) fatSecs.push(r.u32(0x4c + i * 4));
  for (let d = 0; d < nDifat && difatStart < 0xfffffffa; d++) {
    const o = secOff(difatStart);
    for (let i = 0; i < secSize / 4 - 1 && fatSecs.length < nFat; i++) fatSecs.push(r.u32(o + i * 4));
    difatStart = r.u32(o + secSize - 4);
  }
  const fat = [];
  for (const s of fatSecs) { const o = secOff(s); for (let i = 0; i < secSize / 4 && o + i * 4 + 4 <= r.length; i++) fat.push(r.u32(o + i * 4)); }
  const chain = (start, table) => {
    const out = []; const seen = new Set();
    for (let s = start; s < 0xfffffffa && !seen.has(s) && s < table.length; s = table[s]) { seen.add(s); out.push(s); }
    return out;
  };
  const readChain = (start, size) => {
    const secs = chain(start, fat); const buf = new Uint8Array(secs.length * secSize);
    secs.forEach((s, i) => { const o = secOff(s); buf.set(u8.subarray(o, Math.min(o + secSize, u8.length)), i * secSize); });
    return size === undefined ? buf : buf.subarray(0, size);
  };
  const dirBuf = new Reader(readChain(dirStart));
  const entries = [];
  for (let o = 0; o + 128 <= dirBuf.length; o += 128) {
    const nl = dirBuf.u16(o + 64); const type = dirBuf.u8at(o + 66);
    if (!type) continue;
    entries.push({ name: dirBuf.utf16(o, Math.max(0, nl / 2 - 1)), type, start: dirBuf.u32(o + 116), size: dirBuf.u32(o + 120) });
  }
  const root = entries.find((e) => e.type === 5);
  const miniStream = root ? readChain(root.start, root.size) : new Uint8Array();
  const miniFat = [];
  if (nMiniFat) { const mf = new Reader(readChain(miniFatStart)); for (let i = 0; i + 4 <= mf.length; i += 4) miniFat.push(mf.u32(i)); }
  const streams = new Map();
  for (const e of entries) {
    if (e.type !== 2) continue;
    let data;
    if (e.size < cutoff) {
      const secs = chain(e.start, miniFat); data = new Uint8Array(secs.length * miniSize);
      secs.forEach((s, i) => data.set(miniStream.subarray(s * miniSize, s * miniSize + miniSize), i * miniSize));
      data = data.subarray(0, e.size);
    } else data = readChain(e.start, e.size);
    streams.set(e.name, data);
  }
  return streams;
}
