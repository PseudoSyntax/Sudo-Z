// RLA equivalent: replay registry transaction logs (.LOG / .LOG1 / .LOG2)
// into a dirty primary hive. Supports the old (DIRT bitmap, Vista-8) and new
// (HvLE entries, 8.1+) formats per msuhanov's regf specification.
import { Reader } from '../core/bytes.js';

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
/** Marvin32 (64-bit result) used for HvLE Hash-1 / Hash-2. */
export function marvin32(u8, seedLo = 0x7a4e55c5, seedHi = 0x82ef4d88) {
  let lo = seedLo >>> 0, hi = seedHi >>> 0;
  const blk = () => {
    hi = (hi ^ lo) >>> 0; lo = rotl(lo, 20); lo = (lo + hi) >>> 0; hi = rotl(hi, 9);
    hi = (hi ^ lo) >>> 0; lo = rotl(lo, 27); lo = (lo + hi) >>> 0; hi = rotl(hi, 19);
  };
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  let i = 0;
  for (; i + 4 <= u8.length; i += 4) { lo = (lo + dv.getUint32(i, true)) >>> 0; blk(); }
  const rem = u8.length & 3;
  let fin = 0x80;
  if (rem === 1) fin = 0x8000 | u8[i];
  else if (rem === 2) fin = 0x800000 | u8[i] | (u8[i + 1] << 8);
  else if (rem === 3) fin = (0x80000000 | u8[i] | (u8[i + 1] << 8) | (u8[i + 2] << 16)) >>> 0;
  lo = (lo + fin) >>> 0; blk(); blk();
  return (BigInt(hi) << 32n) | BigInt(lo);
}

export function baseBlockChecksum(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, 512);
  let x = 0;
  for (let i = 0; i < 508; i += 4) x = (x ^ dv.getUint32(i, true)) >>> 0;
  if (x === 0) x = 1; else if (x === 0xffffffff) x = 0xfffffffe;
  return x;
}

export const isRegLog = (u8) => u8.length >= 512 && new Reader(u8).magic(0, 'regf') && [1, 2, 6].includes(new Reader(u8).u32(0x1c));

function logInfo(u8) {
  const r = new Reader(u8);
  return { type: r.u32(0x1c), seq1: r.u32(4), seq2: r.u32(8), lastWritten: r.u64(12), hbins: r.u32(0x28), newFormat: r.u32(0x1c) === 6 || r.magic(512, 'HvLE') };
}

function newEntries(u8) {
  const r = new Reader(u8); const out = [];
  for (let p = 512; p + 40 <= u8.length;) {
    if (!r.magic(p, 'HvLE')) break;
    const size = r.u32(p + 4);
    if (size < 40 || size % 512 || p + size > u8.length) break;
    const e = { off: p, size, flags: r.u32(p + 8), seq: r.u32(p + 12), hbins: r.u32(p + 16), count: r.u32(p + 20), h1: r.u64(p + 24), h2: r.u64(p + 32) };
    e.valid = e.hbins % 4096 === 0 && marvin32(u8.subarray(p + 40, p + size)) === e.h1 && marvin32(u8.subarray(p, p + 32)) === e.h2;
    out.push(e);
    p += size;
  }
  return out;
}

/**
 * Replay logs into a dirty hive.
 * @returns {data:Uint8Array, applied:number, notes:string[]}
 */
export function replayHive(hive, logs) {
  const notes = [];
  const hr = new Reader(hive);
  const primarySeq = hr.u32(4), secondarySeq = hr.u32(8);
  const checksumOk = baseBlockChecksum(hive) === hr.u32(0x1fc);
  if (primarySeq === secondarySeq && checksumOk) return { data: hive, applied: 0, notes: ['Hive is clean; transaction logs not needed.'] };
  let buf = new Uint8Array(hive.length); buf.set(hive);
  const ensure = (len) => { if (buf.length < len) { const n = new Uint8Array(len); n.set(buf); buf = n; } };
  const valid = logs.filter((l) => l.data.length >= 1024);
  const infos = valid.map((l) => ({ ...l, info: logInfo(l.data) }));
  let applied = 0, lastSeq = null, flags = null, hbins = hr.u32(0x28);

  if (infos.some((l) => l.info.newFormat)) {
    // New format: apply entries from both logs in sequence order, starting at the earliest log's base block sequence
    const lists = infos.filter((l) => l.info.newFormat).map((l) => ({ name: l.name, start: l.info.seq1, entries: newEntries(l.data), data: l.data }))
      .filter((l) => l.entries.length).sort((a, b) => a.start - b.start);
    let expect = null;
    for (const l of lists) {
      for (const e of l.entries) {
        if (expect === null) {
          if (e.seq !== l.start || e.seq < secondarySeq) continue; // old entries
          expect = e.seq;
        }
        if (e.seq < expect) continue; // already applied
        if (e.seq !== expect) break;
        if (!e.valid) { notes.push(`${l.name}: log entry seq ${e.seq} failed hash check; recovery stops there.`); break; }
        ensure(4096 + e.hbins);
        let p = e.off + 40 + e.count * 8;
        const r = new Reader(l.data);
        for (let i = 0; i < e.count; i++) {
          const po = r.u32(e.off + 40 + i * 8), ps = r.u32(e.off + 44 + i * 8);
          ensure(4096 + po + ps);
          buf.set(l.data.subarray(p, p + ps), 4096 + po);
          p += ps;
        }
        hbins = e.hbins; flags = e.flags & 1; lastSeq = e.seq; applied++; expect = e.seq + 1;
      }
    }
    if (buf.length > 4096 + hbins) buf = buf.subarray(0, 4096 + hbins);
  } else {
    // Old format: first applicable log (matching Last written timestamp) wins, LOG1 preferred
    const cand = infos.filter((l) => l.info.seq1 === l.info.seq2 && new Reader(l.data).magic(512, 'DIRT'))
      .sort((a, b) => (/\.log2$/i.test(a.name) ? 1 : 0) - (/\.log2$/i.test(b.name) ? 1 : 0));
    const pick = cand.find((l) => l.info.lastWritten === hr.u64(12)) || (!checksumOk ? cand[0] : null);
    if (!pick) notes.push('No old-format log with a matching timestamp; hive used as is.');
    else {
      const d = pick.data; const bits = Math.floor(hbins / 512);
      const bmBytes = Math.ceil(bits / 8);
      let pageOff = Math.ceil((512 + 4 + bmBytes) / 512) * 512;
      for (let b = 0; b < bits; b++) {
        if (!((d[516 + (b >> 3)] >> (b & 7)) & 1)) continue;
        if (pageOff + 512 > d.length) { notes.push(`${pick.name}: truncated dirty pages.`); break; }
        ensure(4096 + b * 512 + 512);
        buf.set(d.subarray(pageOff, pageOff + 512), 4096 + b * 512);
        pageOff += 512; applied++;
      }
      lastSeq = pick.info.seq1;
    }
  }
  if (applied) {
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    if (lastSeq !== null) { dv.setUint32(4, lastSeq, true); dv.setUint32(8, lastSeq, true); }
    dv.setUint32(0x28, hbins, true);
    if (flags !== null) dv.setUint32(0x90, (dv.getUint32(0x90, true) & ~1) | flags, true);
    dv.setUint32(0x1fc, baseBlockChecksum(buf), true);
    notes.push(`Replayed ${applied} ${infos.some((l) => l.info.newFormat) ? 'log entr' + (applied === 1 ? 'y' : 'ies') : 'dirty page' + (applied === 1 ? '' : 's')} from ${valid.map((l) => l.name.split(/[\\/]/).pop()).join(', ')} (RLA equivalent).`);
  } else if (!notes.length) notes.push('Transaction logs held no applicable entries.');
  return { data: buf, applied, notes };
}
