// Dependency free ZIP reader. Uses the platform DecompressionStream for
// DEFLATE so nothing is uploaded and no third party library is loaded.
import { Reader, latin1, utf8, filetimeToIso } from './bytes.js';

// MS-DOS date/time (local time, no zone, 2 second precision)
const dosTime = (t, d) => { if (!d) return ''; const y = 1980 + (d >> 9), mo = (d >> 5) & 15, da = d & 31, h = t >> 11, mi = (t >> 5) & 63, s = (t & 31) * 2; if (!mo || !da || mo > 12) return ''; return `${y}-${String(mo).padStart(2, '0')}-${String(da).padStart(2, '0')}T${String(h).padStart(2, '0')}:${String(mi).padStart(2, '0')}:${String(s).padStart(2, '0')}`; };

export const isZip = (u8) => u8.length > 22 && u8[0] === 0x50 && u8[1] === 0x4b && (u8[2] === 3 || u8[2] === 5) ;

async function inflateRaw(data) {
  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([data]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function findEocd(r) {
  const min = Math.max(0, r.length - 65557);
  for (let i = r.length - 22; i >= min; i--) {
    if (r.u8[i] === 0x50 && r.u8[i + 1] === 0x4b && r.u8[i + 2] === 5 && r.u8[i + 3] === 6) return i;
  }
  return -1;
}

/**
 * List and extract entries.
 * returns { entries: [{name, data|null, size, error?}] }
 */
export async function unzip(u8, { maxEntryBytes = 2 * 1024 ** 3 } = {}) {
  const r = new Reader(u8);
  const eocd = findEocd(r);
  if (eocd < 0) throw new Error('ZIP end of central directory not found (truncated or not a zip)');
  let count = r.u16(eocd + 10);
  let cdSize = r.u32(eocd + 12);
  let cdOff = r.u32(eocd + 16);
  // ZIP64
  if (cdOff === 0xffffffff || count === 0xffff) {
    const loc = eocd - 20;
    if (loc >= 0 && r.u32(loc) === 0x07064b50) {
      const z64 = r.u64n(loc + 8);
      if (r.u32(z64) === 0x06064b50) {
        count = r.u64n(z64 + 32);
        cdSize = r.u64n(z64 + 40);
        cdOff = r.u64n(z64 + 48);
      }
    }
  }
  const out = [];
  let p = cdOff;
  for (let i = 0; i < count; i++) {
    if (r.u32(p) !== 0x02014b50) break;
    const flags = r.u16(p + 8), method = r.u16(p + 10);
    const times = { dos: dosTime(r.u16(p + 12), r.u16(p + 14)), mtime: '', atime: '', ctime: '', zone: '' };
    let csize = r.u32(p + 20), usize = r.u32(p + 24);
    const nlen = r.u16(p + 28), xlen = r.u16(p + 30), clen = r.u16(p + 32);
    let lho = r.u32(p + 42);
    const nameBytes = r.bytes(p + 46, nlen);
    const name = (flags & 0x800) ? utf8(nameBytes) : latin1(nameBytes);
    // zip64 extra
    let x = p + 46 + nlen; const xe = x + xlen;
    while (x + 4 <= xe) {
      const id = r.u16(x), sz = r.u16(x + 2);
      if (id === 1) {
        let q = x + 4;
        if (usize === 0xffffffff) { usize = r.u64n(q); q += 8; }
        if (csize === 0xffffffff) { csize = r.u64n(q); q += 8; }
        if (lho === 0xffffffff) { lho = r.u64n(q); q += 8; }
      } else if (id === 0x000a && sz >= 32) { // NTFS extra: UTC FILETIMEs (7-Zip, WinRAR, Windows)
        let q = x + 8; const end = x + 4 + sz;
        while (q + 4 <= end) { const tag = r.u16(q), tsz = r.u16(q + 2); if (tag === 1 && tsz >= 24) { times.mtime = filetimeToIso(r.u64(q + 4)) || ''; times.atime = filetimeToIso(r.u64(q + 12)) || ''; times.ctime = filetimeToIso(r.u64(q + 20)) || ''; times.zone = 'UTC (NTFS extra)'; } q += 4 + tsz; }
      } else if (id === 0x5455 && sz >= 5 && !times.zone) { // extended timestamp: unix mtime (UTC)
        if (r.u8at(x + 4) & 1) { times.mtime = new Date(r.u32(x + 5) * 1000).toISOString(); times.zone = 'UTC (extended timestamp)'; }
      }
      x += 4 + sz;
    }
    p += 46 + nlen + xlen + clen;
    if (name.endsWith('/')) continue; // directory
    const ent = { name, size: usize, data: null, mtime: times.mtime || (times.dos ? times.dos : ''), times };
    try {
      if (flags & 1) throw new Error('encrypted (password protected) entry');
      if (usize > maxEntryBytes) throw new Error(`entry too large for in-browser analysis (${usize} bytes)`);
      if (r.u32(lho) !== 0x04034b50) throw new Error('bad local header');
      const dataStart = lho + 30 + r.u16(lho + 26) + r.u16(lho + 28);
      const comp = r.bytes(dataStart, csize);
      if (method === 0) ent.data = comp.slice();
      else if (method === 8) ent.data = await inflateRaw(comp);
      else throw new Error(`unsupported compression method ${method}${method === 99 ? ' (AES encrypted)' : ''}`);
    } catch (e) {
      ent.error = e.message;
    }
    out.push(ent);
  }
  return { entries: out };
}
