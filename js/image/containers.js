// Disk image containers -> one virtual disk Source.
// raw / dd / img, split raw (.001 .002 / .000 .001), VHD (fixed, dynamic),
// VHDX (fixed, dynamic) and EWF E01 (single or multi segment, zlib chunks).
// Differencing VHD/VHDX need their parent and are reported, not opened.
import { Source, concat } from './source.js';

const ascii = (b, o, n) => String.fromCharCode(...b.subarray(o, o + n));
const be32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const be64 = (b, o) => be32(b, o) * 2 ** 32 + be32(b, o + 4);
const le16 = (b, o) => b[o] | (b[o + 1] << 8);
const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const le64 = (b, o) => le32(b, o) + le32(b, o + 4) * 2 ** 32;
const guid = (b, o) => {
  const h = (i) => b[o + i].toString(16).padStart(2, '0');
  return `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`.toUpperCase();
};

export const IMAGE_EXT = /\.(e01|e\d\d|ex01|raw|dd|img|001|000|vhd|vhdx|qcow2?|bin|disk)$/i;

/** What kind of container is this? Returns {kind, ...} or null. */
export async function sniff(src) {
  const head = await src.read(0, 4096);
  if (ascii(head, 0, 8) === 'EVF\x09\x0d\x0a\xff\x00') return { kind: 'e01' };
  if (ascii(head, 0, 8) === 'LVF\x09\x0d\x0a\xff\x00') return { kind: 'l01', unsupported: 'EWF logical evidence (.L01) holds files, not a disk. Export the files and submit them.' };
  if (ascii(head, 0, 8) === 'vhdxfile') return { kind: 'vhdx' };
  if (ascii(head, 0, 4) === 'KDMV') return { kind: 'vmdk', unsupported: 'VMDK sparse extents are not read yet. Convert to raw (qemu-img convert -O raw) or VHD.' };
  if (ascii(head, 0, 4) === 'QFI\xfb') return { kind: 'qcow2' };
  if (src.size >= 512) {
    const foot = await src.read(src.size - 512, 512);
    if (ascii(foot, 0, 8) === 'conectix' || ascii(foot, 1, 8) === 'conectix') return { kind: 'vhd' };
    if (ascii(head, 0, 8) === 'conectix') return { kind: 'vhd' }; // dynamic disks copy the footer to the start
  }
  return { kind: 'raw' };
}

/** Open container(s) as a virtual disk. srcs = segments in order (E01..E02, .001..002) or one source. */
export async function openContainer(srcs, kind) {
  if (kind === 'vhd') return openVhd(srcs[0]);
  if (kind === 'vhdx') return openVhdx(srcs[0]);
  if (kind === 'e01') return openEwf(srcs);
  if (kind === 'qcow2') return openQcow2(srcs[0]);
  return { disk: srcs.length > 1 ? concat(srcs, srcs[0].name) : srcs[0], info: { format: srcs.length > 1 ? `split raw (${srcs.length} segments)` : 'raw' } };
}

// ---------------------------------------------------------------- VHD
async function openVhd(src) {
  let foot = await src.read(src.size - 512, 512);
  if (ascii(foot, 0, 8) !== 'conectix') { const f2 = await src.read(src.size - 511, 511); if (ascii(f2, 0, 8) === 'conectix') foot = f2; else foot = await src.read(0, 512); }
  const type = be32(foot, 60); const size = be64(foot, 48);
  if (type === 2) return { disk: new Source(size, (o, l) => src.read(o, l), src.name), info: { format: 'VHD (fixed)', size } };
  if (type === 4) throw new Error('Differencing VHD: it only holds changes against a parent disk. Submit a merged or fixed copy.');
  if (type !== 3) throw new Error(`Unknown VHD disk type ${type}`);
  const dyn = await src.read(be64(foot, 16), 1024);
  if (ascii(dyn, 0, 8) !== 'cxsparse') throw new Error('VHD dynamic header missing');
  const batOff = be64(dyn, 16); const entries = be32(dyn, 28); const block = be32(dyn, 32);
  const bat = await src.read(batOff, entries * 4);
  const bitmap = Math.ceil(block / 512 / 8 / 512) * 512;
  const disk = new Source(size, async (o, l) => {
    const out = new Uint8Array(l); let pos = 0;
    while (pos < l) {
      const abs = o + pos; const bi = Math.floor(abs / block); const inb = abs - bi * block; const n = Math.min(l - pos, block - inb);
      const sec = bi < entries ? be32(bat, bi * 4) : 0xffffffff;
      if (sec !== 0xffffffff) out.set(await src.read(sec * 512 + bitmap + inb, n), pos);
      pos += n;
    }
    return out;
  }, src.name);
  return { disk, info: { format: 'VHD (dynamic)', size, blockSize: block } };
}

// ---------------------------------------------------------------- VHDX
const G_BAT = '2DC27766-F623-4200-9D64-115E9BFD4A08';
const G_META = '8B7CA206-4790-4B9A-B8FE-575F050F886E';
const G_PARAMS = 'CAA16737-FA36-4D43-B3B6-33F0AA44E76B';
const G_SIZE = '2FA54224-CD1B-4876-B211-5DBED83BF4B8';
const G_LSS = '8141BF1D-A96F-4709-BA47-F233A8FAAB5F';
async function openVhdx(src) {
  let rt = await src.read(192 * 1024, 64 * 1024);
  if (ascii(rt, 0, 4) !== 'regi') rt = await src.read(256 * 1024, 64 * 1024);
  if (ascii(rt, 0, 4) !== 'regi') throw new Error('VHDX region table not found');
  const regions = {};
  for (let i = 0, n = le32(rt, 8); i < n; i++) { const e = 16 + i * 32; regions[guid(rt, e)] = { off: le64(rt, e + 16), len: le32(rt, e + 24) }; }
  if (!regions[G_BAT] || !regions[G_META]) throw new Error('VHDX BAT or metadata region missing');
  const meta = await src.read(regions[G_META].off, regions[G_META].len);
  if (ascii(meta, 0, 8) !== 'metadata') throw new Error('VHDX metadata header missing');
  const items = {};
  for (let i = 0, n = le16(meta, 10); i < n; i++) { const e = 32 + i * 32; items[guid(meta, e)] = le32(meta, e + 16); }
  const blockSize = le32(meta, items[G_PARAMS]); const flags = le32(meta, items[G_PARAMS] + 4);
  if (flags & 2) throw new Error('Differencing VHDX: it only holds changes against a parent disk. Submit a merged copy.');
  const size = le64(meta, items[G_SIZE]); const lss = items[G_LSS] != null ? le32(meta, items[G_LSS]) : 512;
  const chunkRatio = (2 ** 23 * lss) / blockSize;
  const bat = await src.read(regions[G_BAT].off, regions[G_BAT].len);
  const disk = new Source(size, async (o, l) => {
    const out = new Uint8Array(l); let pos = 0;
    while (pos < l) {
      const abs = o + pos; const bi = Math.floor(abs / blockSize); const inb = abs - bi * blockSize; const n = Math.min(l - pos, blockSize - inb);
      const idx = bi + Math.floor(bi / chunkRatio); const e = idx * 8;
      if (e + 8 <= bat.length) {
        const lo = le32(bat, e), hi = le32(bat, e + 4); const state = lo & 7;
        if (state === 6 || state === 7) { const mb = hi * 4096 + (lo >>> 20); out.set(await src.read(mb * 1048576 + inb, n), pos); }
      }
      pos += n;
    }
    return out;
  }, src.name);
  return { disk, info: { format: 'VHDX', size, blockSize, sectorSize: lss } };
}

// ---------------------------------------------------------------- EWF (E01)
async function inflate(u8) {
  const ds = new DecompressionStream('deflate');
  const stream = new Blob([u8]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function openEwf(segs) {
  // order segments by their segment number field
  const withNo = [];
  for (const s of segs) { const h = await s.read(0, 13); if (ascii(h, 0, 8) === 'EVF\x09\x0d\x0a\xff\x00') withNo.push({ s, no: le16(h, 9) }); }
  withNo.sort((a, b) => a.no - b.no);
  for (let i = 0; i < withNo.length; i++) if (withNo[i].no !== i + 1) throw new Error(`E01 segment ${i + 1} is missing. Submit every segment (.E01, .E02, ...) together.`);
  let chunkSize = 0, sectors = 0, bps = 512, expectedChunks = 0;
  const chunks = []; // {s, off, comp}
  const ends = [];   // end offset for the last chunk of each table
  const info = { format: `EWF E01 (${withNo.length} segment${withNo.length > 1 ? 's' : ''})` };
  for (const { s } of withNo) {
    let off = 13; let lastSectorsEnd = 0; let guard = 0;
    while (off + 76 <= s.size && guard++ < 100000) {
      const d = await s.read(off, 76); const type = ascii(d, 0, 16).replace(/\0.*$/, ''); const next = le64(d, 16); const size = le64(d, 24);
      if (type === 'volume' || type === 'disk') {
        const v = await s.read(off + 76, 94);
        expectedChunks = le32(v, 4); const spc = le32(v, 8); bps = le32(v, 12) || 512; sectors = le64(v, 16);
        chunkSize = spc * bps;
      } else if (type === 'sectors') {
        lastSectorsEnd = off + size;
      } else if (type === 'table') {
        const h = await s.read(off + 76, 24); const n = le32(h, 0); const baseOff = le64(h, 8);
        const t = await s.read(off + 76 + 24, n * 4);
        const first = chunks.length;
        for (let i = 0; i < n; i++) { const e = le32(t, i * 4); chunks.push({ s, off: baseOff + (e & 0x7fffffff), comp: !!(e & 0x80000000) }); }
        for (let i = first; i < chunks.length; i++) chunks[i].end = i + 1 < chunks.length ? chunks[i + 1].off : (lastSectorsEnd || off);
      } else if (type === 'header' && !info.header) {
        try { const raw = await s.read(off + 76, Math.min(size - 76, 65536)); info.header = new TextDecoder().decode(await inflate(raw)).replace(/\r/g, '').slice(0, 2000); } catch { }
      }
      if (type === 'done' || type === 'next' || !next || next <= off) break;
      off = next;
    }
  }
  if (!chunkSize || !chunks.length) throw new Error('E01: no volume or table section found');
  if (expectedChunks && chunks.length < expectedChunks) info.warning = `${expectedChunks - chunks.length} chunk(s) missing (segment missing or truncated); those sectors read as zeros.`;
  const size = sectors ? sectors * bps : chunks.length * chunkSize;
  info.size = size; info.chunkSize = chunkSize; info.bytesPerSector = bps;
  const disk = new Source(size, async (o, l) => {
    const out = new Uint8Array(l); let pos = 0;
    while (pos < l) {
      const abs = o + pos; const ci = Math.floor(abs / chunkSize); const inc = abs - ci * chunkSize; const n = Math.min(l - pos, chunkSize - inc);
      const c = chunks[ci];
      if (c) {
        const raw = await c.s.read(c.off, Math.max(0, Math.min(c.end - c.off, chunkSize + 4096)));
        let data;
        if (c.comp) { try { data = await inflate(raw); } catch (e) { throw new Error(`E01 chunk ${ci} failed to decompress: ${e.message}`); } }
        else data = raw.subarray(0, chunkSize);
        out.set(data.subarray(inc, inc + n), pos);
      }
      pos += n;
    }
    return out;
  }, segs[0].name);
  return { disk, info };
}

// ---------------------------------------------------------------- QCOW2 (KVM / QEMU / many CTF images)
async function openQcow2(src) {
  const h = await src.read(0, 112);
  const ver = be32(h, 4); const clusterBits = be32(h, 20); const size = be64(h, 24);
  if (be64(h, 8)) throw new Error('QCOW2 with a backing file: it only holds changes against another image. Convert with qemu-img convert -O raw.');
  if (be32(h, 32)) throw new Error('Encrypted QCOW2 image.');
  if (ver >= 3 && (be64(h, 72) & 0x8)) throw new Error('QCOW2 with zstd compression is not read. Convert with qemu-img convert -O raw.');
  const cs = 2 ** clusterBits; const l2n = cs / 8; const l1Size = be32(h, 36); const l1Off = be64(h, 40);
  const l1 = await src.read(l1Off, l1Size * 8);
  const MASK = 0x00fffffffffffe00n;
  const l2cache = new Map();
  const x = BigInt(62 - (clusterBits - 8));
  const cmap = new Map();
  const disk = new Source(size, async (o, l) => {
    const out = new Uint8Array(l); let pos = 0;
    while (pos < l) {
      const abs = o + pos; const ci = Math.floor(abs / cs); const inc = abs - ci * cs; const n = Math.min(l - pos, cs - inc);
      const i1 = Math.floor(ci / l2n), i2 = ci % l2n;
      const l1e = i1 < l1Size ? new DataView(l1.buffer, l1.byteOffset + i1 * 8, 8).getBigUint64(0) & MASK : 0n;
      if (l1e) {
        let l2 = l2cache.get(l1e);
        if (!l2) { l2 = await src.read(Number(l1e), cs); l2cache.set(l1e, l2); if (l2cache.size > 64) l2cache.delete(l2cache.keys().next().value); }
        const e = new DataView(l2.buffer, l2.byteOffset + i2 * 8, 8).getBigUint64(0);
        if (e & (1n << 62n)) { // compressed cluster (raw deflate)
          let data = cmap.get(ci);
          if (!data) {
            const hostOff = Number(e & ((1n << x) - 1n)); const sectors = Number((e >> x) & ((1n << (62n - x)) - 1n)) + 1;
            const raw = await src.read(hostOff, sectors * 512 - (hostOff & 511));
            data = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer().catch(() => new ArrayBuffer(cs)));
            cmap.set(ci, data); if (cmap.size > 256) cmap.delete(cmap.keys().next().value);
          }
          out.set(data.subarray(inc, inc + n), pos);
        } else if (!(e & 1n)) {
          const off = e & MASK; if (off) out.set(await src.read(Number(off) + inc, n), pos);
        }
      }
      pos += n;
    }
    return out;
  }, src.name);
  return { disk, info: { format: `QCOW2 v${ver}`, size, clusterSize: cs } };
}
