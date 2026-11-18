// Random-access byte sources for disk images. Nothing here loads a whole image:
// a browser File is read with Blob.slice, a local path through the home server
// with HTTP range reads, and Node with fs.readSync. Reads go through a small
// block cache because NTFS walks touch the same clusters repeatedly.

const BLOCK = 1 << 20; // 1 MiB cache blocks
const CACHE_BLOCKS = 48;

export class Source {
  /** @param {number} size @param {(off:number,len:number)=>Promise<Uint8Array>} raw @param {string} name */
  constructor(size, raw, name = '') {
    this.size = size; this.name = name; this._raw = raw; this._cache = new Map();
  }
  async _block(i) {
    let b = this._cache.get(i);
    if (b) { this._cache.delete(i); this._cache.set(i, b); return b; }
    const off = i * BLOCK; const len = Math.min(BLOCK, this.size - off);
    b = len > 0 ? await this._raw(off, len) : new Uint8Array(0);
    this._cache.set(i, b);
    if (this._cache.size > CACHE_BLOCKS) this._cache.delete(this._cache.keys().next().value);
    return b;
  }
  /** Read len bytes at off. Past the end reads as zeros. */
  async read(off, len) {
    const out = new Uint8Array(len);
    if (len <= 0 || off >= this.size) return out;
    if (len > 8 * BLOCK) { // big sequential read: skip the cache
      const n = Math.min(len, this.size - off);
      out.set((await this._raw(off, n)).subarray(0, n));
      return out;
    }
    let pos = 0;
    while (pos < len && off + pos < this.size) {
      const abs = off + pos; const bi = Math.floor(abs / BLOCK); const inb = abs - bi * BLOCK;
      const b = await this._block(bi);
      const n = Math.min(len - pos, b.length - inb);
      if (n <= 0) break;
      out.set(b.subarray(inb, inb + n), pos); pos += n;
    }
    return out;
  }
}

export const fromBytes = (u8, name) => new Source(u8.length, async (o, l) => u8.subarray(o, o + l), name);

export const fromBlob = (blob, name) => new Source(blob.size, async (o, l) => new Uint8Array(await blob.slice(o, o + l).arrayBuffer()), name || blob.name);

/** Node: fs module + open file descriptor. */
export function fromFd(fs, fd, size, name) {
  return new Source(size, async (o, l) => { const b = new Uint8Array(l); let n = 0; while (n < l) { const r = fs.readSync(fd, b, n, l - n, o + n); if (!r) break; n += r; } return b; }, name);
}

/** Home install: a local image read through the companion server. */
export function fromHttp(url, size, name, headers = {}) {
  return new Source(size, async (o, l) => {
    const r = await fetch(`${url}${url.includes('?') ? '&' : '?'}off=${o}&len=${l}`, { headers });
    if (!r.ok) throw new Error(`image read failed (${r.status})`);
    return new Uint8Array(await r.arrayBuffer());
  }, name);
}

/** A window into another source (a partition). Uncached: the parent caches. */
export const slice = (src, off, size, name) => ({ size, name: name || src.name, read: async (o, l) => { const out = new Uint8Array(l); if (o < size) out.set(await src.read(off + o, Math.min(l, size - o))); return out; } });

/** Several sources back to back (split raw .001 .002 ...). */
export function concat(parts, name) {
  const starts = []; let total = 0;
  for (const p of parts) { starts.push(total); total += p.size; }
  return new Source(total, async (o, l) => {
    const out = new Uint8Array(l); let pos = 0;
    while (pos < l) {
      const abs = o + pos; let i = starts.length - 1; while (i > 0 && starts[i] > abs) i--;
      const p = parts[i]; const inp = abs - starts[i]; const n = Math.min(l - pos, p.size - inp);
      if (n <= 0) break;
      out.set(await p.read(inp, n), pos); pos += n;
    }
    return out;
  }, name);
}
