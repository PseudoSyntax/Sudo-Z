// LZXpress Huffman decompression (MS-XCA 2.2.4). Needed for Windows 8.1+
// compressed Prefetch ("MAM\x04") and some other Windows artifacts.

function buildTable(lengths) {
  // Canonical Huffman -> 32768 entry direct lookup (15 bit max code length)
  const table = new Uint16Array(1 << 15);
  const lens = new Uint8Array(1 << 15);
  const syms = [];
  for (let s = 0; s < 512; s++) if (lengths[s]) syms.push(s);
  syms.sort((a, b) => lengths[a] - lengths[b] || a - b);
  let code = 0, prevLen = 0;
  for (const s of syms) {
    const L = lengths[s];
    code <<= (L - prevLen); prevLen = L;
    const start = code << (15 - L), count = 1 << (15 - L);
    if (start + count > 32768) throw new Error('bad huffman table');
    table.fill(s, start, start + count);
    lens.fill(L, start, start + count);
    code++;
  }
  return { table, lens };
}

export function lzxpressHuffmanDecompress(src, outSize) {
  const out = new Uint8Array(outSize);
  let op = 0, ip = 0;
  const rd16 = () => { const v = ip + 1 < src.length ? src[ip] | (src[ip + 1] << 8) : 0; ip += 2; return v; };
  while (op < outSize) {
    if (ip + 256 > src.length) break;
    const lengths = new Uint8Array(512);
    for (let i = 0; i < 256; i++) { lengths[i * 2] = src[ip + i] & 0x0f; lengths[i * 2 + 1] = src[ip + i] >> 4; }
    ip += 256;
    const { table, lens } = buildTable(lengths);
    let next = (rd16() << 16) >>> 0; next = (next | rd16()) >>> 0;
    let extra = 16;
    const refill = () => {
      if (extra < 0) { next = (next + (rd16() << (-extra))) >>> 0; extra += 16; }
    };
    const blockEnd = Math.min(op + 65536, outSize);
    while (op < blockEnd) {
      const idx = next >>> 17;
      const sym = table[idx], L = lens[idx];
      if (!L) throw new Error('invalid huffman code');
      next = (next << L) >>> 0; extra -= L; refill();
      if (sym < 256) { out[op++] = sym; continue; }
      const s = sym - 256;
      let len = s & 15; const obits = s >> 4;
      if (len === 15) {
        len = src[ip++];
        if (len === 255) {
          len = src[ip] | (src[ip + 1] << 8); ip += 2;
          if (len < 15) throw new Error('invalid match length');
          len -= 15;
        }
        len += 15;
      }
      len += 3;
      let off = obits ? (next >>> (32 - obits)) : 0;
      off += (1 << obits);
      next = obits ? (next << obits) >>> 0 : next; extra -= obits; refill();
      if (off > op) throw new Error('match offset before start of output');
      for (let i = 0; i < len && op < outSize; i++, op++) out[op] = out[op - off];
    }
  }
  return out;
}
