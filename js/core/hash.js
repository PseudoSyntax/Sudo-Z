// Hasher equivalent: MD5 (local implementation), SHA1 and SHA256 (WebCrypto).
import { hex } from './bytes.js';

const K = new Int32Array(64).map((_, i) => (Math.abs(Math.sin(i + 1)) * 2 ** 32) | 0);
const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

export function md5(u8) {
  const len = u8.length;
  const nBlocks = ((len + 8) >>> 6) + 1;
  const tail = new Uint8Array(nBlocks * 64 - Math.floor(len / 64) * 64);
  const fullBytes = Math.floor(len / 64) * 64;
  tail.set(u8.subarray(fullBytes));
  tail[len - fullBytes] = 0x80;
  const bits = len * 8;
  const tv = new DataView(tail.buffer);
  tv.setUint32(tail.length - 8, bits >>> 0, true);
  tv.setUint32(tail.length - 4, Math.floor(bits / 2 ** 32), true);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  const M = new Int32Array(16);
  const dvMain = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const block = (dv, off) => {
    for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
      else { F = C ^ (B | ~D); g = (7 * i) & 15; }
      const s = S[(i >> 4) * 4 + (i & 3)];
      F = (F + A + K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  };
  for (let off = 0; off < fullBytes; off += 64) block(dvMain, off);
  for (let off = 0; off < tail.length; off += 64) block(tv, off);
  const out = new Uint8Array(16); const ov = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((v, i) => ov.setInt32(i * 4, v, true));
  return hex(out);
}

export async function hashAll(u8) {
  const res = { md5: md5(u8) };
  if (globalThis.crypto?.subtle) {
    const [s1, s256] = await Promise.all([
      crypto.subtle.digest('SHA-1', u8),
      crypto.subtle.digest('SHA-256', u8),
    ]);
    res.sha1 = hex(new Uint8Array(s1));
    res.sha256 = hex(new Uint8Array(s256));
  }
  return res;
}
