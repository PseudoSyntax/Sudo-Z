// PECmd equivalent: Windows Prefetch versions 17 (XP), 23 (Vista/7),
// 26 (8.x), 30/31 (10/11, MAM compressed).
import { Reader, filetimeToIso } from '../core/bytes.js';
import { lzxpressHuffmanDecompress } from '../core/lzxpress.js';

export function isPrefetch(u8) {
  const r = new Reader(u8);
  return (u8.length > 8 && r.magic(0, 'MAM') && (u8[3] === 0x04 || u8[3] === 0x84)) || (u8.length > 84 && r.magic(4, 'SCCA'));
}

export function parsePrefetch(u8) {
  let r = new Reader(u8);
  let compressed = false;
  if (r.magic(0, 'MAM')) {
    compressed = true;
    const size = r.u32(4);
    const dataOff = u8[3] === 0x84 ? 12 : 8; // 0x84 variant carries a CRC32
    u8 = lzxpressHuffmanDecompress(u8.subarray(dataOff), size);
    r = new Reader(u8);
  }
  if (!r.magic(4, 'SCCA')) throw new Error('missing SCCA signature after decompression');
  const version = r.u32(0);
  const out = { version, compressed, executable: r.utf16z(0x10, 30), hash: r.u32(0x4c).toString(16).toUpperCase().padStart(8, '0'), runTimes: [], runCount: 0, files: [], volumes: [] };
  const fnOff = r.u32(0x64), fnSize = r.u32(0x68), volOff = r.u32(0x6c), volCount = r.u32(0x70);
  if (version === 17) {
    out.runTimes.push(r.filetime(0x78)); out.runCount = r.u32(0x90);
  } else if (version === 23) {
    out.runTimes.push(r.filetime(0x80)); out.runCount = r.u32(0x98);
  } else if (version === 26 || version === 30 || version === 31) {
    for (let i = 0; i < 8; i++) out.runTimes.push(r.filetime(0x80 + i * 8));
    const metricsOff = r.u32(0x54);
    out.runCount = (version >= 30 && metricsOff === 0x128) ? r.u32(0xc8) : r.u32(0xd0);
  } else throw new Error(`unsupported prefetch version ${version}`);
  out.runTimes = out.runTimes.filter(Boolean);
  // referenced files (UTF-16 null separated)
  if (fnOff && fnSize && fnOff + fnSize <= r.length) {
    out.files = r.utf16(fnOff, fnSize >> 1).split('\0').filter(Boolean);
  }
  // volumes
  const entSize = version === 17 ? 40 : version === 30 || version === 31 ? 96 : 104;
  for (let i = 0; i < volCount && volOff + (i + 1) * entSize <= r.length; i++) {
    const e = volOff + i * entSize;
    const pOff = r.u32(e), pLen = r.u32(e + 4);
    out.volumes.push({
      device: pOff && volOff + pOff + pLen * 2 <= r.length ? r.utf16(volOff + pOff, pLen) : '',
      created: r.filetime(e + 8),
      serial: r.u32(e + 16).toString(16).toUpperCase().padStart(8, '0'),
    });
  }
  // the full path of the executable is usually inside the file list
  const exe = out.executable.toUpperCase();
  out.executablePath = out.files.find((f) => f.toUpperCase().endsWith('\\' + exe)) || null;
  return out;
}
