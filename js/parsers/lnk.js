// LECmd equivalent: Windows Shell Link (.lnk) parser.
import { Reader, filetimeToIso, guidStr, hex } from '../core/bytes.js';
import { parseIdList, idListPath } from './shellitems.js';

const LNK_HDR = [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
export function isLnk(u8, off = 0) {
  if (u8.length < off + 0x4c) return false;
  for (let i = 0; i < LNK_HDR.length; i++) if (u8[off + i] !== LNK_HDR[i]) return false;
  return true;
}
export const LNK_SIG = LNK_HDR;

const DRIVE_TYPES = ['Unknown', 'No root dir', 'Removable', 'Fixed', 'Network', 'CD-ROM', 'RAM disk'];

export function parseLnk(u8) {
  const r = new Reader(u8);
  if (!isLnk(u8)) throw new Error('not a shell link (bad header)');
  const flags = r.u32(0x14);
  const out = {
    flags, fileAttributes: r.u32(0x18),
    targetCreated: r.filetime(0x1c), targetAccessed: r.filetime(0x24), targetModified: r.filetime(0x2c),
    fileSize: r.u32(0x34), showCmd: r.u32(0x3c),
    idList: [], localPath: '', networkPath: '', volume: null,
    name: '', relativePath: '', workingDir: '', arguments: '', iconLocation: '',
    tracker: null, envTarget: '', knownFolder: null,
  };
  let p = 0x4c;
  if (flags & 0x1) {
    const sz = r.u16(p);
    out.idList = parseIdList(r, p + 2, p + 2 + sz);
    out.idListPath = idListPath(out.idList);
    p += 2 + sz;
  }
  if (flags & 0x2) {
    const li = p, liSize = r.u32(li), hdrSize = r.u32(li + 4), liFlags = r.u32(li + 8);
    try {
      if (liFlags & 1) {
        const vOff = li + r.u32(li + 12);
        const vSize = r.u32(vOff);
        const lblOff = r.u32(vOff + 12);
        let label = '';
        if (lblOff === 0x14) label = r.utf16z(vOff + r.u32(vOff + 16), 64); else if (lblOff < vSize) label = r.asciiz(vOff + lblOff, 64);
        out.volume = { driveType: DRIVE_TYPES[r.u32(vOff + 4)] || String(r.u32(vOff + 4)), serial: r.u32(vOff + 8).toString(16).toUpperCase().padStart(8, '0'), label };
        out.localPath = hdrSize >= 0x24 && r.u32(li + 28) ? r.utf16z(li + r.u32(li + 28)) : r.asciiz(li + r.u32(li + 16));
      }
      if (liFlags & 2) {
        const c = li + r.u32(li + 20);
        out.networkPath = r.asciiz(c + r.u32(c + 8));
        const devOff = r.u32(c + 12);
        if (devOff) out.networkDevice = r.asciiz(c + devOff, 32);
      }
      const suffix = hdrSize >= 0x24 && r.u32(li + 32) ? r.utf16z(li + r.u32(li + 32)) : r.asciiz(li + r.u32(li + 24));
      if (suffix) {
        if (out.networkPath) out.networkPath = out.networkPath.replace(/\\$/, '') + '\\' + suffix;
        else if (out.localPath) out.localPath += suffix;
      }
    } catch (e) { out.linkInfoError = e.message; }
    p += liSize;
  }
  const uni = !!(flags & 0x80);
  const readStr = () => {
    const n = r.u16(p); p += 2;
    const s = uni ? r.utf16(p, n) : r.ascii(p, n);
    p += uni ? n * 2 : n; return s;
  };
  if (flags & 0x04) out.name = readStr();
  if (flags & 0x08) out.relativePath = readStr();
  if (flags & 0x10) out.workingDir = readStr();
  if (flags & 0x20) out.arguments = readStr();
  if (flags & 0x40) out.iconLocation = readStr();
  // Extra data blocks
  try {
    while (p + 8 <= r.length) {
      const bs = r.u32(p); if (bs < 4) break;
      const sig = r.u32(p + 4);
      if (p + bs > r.length) break;
      if (sig === 0xa0000003 && bs >= 0x60) {
        const fileDroid = r.bytes(p + 48, 16);
        out.tracker = {
          machineId: r.asciiz(p + 16, 16),
          volumeDroid: guidStr(r.bytes(p + 32, 16)),
          fileDroid: guidStr(fileDroid),
          macAddress: hex(fileDroid.subarray(10, 16)).match(/../g).join(':'),
          birthVolumeDroid: guidStr(r.bytes(p + 64, 16)),
          birthFileDroid: guidStr(r.bytes(p + 80, 16)),
        };
      } else if (sig === 0xa0000001 && bs >= 0x314) {
        out.envTarget = r.utf16z(p + 268, 260) || r.asciiz(p + 8, 260);
      } else if (sig === 0xa000000b && bs >= 0x1c) {
        out.knownFolder = guidStr(r.bytes(p + 8, 16));
      }
      p += bs;
    }
  } catch { /* extra data is best effort */ }
  out.target = out.localPath || out.networkPath || out.envTarget || out.idListPath || out.relativePath || '';
  out.commandLine = (out.target + (out.arguments ? ' ' + out.arguments : '')).trim();
  return out;
}
