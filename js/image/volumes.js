// Partition tables (MBR with extended partitions, GPT) and file system sniffing.
import { slice } from './source.js';

const ascii = (b, o, n) => String.fromCharCode(...b.subarray(o, o + n));
const le16 = (b, o) => b[o] | (b[o + 1] << 8);
const le32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const le64 = (b, o) => le32(b, o) + le32(b, o + 4) * 2 ** 32;
const guid = (b, o) => {
  const h = (i) => b[o + i].toString(16).padStart(2, '0');
  return `${h(3)}${h(2)}${h(1)}${h(0)}-${h(5)}${h(4)}-${h(7)}${h(6)}-${h(8)}${h(9)}-${h(10)}${h(11)}${h(12)}${h(13)}${h(14)}${h(15)}`.toUpperCase();
};
const GPT_TYPES = {
  'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7': 'Basic data', 'C12A7328-F81F-11D2-BA4B-00A0C93EC93B': 'EFI system', 'E3C9E316-0B5C-4DB8-817D-F92DF00215AE': 'Microsoft reserved',
  'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC': 'Windows recovery', '5808C8AA-7E8F-42E0-85D2-E1E90434CFB3': 'LDM metadata', 'AF9B60A0-1431-4F62-BC68-3311714A69AD': 'LDM data',
  '0FC63DAF-8483-4772-8E79-3D69D8477DE4': 'Linux data', 'E6D6D379-F507-44C2-A23C-238F2A3DF928': 'Linux LVM',
};

/** File system of the volume starting at byte off. */
export async function fsType(src, off = 0) {
  const b = await src.read(off, 4096);
  if (ascii(b, 3, 8) === 'NTFS    ') return 'NTFS';
  if (ascii(b, 3, 8) === '-FVE-FS-') return 'BitLocker';
  if (ascii(b, 3, 8) === 'MSWIN4.1' && guid(b, 0x1a8) === '4967D63B-2E29-4AD8-8399-F6A339E3D001') return 'BitLocker';
  if (ascii(b, 3, 8) === 'EXFAT   ') return 'exFAT';
  if (ascii(b, 0x52, 5) === 'FAT32' || ascii(b, 0x36, 3) === 'FAT') return 'FAT';
  if (ascii(b, 0, 8) === 'LUKS\xba\xbe\x00\x01' || ascii(b, 0, 6) === 'LUKS\xba\xbe') return 'LUKS';
  if (ascii(b, 3, 8) === 'ReFS\x00\x00\x00\x00') return 'ReFS';
  const sb = await src.read(off + 1024, 128);
  if (le16(sb, 56) === 0xef53) return 'ext';
  if (ascii(sb, 0, 2) === 'H+' || ascii(sb, 0, 2) === 'HX') return 'HFS+';
  if (ascii(b, 32, 4) === 'NXSB') return 'APFS';
  if (ascii(b, 0, 4) === 'XFSB') return 'XFS';
  return null;
}

/** List volumes: [{index, start, size, scheme, type, fs, name}] */
export async function listVolumes(disk) {
  const vols = [];
  const s0 = await disk.read(0, 512);
  const fs0 = await fsType(disk, 0);
  if (fs0 && fs0 !== 'FAT' || fs0 === 'FAT' && !(s0[446 + 4] && le32(s0, 446 + 8) && le32(s0, 446 + 12) && le32(s0, 446 + 8) < disk.size / 512)) return [{ index: 0, start: 0, size: disk.size, scheme: 'none (volume image)', type: '', fs: fs0 }];
  // GPT (512 or 4096 byte sectors)
  for (const ss of [512, 4096]) {
    const h = await disk.read(ss, 512);
    if (ascii(h, 0, 8) !== 'EFI PART') continue;
    const lba = le64(h, 72), n = Math.min(le32(h, 80), 512), es = le32(h, 84) || 128;
    const t = await disk.read(lba * ss, n * es);
    for (let i = 0; i < n; i++) {
      const e = i * es; const type = guid(t, e);
      if (type === '00000000-0000-0000-0000-000000000000') continue;
      const first = le64(t, e + 32), last = le64(t, e + 40);
      const name = new TextDecoder('utf-16le').decode(t.subarray(e + 56, e + 128)).replace(/\0.*$/, '');
      const start = first * ss, size = (last - first + 1) * ss;
      vols.push({ index: vols.length + 1, start, size, scheme: 'GPT', type: GPT_TYPES[type] || type, name, fs: await fsType(disk, start) });
    }
    return vols;
  }
  if (s0[510] === 0x55 && s0[511] === 0xaa) {
    const prim = (sec, base) => [0, 1, 2, 3].map((i) => { const e = 446 + i * 16; return { type: sec[e + 4], lba: le32(sec, e + 8) + base, count: le32(sec, e + 12) }; }).filter((p) => p.type && p.count);
    const parts = prim(s0, 0);
    if (parts.some((p) => p.type === 0xee)) return vols; // protective MBR without a readable GPT
    for (const p of parts) {
      if ([0x05, 0x0f, 0x85].includes(p.type)) { // extended: walk the EBR chain
        let ebr = p.lba; let guard = 0;
        while (ebr && guard++ < 128) {
          const s = await disk.read(ebr * 512, 512); if (s[510] !== 0x55 || s[511] !== 0xaa) break;
          const [l, nx] = [0, 1].map((i) => { const e = 446 + i * 16; return { type: s[e + 4], lba: le32(s, e + 8), count: le32(s, e + 12) }; });
          if (l.type && l.count) { const start = (ebr + l.lba) * 512; vols.push({ index: vols.length + 1, start, size: l.count * 512, scheme: 'MBR (logical)', type: '0x' + l.type.toString(16), fs: await fsType(disk, start) }); }
          ebr = nx.type ? p.lba + nx.lba : 0;
        }
        continue;
      }
      const start = p.lba * 512;
      if (start >= disk.size) continue;
      vols.push({ index: vols.length + 1, start, size: p.count * 512, scheme: 'MBR', type: '0x' + p.type.toString(16), fs: await fsType(disk, start) });
    }
    if (vols.length) return vols;
  }
  if (fs0) return [{ index: 0, start: 0, size: disk.size, scheme: 'none (volume image)', type: '', fs: fs0 }];
  return vols;
}

export const volumeSource = (disk, v) => slice(disk, v.start, Math.min(v.size, disk.size - v.start), disk.name);
