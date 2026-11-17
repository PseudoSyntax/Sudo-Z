// Shell item (PIDL) decoder shared by LECmd (target ID list), JLECmd and
// SBECmd (ShellBags).
import { Reader, guidStr, dosDateTime } from '../core/bytes.js';

export const KNOWN_FOLDERS = {
  '20D04FE0-3AEA-1069-A2D8-08002B30309D': 'My Computer',
  '59031A47-3F72-44A7-89C5-5595FE6B30EE': 'Users Files',
  '450D8FBA-AD25-11D0-98A8-0800361B1103': 'My Documents',
  '208D2C60-3AEA-1069-A2D7-08002B30309D': 'My Network Places',
  'F02C1A0D-BE21-4350-88B0-7367FC96EF3C': 'Network',
  '645FF040-5081-101B-9F08-00AA002F954E': 'Recycle Bin',
  '21EC2020-3AEA-1069-A2DD-08002B30309D': 'Control Panel',
  '26EE0668-A00A-44D7-9371-BEB064C98683': 'Control Panel',
  '5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0': 'Control Panel Home',
  '871C5380-42A0-1069-A2EA-08002B30309D': 'Internet Explorer',
  '679F85CB-0220-4080-B29B-5540CC05AAB6': 'Quick Access',
  '031E4825-7B94-4DC3-B131-E946B44C8DD5': 'Libraries',
  '22877A6D-37A1-461A-91B0-DBDA5AAEBC99': 'Recent Places',
  '374DE290-123F-4565-9164-39C4925E467B': 'Downloads',
  '088E3905-0323-4B02-9826-5D99428E115F': 'Downloads',
  'B4BFCC3A-DB2C-424C-B029-7FE99A87C641': 'Desktop',
  'D3162B92-9365-467A-956B-92703ACA08AF': 'Documents',
  'A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0': 'Documents',
  '1CF1260C-4DD0-4EBB-811F-33C572699FDE': 'Music',
  '3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA': 'Pictures',
  '24AD3AD4-A569-4530-98E1-AB02F9417AA8': 'Pictures',
  'A0953C92-50DC-43BF-BE83-3742FED03C9C': 'Videos',
  'F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A': 'Videos',
  '018D5C66-4533-4307-9B53-224DE2ED1FE6': 'OneDrive',
  '9E3995AB-1F9C-4F13-B827-48B24B6C7174': 'User Pinned',
  '0DB7E03F-FC29-4DC6-9020-FF41B59E513A': '3D Objects',
  'F3364BA0-65B9-11CE-A9BA-00AA004AE837': 'Shell File System Folder',
  '04731B67-D933-450A-90E6-4ACD2E9408FE': 'Search Folder',
  '9343812E-1C37-4A49-A12E-4B2D810D956B': 'Search Home',
};

function fileEntryLongName(r, start, end) {
  // locate the 0xBEEF0004 extension block
  for (let o = start; o + 8 <= end; o += 2) {
    if (r.u32(o + 4) === 0xbeef0004) {
      const size = r.u16(o), ver = r.u16(o + 2);
      const off = ver >= 9 ? 0x2e : ver >= 8 ? 0x2a : ver >= 7 ? 0x26 : 0x14;
      if (off < size && o + off < end) {
        const name = r.utf16z(o + off, (size - off) >> 1);
        const mft = ver >= 7 && o + 0x1c <= end ? { entry: r.u32(o + 0x14) + r.u16(o + 0x18) * 2 ** 32, seq: r.u16(o + 0x1a) } : null;
        return { name, created: dosDateTime(r.u16(o + 10), r.u16(o + 8)), accessed: dosDateTime(r.u16(o + 14), r.u16(o + 12)), mft };
      }
    }
  }
  return null;
}

/** Decode one shell item. r = Reader over the item including its 2 byte size. */
export function decodeShellItem(r) {
  const size = r.length;
  if (size < 3) return { type: 'empty', name: '' };
  const cls = r.u8at(2);
  try {
    if (cls === 0x1f) {
      const g = size >= 20 ? guidStr(r.bytes(4, 16)) : '';
      return { type: 'root', name: KNOWN_FOLDERS[g] ? `${KNOWN_FOLDERS[g]}` : `{${g}}`, guid: g };
    }
    if ((cls & 0x70) === 0x20) {
      const s = r.asciiz(3, 20);
      return { type: 'volume', name: s.replace(/\\$/, '') + (s ? '' : '[volume]') };
    }
    if ((cls & 0x70) === 0x30) {
      const isDir = !!(cls & 0x01);
      const fsize = r.u32(4);
      const modified = dosDateTime(r.u16(10), r.u16(8));
      const unicode = !!(cls & 0x04);
      let p = 14;
      const short = unicode ? r.utf16z(p, 128) : r.asciiz(p, 260);
      p += unicode ? (short.length + 1) * 2 : short.length + 1;
      if (p & 1) p++;
      const ext = fileEntryLongName(r, p, size);
      return { type: isDir ? 'directory' : 'file', name: ext?.name || short, shortName: short, size: fsize, modified, created: ext?.created, accessed: ext?.accessed, mft: ext?.mft };
    }
    if ((cls & 0x70) === 0x40) {
      const s = r.asciiz(5, 260);
      return { type: 'network', name: s };
    }
    if (cls === 0x61) {
      // URI
      const raw = r.bytes(0, size);
      const u16 = new TextDecoder('utf-16le').decode(raw.subarray(0, size & ~1));
      const u16b = new TextDecoder('utf-16le').decode(raw.subarray(1, 1 + ((size - 1) & ~1)));
      const asc = r.ascii(0, size);
      const m = u16.match(/[a-z][a-z0-9+.-]{1,15}:\/\/[^\0]+/i) || u16b.match(/[a-z][a-z0-9+.-]{1,15}:\/\/[^\0]+/i) || asc.match(/[a-z][a-z0-9+.-]{1,15}:\/\/[\x21-\x7e]+/i);
      return { type: 'uri', name: m ? m[0] : '[URI]' };
    }
    if (cls === 0x71) return { type: 'controlpanel', name: size >= 30 ? `{${guidStr(r.bytes(14, 16))}}` : '[Control Panel]' };
    if (cls === 0x74 || cls === 0x00) {
      // Users property view / delegate. Try to find an embedded file entry long name.
      const ext = fileEntryLongName(r, 4, size);
      if (ext) return { type: 'delegate', name: ext.name, created: ext.created, accessed: ext.accessed, mft: ext.mft };
      // MTP / other: pull a UTF-16 string if one looks like a name
      const m = /[\x20-\x7e]\x00(?:[\x20-\x7e]\x00){3,}/.exec(String.fromCharCode(...r.bytes(0, Math.min(size, 512))));
      if (m) return { type: 'property', name: m[0].replace(/\x00/g, '') };
    }
  } catch { /* fall through */ }
  return { type: `0x${cls.toString(16)}`, name: `[shell item 0x${cls.toString(16)}]` };
}

/** Parse an IDList (sequence of shell items terminated by 0 size). */
export function parseIdList(r, off, end) {
  const items = [];
  let p = off;
  while (p + 2 <= end) {
    const sz = r.u16(p);
    if (sz === 0) break;
    if (p + sz > end || sz < 3) break;
    items.push(decodeShellItem(r.sub(p, sz)));
    p += sz;
  }
  return items;
}

export function idListPath(items) {
  const parts = [];
  for (const it of items) {
    if (it.type === 'root' && (it.name === 'My Computer' || it.name === 'Users Files')) continue;
    if (!it.name) continue;
    parts.push(it.name);
  }
  return parts.join('\\').replace(/\\\\+/g, '\\');
}
