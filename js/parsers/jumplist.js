// JLECmd equivalent: automaticDestinations-ms (CFB + DestList + LNK streams)
// and customDestinations-ms (concatenated LNKs).
import { Reader, filetimeToIso, indexOfBytes } from '../core/bytes.js';
import { readCfb } from '../core/cfb.js';
import { parseLnk, LNK_SIG } from './lnk.js';

export const APP_IDS = {
  '1bc392b8e104a00e': 'Remote Desktop Connection (mstsc)',
  '5f7b5f1e01b83767': 'Quick Access / Explorer',
  'f01b4d95cf55d32a': 'Windows Explorer (8.1/10)',
  '1b4dd67f29cb1962': 'Windows Explorer pinned/recent',
  '9b9cdc69c1c24e2b': 'Notepad (64-bit)',
  '5d696d521de238c3': 'Google Chrome',
  '28c8b86deab549a1': 'Internet Explorer',
  '7e4dca80246863e3': 'Control Panel',
  '9d1f905ce5044aee': 'Microsoft Edge (legacy)',
  '6824f4a902c78fbd': 'Mozilla Firefox',
  'b74736c2bd8cc8a5': 'WinZip',
  '290532160612e071': 'WinRAR',
  'fb3b0dbfee58fac8': 'Microsoft Word',
  'a7bd71699cd38d1c': 'Microsoft Word 2010',
  'adecfb853d77462a': 'Microsoft Word 2007',
  '9839aec31243a928': 'Microsoft Excel 2010',
  'b8ab77100df80ab2': 'Microsoft Excel',
  'd00655d2aa12ff6d': 'Microsoft PowerPoint 2010',
  '12dc1ea8e34b5a6': 'Microsoft Paint',
  '3094cdb43bf5e9c2': 'Microsoft OneNote',
  '6728dd69a3088f97': 'Windows Command Processor',
  'f5ac5390b9115fdb': 'PowerPoint',
  '4ac2a7d4ab6c4d1d': 'Windows PowerShell',
  'bc03160ee1a59fc1': 'Outlook',
  'e31a6a8a7506f733': 'Image Viewer',
  'ccba5a5986c77e43': 'Microsoft Edge (Chromium)',
};

export const appIdFromName = (name) => (name.match(/([0-9a-f]{16})\.(automatic|custom)Destinations-ms$/i) || [])[1]?.toLowerCase() || null;

function parseDestList(u8) {
  const r = new Reader(u8);
  const version = r.u32(0), count = r.u32(4);
  const entries = [];
  let p = 32;
  for (let i = 0; i < count && p + 0x72 <= r.length; i++) {
    const e = { hostname: r.asciiz(p + 0x48, 16), entryId: r.u32(p + 0x58), lastModified: r.filetime(p + 0x64), pinned: r.i32(p + 0x6c) !== -1 };
    if (version >= 3) {
      e.accessCount = r.u32(p + 0x74);
      const len = r.u16(p + 0x80);
      e.path = r.utf16(p + 0x82, len);
      p += 0x82 + len * 2 + 4;
    } else {
      e.lastModified = r.filetime(p + 0x64);
      const len = r.u16(p + 0x70);
      e.path = r.utf16(p + 0x72, len);
      p += 0x72 + len * 2;
    }
    entries.push(e);
  }
  return { version, entries };
}

export function parseAutomaticDest(u8, name) {
  const streams = readCfb(u8);
  const out = { appId: appIdFromName(name), entries: [], destList: null };
  out.appName = APP_IDS[out.appId] || null;
  const dl = streams.get('DestList');
  if (dl) { try { out.destList = parseDestList(dl); } catch (e) { out.destListError = e.message; } }
  for (const [sname, data] of streams) {
    if (sname === 'DestList') continue;
    try {
      const lnk = parseLnk(data);
      const id = parseInt(sname, 16);
      const dle = out.destList?.entries.find((e) => e.entryId === id);
      out.entries.push({ stream: sname, ...lnk, lastUsed: dle?.lastModified || null, accessCount: dle?.accessCount, pinned: dle?.pinned, hostname: dle?.hostname, destPath: dle?.path });
    } catch { /* non-LNK stream */ }
  }
  out.entries.sort((a, b) => (b.lastUsed || '').localeCompare(a.lastUsed || ''));
  return out;
}

export function parseCustomDest(u8, name) {
  const out = { appId: appIdFromName(name), entries: [] };
  out.appName = APP_IDS[out.appId] || null;
  let p = indexOfBytes(u8, LNK_SIG, 0);
  while (p >= 0) {
    const next = indexOfBytes(u8, LNK_SIG, p + 20);
    try { out.entries.push(parseLnk(u8.subarray(p, next > 0 ? next : u8.length))); } catch { }
    p = next;
  }
  return out;
}
