// Disk image intake: container -> volumes -> NTFS -> triage targets -> files the
// normal parsers understand. The result looks like a KAPE Targets collection.
import { sniff, openContainer, IMAGE_EXT } from './containers.js';
import { listVolumes, volumeSource } from './volumes.js';
import { Ntfs } from './ntfs.js';
import { selectTargets, TOTAL_CAP, FILE_CAP } from './targets.js';

export { IMAGE_EXT };

const segKey = (n) => n.replace(/\.(e\d\d|ex\d\d|\d{3})$/i, '').toLowerCase();
const segOrder = (n) => { const m = n.match(/\.(?:e|ex)?(\d+)$/i); return m ? parseInt(m[1], 10) : 0; };

/** Group segment files (x.E01 x.E02, x.001 x.002) into one image each. items: [{name, src}] */
export function groupSegments(items) {
  const groups = new Map();
  for (const it of items) {
    const multi = /\.(e\d\d|ex\d\d|\d{3})$/i.test(it.name);
    const k = multi ? segKey(it.name) : it.name.toLowerCase() + '#';
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }
  return [...groups.values()].map((g) => g.sort((a, b) => segOrder(a.name) - segOrder(b.name)));
}

/** Is this source a disk image we can open? Cheap: reads the first 4 KB and the last 512 bytes. */
export async function probeImage(name, src) {
  const k = await sniff(src);
  if (k.kind !== 'raw') return k;
  // raw: only call it a disk if a partition table or a known volume is present
  if (!IMAGE_EXT.test(name) || src.size < 1024 * 1024) return null;
  try { const { disk } = await openContainer([src], 'raw'); const v = await listVolumes(disk); return v.some((x) => x.fs) ? k : null; } catch { return null; }
}

/**
 * Extract triage targets from one image (one or more segments).
 * @returns {Promise<{files:{name,data,parent}[], record:object}>}
 */
export async function extractImage(segs, { onProgress = () => {}, log = () => {}, kind } = {}) {
  const name = segs[0].name;
  const label = name.split(/[\\/]/).pop();
  const notes = []; const files = [];
  const vtable = []; const xtable = [];
  const k = kind ? { kind } : await sniff(segs[0].src);
  if (k.unsupported) throw new Error(k.unsupported);
  const { disk, info } = await openContainer(segs.map((s) => s.src), k.kind);
  if (info.warning) notes.push(info.warning);
  const vols = await listVolumes(disk);
  if (!vols.length) notes.push('No partition table or known file system found.');
  let total = 0;
  const letters = new Map(); let nextLetter = 'D'.charCodeAt(0);
  for (const v of vols) {
    const row = [v.index, v.scheme, v.type, v.name || '', v.fs || 'unknown', v.start, v.size, ''];
    vtable.push(row);
    if (v.fs !== 'NTFS') {
      row[7] = v.fs === 'BitLocker' ? 'Encrypted. Unlock it (manage-bde -unlock, or mount with the recovery key) and image the unlocked volume.' : v.fs ? `${v.fs} is not read; only NTFS volumes are triaged.` : 'Unknown file system';
      if (v.fs === 'BitLocker') notes.push(`Volume ${v.index} is BitLocker encrypted; its artifacts could not be read.`);
      continue;
    }
    const vname = `${label}/vol${v.index}`;
    let nt;
    try {
      onProgress(0.02, `${label}: reading $MFT of volume ${v.index}`);
      nt = await new Ntfs(volumeSource(disk, v)).open({ onProgress: (p) => onProgress(0.02 + p * 0.2, `${label}: indexing $MFT (vol ${v.index})`) });
    } catch (e) { row[7] = `NTFS could not be opened: ${e.message}`; notes.push(`Volume ${v.index}: ${e.message}`); continue; }
    const picks = selectTargets(nt);
    // drive letter guess: the volume holding Windows is C:, the rest D:, E: ...
    const isOs = [...picks].some((p) => /^windows\/system32\//i.test(p.file.path));
    const letter = isOs && ![...letters.values()].includes('C') ? 'C' : String.fromCharCode(nextLetter++);
    letters.set(v.index, letter);
    const perLabel = new Map(); const perBudget = new Map();
    let got = 0, skipped = 0;
    row[7] = `${nt.recs.length} MFT records, ${picks.length} target files`;
    // $MFT comes straight from the reader (already in memory)
    for (let i = 0; i < picks.length; i++) {
      const p = picks[i];
      if (i % 10 === 0) { onProgress(0.22 + (i / picks.length) * 0.7, `${label}: extracting ${p.file.path.split('/').pop()}`); await new Promise((r) => setTimeout(r, 0)); }
      const cap = Math.min(p.opts.max || FILE_CAP, TOTAL_CAP - total, p.opts.budget ? p.opts.budget - (perBudget.get(p.label) || 0) : Infinity);
      if (cap <= 0 || (p.opts.limit && (perLabel.get(p.label) || 0) >= p.opts.limit) || (p.opts.max && p.stream.size > p.opts.max && p.opts.last)) { skipped++; continue; }
      perLabel.set(p.label, (perLabel.get(p.label) || 0) + 1);
      let data;
      try {
        if (p.file.id === 0) data = nt.mftBytes.subarray(0, Math.min(nt.mftBytes.length, cap));
        else data = await nt.readStream(p.stream, { max: cap, dropSparse: !!p.opts.dropSparse });
      } catch (e) { xtable.push([p.label, p.file.path, p.stream.size, '', '', `skipped: ${e.message}`]); skipped++; continue; }
      const truncated = p.stream.size > data.length && !p.opts.dropSparse;
      total += data.length; got++; perBudget.set(p.label, (perBudget.get(p.label) || 0) + data.length);
      const out = p.opts.as ? p.file.path.replace(/[^/]+$/, p.opts.as) : p.file.path;
      files.push({ name: `${vname}/${out}`, data, parent: name, winPath: `${letter}:\\${p.file.path.replace(/\//g, '\\')}`, fromImage: true, si: p.file.si });
      xtable.push([p.label, '/' + p.file.path + (p.opts.stream ? ':' + p.opts.stream : ''), data.length, p.file.si?.created || '', p.file.si?.modified || '', truncated ? `truncated at ${data.length} bytes` : p.file.id]);
    }
    if (skipped) notes.push(`Volume ${v.index}: ${skipped} target file(s) skipped (size cap of ${TOTAL_CAP / 1024 ** 3} GB reached or unreadable).`);
    log(`${label} vol${v.index}: ${got} files extracted`);
  }
  const tables = [
    { title: 'Image', columns: ['Property', 'Value'], rows: [['Format', info.format], ['Virtual size', info.size || disk.size], ...(info.chunkSize ? [['Chunk size', info.chunkSize]] : []), ...(segs.length > 1 ? [['Segments', segs.map((s) => s.name.split(/[\\/]/).pop()).join(', ')]] : []), ...(info.header ? [['Acquisition header', info.header]] : [])] },
    { title: 'Volumes', columns: ['#', 'Scheme', 'Type', 'Name', 'File system', 'Offset', 'Size', 'Result'], rows: vtable },
    { title: 'Extracted triage files', columns: ['Target', 'Path', 'Bytes', 'Created (SI)', 'Modified (SI)', 'MFT entry / note'], rows: xtable, note: 'KAPE-style target set. Each file below is parsed like any other submitted artifact.' },
  ];
  const ntfsVols = vols.filter((v) => v.fs === 'NTFS').length;
  const record = {
    name, size: segs.reduce((n, s) => n + s.src.size, 0), parent: null, hashes: null,
    status: files.length ? 'parsed' : 'partial', tool: 'Disk image (Sudo-Z)', artifact: info.format,
    summary: `${vols.length} volume(s), ${ntfsVols} NTFS, ${files.length} triage file(s) extracted (${(total / 1024 ** 2).toFixed(1)} MB)`,
    tables, notes, ms: 0,
  };
  return { files, record };
}
