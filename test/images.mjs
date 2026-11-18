// Disk image reader checks against the dfvfs test images.
// usage: node test/images.mjs <dir with dfvfs test_data files>
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fromFd } from '../js/image/source.js';
import { sniff, openContainer } from '../js/image/containers.js';
import { listVolumes, volumeSource } from '../js/image/volumes.js';
import { Ntfs } from '../js/image/ntfs.js';
import { analyze } from '../js/engine.js';

const D = (process.argv[2] || '.').replace(/\/?$/, '/');
const src = (n) => fromFd(fs, fs.openSync(D + n, 'r'), fs.statSync(D + n).size, n);
const md5 = (u8) => crypto.createHash('md5').update(u8).digest('hex');
let fail = 0;
const check = (ok, msg) => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${msg}`); if (!ok) fail++; };

async function disk(names) { const ss = names.map(src); const k = await sniff(ss[0]); return { k, ...(await openContainer(ss, k.kind)) }; }

// containers decode to the same bytes as the raw image
const raw = md5(await (await disk(['ext2.raw'])).disk.read(0, 4194304));
for (const set of [['ext2.E01'], ['ext2.split.E01', 'ext2.split.E02'], ['ext2.vhdx'], ['ext2.vhd'], ['ext2.qcow2'], ['ext2.splitraw.000', 'ext2.splitraw.001']]) {
  const { k, disk: d } = await disk(set);
  check(md5(await d.read(0, 4194304)) === raw, `${set.join(' + ')} (${k.kind}) matches ext2.raw`);
}

// NTFS: files and content through every container
for (const n of ['ntfs.raw', 'ntfs-fixed.vhd', 'ntfs-dynamic.vhd', 'ntfs-fixed.vhdx', 'ntfs-dynamic.vhdx']) {
  const { disk: d } = await disk([n]);
  const v = (await listVolumes(d)).find((x) => x.fs === 'NTFS');
  if (!v) { check(false, `${n}: NTFS volume found`); continue; }
  const nt = await new Ntfs(volumeSource(d, v)).open();
  const f = [...nt.files()].find((x) => x.path === 'a_directory/another_file');
  const txt = f ? new TextDecoder().decode(await nt.readStream(f.streams[''])) : '';
  check(/^This is another file\./.test(txt), `${n}: a_directory/another_file read through ${v.scheme}`);
}

// partition tables and encrypted volumes
check((await listVolumes((await disk(['gpt.raw'])).disk)).length === 2, 'gpt.raw: 2 GPT partitions');
check((await listVolumes((await disk(['mbr.raw'])).disk)).some((v) => v.scheme === 'MBR (logical)'), 'mbr.raw: logical partition in extended partition');
check((await listVolumes((await disk(['bdetogo.raw'])).disk))[0]?.fs === 'BitLocker', 'bdetogo.raw: BitLocker To Go detected');

// end to end through the engine
const rep = await analyze(['windows_volume.qcow2', 'ntfs-differential.vhdx'].map((n) => ({ name: n, src: src(n) })));
const img = rep.files.find((f) => f.name === 'windows_volume.qcow2');
check(img?.tool === 'Disk image (Sudo-Z)' && rep.files.some((f) => f.name === 'windows_volume.qcow2/vol0/$MFT' && f.tool === 'MFTECmd'), 'engine: QCOW2 image triaged and its $MFT parsed');
check(rep.files.find((f) => f.name === 'ntfs-differential.vhdx')?.status === 'error', 'engine: differencing VHDX reported, not crashed');

console.log(fail ? `${fail} check(s) failed` : 'all image checks passed');
process.exit(fail ? 1 : 0);
