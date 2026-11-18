// Kernel rootkit checks on hand-made Volatility 3 output (test/fixtures/vol-rootkit).
import fs from 'node:fs';
import { analyze } from '../js/engine.js';
const dir = new URL('./fixtures/vol-rootkit/', import.meta.url);
const rep = await analyze(fs.readdirSync(dir).map((n) => ({ name: n, data: new Uint8Array(fs.readFileSync(new URL(n, dir))) })));
const t = rep.findings.map((f) => `${f.sev} ${f.title}`);
const want = [
  /critical .*System call table hooked: 1 entry point into rk_drv/,
  /critical .*1 system call table entry point outside every loaded module/,
  /critical .*private service table/,
  /critical .*unlinked from the active process list \(DKOM\): rk_agent\.exe/,
  /critical .*unlinked from the loaded module list \(DKOM\)/,
  /critical .*kernel callback\(s\) registered from unknown memory/,
  /critical .*IRP handler\(s\) point into unknown memory/,
  /high .*kernel timer\(s\) run code from unknown memory/,
  /critical .*kernel thread\(s\) running from memory that belongs to no driver/,
];
let fail = 0;
for (const w of want) { const ok = t.some((x) => w.test(x)); console.log(`${ok ? 'PASS' : 'FAIL'}  ${w}`); if (!ok) fail++; }
for (const [rx, why] of [[/explorer\.exe.*DKOM/, 'explorer in all views'], [/Ntfs|CLASSPNP|Disk/, 'framework / own-driver IRP handlers'], [/WdFilter/, 'Defender callback']]) { const bad = t.filter((x) => rx.test(x)); console.log(`${bad.length ? 'FAIL' : 'PASS'}  no finding for ${why}`); if (bad.length) { fail++; console.log(bad); } }
process.exit(fail ? 1 : 0);
