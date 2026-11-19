// Code injection checks on hand-made Volatility 3 output (test/fixtures/vol-inject).
import fs from 'node:fs';
import { analyze } from '../js/engine.js';
const dir = new URL('./fixtures/vol-inject/', import.meta.url);
const files = fs.readdirSync(dir).map((n) => ({ name: n, data: new Uint8Array(fs.readFileSync(new URL(n, dir))) }));
const rep = await analyze(files);
const t = rep.findings.map((f) => `${f.sev} ${f.title}`);
const want = [
  /critical .*lsass\.exe \(PID 700\) has 1 loaded module\(s\) with no file behind them \(MappedPath N\/A\)/,
  /critical .*lsass\.exe \(PID 700\) loaded 1 DLL\(s\) from outside/,
  /critical .*(MZ header wiped|MZ header erased)/,
  /critical .*code injection in lsass\.exe \(PID 700\) confirmed/,
  /critical .*Skeleton Key/,
  /high .*notepad\.exe \(PID 1500\) main module maps svchost\.exe/,
  /high .*PEB masquerading in notepad\.exe/,
];
let fail = 0;
for (const w of want) { const ok = t.some((x) => w.test(x)); console.log(`${ok ? 'PASS' : 'FAIL'}  ${w}`); if (!ok) fail++; }
// System32 DLL mapped as a resource (all lists false) must not be flagged
const fp = t.filter((x) => /shell32\.dll/.test(x));
console.log(`${fp.length ? 'FAIL' : 'PASS'}  no finding for shell32.dll resource mapping in svchost`); if (fp.length) fail++;
process.exit(fail ? 1 : 0);
