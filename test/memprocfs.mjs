// MemProcFS forensic CSV detection and FindEvil grading (test/fixtures/memprocfs).
import fs from 'node:fs';
import { analyze, detect } from '../js/engine.js';
import { detectMemProcFs, EVIL, MPFS_CSV } from '../js/tools/memprocfs.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };
const enc = new TextEncoder();

// ---------------------------------------------------------------- header detection
for (const [kind, cols] of MPFS_CSV) ok(detectMemProcFs(`${kind}.csv`, cols + '\n1,2,3\n') === kind, `header recognised: ${kind}.csv`);
ok(detectMemProcFs('findevil.csv', 'PID,ProcessName,Type,Address,Description,NewColumn\n') === 'findevil', 'extra columns in a newer MemProcFS build still match');
ok(detectMemProcFs('timeline_all.csv', 'Time,Type,Action,PID,Value32,Value64,Text,Pad\n') === 'timeline', 'timeline_all.csv maps to the timeline handler');
ok(detectMemProcFs('whatever.csv', 'Date,User,Action\n') === null, 'an unrelated CSV is not claimed');
ok(detectMemProcFs('20261119_Amcache_UnassociatedFileEntries.csv', 'ApplicationName,ProgramId,SHA1\n') === null, 'an EZ tool CSV is not claimed');
ok(detect('findevil.csv', enc.encode('PID,ProcessName,Type,Address,Description\n1,a.exe,PE_INJECT,0x1,x\n')).id === 'mpfs', 'engine routes it to the MemProcFS handler');

// ---------------------------------------------------------------- the detection types the analyst asked about
for (const t of ['PROC_NOLINK', 'PROC_PARENT', 'PROC_USER', 'PE_INJECT', 'PRIVATE_RWX', 'PRIVATE_RX', 'NOIMAGE_RWX', 'NOIMAGE_RX']) ok(!!EVIL[t] && EVIL[t].what.length > 60 && EVIL[t].mitre.length, `${t} described and mapped to MITRE`);
ok(Object.keys(EVIL).length === 22, `all 22 FindEvil types covered (got ${Object.keys(EVIL).length})`);
for (const t of ['PROC_NOLINK', 'PE_INJECT', 'PEB_MASQ', 'PE_HDR_SPOOF', 'PROC_BAD_DTB', 'AV_DETECT']) ok(EVIL[t].sev === 'critical', `${t} is critical`);
for (const t of ['PRIVATE_RWX', 'NOIMAGE_RWX', 'PROC_PARENT', 'PROC_USER']) ok(EVIL[t].sev === 'high', `${t} is high`);
for (const t of ['PRIVATE_RX', 'NOIMAGE_RX', 'HIGH_ENTROPY']) ok(EVIL[t].sev === 'medium', `${t} is medium (a JIT can produce it)`);

// ---------------------------------------------------------------- end to end on the fixtures
const dir = new URL('./fixtures/memprocfs/', import.meta.url);
const rep = await analyze(fs.readdirSync(dir).map((n) => ({ name: n, data: new Uint8Array(fs.readFileSync(new URL(n, dir))) })));
const t = rep.findings.map((f) => `${f.sev} ${f.title}`);
const hit = (rx, m) => ok(t.some((x) => rx.test(x)), m);
ok(rep.files.every((f) => f.tool === 'MemProcFS'), 'every fixture parsed by the MemProcFS handler');
hit(/critical .*FindEvil PROC_NOLINK in rk_agent\.exe \(PID 3010\)/, 'PROC_NOLINK: process missing from the EPROCESS list');
hit(/high .*FindEvil PROC_PARENT in rk_agent\.exe/, 'PROC_PARENT: unexpected parent');
hit(/high .*FindEvil PROC_USER in rk_agent\.exe/, 'PROC_USER: unexpected token user context');
hit(/critical .*FindEvil PE_INJECT in explorer\.exe/, 'PE_INJECT: image with no file on disk');
hit(/high .*FindEvil PRIVATE_RWX in explorer\.exe/, 'PRIVATE_RWX: executable private memory');
hit(/high .*FindEvil NOIMAGE_RWX in svchost\.exe/, 'NOIMAGE_RWX: executable pages not mapped from an image');
hit(/critical .*FindEvil PEB_MASQ in lsass\.exe/, 'PEB_MASQ');
hit(/high .*FindEvil PE_PATCHED in explorer\.exe/, 'PE_PATCHED');
hit(/critical .*YARA rule matched in memory: Windows_Trojan_CobaltStrike/, 'yara.csv hit becomes a finding');
hit(/info .*FindEvil TIME_CHANGE in this image/, 'a hit with no process reads sensibly');
ok(t.filter((x) => /FindEvil (NOIMAGE_RX|PRIVATE_RX) in dotnet\.exe/.test(x)).every((x) => /^low /.test(x)), 'executable memory in a JIT runtime is lowered to low');
const jit = rep.findings.find((f) => /NOIMAGE_RX in dotnet/.test(f.title));
ok(jit && /just in time compiler/.test(jit.detail), 'and the finding says why it was lowered');

// the other CSVs feed the shared context rather than just rendering
ok(rep.indicators.some((i) => i.value === '203.0.113.44' && i.type === 'ipv4'), 'net.csv public address becomes an indicator');
ok(!rep.indicators.some((i) => i.value === '10.0.0.9' && i.type === 'ipv4'), 'an internal address is not filed as external');
hit(/high .*rk_agent\.exe connected to 203\.0\.113\.44:443/, 'a program in Temp talking to a public address is flagged');
ok(rep.programs.some((p) => p.name === 'rk_agent.exe' && p.risk >= 70), 'the bad process tops the Programs view');
ok(rep.timeline.some((e) => /Process running \(memory\)/.test(e.type)) && rep.timeline.some((e) => /Network connection \(memory\)/.test(e.type)), 'process and network rows reach the timeline');
ok(rep.findings.some((f) => /Service \(memory\): RkSvc/.test(f.title)), 'services.csv becomes persistence');
const sum = rep.files.find((f) => f.name === 'findevil.csv').tables.find((x) => x.title === 'FindEvil summary');
ok(sum && sum.rows.length === 11 && sum.rows[0][3] === 'critical', 'FindEvil summary table, worst first');

// one execution entry per process, not one per detection type
const dup = rep.findings.filter((f) => /located in user Temp \(rk_agent\.exe\)/.test(f.title) && /FindEvil/.test(f.title));
ok(dup.length === 1, `one path finding per process, not one per FindEvil type (got ${dup.length})`);

console.log(fail ? `\n${fail} FAILED` : '\nall MemProcFS checks passed');
process.exit(fail ? 1 : 0);
