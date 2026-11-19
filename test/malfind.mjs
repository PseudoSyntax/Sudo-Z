// malfind region identification: naming the implant from its opening bytes.
import fs from 'node:fs';
import { analyze } from '../js/engine.js';
import { classifyShellcode, shellcodeMarks, normHex } from '../js/ioc/shellcode.js';
import { runBstrings } from '../js/core/strings.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };

// ---------------------------------------------------------------- the byte classifier
const cases = [
  ['4d 5a e8 00 00 00 00 5b 52 45 55 89 e5', 'reflective_dll', 'metsrv / reflective DLL: MZ followed by a call'],
  ['fc 48 83 e4 f0 e8 c0 00 00 00 41 51', 'msf_x64_stager', 'Metasploit x64 stager prologue'],
  ['fc e8 89 00 00 00 60 89 e5 31 d2', 'msf_x86_stager', 'Metasploit x86 stager prologue'],
  ['fc e8 82 00 00 00 60 89 e5', 'msf_x86_stager', 'the older x86 call offset still matches'],
  ['60 89 e5 31 d2 64 8b 52 30 8b 52 0c', 'msf_block_api_x86', 'Metasploit block_api PEB walk (x86)'],
  ['65 48 8b 52 60 48 8b 52 18', 'msf_block_api_x64', 'Metasploit block_api PEB walk (x64)'],
  ['4c 8b d1 b8 55 00 00 00', 'syscall_stub', 'direct syscall stub'],
  ['e8 00 00 00 00 5b 81 eb', 'getpc', 'GetPC stub'],
  ['50 45 00 00 64 86 06 00', 'pe_no_mz', 'PE with the MZ erased'],
  ['eb fe 90 90', 'stall', 'infinite loop'],
  ['90 90 90 90 90 90 90 90 90', 'nopsled', 'NOP sled'],
];
for (const [hex, id, what] of cases) ok(classifyShellcode(hex)?.id === id, what);
for (const [hex, what] of [['4d 5a 90 00 03 00 00 00', 'an unmodified PE header'], ['48 89 5c 24 08 57', 'an ordinary x64 prologue'], ['55 8b ec 83 ec 20', 'an ordinary x86 prologue'], ['00 00 00 00 00 00 00 00 00', 'zeroed memory']]) {
  const r = classifyShellcode(hex);
  ok(r && r.benign, `not reported as an implant: ${what}`);
}
ok(classifyShellcode('de ad be ef 11 22') === null, 'unknown bytes are not forced into a family');
ok(normHex('0x4D 0x5A 0xE8') === '4d 5a e8' && normHex('4D5AE8') === '4d 5a e8', 'hex normalised from either shape');
const marks = shellcodeMarks('4d 5a e8 00 00 00 00 5b 4c 77 26 07');
ok(marks.length === 2 && marks.some((m) => /Reflective DLL/.test(m)) && marks.some((m) => /LoadLibraryA/.test(m)), 'a region can match more than one signature');
ok(/Meterpreter metsrv/.test(classifyShellcode('4d 5a e8 00')?.why ? classifyShellcode('4d 5a e8 00').family : ''), 'the reflective DLL family names Meterpreter metsrv');
for (const id of ['msf_x64_stager', 'msf_x86_stager', 'reflective_dll']) {
  const s = classifyShellcode({ msf_x64_stager: 'fc 48 83 e4 f0', msf_x86_stager: 'fc e8 89 00 00 00', reflective_dll: '4d 5a e8 00' }[id]);
  ok(s.sev === 'critical' && s.next && s.why.length > 80, `${id} is critical and says what to do next`);
}

// ---------------------------------------------------------------- Meterpreter strings
const enc = new TextEncoder();
const hits = runBstrings(enc.encode('x\u0000metsrv.x64.dll\u0000core_channel_open\u0000stdapi_sys_process_execute\u0000')).hits;
ok(hits.some((h) => /Meterpreter \/ Metasploit payload strings/.test(h.title) && h.sev === 'critical'), 'Meterpreter stage strings raise a critical keyword hit');

// ---------------------------------------------------------------- end to end through the engine
const dir = new URL('./fixtures/vol-malfind/', import.meta.url);
const rep = await analyze(fs.readdirSync(dir).map((n) => ({ name: n, data: new Uint8Array(fs.readFileSync(new URL(n, dir))) })));
const t = rep.findings.map((f) => `${f.sev} ${f.title}`);
const hit = (rx, m) => ok(t.some((x) => rx.test(x)), m);
hit(/critical .*Reflective DLL \(Meterpreter metsrv, Cobalt Strike beacon, sRDI\) in explorer\.exe \(PID 1500\)/, 'metsrv region named, not called "shellcode-like"');
hit(/critical .*Metasploit \/ Meterpreter stager \(x64\) in explorer\.exe \(PID 1500\)/, 'x64 stager named in the same process');
hit(/critical .*Metasploit \/ Meterpreter stager \(x86\) in svchost\.exe \(PID 900\)/, 'x86 stager named');
hit(/critical .*PE image with its MZ header erased in rk_agent\.exe/, 'erased PE header named');
hit(/high .*Direct syscall stub in lsass\.exe/, 'syscall stub in lsass named');
ok(!t.some((x) => /dotnet\.exe/.test(x) && /Metasploit|Reflective|shellcode/.test(x)), 'an ordinary prologue in a JIT process is not named as an implant');
hit(/low .*1 injected\/executable private region\(s\) in dotnet\.exe/, 'a JIT process with no signature stays low');
hit(/medium .*1 injected\/executable private region\(s\) in notepad\.exe/, 'unknown bytes in an ordinary process stay medium and say to read the disassembly');
const unknown = rep.findings.find((f) => /notepad\.exe/.test(f.title));
ok(unknown && /match no implant signature/.test(unknown.detail), 'and the finding admits it could not name it');
const tbl = rep.files[0].tables.find((x) => x.title === 'Malfind regions');
ok(tbl && tbl.columns.includes('Identified as'), 'Identified as column added to the regions table');
ok(tbl && tbl.rows.find((r) => r[1] === 'dotnet.exe')[6].startsWith('('), 'a benign prologue is shown in brackets, not as a detection');
const mp = rep.findings.filter((f) => /explorer\.exe \(PID 1500\)/.test(f.title));
ok(mp.length === 2, `both regions in explorer reported separately, with no duplicate generic finding (got ${mp.length})`);

console.log(fail ? `\n${fail} FAILED` : '\nall malfind checks passed');
process.exit(fail ? 1 : 0);
