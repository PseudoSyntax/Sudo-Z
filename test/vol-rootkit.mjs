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
for (const [rx, why] of [[/explorer\.exe.*DKOM/, 'explorer in all views'], [/Ntfs|CLASSPNP|Disk/, 'framework / own-driver IRP handlers'], [/WdFilter/, 'Defender callback'],
  [/DKOM.*System \(PID 4\)|System \(PID 4\).*DKOM/, 'System absent from csrss handles'], [/smss\.exe.*DKOM/, 'smss.exe absent from csrss and session'],
  [/csrss\.exe.*DKOM/, 'csrss.exe absent from its own handle table'], [/oldtool\.exe/, 'a process that had exited']]) {
  const bad = t.filter((x) => rx.test(x)); console.log(`${bad.length ? 'FAIL' : 'PASS'}  no finding for ${why}`); if (bad.length) { fail++; console.log(bad); }
}

// ---------------------------------------------------------------- 7 view cross-view table and the -R rules
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };
const xt = rep.files.flatMap((f) => f.tables || []).find((x) => /Cross-view process listing/.test(x.title));
ok(!!xt, 'cross-view table built');
if (xt) {
  const col = (n) => xt.columns.indexOf(n);
  const row = (name) => xt.rows.find((r) => r[0] === name);
  ok(xt.columns.join(',') === 'Name,PID,pslist,psscan,thrdscan,csrss,pspcid,session,deskthrd,ExitTime,Why a view is blank', 'all seven views are columns: ' + xt.columns.join(','));
  const rk = row('rk_agent.exe');
  ok(rk && rk[col('pslist')] === 'NO' && rk[col('pspcid')] === 'Y' && rk[col('session')] === 'Y' && rk[col('deskthrd')] === 'Y', 'hidden process: missing from pslist, found by pspcid, session and deskthrd');
  const sys = row('System');
  ok(sys && sys[col('csrss')] === 'n/a' && /starts before csrss/.test(sys[col('Why a view is blank')]), 'System: csrss absence marked n/a with the reason');
  ok(sys && sys[col('deskthrd')] === 'n/a' && sys[col('session')] === 'n/a', 'System: session and deskthrd absences are expected too');
  const smss = row('smss.exe');
  ok(smss && smss[col('csrss')] === 'n/a' && smss[col('session')] === 'n/a' && smss[col('deskthrd')] === 'n/a', 'smss.exe: runs before csrss and before any session');
  const csr = row('csrss.exe');
  ok(csr && csr[col('csrss')] === 'n/a' && /does not hold a handle to itself/.test(csr[col('Why a view is blank')]), 'csrss.exe: cannot appear in its own handle table');
  ok(csr && csr[col('deskthrd')] === 'n/a' && csr[col('session')] === 'Y', 'csrss.exe: session 0, no desktop threads expected');
  const old = row('oldtool.exe');
  ok(old && old[col('pslist')] === 'n/a' && /exited/.test(old[col('Why a view is blank')]), 'terminated process: absences explained by its exit');
  const stale = row('stale.exe');
  ok(stale && stale[col('pslist')] === 'NO' && stale[col('pspcid')] === 'NO', 'psscan-only object with no exit time still shows as missing');
}
const hidden = rep.findings.find((f) => /unlinked from the active process list \(DKOM\): rk_agent/.test(f.title));
ok(hidden && /pspcid/.test(f6(hidden)) && /session/.test(f6(hidden)) && /deskthrd/.test(f6(hidden)), 'finding lists every corroborating view');
function f6(f) { return `${f.detail} ${f.evidence}`; }
ok(hidden && /PspCidTable|pspcid/.test(hidden.detail), 'finding explains why a kernel-owned view matters');
const once = rep.findings.filter((f) => /rk_agent\.exe/.test(f.title) && /DKOM|unlinked/.test(f.title));
ok(once.length === 1, `hidden process reported once, not duplicated by the pslist/psscan check (got ${once.length})`);

// ---------------------------------------------------------------- IDT and API hooks (no Volatility 3 equivalent)
const tt = rep.findings.map((f) => `${f.sev} ${f.title}`);
const hit = (rx, m) => ok(tt.some((x) => rx.test(x)), m);
hit(/critical .*1 interrupt handler\(s\) point into memory that belongs to no module/, 'IDT: handler in unmapped memory is critical');
hit(/high .*1 interrupt handler\(s\) owned by rk_drv rather than the kernel/, 'IDT: third-party driver holding a vector');
hit(/critical .*1 interrupt vector\(s\) have a different handler on different processors/, 'IDT: per CPU mismatch (single core hook)');
hit(/critical .*3 API hooks in explorer\.exe \(PID 1500\) point into memory that belongs to no module/, 'apihooks: inline hooks grouped per process');
hit(/critical .*1 import table entry in explorer\.exe \(PID 1500\) point into memory that belongs to no module/, 'apihooks: IAT hooks reported as their own group');
hit(/medium .*1 API hooks in svchost\.exe \(PID 900\) redirected into edrsensor\.dll/, 'apihooks: a named module is medium, not critical');
ok(!tt.some((x) => /svchost\.exe.*critical/.test(x)), 'apihooks: EDR style hook is not raised to critical');
const idtT = rep.files.flatMap((f) => f.tables || []).find((x) => x.title === 'Interrupt Descriptor Table');
ok(idtT && idtT.rows.length === 3, 'IDT table rendered');
const ahT = rep.files.flatMap((f) => f.tables || []).find((x) => x.title === 'User mode API hooks');
ok(ahT && ahT.rows.length === 5 && ahT.columns.includes('Destination owner'), 'API hook table rendered');
const amsi = rep.findings.find((f) => /point into memory that belongs to no module/.test(f.title) && /explorer/.test(f.title));
ok(amsi && /AmsiScanBuffer/.test(amsi.evidence) && /ws2_32/.test(amsi.evidence) === false, 'inline and iat hooks are reported separately');
ok(amsi && /vadinfo|vaddump/.test(amsi.detail), 'finding says how to dump the injected code');

process.exit(fail ? 1 : 0);
