// Cross-artifact execution checks (Prefetch, ShimCache, Amcache, UserAssist, SRUM) on a built single-host case.
import { Context } from '../js/ioc/context.js';
import { analyseExecution, executionFor } from '../js/ioc/execution.js';
import { normKey } from '../js/ioc/context.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };
const files = [{ name: 'C/Windows/System32/config/SYSTEM' }, { name: 'C/Users/bob/NTUSER.DAT' }];

// 1. normal host: 12 .pf files; evil.exe ran (UserAssist + SRUM) after the oldest .pf but has none; tool.exe only in ShimCache
let ctx = new Context(); ctx.hosts.add('WKS1');
for (let i = 0; i < 12; i++) ctx.evidence({ artifact: 'Prefetch', path: `C:\\Windows\\System32\\app${i}.exe`, time: `2026-03-0${(i % 9) + 1}T10:00:00Z`, lastRuns: [`2026-03-0${(i % 9) + 1}T10:00:00Z`], runCount: 3, file: `C/Windows/Prefetch/APP${i}.EXE-1234.pf` });
ctx.evidence({ artifact: 'UserAssist', path: 'C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe', time: '2026-03-05T12:00:00Z', runCount: 2, user: 'bob', file: 'C/Users/bob/NTUSER.DAT' });
ctx.evidence({ artifact: 'SRUM', path: 'C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe', first: '2026-03-05T12:00:00Z', last: '2026-03-05T13:00:00Z', sent: 5e8, recv: 1e5, file: 'C/Windows/System32/sru/SRUDB.dat' });
ctx.evidence({ artifact: 'ShimCache', path: 'C:\\ProgramData\\tool.exe', time: '2026-03-04T09:00:00Z', position: 3, file: 'C/Windows/System32/config/SYSTEM' });
ctx.evidence({ artifact: 'Amcache', path: 'C:\\Program Files\\App\\app.exe', time: '2026-01-01T00:00:00Z', sha1: 'a'.repeat(40), file: 'C/Windows/AppCompat/Programs/Amcache.hve' });
ctx.evidence({ artifact: 'Amcache', path: 'C:\\Program Files\\App\\app.exe', time: '2026-03-05T11:00:00Z', sha1: 'b'.repeat(40), file: 'C/Windows/AppCompat/Programs/Amcache.hve' });
let r = analyseExecution(ctx, files, {});
const t = () => ctx.findings.map((f) => `${f.sev} ${f.title}`);
ok(t().some((x) => /^(medium|high) 1 program\(s\) ran but have no Prefetch file/.test(x)), 'evil.exe ran (UserAssist + SRUM) but has no .pf');
ok(t().some((x) => /different SHA1s in Amcache/.test(x)), 'same path, two SHA1s in Amcache');
ok(t().some((x) => /present but not proven to have run/.test(x)), 'tool.exe only in ShimCache: present, not proven run');
ok(r.coverage.every((c) => c.state === 'Collected'), 'all five artifacts marked collected');
const ev = executionFor(ctx, normKey('C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe'));
ok(ev.executed === 'Yes' && ev.firstRun === '2026-03-05T12:00:00Z' && /477|476/.test(ev.SRUM) && /2x by bob/.test(ev.UserAssist), 'matrix row for evil.exe (executed, first run, SRUM bytes, UserAssist user)');

// 2. Prefetch disabled and nothing collected for it
ctx = new Context(); ctx.hosts.add('WKS1');
ctx.settings.enablePrefetcher = { value: 0, time: '2026-03-05T11:00:00Z', file: 'C/Windows/System32/config/SYSTEM' };
for (let i = 0; i < 25; i++) ctx.evidence({ artifact: 'UserAssist', path: `C:\\Tools\\t${i}.exe`, time: '2026-03-05T12:00:00Z', runCount: 1, user: 'bob', file: 'C/Users/bob/NTUSER.DAT' });
r = analyseExecution(ctx, files, { attackFirst: '2026-03-05T10:00:00Z' });
ok(t().some((x) => /^high Prefetch is disabled/.test(x)), 'EnablePrefetcher = 0 changed during the attack window is high');
ok(!t().some((x) => /Prefetch file\(s\) although/.test(x)), 'no "Prefetch wiped" finding when Prefetch is switched off');
ok(t().some((x) => /Execution evidence not collected: Prefetch, ShimCache, Amcache, SRUM/.test(x)), 'missing artifacts listed with where to collect them');

// 3. Prefetch folder almost empty while plenty ran elsewhere
ctx = new Context(); ctx.hosts.add('WKS1');
ctx.evidence({ artifact: 'Prefetch', path: 'C:\\Windows\\System32\\cmd.exe', time: '2026-03-05T12:00:00Z', lastRuns: ['2026-03-05T12:00:00Z'], runCount: 1, file: 'C/Windows/Prefetch/CMD.EXE-1.pf' });
for (let i = 0; i < 25; i++) ctx.evidence({ artifact: 'SRUM', path: `C:\\Apps\\a${i}.exe`, first: '2026-03-05T12:00:00Z', last: '2026-03-05T12:00:00Z', sent: 10, recv: 10, file: 'C/Windows/System32/sru/SRUDB.dat' });
analyseExecution(ctx, files, {});
ok(t().some((x) => /^high Only 1 Prefetch file\(s\) although 25 programs/.test(x)), 'nearly empty Prefetch with execution everywhere else is high');
console.log(fail ? `${fail} failure(s)` : 'execution evidence checks passed');
process.exit(fail ? 1 : 0);
