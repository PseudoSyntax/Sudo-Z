// Universal grep across every submitted file: premade patterns, own regexes, grep output modes.
import { searchStrings, buildMatcher, BUILTIN } from '../js/core/bsearch.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };
const enc = new TextEncoder();
const files = [
  { name: 'proxy.log', data: enc.encode('GET /panel.php HTTP/1.1\nHost: c2.example.ru\nMozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120\nclient 203.0.113.9 -> 198.51.100.7:8443\n') },
  { name: 'notes.txt', data: enc.encode('internal hosts 10.0.0.5 and 192.168.1.20\nmailto bob@corp.example.com\nCVE-2024-3400 patched\nsha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n') },
  { name: 'drop.ps1', data: enc.encode('rundll32.exe C:\\Users\\bob\\AppData\\Local\\Temp\\a.dll,Start\nhxxp://evil.example.com/stage2\nHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk\n') },
  { name: 'empty.dat', data: enc.encode('lorem ipsum dolor sit amet, nothing of interest\n') },
];
const base = { mode: 'builtin', patterns: [], query: '', min: 3, ascii: true, unicode: false, onlyMatch: true, caseSensitive: false, limit: 100000 };
const run = (o) => searchStrings(files, { ...base, ...o });
const vals = (r, pat) => r.rows.filter((x) => !pat || x[5] === pat).map((x) => x[4]);

// ---------------------------------------------------------------- premade patterns
let r = await run({ patterns: ['ipv4'] });
ok(vals(r, 'ipv4').includes('203.0.113.9') && vals(r, 'ipv4').includes('10.0.0.5'), 'ipv4 finds public and private addresses across files');
r = await run({ patterns: ['priv_ip'] });
ok(vals(r).sort().join() === '10.0.0.5,192.168.1.20', 'priv_ip finds only RFC1918 and friends');
r = await run({ patterns: ['url'] });
ok(vals(r).some((x) => /^hxxp:\/\/evil\.example\.com\/stage2$/.test(x)), 'url finds a defanged URL mid-string (url3986 only matches a whole string)');
r = await run({ patterns: ['domain'] });
ok(vals(r).includes('c2.example.ru') && vals(r).includes('evil.example.com'), 'domain finds bare host names');
r = await run({ patterns: ['port_url'] });
ok(vals(r).includes('198.51.100.7:8443'), 'port_url finds host:port');
r = await run({ patterns: ['email'] });
ok(vals(r).includes('bob@corp.example.com'), 'email');
r = await run({ patterns: ['cve'] });
ok(vals(r).join() === 'CVE-2024-3400', 'cve');
r = await run({ patterns: ['sha256'] });
ok(vals(r)[0]?.length === 64, 'sha256');
r = await run({ patterns: ['jwt'] });
ok(vals(r).length === 1 && vals(r)[0].startsWith('eyJhbGciOiJIUzI1NiJ9.'), 'jwt');
r = await run({ patterns: ['http_req'] });
ok(vals(r).some((x) => x.startsWith('GET /panel.php')) && vals(r).some((x) => /^Host:/.test(x)), 'http_req finds request lines and Host headers');
r = await run({ patterns: ['useragent'] });
ok(vals(r)[0]?.startsWith('Mozilla/5.0 (Windows NT 10.0'), 'useragent');
r = await run({ patterns: ['run_key'] });
ok(vals(r).some((x) => /currentversion\\run/i.test(x)), 'run_key finds autostart registry paths');
r = await run({ patterns: ['lolbin_cmd'] });
ok(vals(r).some((x) => /^rundll32\.exe /.test(x)), 'lolbin_cmd finds a LOLBin command line');
r = await run({ patterns: ['win_path'] });
ok(vals(r).some((x) => /Temp\\a\.dll/.test(x)), 'win_path');
for (const n of ['url', 'priv_ip', 'domain', 'onion', 'port_url', 'md5', 'sha1', 'sha256', 'jwt', 'cve', 'useragent', 'http_req', 'run_key', 'lolbin_cmd', 'b64_blob', 'implant']) ok(!!BUILTIN[n] && BUILTIN[n][0].length > 10, `${n} is listed with a description`);

// ---------------------------------------------------------------- several patterns at once, and your own regex alongside
r = await run({ patterns: ['ipv4', 'cve', 'email'] });
ok(new Set(r.rows.map((x) => x[5])).size === 3, 'three premade patterns in one pass, each hit labelled with its pattern');
r = await run({ patterns: ['ipv4'], query: 'panel\\.php' });
ok(r.rows.some((x) => x[5] === 'custom' && x[4] === 'panel.php') && r.rows.some((x) => x[5] === 'ipv4'), 'own regex ORed with the ticked patterns');
r = await run({ mode: 'regex', query: 'evil\\.example\\.com\nc2\\.example\\.ru' });
ok(r.rows.length === 2 && new Set(r.rows.map((x) => x[5])).size === 2 && r.rows.every((x) => /^lr\d?$/.test(x[5])), 'regex mode takes one pattern per line, each labelled separately');
ok(buildMatcher({ mode: 'builtin', patterns: [], query: '' })('anything') === null, 'no pattern at all matches nothing rather than everything');

// ---------------------------------------------------------------- grep output modes
r = await run({ patterns: ['ipv4'], output: 'files' });
ok(r.output === 'files' && r.columns[0] === 'File' && r.rows.length === 2 && r.rows.every((x) => x[1] > 0), 'files with matches (-l): one row per file, worst first');
ok(!r.rows.some((x) => x[0] === 'empty.dat'), 'a file with no hit is not listed');
r = await run({ patterns: ['domain', 'ipv4'], output: 'count' });
ok(r.output === 'count' && r.rows[0][2].includes('('), 'count per file (-c) breaks the total down by pattern');
r = await run({ patterns: ['ipv4'], invert: true, min: 8 });
ok(r.rows.length && r.rows.every((x) => !/\b\d+\.\d+\.\d+\.\d+\b/.test(x[4])) && r.rows.every((x) => x[5] === 'not matched'), 'invert (-v) keeps only the strings that match nothing');

// ---------------------------------------------------------------- scoping
r = await run({ patterns: ['ipv4'], fileFilter: 'notes' });
ok(r.rows.length && r.rows.every((x) => x[0] === 'notes.txt'), 'file filter narrows the search to matching names');
r = await run({ patterns: ['ipv4'], fileFilter: '\\.(log|txt)$' });
ok(new Set(r.rows.map((x) => x[0])).size === 2, 'the file filter takes a regex too');
r = await run({ patterns: ['ipv4'], limit: 2 });
ok(r.rows.length === 2 && r.truncated, 'the result limit stops the scan and says so');
r = await run({ patterns: ['ipv4'], onlyMatch: false });
ok(r.rows.some((x) => x[4].length > 20), 'with "only the match" off, the whole containing string comes back as context');

console.log(fail ? `\n${fail} FAILED` : '\nall grep checks passed');
process.exit(fail ? 1 : 0);
