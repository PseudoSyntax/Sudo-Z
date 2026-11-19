// VirusTotal lookups: value recognition, verdicts, and that nothing is sent without a click.
import { kindOf, verdict, summarise, refang, isHash, isDomain, isIp, isUrl, lookup } from '../js/ioc/vt.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };

// ---------------------------------------------------------------- what each value is
for (const [v, kind, path] of [
  ['44d88612fea8a8f36de82e1278abb02f', 'file', 'files/44d88612fea8a8f36de82e1278abb02f'],
  ['3395856ce81f2b7382dee72602f798b642f14140', 'file', 'files/3395856ce81f2b7382dee72602f798b642f14140'],
  ['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'file', 'files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'],
  ['evil.example.com', 'domain', 'domains/evil.example.com'],
  ['203.0.113.9', 'ip_address', 'ip_addresses/203.0.113.9'],
]) { const k = kindOf(v); ok(k && k.kind === kind && k.path === path, `${v.slice(0, 24)} recognised as ${kind}`); }
ok(kindOf('http://bad.example.com/a').kind === 'url' && kindOf('http://bad.example.com/a').path === 'urls/aHR0cDovL2JhZC5leGFtcGxlLmNvbS9h', 'a URL is identified by its unpadded base64url, as the API expects');
ok(kindOf('not a thing') === null && kindOf('') === null, 'anything else is not offered a lookup');
ok(isHash('44d88612fea8a8f36de82e1278abb02f') && !isHash('44d88612fea8a8f36de82e1278abb02') && !isHash('zz') , 'hash lengths: 32, 40, 64 only');
ok(isDomain('a.co') && !isDomain('localhost') && !isDomain('-bad.com'), 'domain shape');
ok(isIp('10.0.0.1') && !isIp('999.1.1.1'), 'ipv4 shape');
ok(isUrl('https://x.y/z') && !isUrl('x.y/z'), 'url shape');

// defanged indicators still look up, because that is how Sudo-Z displays them
ok(refang('evil[.]example[.]com') === 'evil.example.com', 'refang [.]');
ok(refang('hxxps://bad[.]com/a') === 'https://bad.com/a', 'refang hxxps and [.]');
ok(kindOf('evil[.]example[.]com').value === 'evil.example.com', 'kindOf refangs before deciding');
ok(kindOf('203[.]0[.]113[.]9').kind === 'ip_address', 'a defanged IP is still an IP');

// ---------------------------------------------------------------- verdicts
ok(verdict({ malicious: 45, suspicious: 2, undetected: 20, harmless: 0, timeout: 0, total: 67 }).sev === 'critical', '45 malicious is critical');
ok(verdict({ malicious: 4, suspicious: 0, undetected: 60, harmless: 0, timeout: 0, total: 64 }).sev === 'high', '4 malicious is high');
ok(verdict({ malicious: 1, suspicious: 1, undetected: 60, harmless: 0, timeout: 0, total: 62 }).sev === 'medium', '1 malicious is medium, not critical: single-engine hits are often wrong');
ok(verdict({ malicious: 0, suspicious: 0, undetected: 70, harmless: 2, timeout: 0, total: 72 }).sev === 'low', 'no detections reads as clean, with the engine count');
ok(verdict(null).text === 'not in VirusTotal' && verdict({ total: 0 }).sev === 'info', 'nothing known is stated as such, not as clean');

// ---------------------------------------------------------------- the response summary
const fileResp = { data: { attributes: {
  last_analysis_stats: { malicious: 56, suspicious: 1, undetected: 9, harmless: 0, timeout: 0 },
  md5: '44d88612fea8a8f36de82e1278abb02f', sha1: '3395856ce81f2b7382dee72602f798b642f14140',
  sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', vhash: '0150d6c5e4cc', authentihash: 'aa',
  ssdeep: '3:a:b', tlsh: 'T1xx', pe_info: { imphash: 'ff', rich_pe_header_hash: 'ee' },
  size: 68, type_description: 'Win32 EXE', first_submission_date: 1300000000, last_analysis_date: 1700000000,
  popular_threat_classification: { suggested_threat_label: 'trojan.eicar/test', popular_threat_name: [{ value: 'eicar' }] },
  names: ['eicar.com', 'test.txt'], tags: ['peexe'],
  last_analysis_results: { Alpha: { category: 'malicious', result: 'EICAR-Test' }, Beta: { category: 'undetected', result: null }, Gamma: { category: 'suspicious', result: 'Heur' } },
} } };
const fs_ = summarise('file', fileResp);
ok(fs_.malicious === 56 && fs_.total === 66, 'engine counts and total');
ok(fs_.hashes.length === 9 && fs_.hashes.some(([k]) => k === 'Imphash') && fs_.hashes.some(([k]) => k === 'Rich PE header hash') && fs_.hashes.some(([k]) => k === 'SSDEEP') && fs_.hashes.some(([k]) => k === 'TLSH'), 'all nine hash variations, including imphash, rich header, ssdeep and tlsh');
ok(fs_.label === 'trojan.eicar/test' && fs_.families.join() === 'eicar', 'threat label and family');
ok(fs_.engines.length === 2 && fs_.engines.every((e) => /Alpha|Gamma/.test(e)), 'only the engines that flagged it are listed');
ok(/^2011-03-/.test(fs_.firstSeen) && /^2023-11-/.test(fs_.lastSeen), 'dates converted from epoch seconds');
const ds = summarise('domain', { data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 0, undetected: 60, harmless: 10, timeout: 0 }, registrar: 'Reg Ltd', categories: { x: 'malware' }, as_owner: 'AS1', country: 'RU' } } });
ok(ds.malicious === 3 && ds.registrar === 'Reg Ltd' && ds.categories[0] === 'x: malware' && ds.country === 'RU', 'domain summary keeps registrar, categories and country');
ok(!ds.hashes, 'hash variations are only added for files');
ok(summarise('file', {}).total === 0, 'an empty response does not throw');

// ---------------------------------------------------------------- nothing is sent without a key or a click
let called = 0;
globalThis.fetch = async () => { called++; throw new TypeError('should not be called'); };
const r = await lookup('44d88612fea8a8f36de82e1278abb02f', { key: '' });
ok(!r.ok && r.error === 'no API key' && called === 0, 'with no key, no request is made at all');
ok(r.gui === 'https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f', 'and the VirusTotal page link is offered instead');
const r2 = await lookup('not a thing', { key: 'k'.repeat(64) });
ok(!r2.ok && called === 0, 'a value that is not a hash, domain, IP or URL is never sent');

globalThis.fetch = async (url, o) => { called++; ok(/\/api\/v3\/files\/44d88/.test(url) && o.headers['x-apikey'] === 'k'.repeat(64), 'the key goes in the x-apikey header, to the v3 API'); return { ok: true, status: 200, json: async () => fileResp }; };
called = 0;
const r3 = await lookup('44d88612fea8a8f36de82e1278abb02f', { key: 'k'.repeat(64) });
ok(called === 1 && r3.ok && r3.summary.malicious === 56 && r3.via === 'browser', 'one click, one request');
globalThis.fetch = async () => ({ ok: false, status: 404, json: async () => ({}) });
const r4 = await lookup('44d88612fea8a8f36de82e1278abb02f', { key: 'k'.repeat(64) });
ok(r4.ok && r4.notFound, '404 is reported as not known to VirusTotal, not as an error');
globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({}) });
ok(!(await lookup('44d88612fea8a8f36de82e1278abb02f', { key: 'k'.repeat(64) })).ok, 'a rejected key is an error');
globalThis.fetch = async () => ({ ok: false, status: 429, json: async () => ({}) });
ok(/rate limit/.test((await lookup('44d88612fea8a8f36de82e1278abb02f', { key: 'k'.repeat(64) })).error), 'the rate limit says what the free quota is');
globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
const r5 = await lookup('evil.example.com', { key: 'k'.repeat(64) });
ok(!r5.ok && /cross-origin|home install/.test(r5.error) && r5.gui, 'a CORS failure explains itself and still offers the page link');
let viaServer = 0;
globalThis.fetch = async (url) => { if (/virustotal/.test(url)) throw new TypeError('Failed to fetch'); viaServer++; return { ok: true, json: async () => ({ data: fileResp }) }; };
const r6 = await lookup('evil.example.com', { key: 'k'.repeat(64), local: true });
ok(viaServer === 1 && r6.ok && r6.via === 'home server', 'with the home install running, the lookup falls back through the local server');

console.log(fail ? `\n${fail} FAILED` : '\nall VirusTotal checks passed');
process.exit(fail ? 1 : 0);
