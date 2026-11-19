// Suspicious ports, judged with their context rather than from a bare list.
import { classifyPort, portPatterns, PORTS, offStandard } from '../js/ioc/ports.js';
let fail = 0;
const ok = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'}  ${m}`); if (!c) fail++; };
const sev = (p, o) => classifyPort(p, o)?.sev;

// ---------------------------------------------------------------- the ports that are bad anywhere
ok(sev(4444, { owner: 'svchost.exe' }) === 'medium' && sev(4444, { owner: 'rk.exe', path: 'C:\\Users\\bob\\AppData\\Local\\Temp\\rk.exe' }) === 'critical', 'Metasploit 4444: notable from svchost, critical from a user folder');
ok(sev(50050, { owner: 'beacon.exe', path: 'C:\\Users\\bob\\beacon.exe' }) === 'critical', 'Cobalt Strike team server port is critical');
ok(classifyPort(50050, {}).why.length > 40, 'and it explains that a client reaching 50050 is an operator console');
for (const p of [9001, 9050, 9051, 9030]) ok(classifyPort(p, {}).cat === 'Command and Control' && /Tor/.test(classifyPort(p, {}).name), `Tor port ${p} is named`);
ok(sev(6667, { owner: 'cmd.exe' }) === 'critical', 'IRC from a LOLBin is critical');
ok(sev(3333, {}) === 'high' && classifyPort(3333, {}).mitre.includes('T1496'), 'stratum mining pool maps to resource hijacking');
ok(sev(69, {}) === 'high' && /no authentication/i.test(classifyPort(69, {}).why), 'TFTP is called out as unauthenticated');

// ---------------------------------------------------------------- context, not the number
ok(sev(445, { owner: 'explorer.exe', peerPrivate: true }) === 'low', 'SMB to the local network from explorer is ordinary');
ok(sev(445, { owner: 'rk.exe', path: 'C:\\ProgramData\\rk.exe', peerPrivate: true }) === 'high', 'SMB from a program in ProgramData is lateral movement even inside the network');
ok(sev(445, { owner: 'rundll32.exe', peerPrivate: false }) === 'critical', 'SMB out to a public address from rundll32 is critical');
ok(classifyPort(445, { owner: 'explorer.exe', peerPrivate: true }).reasons.some((r) => /normal traffic/.test(r)), 'and it says why it was lowered');
ok(classifyPort(445, { owner: 'rk.exe', peerPrivate: true }).reasons.some((r) => /not one that normally would/.test(r)), 'the local-network discount is for the program, not the subnet');
ok(sev(5985, { owner: 'wsmprovhost.exe', peerPrivate: true }) === 'low', 'WinRM between managed hosts is ordinary');
ok(sev(5985, { owner: 'mimikatz.exe', peerPrivate: true }) === 'high', 'WinRM from a program that has no business speaking it is raised');
ok(sev(3389, { owner: 'mstsc.exe', peerPrivate: true }) === 'low' && sev(3389, { owner: 'mstsc.exe', peerPrivate: false }) === 'high', 'RDP: mstsc to the local network is ordinary, straight out to the internet is high');
ok(sev(3389, { owner: 'rk.exe', path: 'C:\\Users\\b\\rk.exe', peerPrivate: true }) === 'high', 'RDP from a user folder binary is high even inside the network');
ok(sev(22, { owner: 'ssh.exe' }) === 'low' && sev(22, { owner: 'svc.exe', path: 'C:\\Users\\a\\AppData\\svc.exe' }) === 'high', 'SSH from ssh.exe is fine, from a user folder binary it is a tunnel');
ok(classifyPort(22, {}).why.includes('-R'), 'and the SSH note says to check for -R or -D');
ok(sev(4444, { peerIsLoopback: true }) === undefined, 'a process talking to itself on loopback is not a network finding');
ok(classifyPort(443, { owner: 'chrome.exe' }) === null && classifyPort(80, {}) === null, 'ordinary web ports produce nothing');
ok(classifyPort(0, {}) === null && classifyPort(70000, {}) === null && classifyPort('x', {}) === null, 'nonsense port numbers are ignored');

// ---------------------------------------------------------------- listeners
ok(sev(31337, { listening: true, owner: 'svc.exe' }) === 'critical', 'a listener on a known backdoor port');
const hp = classifyPort(52101, { listening: true, owner: 'update.exe', path: 'C:\\Users\\bob\\AppData\\Roaming\\update.exe' });
ok(hp && hp.sev === 'medium' && /backdoor until shown otherwise/.test(hp.why), 'an unlisted high port listener from a user folder is still reported');
const hp2 = classifyPort(52101, { listening: true, owner: 'rundll32.exe', path: 'C:\\Users\\bob\\x.exe' });
ok(hp2 && hp2.sev === 'high', 'the same listener from a LOLBin in a user folder is higher');
ok(classifyPort(52101, { listening: true, owner: 'chrome.exe', path: 'C:\\Program Files\\Google\\chrome.exe' }) === null, 'a browser listening on a high port is not reported');
ok(classifyPort(52101, { owner: 'update.exe', path: 'C:\\Users\\bob\\update.exe' }) === null, 'the same port as an outbound connection is not reported: only listeners');

// ---------------------------------------------------------------- patterns no single row shows
const scan = portPatterns([...Array(30)].map((_, i) => ({ peer: '10.0.0.5', port: 1000 + i, owner: 'scan.exe', time: '2026-03-05T12:00:00Z' })));
ok(scan.length === 1 && scan[0].kind === 'scan' && scan[0].sev === 'high' && /30 different ports on 10\.0\.0\.5/.test(scan[0].title), 'many ports on one host is a port scan');
ok(scan[0].mitre.includes('T1046'), 'mapped to network service discovery');
const sweep = portPatterns([...Array(14)].map((_, i) => ({ peer: `10.0.0.${i + 1}`, port: 445, owner: 'rk.exe', time: '2026-03-05T12:00:00Z' })));
ok(sweep.length === 1 && sweep[0].kind === 'sweep' && sweep[0].sev === 'high' && /SMB 445 sweep/.test(sweep[0].title) && sweep[0].mitre.includes('T1021'), 'many hosts on 445 is lateral movement, not just discovery');
const sweep2 = portPatterns([...Array(12)].map((_, i) => ({ peer: `10.0.0.${i + 1}`, port: 8080, owner: 'x.exe', time: '' })));
ok(sweep2[0].sev === 'medium' && sweep2[0].mitre.includes('T1046'), 'many hosts on an ordinary port is a sweep at medium');
ok(portPatterns([{ peer: '10.0.0.5', port: 445, owner: 'a' }]).length === 0, 'one connection is not a pattern');
ok(portPatterns([...Array(30)].map((_, i) => ({ peer: '10.0.0.5', port: 1000 + i, owner: 'a', listening: true }))).length === 0, 'listeners are not counted as scanning');

// ---------------------------------------------------------------- off-standard service ports
ok(offStandard('rdp', 4433).expect === 3389 && offStandard('rdp', 3389) === null, 'a service answering off its own port is flagged');

// ---------------------------------------------------------------- the table itself
ok(Object.keys(PORTS).length >= 45, `${Object.keys(PORTS).length} ports described`);
ok(Object.values(PORTS).every((p) => p.name && p.base && p.cat && Array.isArray(p.mitre) && p.mitre.length), 'every entry has a name, a base severity, a category and a MITRE technique');

// ---------------------------------------------------------------- end to end through the engine
const fs = await import('node:fs');
const { analyze } = await import('../js/engine.js');
const dir = new URL('./fixtures/vol-ports/', import.meta.url);
const rep = await analyze(fs.readdirSync(dir).map((n) => ({ name: n, data: new Uint8Array(fs.readFileSync(new URL(n, dir))) })));
const t = rep.findings.map((f) => `${f.sev} ${f.title}`);
const hit = (rx, m) => ok(t.some((x) => rx.test(x)), m);
hit(/critical .*rk_agent\.exe connected out on port 4444 \(Metasploit \/ meterpreter default\)/, 'netscan: Metasploit port from a Temp binary is critical');
hit(/critical .*connected out on port 50050 \(Cobalt Strike team server\)/, 'netscan: Cobalt Strike team server port');
hit(/critical .*rundll32\.exe connected out on port 9050 \(Tor SOCKS\)/, 'netscan: Tor from a LOLBin');
hit(/critical .*rk_agent\.exe is listening on port 31337/, 'netscan: a backdoor port listener');
hit(/high .*rk_agent\.exe connected out on port 445 \(SMB\)/, 'netscan: SMB from a Temp binary is high even to the local network');
hit(/low .*explorer\.exe connected out on port 445 \(SMB\)/, 'netscan: the same port from explorer stays low');
hit(/high .*SMB 445 sweep: rk_agent\.exe reached 15 hosts/, 'netscan: the sweep across 15 hosts');
hit(/high .*Port scan: rk_agent\.exe reached 30 different ports on 10\.0\.2\.9/, 'netscan: the scan across 30 ports');
ok(!t.some((x) => /chrome\.exe.*port 443/.test(x)), 'chrome on 443 produces nothing at all');
const dup = t.filter((x) => /rk_agent\.exe connected out on port 445/.test(x));
ok(dup.length === 1, `the same process and port is reported once, not once per connection (got ${dup.length})`);
const one = rep.findings.find((f) => /port 4444/.test(f.title));
ok(one && one.mitre.includes('T1571') && /Here: /.test(one.detail) && /PID 3010/.test(one.evidence), 'the finding carries the technique, the reasoning and the evidence');

console.log(fail ? `\n${fail} FAILED` : '\nall port checks passed');
process.exit(fail ? 1 : 0);
