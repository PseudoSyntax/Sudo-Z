// Ports, judged with their context rather than from a list.
//
// A port number on its own is weak evidence. 445 outbound is what a domain joined
// workstation does all day; 445 outbound from a binary in Temp is lateral movement.
// 4444 is suspicious wherever it appears. So every check here takes who opened the
// socket, which way it goes, and whether the peer is on the local network.

const C2 = 'Command and Control', LAT = 'Lateral Movement', EXF = 'Exfiltration', REC = 'Discovery';

/**
 * port -> what it is. base is the severity for an outbound connection to a public
 * address by an ordinary process; the callers raise or lower it from there.
 */
export const PORTS = {
  // offensive tooling defaults. These are the ones worth waking someone for.
  4444: { name: 'Metasploit / meterpreter default', base: 'high', cat: C2, mitre: ['T1571'], why: 'The default LPORT for msfvenom and the Metasploit handler. Almost nothing legitimate listens here.' },
  4445: { name: 'Metasploit second stage', base: 'high', cat: C2, mitre: ['T1571'] },
  50050: { name: 'Cobalt Strike team server', base: 'critical', cat: C2, mitre: ['T1571'], why: 'The team server port. A client talking to 50050 is an operator console; a beacon normally would not, so this usually means the host is the attacker\'s, or someone is testing from it.' },
  1337: { name: 'commonly used by offensive tooling', base: 'high', cat: C2, mitre: ['T1571'] },
  31337: { name: 'Back Orifice / elite, long used by backdoors', base: 'high', cat: C2, mitre: ['T1571'] },
  8888: { name: 'common alternate C2 and tooling port', base: 'medium', cat: C2, mitre: ['T1571'] },
  5555: { name: 'common C2, also Android adb', base: 'medium', cat: C2, mitre: ['T1571'] },
  6666: { name: 'common C2 and IRC botnet', base: 'high', cat: C2, mitre: ['T1571'] },
  9999: { name: 'common C2 and mining', base: 'medium', cat: C2, mitre: ['T1571'] },
  2222: { name: 'alternate SSH, common for tunnels', base: 'medium', cat: C2, mitre: ['T1572'] },
  1234: { name: 'common toy and backdoor port', base: 'medium', cat: C2, mitre: ['T1571'] },
  // Tor
  9001: { name: 'Tor OR', base: 'high', cat: C2, mitre: ['T1090.003'], why: 'Tor relay traffic. On a workstation this is either deliberate anonymised traffic or a payload reaching a hidden service.' },
  9030: { name: 'Tor directory', base: 'high', cat: C2, mitre: ['T1090.003'] },
  9050: { name: 'Tor SOCKS', base: 'high', cat: C2, mitre: ['T1090.003'] },
  9051: { name: 'Tor control', base: 'high', cat: C2, mitre: ['T1090.003'] },
  9150: { name: 'Tor Browser SOCKS', base: 'medium', cat: C2, mitre: ['T1090.003'] },
  // IRC, still used by commodity botnets
  6667: { name: 'IRC', base: 'high', cat: C2, mitre: ['T1071'], why: 'IRC from a workstation is rare now and remains a commodity botnet channel.' },
  6697: { name: 'IRC over TLS', base: 'high', cat: C2, mitre: ['T1071'] },
  // tunnels and proxies
  1080: { name: 'SOCKS proxy', base: 'medium', cat: C2, mitre: ['T1090'] },
  3128: { name: 'Squid / HTTP proxy', base: 'low', cat: C2, mitre: ['T1090'] },
  // lateral movement and remote management: normal inside a network, notable from the wrong process
  445: { name: 'SMB', base: 'medium', cat: LAT, mitre: ['T1021.002'], internalOk: true, why: 'Normal between a workstation and its file servers and domain controllers. From a binary in a user folder, or to many hosts at once, it is lateral movement.' },
  139: { name: 'NetBIOS session', base: 'medium', cat: LAT, mitre: ['T1021.002'], internalOk: true },
  135: { name: 'RPC endpoint mapper (WMI, DCOM, PsExec)', base: 'medium', cat: LAT, mitre: ['T1021.003', 'T1047'], internalOk: true },
  5985: { name: 'WinRM (HTTP)', base: 'medium', cat: LAT, mitre: ['T1021.006'], internalOk: true, why: 'PowerShell remoting. Legitimate in managed estates, and a favourite for moving between hosts.' },
  5986: { name: 'WinRM (HTTPS)', base: 'medium', cat: LAT, mitre: ['T1021.006'], internalOk: true },
  47001: { name: 'WinRM listener (legacy)', base: 'medium', cat: LAT, mitre: ['T1021.006'], internalOk: true },
  3389: { name: 'RDP', base: 'medium', cat: LAT, mitre: ['T1021.001'], internalOk: true, why: 'Outbound RDP from a workstation is worth explaining. To the internet it is worth explaining urgently.' },
  5900: { name: 'VNC', base: 'medium', cat: LAT, mitre: ['T1021.005'], internalOk: true },
  5938: { name: 'TeamViewer', base: 'medium', cat: C2, mitre: ['T1219'] },
  6129: { name: 'DameWare', base: 'medium', cat: C2, mitre: ['T1219'] },
  5631: { name: 'pcAnywhere data', base: 'medium', cat: C2, mitre: ['T1219'] },
  22: { name: 'SSH', base: 'medium', cat: C2, mitre: ['T1572'], why: 'Outbound SSH from a Windows workstation is often a tunnel. Check the command line for -R or -D.' },
  // clear text and legacy, interesting because data leaves readable
  21: { name: 'FTP', base: 'medium', cat: EXF, mitre: ['T1048.003'] },
  23: { name: 'Telnet', base: 'high', cat: LAT, mitre: ['T1021'] },
  69: { name: 'TFTP', base: 'high', cat: 'Ingress Tool Transfer', mitre: ['T1105'], why: 'No authentication and no encryption. Mostly seen when something is pulling a payload down.' },
  512: { name: 'rexec', base: 'high', cat: LAT, mitre: ['T1021'] },
  513: { name: 'rlogin', base: 'high', cat: LAT, mitre: ['T1021'] },
  514: { name: 'rsh / syslog', base: 'medium', cat: LAT, mitre: ['T1021'] },
  873: { name: 'rsync', base: 'medium', cat: EXF, mitre: ['T1048'] },
  // databases, which should not be reachable from a workstation
  1433: { name: 'MSSQL', base: 'medium', cat: LAT, mitre: ['T1210'], internalOk: true },
  3306: { name: 'MySQL', base: 'medium', cat: LAT, mitre: ['T1210'], internalOk: true },
  5432: { name: 'PostgreSQL', base: 'medium', cat: LAT, mitre: ['T1210'], internalOk: true },
  6379: { name: 'Redis', base: 'high', cat: LAT, mitre: ['T1210'], why: 'Redis is unauthenticated by default and is a routine way in.' },
  27017: { name: 'MongoDB', base: 'medium', cat: LAT, mitre: ['T1210'] },
  9200: { name: 'Elasticsearch', base: 'medium', cat: LAT, mitre: ['T1210'] },
  11211: { name: 'memcached', base: 'medium', cat: LAT, mitre: ['T1210'] },
  // mining pools (stratum)
  3333: { name: 'stratum mining pool', base: 'high', cat: 'Impact', mitre: ['T1496'] },
  7777: { name: 'stratum mining pool, also used by RATs', base: 'medium', cat: 'Impact', mitre: ['T1496'] },
  14444: { name: 'stratum mining pool', base: 'high', cat: 'Impact', mitre: ['T1496'] },
  45700: { name: 'stratum mining pool', base: 'high', cat: 'Impact', mitre: ['T1496'] },
};

// processes that legitimately open a lot of sockets on odd ports
const NET_OK = /^(chrome|msedge|firefox|iexplore|opera|brave|svchost|system|lsass|services|spoolsv|teams|ms-teams|slack|discord|zoom|outlook|onedrive|dropbox|steam|epicgameslauncher|node|java|javaw|python\d*|dotnet|docker|vmware|vmnat|teamviewer|anydesk|ssh|putty|code|devenv|nginx|httpd|w3wp|sqlservr|mongod|redis-server)(\.exe)?$/i;
// the few that should be making SMB, RPC and WinRM calls
const ADMIN_OK = /^(explorer|svchost|system|lsass|services|wmiprvse|mmc|net|net1|dfsrs|spoolsv|winlogon|taskhostw|searchprotocolhost|msiexec|wsmprovhost|powershell|pwsh|cmd|conhost|psexec|psexesvc|procexp\d*|sysmon\d*|teams|outlook|onedrive|mstsc|rdpclip|tsclient|vmconnect|sqlcmd|osql|bcp|mysql|psql|redis-cli|mongo|mongosh|dameware|vncviewer|winscp|robocopy|xcopy)(\.exe)?$/i;
const USER_PATH = /\\users\\|\\programdata\\|\\windows\\temp\\|\\appdata\\|\\\$recycle|\\perflogs\\|\\temp\\/i;
const LOLBIN = /^(powershell|pwsh|rundll32|regsvr32|mshta|certutil|bitsadmin|msbuild|installutil|regasm|regsvcs|wscript|cscript|wmic|curl|wget|notepad|calc|cmd|dllhost|odbcconf|forfiles|cmstp|hh|ieexec|msdt|presentationhost|xwizard)(\.exe)?$/i;

const UP = { info: 'low', low: 'medium', medium: 'high', high: 'critical', critical: 'critical' };
const DOWN = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

/**
 * @param port the remote port for an outbound connection, the local port for a listener
 * @param o {proto, listening, owner, path, peerPrivate, peerIsLoopback}
 * @returns {{port, name, sev, why, cat, mitre, reasons[]}|null}
 */
export function classifyPort(port, o = {}) {
  const p = Number(port);
  if (!p || p < 1 || p > 65535) return null;
  const { listening = false, owner = '', path = '', peerPrivate = false, peerIsLoopback = false } = o;
  const proc = String(owner || '').split(/[\\/]/).pop();
  const inUserPath = USER_PATH.test(String(path || ''));
  const known = PORTS[p];
  const reasons = [];
  if (peerIsLoopback) return null; // a process talking to itself is not a network finding

  if (!known) {
    // nothing in the list: a listener on a high port from a user folder is still worth saying
    if (listening && p >= 1024 && (inUserPath || (!NET_OK.test(proc) && LOLBIN.test(proc)))) {
      return { port: p, name: 'high port listener', sev: inUserPath && LOLBIN.test(proc) ? 'high' : 'medium', cat: C2, mitre: ['T1571'],
        why: 'A process is accepting connections on a high port. Nothing on a workstation normally listens except services you can name, so a listener from a user folder or a living off the land binary is a backdoor until shown otherwise.',
        reasons: [inUserPath ? 'the program lives in a user writable folder' : `${proc} does not normally listen`] };
    }
    return null;
  }

  let sev = known.base;
  // Inside the network these are ordinary admin traffic, but only when an ordinary admin
  // program is doing it. The discount is for the process, not the subnet.
  const expectedProc = ADMIN_OK.test(proc);
  if (known.internalOk && peerPrivate && expectedProc && !inUserPath) { sev = DOWN[sev]; reasons.push(`${proc} talking to the local network on this port is normal traffic`); }
  else if (known.internalOk && peerPrivate) reasons.push('the peer is on the local network, but the program doing it is not one that normally would');
  if (known.internalOk && !peerPrivate && !listening) { sev = UP[sev]; reasons.push('the peer is a public address, which this protocol has no business reaching'); }
  // who opened it matters more than the number
  if (inUserPath) { sev = UP[sev]; reasons.push('the program lives in a user writable folder'); }
  else if (LOLBIN.test(proc)) { sev = UP[sev]; reasons.push(`${proc} is a living off the land binary`); }
  else if (NET_OK.test(proc) && !inUserPath) { sev = DOWN[sev]; reasons.push(`${proc} opens network connections as part of its normal work`); }
  if (known.internalOk && proc && !expectedProc && !inUserPath) {
    sev = UP[sev]; reasons.push(`${proc} is not a program that normally speaks this protocol`);
  }
  if (listening && !NET_OK.test(proc)) { sev = UP[sev]; reasons.push(`${proc} is listening rather than connecting out`); }
  return { port: p, name: known.name, sev, cat: known.cat, mitre: known.mitre, why: known.why || '', reasons };
}

/**
 * Patterns across a set of connections that no single row shows.
 * @param conns [{peer, port, proto, owner, path, time, listening}]
 */
export function portPatterns(conns) {
  const out = [];
  const byOwnerHost = new Map(), byOwnerPort = new Map();
  for (const c of conns) {
    if (c.listening || !c.peer || !c.port) continue;
    const who = String(c.owner || '?');
    const a = byOwnerHost.get(`${who}|${c.peer}`) || { who, peer: c.peer, ports: new Set(), time: c.time };
    a.ports.add(Number(c.port)); byOwnerHost.set(`${who}|${c.peer}`, a);
    const b = byOwnerPort.get(`${who}|${c.port}`) || { who, port: Number(c.port), hosts: new Set(), time: c.time };
    b.hosts.add(c.peer); byOwnerPort.set(`${who}|${c.port}`, b);
  }
  for (const a of byOwnerHost.values()) {
    if (a.ports.size < 10) continue;
    out.push({ kind: 'scan', sev: a.ports.size >= 25 ? 'high' : 'medium', cat: REC, mitre: ['T1046'], time: a.time,
      title: `Port scan: ${a.who} reached ${a.ports.size} different ports on ${a.peer}`,
      detail: 'One process opening many ports on a single host is a port scan. Services do not behave this way.',
      evidence: [...a.ports].sort((x, y) => x - y).slice(0, 40).join(', ') });
  }
  for (const b of byOwnerPort.values()) {
    if (b.hosts.size < 10) continue;
    const k = PORTS[b.port];
    out.push({ kind: 'sweep', sev: b.hosts.size >= 25 || (k && /Lateral/.test(k.cat)) ? 'high' : 'medium', cat: k && /Lateral/.test(k.cat) ? LAT : REC, mitre: k && /Lateral/.test(k.cat) ? ['T1021'] : ['T1046'], time: b.time,
      title: `${k ? k.name + ' ' : 'Port '}${b.port} sweep: ${b.who} reached ${b.hosts.size} hosts on the same port`,
      detail: k && /Lateral/.test(k.cat)
        ? 'One process touching many hosts on a lateral movement port is how an operator finds somewhere to land, or how a worm spreads.'
        : 'One process touching many hosts on the same port is a network sweep.',
      evidence: [...b.hosts].slice(0, 30).join(', ') });
  }
  return out;
}

/** A service answering on a port that is not its own, which is how operators hide a listener. */
export function offStandard(service, port) {
  const expect = { rdp: 3389, winrm: 5985, smb: 445, ssh: 22, http: 80, https: 443, dns: 53 }[String(service).toLowerCase()];
  return expect && Number(port) !== expect ? { expect, got: Number(port) } : null;
}
