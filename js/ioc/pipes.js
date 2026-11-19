// Named pipe intelligence shared by EVTX (Sysmon 17/18) and Volatility 3
// (windows.handles / windows.filescan). Three layers:
//   1. default pipe names of known offensive tools (Cobalt Strike, PsExec
//      clones, Impacket, Covenant, PoshC2 ...)
//   2. behaviour patterns that do not depend on a name: Potato / PrintSpoofer
//      nested pipe impersonation, PowerShell hosted inside a non-PowerShell
//      process (PSHost.* pipes), random-looking pipes held by processes that
//      should not be serving pipes
//   3. an allowlist of common legitimate pipes so the random-name check stays
//      quiet on browsers, .NET, Office, VMware and Windows services.

const KNOWN = [
  { rx: /^msagent_[0-9a-f]{1,4}$/i, tool: 'Cobalt Strike SMB beacon (default)', sev: 'critical', mitre: ['T1090.001', 'T1021.002'] },
  { rx: /^MSSE-\d+-server$/i, tool: 'Cobalt Strike artifact kit (default)', sev: 'critical', mitre: ['T1559'] },
  { rx: /^postex_(ssh_)?[0-9a-f]{3,4}$/i, tool: 'Cobalt Strike post-exploitation job (default)', sev: 'critical', mitre: ['T1559'] },
  { rx: /^status_[0-9a-f]{1,2}$/i, tool: 'Cobalt Strike (default status pipe)', sev: 'high', mitre: ['T1559'] },
  { rx: /^mojo\.5688\.8052\./i, tool: 'Cobalt Strike malleable profile imitating Chrome', sev: 'critical', mitre: ['T1559', 'T1036'] },
  { rx: /^(?:ntsvcs|scerpc|wkssvc|spoolss|samr|interprocess|demoagent|isapi_http|isapi_dg)_?[0-9a-f]{2,}$|^(?:win_svc|winsession|DserNamePipe\w*)$/i, tool: 'Cobalt Strike malleable profile pipe name', sev: 'high', mitre: ['T1559', 'T1036'] },
  { rx: /^RemCom_communica/i, tool: 'RemCom / Impacket psexec.py', sev: 'critical', mitre: ['T1569.002', 'T1021.002'] },
  { rx: /^PSEXESVC/i, tool: 'PsExec', sev: 'high', mitre: ['T1569.002', 'T1021.002'] },
  { rx: /^PAExec/i, tool: 'PAExec', sev: 'high', mitre: ['T1569.002', 'T1021.002'] },
  { rx: /^csexecsvc/i, tool: 'CSExec', sev: 'high', mitre: ['T1569.002', 'T1021.002'] },
  { rx: /^gruntsvc$/i, tool: 'Covenant Grunt (default)', sev: 'critical', mitre: ['T1090.001'] },
  { rx: /^jaccdpqnvbrrxlaf$/i, tool: 'PoshC2 (default)', sev: 'critical', mitre: ['T1090.001'] },
  { rx: /^msf-pipe/i, tool: 'Metasploit named pipe payload (default)', sev: 'critical', mitre: ['T1090.001', 'T1055'] },
  { rx: /^(mimikatz|kekeo|lsadump)/i, tool: 'Credential dumping tool', sev: 'critical', mitre: ['T1003'] },
  { rx: /^(RoguePotato|JuicyPotato|SweetPotato|GodPotato|EfsPotato|PrintSpoofer)/i, tool: 'Potato / PrintSpoofer privilege escalation', sev: 'critical', mitre: ['T1134.001'] },
];

// common legitimate pipes (prefix match on the name after \Device\NamedPipe\)
const LEGIT = /^(mojo\.\d+\.\d+\.\d+|crashpad_|chrome\.|chromium|gecko-crash-server-pipe|cubeb-pipe|CoreFxPipe_|dotnet-diagnostic-|clr-debug-pipe|LOCAL\\|Winsock2\\|PIPE_EVENTROOT|MsFteWds|Sessions\\|wkssvc$|srvsvc$|lsass$|ntsvcs$|epmapper$|InitShutdown$|atsvc$|eventlog$|spoolss$|samr$|netlogon$|lsarpc$|scerpc$|svcctl$|winreg$|protected_storage$|W32TIME_ALT$|TermSrv_API_service|Ctx_WinStation_API_service|SearchTextHarvester|GoogleCrashServices|openssh-ssh-agent|ProtectedPrefix|vgauth-service|vmware-|VBox|OfficeClickToRun|Microsoft\.|MicrosoftEdge|edge\.|discord-ipc-|docker_engine|uv_|PSHost\.|python|tapsrv|ROUTER$|RpcProxy|SQLLocal|sql\\query|MSSQL\$|AppContracts_|TSVCPIPE-|iisipm|IISFCGI-|WiFiNetworkManager|dbxsvc|Adobe|AcroCEF|zoom|Slack|Teams|ms-teams|onedrive|OneDrive|GoogleUpdate|nvcontainer|NVIDIA|amdfendr|AmdPpm|LogiOptions|Steam|Spotify|keybase|1Password|Dropbox|BraveCrashpad|firefox-|Firefox|wpcap|npcap|Global\\|Anonymous Pipe|$)/i;

// processes that rarely serve named pipes; Cobalt Strike and friends spawn into these
const ODD_OWNERS = /^(rundll32|regsvr32|mshta|wscript|cscript|msbuild|installutil|regasm|regsvcs|notepad|werfault|wuauclt|gpupdate|searchprotocolhost|dllhost|msiexec|cmstp|calc|mspaint|write)\.exe$/i;
const USER_PATH = /\\(users|documents and settings)\\|\\programdata\\|\\windows\\temp\\|\\perflogs\\|\\\$recycle\.bin\\|\\appdata\\/i;
const PS_HOSTS = /^(powershell|pwsh|powershell_ise|wsmprovhost|sqlps|sqlagent|devenv|code|azuredatastudio|exchangemanagementshell|microsoft\.exchange\.\w+|w3wp|scriptrunner|sdiagnhost|mmc|msmpeng|senseir|mssense|ccmexec|intunemanagementextension|agentexecutor|monitoringhost|healthservice|dsc_?\w*|windowsterminal|wt|openconsole)$/i;

export const normPipe = (raw) => String(raw || '').replace(/^\\?Device\\NamedPipe\\|^\\\\\.\\pipe\\|^\\+/i, '');

function looksRandom(n) {
  if (n.includes('\\') || n.length < 6 || n.length > 40) return false;
  if (/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(n)) return true; // bare GUID
  if (!/^[A-Za-z0-9_-]+$/.test(n)) return false;
  const letters = n.replace(/[^a-z]/gi, '');
  const digits = n.replace(/\D/g, '').length;
  if (letters.length >= 8 && !digits) return (letters.match(/[aeiou]/gi) || []).length / letters.length < 0.2; // consonant soup
  return digits >= 2 && letters.length >= 3 && !/^[a-z]+[_-]?\d{1,6}$/i.test(n) && /[a-z]\d|\d[a-z]/i.test(n);
}

/**
 * Grade one named pipe.
 * @param {string} raw pipe name in any of the usual forms
 * @param {{name?: string, path?: string, pid?: number|string}} owner process holding the pipe, if known
 * @returns {null | {sev, title, detail, mitre, category, tool?}}
 */
export function classifyPipe(raw, owner = {}) {
  const pipe = normPipe(raw);
  if (!pipe) return null;
  const who = owner.name ? `${owner.name}${owner.pid != null ? ` (PID ${owner.pid})` : ''}` : 'unknown process';

  // nested \pipe\ = a client was tricked into connecting to an attacker pipe so its token can be impersonated
  const nest = pipe.match(/(^|\\)pipe\\(spoolss|srvsvc|epmapper|lsarpc|samr|netlogon|efsrpc|lsass)$/i);
  if (nest && pipe.toLowerCase() !== nest[2].toLowerCase()) return { sev: 'critical', category: 'Privilege Escalation', mitre: ['T1134.001', 'T1068'], title: `Pipe impersonation (Potato / PrintSpoofer style): \\${pipe}`, detail: `A pipe ending in \\pipe\\${nest[2]} inside another pipe name is the trick PrintSpoofer, RoguePotato, GodPotato and EfsPotato use to make SYSTEM connect and steal its token. Held by ${who}.` };

  for (const k of KNOWN) if (k.rx.test(pipe)) return { sev: k.sev, category: /T1569|T1021/.test(k.mitre.join()) ? 'Lateral Movement' : /T1134|T1003/.test(k.mitre.join()) ? 'Credential Access' : 'Command and Control', mitre: k.mitre, tool: k.tool, title: `Named pipe of ${k.tool}: \\${pipe}`, detail: `Default or well known pipe name. Held by ${who}.` };

  // PSHost.<filetime>.<pid>.DefaultAppDomain.<host> is created by every process that loads the PowerShell engine
  const ps = pipe.match(/^PSHost\.\d+\.(\d+)\.DefaultAppDomain\.(.+)$/i);
  if (ps) {
    const host = ps[2].replace(/\.exe$/i, '');
    if (!PS_HOSTS.test(host)) return { sev: 'high', category: 'Execution', mitre: ['T1059.001', 'T1055'], title: `PowerShell engine loaded inside ${host}.exe (PID ${ps[1]})`, detail: `PSHost pipes reveal which process is running PowerShell. ${host}.exe is not a PowerShell host, so this is unmanaged PowerShell: Cobalt Strike powerpick, PowerShell injected into another process, or a custom loader. Script block logging (4104) may still show the code.` };
    return null;
  }

  if (LEGIT.test(pipe)) return null;

  const on = String(owner.name || '').toLowerCase();
  const oddOwner = ODD_OWNERS.test(on);
  const userOwner = owner.path && USER_PATH.test(owner.path);
  const rnd = looksRandom(pipe);
  if (oddOwner || userOwner) {
    const why = oddOwner ? `${owner.name} rarely serves named pipes, but it is the default process Cobalt Strike and similar frameworks spawn into` : `the owning program runs from a user-writable folder (${owner.path})`;
    return { sev: rnd ? 'high' : 'medium', category: 'Command and Control', mitre: ['T1090.001', 'T1559'], title: `${rnd ? 'Random-looking named pipe' : 'Named pipe'} \\${pipe} held by ${who}`, detail: `Named pipes carry SMB beacon traffic and post-exploitation job output. Here ${why}.` };
  }
  return null; // random names alone are too common to report without a suspicious owner
}

/** Pull pipe names out of free text (command lines, scripts). */
export const pipesInText = (s) => [...String(s || '').matchAll(/\\\\\.\\pipe\\([^\s"'<>|]+)/gi)].map((m) => m[1]);
