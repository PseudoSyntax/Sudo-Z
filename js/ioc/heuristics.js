// Shared heuristics. Every artifact that yields an executable path or command
// line runs through classifyPath / classifyCommand, so the same logic grades a
// Prefetch entry, a Run key, a 4688 event or a Sysmon 1 event.

const P = (s) => s.toLowerCase();

export const SUSPICIOUS_DIRS = [
  { rx: /\\users\\public\\/i, w: 3, label: 'Users\\Public' },
  { rx: /\\appdata\\local\\temp\\/i, w: 3, label: 'user Temp' },
  { rx: /\\windows\\temp\\/i, w: 3, label: 'Windows\\Temp' },
  { rx: /^(?:[a-z]:)?\\?(?:\\device\\harddiskvolume\d+)?\\?programdata\\[^\\]+\.(exe|dll|scr|bat|ps1|vbs|js|hta)$/i, w: 3, label: 'ProgramData root' },
  { rx: /\\\$recycle\.bin\\|\\recycler\\/i, w: 5, label: 'Recycle Bin', ext: /\.(exe|dll|scr|com|pif|cpl|sys|ps1|bat|cmd|vbs|vbe|js|jse|hta|msi)$/i },
  { rx: /\\perflogs\\/i, w: 4, label: 'PerfLogs', ext: /\.(exe|dll|scr|ps1|bat|cmd|vbs|js|hta|zip|7z|rar|dmp|txt|csv)$/i },
  { rx: /\\windows\\(debug|tracing|fonts|tasks|addins|media|cursors|registration|l2schemas)\\[^\\]+\.(exe|dll|scr|ps1|bat)$/i, w: 3, label: 'unusual Windows subfolder' },
  { rx: /\\appdata\\roaming\\[^\\]+\.(exe|dll|scr|bat|ps1|vbs|js)$/i, w: 3, label: 'AppData\\Roaming root' },
  { rx: /\\appdata\\local\\[^\\]+\.(exe|dll|scr|bat|ps1|vbs|js)$/i, w: 3, label: 'AppData\\Local root' },
  { rx: /\\downloads\\/i, w: 1, label: 'Downloads' },
  { rx: /\\desktop\\[^\\]+\.(exe|scr|bat|ps1|vbs|hta)$/i, w: 1, label: 'Desktop' },
  { rx: /\\appdata\\local\\microsoft\\windows\\inetcache\\|\\temporary internet files\\|\\content\.outlook\\/i, w: 3, label: 'browser/Outlook cache', ext: /\.(exe|dll|scr|com|pif|cpl|ps1|bat|cmd|vbs|vbe|jse|wsf|hta|msi|lnk|iso|img|jar)$/i },
  { rx: /\\system volume information\\/i, w: 3, label: 'System Volume Information' },
  { rx: /^\\\\[^\\]+\\(admin|c|ipc)\$/i, w: 3, label: 'admin share' },
  { rx: /^\\\\(tsclient|vboxsrv)\\/i, w: 2, label: 'redirected/host share' },
  { rx: /\\intel\\[^\\]+\.(exe|dll)$|\\(hp|dell|lenovo)\\[^\\]+\.exe$/i, w: 1, label: 'vendor-folder impersonation' },
];

// Living-off-the-land binaries worth surfacing when executed.
export const LOLBINS = new Set(['powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe', 'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'msiexec.exe', 'cmstp.exe', 'odbcconf.exe', 'msxsl.exe', 'pcalua.exe', 'forfiles.exe', 'esentutl.exe', 'expand.exe', 'extrac32.exe', 'hh.exe', 'ieexec.exe', 'infdefaultinstall.exe', 'mavinject.exe', 'presentationhost.exe', 'syncappvpublishingserver.exe', 'control.exe', 'csc.exe', 'vbc.exe', 'jsc.exe', 'dnscmd.exe', 'ftp.exe', 'replace.exe', 'scriptrunner.exe', 'xwizard.exe', 'atbroker.exe', 'bash.exe', 'wsl.exe', 'curl.exe', 'tar.exe', 'finger.exe', 'certreq.exe', 'desktopimgdownldr.exe', 'diskshadow.exe', 'ntdsutil.exe', 'vssadmin.exe', 'wbadmin.exe', 'bcdedit.exe', 'wevtutil.exe', 'schtasks.exe', 'at.exe', 'sc.exe', 'reg.exe', 'net.exe', 'net1.exe', 'netsh.exe', 'nltest.exe', 'dsquery.exe', 'whoami.exe', 'systeminfo.exe', 'tasklist.exe', 'taskkill.exe', 'qwinsta.exe', 'quser.exe', 'query.exe', 'arp.exe', 'nbtstat.exe', 'route.exe', 'ipconfig.exe', 'netstat.exe', 'klist.exe', 'setspn.exe', 'cipher.exe', 'fsutil.exe', 'icacls.exe', 'takeown.exe', 'attrib.exe', 'makecab.exe', 'msdt.exe', 'wuauclt.exe', 'appinstaller.exe', 'mpcmdrun.exe', 'adfind.exe', 'psexec.exe', 'psexec64.exe', 'psexesvc.exe', 'paexec.exe', 'winrs.exe', 'wmiprvse.exe']);

const DISCOVERY = new Set(['whoami.exe', 'systeminfo.exe', 'tasklist.exe', 'qwinsta.exe', 'quser.exe', 'query.exe', 'arp.exe', 'nbtstat.exe', 'route.exe', 'ipconfig.exe', 'netstat.exe', 'klist.exe', 'nltest.exe', 'dsquery.exe', 'setspn.exe', 'net.exe', 'net1.exe', 'adfind.exe']);

// Offensive tools, remote access and exfil utilities by file name.
export const TOOL_NAMES = [
  { rx: /^(mimikatz|mimi(drv|lib|katz)|kiwi|sekurlsa)(64|32|_x64)?\.(exe|dll|sys)$/i, sev: 'critical', label: 'Mimikatz' },
  { rx: /^(rubeus|kekeo|safetykatz|sharpkatz|sharphound|sharpup|seatbelt|sharpwmi|sharprdp|certify|whisker|sharpdpapi|sharpchrome|lazagne|nanodump|pypykatz|dumpert|handlekatz|ppldump|pplkiller)\.exe$/i, sev: 'critical', label: 'credential/AD offensive tool' },
  { rx: /^(psexesvc|paexec|remcom|csexec|smbexec|wmiexec|atexec|dcomexec)(.*)\.exe$/i, sev: 'high', label: 'remote execution service' },
  { rx: /^ps(exec|exec64|info|loggedon|kill|list|service|getsid|file)\.exe$/i, sev: 'medium', label: 'Sysinternals PsTools' },
  { rx: /^procdump(64)?\.exe$/i, sev: 'medium', label: 'ProcDump (LSASS dumping risk)' },
  { rx: /^(bloodhound|azurehound|adexplorer(64)?|adfind|pingcastle|ldapdomaindump|kerbrute|crackmapexec|cme|nxc|netexec|impacket.*|responder|inveigh|chisel|ligolo.*|frpc|frps|plink|ngrok|cloudflared|socat|ncat|nc|nc64|netcat|proxifier|iox|gost|rsocx|revsocks|stowaway)\.exe$/i, sev: 'high', label: 'discovery/tunnelling tool' },
  { rx: /^(advanced_ip_scanner.*|advanced_port_scanner.*|netscan(64)?|softperfect.*|angryip.*|ipscan.*|nmap|zenmap|masscan|lansweeper.*|rustscan)\.exe$/i, sev: 'medium', label: 'network scanner' },
  { rx: /^(rclone|megasync|megacmd.*|mega.*\.exe|filezilla|winscp|pscp|restic|s3browser.*|cyberduck|goodsync.*|freefilesync|syncthing)\.exe$/i, sev: 'medium', label: 'file transfer / exfil utility' },
  { rx: /^(anydesk|teamviewer.*|tv_w32|tv_x64|screenconnect.*|connectwisecontrol.*|splashtop.*|srservice|atera.*|ateraagent|rustdesk|meshagent|meshcentral.*|tightvnc.*|tvnserver|ultravnc.*|winvnc.*|logmein.*|remoteutilities.*|rutserv|rfusclient|netsupport.*|client32|ammyy.*|aa_v3|supremo.*|dwagent|zohoassist.*|simplehelp.*|level.*agent)\.exe$/i, sev: 'medium', label: 'remote access software' },
  { rx: /^(cobaltstrike|beacon|artifact(64)?|sliver.*|havoc|demon|metasploit|meterpreter|msfvenom|covenant|grunt|empire|brute ratel|badger|mythic|poshc2|merlin)\.(exe|dll)$/i, sev: 'critical', label: 'C2 framework artifact' },
  { rx: /^(7z|7za|7zr|rar|winrar)\.exe$/i, sev: 'low', label: 'archiver (possible staging)' },
  { rx: /^(defendercontrol|dcontrol|gmer|processhacker|systeminformer|pchunter(32|64)?|powertool(64)?|kprocesshacker|backstab|terminator|edrkillshifter|killav|av_kill.*|blackout|aukill)\.exe$/i, sev: 'high', label: 'security tool tampering utility' },
  { rx: /^(vssadmin|wbadmin|bcdedit|cipher)\.exe$/i, sev: 'low', label: 'backup/recovery utility' },
];

// Names of system binaries that should only live in System32/SysWOW64/WinSxS.
const SYSTEM_NAMES = new Set(['svchost.exe', 'lsass.exe', 'csrss.exe', 'smss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'spoolsv.exe', 'taskhost.exe', 'taskhostw.exe', 'conhost.exe', 'dllhost.exe', 'lsm.exe', 'rundll32.exe', 'regsvr32.exe', 'cmd.exe', 'powershell.exe', 'explorer.exe', 'searchindexer.exe', 'wmiprvse.exe', 'ctfmon.exe', 'dwm.exe', 'sihost.exe', 'runtimebroker.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe', 'notepad.exe', 'calc.exe']);
const TYPO = /^(scvhost|svchosts|svch0st|svhost|svchost32|lsas|lsasss|lssas|isass|1sass|csrrs|crss|smsss|wininnit|winlogin|winlog0n|servics|spoolsvc|taskhosts|expl0rer|exploer|explorere|iexplorer|rundl32|rundll|regsrv32|powershel|powershell32)\.exe$/i;

const EXEC_EXT = /\.(exe|dll|scr|com|pif|cpl|sys|ocx|bat|cmd|ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|jar|lnk|iso|img|vhd|vhdx|one|chm|xll|appref-ms|application)$/i;
const DECOY_DOUBLE = /\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|zip|rar|mp4|mp3|csv|rtf)\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|hta|lnk|ps1|msi|iso|img)$/i;

export const baseName = (p) => (p || '').replace(/["']/g, '').split(/[\\/]/).pop().trim();

/**
 * Grade a file path. Returns { score, reasons[], tool?, sev }
 */
export function expandPath(path) {
  return String(path || '').replace(/^"|"$/g, '').trim()
    .replace(/^\\\?\?\\|^\\\\\?\\/, '')
    .replace(/^(%systemroot%|%windir%|\\systemroot)(?=\\)/i, 'C:\\Windows')
    .replace(/^system32\\/i, 'C:\\Windows\\System32\\')
    .replace(/^%programfiles%/i, 'C:\\Program Files').replace(/^%programfiles\(x86\)%/i, 'C:\\Program Files (x86)')
    .replace(/^%programdata%/i, 'C:\\ProgramData').replace(/^%systemdrive%/i, 'C:');
}

// Known-benign noise that otherwise trips the directory rules.
const BENIGN_PATH = /\\is-[a-z0-9]{5}\.tmp\\|\\~setup\\|\\vmware-user\\|\\users\\public\\desktop\\[^\\]+\.lnk$|\\temp\\[^\\]*\\(windows-kb|ndp\d+|vcredist|dotnet)|\\microsoft\\edgeupdate\\|\\google\\update\\|\\appdata\\local\\microsoft\\(onedrive|teams|windowsapps)\\/i;

export function classifyPath(path) {
  const out = { score: 0, reasons: [], sev: null };
  if (!path) return out;
  const p = expandPath(path);
  const name = baseName(p).toLowerCase();
  for (const d of SUSPICIOUS_DIRS) if (!BENIGN_PATH.test(p) && !/\.lnk$/i.test(name) && d.rx.test(p) && (d.ext ? d.ext.test(name) : EXEC_EXT.test(name))) { out.score += d.w; out.reasons.push(`located in ${d.label}`); }
  for (const t of TOOL_NAMES) if (t.rx.test(name)) { out.tool = t.label; out.toolSev = t.sev; out.reasons.push(`file name matches ${t.label}`); out.score += { critical: 10, high: 6, medium: 3, low: 1 }[t.sev]; break; }
  if (DECOY_DOUBLE.test(name)) { out.score += 6; out.reasons.push('double extension decoy'); }
  if (/[\u202e\u200f]/.test(name)) { out.score += 8; out.reasons.push('right-to-left override in name'); }
  if (TYPO.test(name)) { out.score += 8; out.reasons.push('typosquats a Windows system binary'); }
  if (SYSTEM_NAMES.has(name) && /^(?:[a-z]:|\\device\\harddiskvolume\d+|\\volume\{[^}]+\}|%\w+%)?\\/i.test(p) &&
    !/\\windows\\(system32|syswow64|winsxs|servicing|softwaredistribution|prefetch|\$|ccmcache|ccm\\|temp\\[^\\]*\\(amd64|x86)|microsoft\.net|immersivecontrolpanel|systemapps)|\\windows\\explorer\.exe$|\\windows\\notepad\.exe$|\\windows\\(regedit|hh)\.exe$|\\windows\\splwow64\.exe$/i.test(p) && /\\/.test(p)) {
    out.score += 7; out.reasons.push(`${name} outside System32 (masquerading)`);
  }
  if (/^[a-f0-9]{8,}\.exe$|^[a-z]{1,2}\.exe$|^\d+\.exe$/i.test(name)) { out.score += 2; out.reasons.push('random/short executable name'); }
  if (/\.(exe|dll|scr)$/i.test(name) && /\\[^\\]*(update|patch|crack|keygen|activator|kms)[^\\]*\.exe$/i.test(p) && /temp|downloads|public/i.test(p)) { out.score += 2; out.reasons.push('update/crack themed executable in user-writable path'); }
  out.sev = out.score >= 8 ? 'high' : out.score >= 5 ? 'medium' : out.score >= 3 ? 'low' : null;
  if (out.toolSev === 'critical') out.sev = 'critical';
  else if (out.toolSev === 'high' && out.sev !== 'critical') out.sev = 'high';
  return out;
}

export const CMD_RULES = [
  { rx: /\s-(e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{16,}/i, w: 6, label: 'PowerShell encoded command', mitre: 'T1059.001' },
  { rx: /(iex|invoke-expression)\b.{0,80}(downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod|net\.webclient)/i, w: 8, label: 'PowerShell download-and-execute cradle', mitre: 'T1105' },
  { rx: /(new-object\s+(system\.)?net\.webclient|\.downloadfile\(|\.downloadstring\(|start-bitstransfer|invoke-webrequest|\biwr\b|\bwget\b\s+http|\bcurl(\.exe)?\b\s.{0,80}https?:\/\/)/i, w: 4, label: 'downloads content from the internet', mitre: 'T1105' },
  { rx: /-(w|wi|win|window|windowstyle)\s+(h|hid|hidden|1)\b/i, w: 3, label: 'hidden PowerShell window', mitre: 'T1564.003' },
  { rx: /-(ep|exec|executionpolicy)\s+(bypass|unrestricted)|-nop\b|-noprofile\b.{0,30}-(w|win)\s+h/i, w: 2, label: 'execution policy bypass / no profile', mitre: 'T1059.001' },
  { rx: /frombase64string|\[convert\]::|-bxor|\[char\]\s*\d+\s*\+|\breverse\b.{0,20}-join|gzipstream|deflatestream/i, w: 3, label: 'obfuscation / in-memory decoding', mitre: 'T1027' },
  { rx: /certutil(\.exe)?\s.{0,40}(-urlcache|-verifyctl|-decode|-encode|-split\s|-f\s+http)/i, w: 7, label: 'certutil used to download/decode', mitre: 'T1140' },
  { rx: /bitsadmin(\.exe)?\s.{0,40}\/(transfer|addfile|create|setnotifycmdline)/i, w: 6, label: 'BITS job download/persistence', mitre: 'T1197' },
  { rx: /mshta(\.exe)?\s+["']?(https?:|javascript:|vbscript:|\\\\)/i, w: 8, label: 'mshta executing remote/inline script', mitre: 'T1218.005' },
  { rx: /regsvr32(\.exe)?\s.{0,60}\/i:\s*https?:|regsvr32.{0,60}scrobj\.dll/i, w: 8, label: 'regsvr32 Squiblydoo (scrobj)', mitre: 'T1218.010' },
  { rx: /rundll32(\.exe)?\s.{0,40}(javascript:|mshtml,RunHTMLApplication|url\.dll,(OpenURL|FileProtocolHandler)|shdocvw\.dll,OpenURL|zipfldr\.dll,RouteTheCall|advpack\.dll,(RegisterOCX|LaunchINFSection)|pcwutl\.dll,LaunchApplication|ieadvpack|setupapi\.dll,InstallHinfSection|shell32\.dll,(ShellExec_RunDLL|Control_RunDLL)\s.{0,40}\\(temp|public|appdata))/i, w: 7, label: 'rundll32 proxy execution', mitre: 'T1218.011' },
  { rx: /rundll32(\.exe)?\s+[^,\s]+\\(temp|public|appdata|programdata|downloads)\\[^,]+,/i, w: 5, label: 'rundll32 loading DLL from user-writable path', mitre: 'T1218.011' },
  { rx: /comsvcs(\.dll)?\s*,?\s*#?(minidump|24)\b/i, w: 10, label: 'LSASS dump via comsvcs MiniDump', mitre: 'T1003.001' },
  { rx: /procdump(64)?(\.exe)?\s.{0,60}(lsass|-ma\s+\d{2,})/i, w: 10, label: 'ProcDump against LSASS', mitre: 'T1003.001' },
  { rx: /(sekurlsa::|lsadump::|kerberos::(golden|ptt)|privilege::debug|crypto::capi|token::elevate|misc::memssp)/i, w: 10, label: 'Mimikatz command syntax', mitre: 'T1003' },
  { rx: /vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?\s+shadowcopy\s+delete|win32_shadowcopy.{0,40}delete|wbadmin(\.exe)?\s+delete|bcdedit(\.exe)?.{0,40}(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)/i, w: 10, label: 'shadow copy / backup deletion (ransomware precursor)', mitre: 'T1490' },
  { rx: /vssadmin(\.exe)?\s+create\s+shadow|ntdsutil(\.exe)?.{0,40}(ifm|snapshot)|copy\s+.{0,40}\\(harddiskvolumeshadowcopy|globalroot).{0,60}(ntds\.dit|\\sam|\\system)/i, w: 9, label: 'NTDS.dit / hive theft via shadow copy', mitre: 'T1003.003' },
  { rx: /reg(\.exe)?\s+save\s+hklm\\(sam|system|security)/i, w: 9, label: 'registry hive dump (SAM/SYSTEM/SECURITY)', mitre: 'T1003.002' },
  { rx: /wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog|limit-eventlog/i, w: 9, label: 'event log clearing', mitre: 'T1070.001' },
  { rx: /\bnet1?(\.exe)?\s+user\s+\S+\s+\S+\s+\/add|new-localuser/i, w: 7, label: 'local account creation', mitre: 'T1136.001' },
  { rx: /\bnet1?(\.exe)?\s+(localgroup|group)\s+"?(administrators|domain admins|enterprise admins|remote desktop users)"?\s+\S+\s+\/add|add-localgroupmember/i, w: 8, label: 'user added to privileged group', mitre: 'T1098' },
  { rx: /schtasks(\.exe)?\s.{0,20}\/create/i, w: 4, label: 'scheduled task creation', mitre: 'T1053.005' },
  { rx: /\bsc(\.exe)?\s+(\\\\\S+\s+)?(create|config)\s/i, w: 4, label: 'service creation/modification', mitre: 'T1543.003' },
  { rx: /reg(\.exe)?\s+add\s.{0,80}\\(currentversion\\(run|runonce|policies\\explorer\\run)|winlogon|image file execution options|services\\)/i, w: 6, label: 'registry persistence via reg add', mitre: 'T1547.001' },
  { rx: /new-itemproperty.{0,120}\\currentversion\\run|set-itemproperty.{0,120}\\currentversion\\run/i, w: 6, label: 'Run key persistence via PowerShell', mitre: 'T1547.001' },
  { rx: /set-mppreference\s.{0,40}-(disable\w+|exclusion\w+)|add-mppreference\s.{0,20}-exclusion|mpcmdrun(\.exe)?\s.{0,20}-removedefinitions|sc(\.exe)?\s+(stop|delete|config)\s+(windefend|sense|wdboot|wdfilter|wdnissvc)/i, w: 9, label: 'Defender tampering', mitre: 'T1562.001' },
  { rx: /netsh(\.exe)?\s.{0,40}(advfirewall\s+set\s.{0,30}state\s+off|firewall\s+set\s+opmode\s+disable)/i, w: 7, label: 'firewall disabled', mitre: 'T1562.004' },
  { rx: /netsh(\.exe)?\s.{0,30}interface\s+portproxy\s+add/i, w: 8, label: 'netsh port forwarding (pivot/tunnel)', mitre: 'T1090' },
  { rx: /netsh(\.exe)?\s.{0,40}advfirewall\s+firewall\s+add\s+rule.{0,120}(3389|allow)/i, w: 4, label: 'firewall rule added', mitre: 'T1562.004' },
  { rx: /reg(\.exe)?\s+add\s.{0,80}terminal server.{0,40}fdenytsconnections.{0,30}\b0\b/i, w: 7, label: 'RDP enabled via registry', mitre: 'T1021.001' },
  { rx: /reg(\.exe)?\s+add\s.{0,80}wdigest.{0,40}uselogoncredential.{0,20}\b1\b/i, w: 9, label: 'WDigest cleartext credentials enabled', mitre: 'T1112' },
  { rx: /wmic(\.exe)?\s.{0,60}(\/node:|process\s+call\s+create)/i, w: 6, label: 'WMIC remote/process creation', mitre: 'T1047' },
  { rx: /invoke-wmimethod|invoke-cimmethod.{0,60}win32_process|\[wmiclass\]/i, w: 5, label: 'WMI process creation (PowerShell)', mitre: 'T1047' },
  { rx: /\\\\[^\\\s]+\\(admin|c)\$\\/i, w: 4, label: 'admin share access', mitre: 'T1021.002' },
  { rx: /\bpsexec(64)?(\.exe)?\s+.{0,20}\\\\|paexec|-accepteula\s.{0,40}\\\\/i, w: 6, label: 'PsExec style remote execution', mitre: 'T1569.002' },
  { rx: /(nltest(\.exe)?\s+\/(dclist|domain_trusts|dsgetdc)|net1?(\.exe)?\s+(group\s+"?domain admins"?|view\s+\/all|group\s+\/domain)|adfind(\.exe)?\s|dsquery(\.exe)?\s|get-addomain|get-adcomputer|get-netdomain|setspn(\.exe)?\s+-[tq]\s)/i, w: 3, label: 'Active Directory discovery', mitre: 'T1087.002' },
  { rx: /\bwhoami(\.exe)?\s+\/(all|priv|groups)|systeminfo|tasklist\s+\/v|quser|qwinsta|net1?(\.exe)?\s+(user|localgroup|session|share|use)\b/i, w: 1, label: 'host/user discovery', mitre: 'T1033' },
  { rx: /\bcmd(\.exe)?\s+\/[ckr]\s.{0,10}(echo|copy|move|del|start)\s.{0,80}(>|&&)/i, w: 1, label: 'cmd chained commands', mitre: 'T1059.003' },
  { rx: /(cmd|powershell)(\.exe)?\s.{0,40}\^.{0,5}\^|c\^m\^d|p\^o\^w|%comspec:~|set\s+\w+=.{0,40}&&\s*call\s+%/i, w: 5, label: 'cmd caret / variable obfuscation', mitre: 'T1027' },
  { rx: /\b(rclone(\.exe)?\s+(copy|sync|move)|megacmd|mega-put|curl(\.exe)?\s.{0,40}-(T|F|-upload-file|d\s+@)|scp\s|pscp(\.exe)?\s)/i, w: 7, label: 'data upload / exfiltration command', mitre: 'T1567' },
  { rx: /(7z|7za|rar|winrar|makecab|compress-archive)(\.exe)?\s+(a|-a)\s.{0,120}(-p|-hp|\\temp|\\public|\\perflogs|\\programdata)/i, w: 5, label: 'archive staging (password protected or in staging dir)', mitre: 'T1560.001' },
  { rx: /msiexec(\.exe)?\s.{0,30}\/(i|package)\s+https?:/i, w: 7, label: 'msiexec installing from URL', mitre: 'T1218.007' },
  { rx: /\b(msbuild|installutil|regasm|regsvcs|cmstp)(\.exe)?\s.{0,80}\\(temp|public|appdata|programdata|users)\\/i, w: 6, label: 'signed binary proxy execution from user path', mitre: 'T1127' },
  { rx: /\bcscript|wscript(\.exe)?\s.{0,60}\\(temp|appdata|public|downloads)\\.{0,80}\.(js|jse|vbs|vbe|wsf)/i, w: 5, label: 'script host running script from user-writable path', mitre: 'T1059.005' },
  { rx: /\bat(\.exe)?\s+\d{1,2}:\d{2}|\\\\\S+\s+\d{1,2}:\d{2}\s+(\/every|cmd)/i, w: 4, label: 'legacy AT job', mitre: 'T1053.002' },
  { rx: /icacls(\.exe)?\s.{0,60}\/grant\s+everyone:\(?f|takeown(\.exe)?\s+\/f\s.{0,20}\/r|attrib(\.exe)?\s.{0,20}\+h\s.{0,20}\+s/i, w: 3, label: 'permission/attribute manipulation', mitre: 'T1222' },
  { rx: /fsutil(\.exe)?\s+usn\s+deletejournal|cipher(\.exe)?\s+\/w:/i, w: 8, label: 'anti-forensics (USN delete / wipe)', mitre: 'T1070' },
  { rx: /(\.onion\b|pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|temp\.sh|anonfiles|file\.io|gofile\.io|mega\.nz|ngrok\.io|ngrok-free\.app|trycloudflare\.com|raw\.githubusercontent\.com|discord(app)?\.com\/api\/webhooks|cdn\.discordapp\.com\/attachments|api\.telegram\.org|workers\.dev|duckdns\.org|no-ip\.|ddns\.net|serveo\.net|portmap\.io)/i, w: 5, label: 'reference to paste/file-share/tunnel service', mitre: 'T1102' },
  { rx: /https?:\/\/(?!(?:10|127|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.)\d{1,3}(\.\d{1,3}){3}(:\d+)?\//i, w: 4, label: 'URL to raw IP address', mitre: 'T1105' },
];

export function classifyCommand(cmd) {
  const out = { score: 0, reasons: [], mitre: new Set() };
  if (!cmd || cmd.length < 4) return out;
  const c = cmd.replace(/\s+/g, ' ');
  for (const r of CMD_RULES) if (r.rx.test(c)) { out.score += r.w; out.reasons.push(r.label); out.mitre.add(r.mitre); }
  if (c.length > 1000 && /powershell|cmd|wscript|mshta/i.test(c)) { out.score += 2; out.reasons.push('unusually long command line'); }
  out.sev = out.score >= 9 ? 'critical' : out.score >= 6 ? 'high' : out.score >= 4 ? 'medium' : out.score >= 2 ? 'low' : null;
  out.mitre = [...out.mitre];
  return out;
}

export const isLolbin = (path) => LOLBINS.has(baseName(path).toLowerCase());
export const isDiscovery = (path) => DISCOVERY.has(baseName(path).toLowerCase());

/** Normalise \Device\HarddiskVolumeN / \VOLUME{...} prefixes for display. */
export function normPath(p) {
  if (!p) return '';
  return String(p).replace(/^\\\?\?\\/, '').replace(/^\\VOLUME\{[^}]+\}/i, '<vol>').replace(/^\\DEVICE\\HARDDISKVOLUME\d+/i, '<vol>');
}

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const maxSev = (...s) => s.filter(Boolean).sort((a, b) => SEV_RANK[b] - SEV_RANK[a])[0] || null;
