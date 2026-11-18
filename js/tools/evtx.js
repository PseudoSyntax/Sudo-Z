// EvtxECmd + detection rules. EvtxECmd itself only normalises events with
// maps; Sudo-Z layers detection logic (similar in spirit to Hayabusa /
// Chainsaw / Sigma) on top so the output is an IOC report, not just CSV.
import { parseEvtx, payloadString } from '../parsers/evtx.js';
import { classifyCommand, classifyPath, baseName, isLolbin } from '../ioc/heuristics.js';
import { isPrivateIp } from '../ioc/indicators.js';
import { KEYWORD_RULES } from '../core/strings.js';
import { expectedParents } from '../ioc/baseline.js';
import { classifyPipe, normPipe } from '../ioc/pipes.js';

const LOGON_TYPES = { 2: 'Interactive', 3: 'Network', 4: 'Batch', 5: 'Service', 7: 'Unlock', 8: 'NetworkCleartext', 9: 'NewCredentials', 10: 'RemoteInteractive (RDP)', 11: 'CachedInteractive', 12: 'CachedRemoteInteractive', 13: 'CachedUnlock' };
const PRIV_GROUPS = /^(administrators|domain admins|enterprise admins|schema admins|remote desktop users|backup operators|account operators|server operators|dnsadmins|group policy creator owners|exchange (trusted subsystem|windows permissions)|organization management|remote management users|hyper-v administrators)$/i;
const OFFICE = /\\(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|visio|eqnedt32|wordpad)\.exe$/i;
const BROWSER = /\\(chrome|msedge|firefox|iexplore|opera|brave)\.exe$/i;
const SCRIPTY = /\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msbuild|installutil|wmic|schtasks|bash|curl)\.exe$/i;
const LSASS_ACCESS = /^0x(1010|1410|1418|1438|143a|1f0fff|1fffff|1f1fff|1f3fff|40|1000|1400|101000|0810)$/i;

const r0 = (t) => (t ? String(t).slice(0, 19).replace('T', ' ') : '?');
const ip = (v) => (v && v !== '-' && v !== '::1' && v !== '127.0.0.1' && !/^fe80/i.test(v) ? v : null);

export function runEvtx(u8, f, ctx) {
  const parsed = parseEvtx(u8);
  const recs = parsed.records;
  const notable = [];
  const logons = new Map(); // user|ip|type -> {count, first, last}
  const fails = new Map(); // ip -> {users:Set, count, first, last}
  const failsByUser = new Map();
  const kerbFail = new Map();
  const rc4 = new Map();
  const channels = new Map();
  const eventIds = new Map();

  const note = (r, sev, title, detail, mitre = [], category = 'Event Log', evidence) => {
    const fd = { sev, category, tool: 'EvtxECmd', file: f.name, time: r.TimeCreated, title: `${r.EventId} ${title}`, detail: detail || '', evidence: evidence || payloadString(r, 1200), mitre };
    ctx.finding(fd);
    notable.push([r.TimeCreated, sev, r.EventId, r.Channel, title, (evidence || payloadString(r, 400))]);
  };
  const ev = (r, type, desc) => ctx.event({ time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, type: `${r.EventId} ${type}`, desc });

  for (const r of recs) {
    const d = r.Data; const id = r.EventId; const ch = (r.Channel || '').toLowerCase(); const prov = (r.Provider || '').toLowerCase();
    channels.set(r.Channel, (channels.get(r.Channel) || 0) + 1);
    eventIds.set(`${r.Channel}|${id}`, (eventIds.get(`${r.Channel}|${id}`) || 0) + 1);
    if (r.Computer) ctx.hosts.add(r.Computer);

    // ---------------------------------------------------------- Security
    if (ch === 'security' || prov === 'microsoft-windows-security-auditing' || prov === 'microsoft-windows-eventlog') {
      switch (id) {
        case 1102: note(r, 'critical', 'Security log cleared', `by ${d.SubjectDomainName || ''}\\${d.SubjectUserName || r.Data['LogFileCleared.SubjectUserName'] || '?'}`, ['T1070.001'], 'Defense Evasion'); break;
        case 1100: note(r, 'medium', 'Event logging service shut down', 'Can precede log tampering.', ['T1562.002'], 'Defense Evasion'); break;
        case 4624: {
          const lt = +d.LogonType; const src = ip(d.IpAddress);
          const k = `${d.TargetDomainName}\\${d.TargetUserName}|${src || d.WorkstationName || '-'}|${lt}`;
          const e = logons.get(k) || { count: 0, first: r.TimeCreated, last: r.TimeCreated }; e.count++; e.last = r.TimeCreated; logons.set(k, e);
          if (lt === 10 || lt === 12) { ev(r, 'RDP logon', `${d.TargetDomainName}\\${d.TargetUserName} from ${src || d.WorkstationName}`); if (src) ctx.indicators.add(isPrivateIp(src) ? 'internal_ip' : 'ipv4', src, f.name, `RDP logon ${d.TargetUserName}`); }
          if (lt === 9 && /seclogo/i.test(d.LogonProcessName || '')) note(r, 'high', 'Logon type 9 via seclogo (runas /netonly or pass-the-hash)', `${d.SubjectUserName} -> ${d.TargetOutboundDomainName || ''}\\${d.TargetOutboundUserName || d.TargetUserName} process ${d.ProcessName || ''}`, ['T1550.002'], 'Lateral Movement');
          if (lt === 3 && /ntlm/i.test(d.AuthenticationPackageName || '') && d.KeyLength === '0' && !/anonymous/i.test(d.TargetUserName || '') && src && !/\$$/.test(d.TargetUserName || '')) {
            ev(r, 'NTLM network logon (KeyLength 0)', `${d.TargetUserName} from ${src} ${d.WorkstationName || ''}`);
          }
          if (lt === 3 && src) { ctx.indicators.add(isPrivateIp(src) ? 'internal_ip' : 'ipv4', src, f.name, `network logon ${d.TargetUserName}`); if (!isPrivateIp(src)) note(r, 'medium', `Network logon from public IP ${src}`, `${d.TargetDomainName}\\${d.TargetUserName} via ${d.AuthenticationPackageName}`, ['T1078', 'T1133'], 'Initial Access'); }
          if ((lt === 10) && src && !isPrivateIp(src)) note(r, 'high', `RDP logon from public IP ${src}`, `${d.TargetDomainName}\\${d.TargetUserName}`, ['T1021.001', 'T1133'], 'Initial Access');
          if (d.TargetUserName) ctx.users.add(d.TargetUserName);
          break;
        }
        case 4625: {
          const src = ip(d.IpAddress) || d.WorkstationName || '-';
          const e = fails.get(src) || { users: new Set(), count: 0, first: r.TimeCreated, last: r.TimeCreated, types: new Set() };
          e.users.add(d.TargetUserName); e.count++; e.last = r.TimeCreated; e.types.add(d.LogonType); fails.set(src, e);
          const u = `${d.TargetDomainName}\\${d.TargetUserName}`; failsByUser.set(u, (failsByUser.get(u) || 0) + 1);
          break;
        }
        case 4648: {
          const tgt = d.TargetServerName || '';
          if (tgt && !/^(localhost|127\.0\.0\.1|-)$/i.test(tgt) && !/^krbtgt|\$$/i.test(d.TargetUserName || '')) {
            ev(r, 'Explicit credential logon', `${d.SubjectUserName} as ${d.TargetDomainName}\\${d.TargetUserName} to ${tgt} via ${d.ProcessName}`);
            const sev = /psexec|wmic|powershell|cmd\.exe|rundll32|mstsc/i.test(d.ProcessName || '') ? 'medium' : 'low';
            note(r, sev, `Explicit credentials used against ${tgt}`, `${d.SubjectUserName} -> ${d.TargetDomainName}\\${d.TargetUserName} using ${d.ProcessName}`, ['T1078', 'T1021'], 'Lateral Movement');
          }
          break;
        }
        case 4688: {
          const img = d.NewProcessName || ''; const cmd = d.CommandLine || '';
          ev(r, 'Process created', `${img} ${cmd} (parent ${d.ParentProcessName || '?'})`);
          ctx.exec_({ path: img, args: cmd, time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, source: 'Security 4688', extraDetail: `parent ${d.ParentProcessName || '?'} user ${d.SubjectUserName || ''}` });
          parentChild(r, d.ParentProcessName, img, cmd, note);
          break;
        }
        case 4697: ctx.persist({ mechanism: 'Service installed (4697)', name: d.ServiceName, command: d.ServiceFileName, time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, alwaysReport: 'low', mitre: ['T1543.003'] }); ev(r, 'Service installed', `${d.ServiceName}: ${d.ServiceFileName}`); break;
        case 4698: case 4702: {
          const xml = d.TaskContent || d.TaskContentNew || '';
          const cmd = [...xml.matchAll(/<Command>([^<]*)<\/Command>(?:\s*<Arguments>([^<]*)<\/Arguments>)?/g)].map((m) => `${m[1]} ${m[2] || ''}`.trim()).join(' ; ');
          ev(r, id === 4698 ? 'Scheduled task created' : 'Scheduled task updated', `${d.TaskName} -> ${cmd}`);
          ctx.persist({ mechanism: id === 4698 ? 'Scheduled task created (4698)' : 'Scheduled task updated (4702)', name: d.TaskName, command: cmd, time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, alwaysReport: /^\\Microsoft\\/i.test(d.TaskName || '') ? null : 'low', mitre: ['T1053.005'] });
          break;
        }
        case 4699: note(r, 'low', `Scheduled task deleted: ${d.TaskName}`, `by ${d.SubjectUserName}`, ['T1070'], 'Defense Evasion'); break;
        case 4720: note(r, 'medium', `User account created: ${d.TargetDomainName}\\${d.TargetUserName}`, `by ${d.SubjectUserName}`, ['T1136'], 'Persistence'); ctx.users.add(d.TargetUserName); break;
        case 4722: ev(r, 'Account enabled', `${d.TargetUserName} by ${d.SubjectUserName}`); break;
        case 4724: ev(r, 'Password reset attempt', `${d.TargetUserName} by ${d.SubjectUserName}`); if (/^(administrator|krbtgt)$/i.test(d.TargetUserName || '')) note(r, 'medium', `Password reset on ${d.TargetUserName}`, `by ${d.SubjectUserName}`, ['T1098'], 'Persistence'); break;
        case 4726: note(r, 'low', `User account deleted: ${d.TargetUserName}`, `by ${d.SubjectUserName}`, ['T1531'], 'Impact'); break;
        case 4728: case 4732: case 4756: {
          const grp = d.TargetUserName || ''; const member = d.MemberName && d.MemberName !== '-' ? d.MemberName : d.MemberSid;
          const sev = PRIV_GROUPS.test(grp) ? 'high' : 'low';
          note(r, sev, `Member added to group ${grp}`, `${member} by ${d.SubjectUserName}`, ['T1098'], 'Persistence'); break;
        }
        case 4741: if (!/\$$/.test(d.SubjectUserName || '')) note(r, 'medium', `Computer account created: ${d.TargetUserName}`, `by user ${d.SubjectUserName} (machine accounts created by users enable RBCD / noPac abuse)`, ['T1136.002'], 'Persistence'); break;
        case 4719: note(r, 'medium', 'System audit policy changed', `${d.SubcategoryGuid || ''} ${d.AuditPolicyChanges || ''} by ${d.SubjectUserName}`, ['T1562.002'], 'Defense Evasion'); break;
        case 4616: if (!/svchost|vmtoolsd|w32tm/i.test(d.ProcessName || '')) note(r, 'medium', 'System time changed', `${d.PreviousTime} -> ${d.NewTime} by ${d.SubjectUserName} (${d.ProcessName})`, ['T1070.006'], 'Defense Evasion'); break;
        case 4657: if (/currentversion\\run|image file execution options|winlogon|\\services\\/i.test(d.ObjectName || '')) ctx.persist({ mechanism: 'Registry modified (4657)', name: `${d.ObjectName}\\${d.ObjectValueName}`, command: d.NewValue || '', time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, alwaysReport: 'medium', mitre: ['T1112'] }); break;
        case 4768: if (d.PreAuthType === '0') note(r, 'high', `Kerberos TGT without pre-auth for ${d.TargetUserName} (AS-REP roasting)`, `from ${d.IpAddress}`, ['T1558.004'], 'Credential Access'); break;
        case 4769: {
          if (/^0x17$/i.test(d.TicketEncryptionType || '') && !/\$$|^krbtgt/i.test(d.ServiceName || '') && d.Status === '0x0') {
            const k = `${d.TargetUserName}|${d.IpAddress}`; const e = rc4.get(k) || { svcs: new Set(), first: r.TimeCreated }; e.svcs.add(d.ServiceName); e.last = r.TimeCreated; rc4.set(k, e);
          }
          break;
        }
        case 4771: { if (d.Status === '0x18') { const s = ip(d.IpAddress?.replace(/^::ffff:/, '')) || '-'; const e = kerbFail.get(s) || { users: new Set(), count: 0, first: r.TimeCreated }; e.users.add(d.TargetUserName); e.count++; e.last = r.TimeCreated; kerbFail.set(s, e); } break; }
        case 4776: if (d.Status && d.Status !== '0x0') { const s = d.Workstation || '-'; const e = fails.get('NTLM:' + s) || { users: new Set(), count: 0, first: r.TimeCreated, types: new Set(['NTLM']) }; e.users.add(d.TargetUserName); e.count++; e.last = r.TimeCreated; fails.set('NTLM:' + s, e); } break;
        case 4740: note(r, 'low', `Account locked out: ${d.TargetUserName}`, `caller ${d.TargetDomainName || ''}`, ['T1110'], 'Credential Access'); break;
        case 4794: note(r, 'high', 'DSRM administrator password set', `by ${d.SubjectUserName}`, ['T1098'], 'Persistence'); break;
        case 4765: case 4766: note(r, 'high', 'SID History added to account', `${d.TargetUserName}`, ['T1134.005'], 'Privilege Escalation'); break;
        case 5140: { const sh = d.ShareName || ''; if (/\\(admin|c|d|e)\$$/i.test(sh)) { note(r, 'medium', `Admin share ${sh} accessed`, `${d.SubjectDomainName}\\${d.SubjectUserName} from ${d.IpAddress}`, ['T1021.002'], 'Lateral Movement'); } if (ip(d.IpAddress)) ctx.indicators.add(isPrivateIp(d.IpAddress) ? 'internal_ip' : 'ipv4', d.IpAddress, f.name, `share ${sh}`); break; }
        case 5145: {
          const t = (d.RelativeTargetName || '').toLowerCase(); const sh = d.ShareName || '';
          if (/^(svcctl|atsvc|winreg|lsarpc|samr|drsuapi|netlogon|srvsvc)$/.test(t) && /ipc\$/i.test(sh)) note(r, /svcctl|atsvc/.test(t) ? 'high' : 'low', `Named pipe ${t} accessed over IPC$`, `${d.SubjectDomainName}\\${d.SubjectUserName} from ${d.IpAddress}:${d.IpPort} (${{ svcctl: 'remote service creation (PsExec/smbexec)', atsvc: 'remote scheduled task', winreg: 'remote registry', samr: 'SAM enumeration', lsarpc: 'LSA enumeration', drsuapi: 'DCSync / replication', netlogon: 'Netlogon (Zerologon?)', srvsvc: 'share enumeration' }[t]})`, ['T1021.002', 'T1569.002'], 'Lateral Movement');
          if (/psexesvc|remcom|paexec|csexec/i.test(t)) note(r, 'critical', `PsExec-style pipe/file ${t} via share`, `${d.SubjectUserName} from ${d.IpAddress}`, ['T1569.002'], 'Lateral Movement');
          if (/\.(exe|dll|bat|ps1)$/i.test(t) && /admin\$|c\$/i.test(sh)) note(r, 'high', `Executable written/read via ${sh}: ${t}`, `${d.SubjectUserName} from ${d.IpAddress}`, ['T1570'], 'Lateral Movement');
          break;
        }
      }
    }

    // ---------------------------------------------------------- System
    if (ch === 'system') {
      if (id === 104 && /eventlog/i.test(prov)) note(r, 'critical', `Event log cleared (${d.Channel || d['LogFileCleared.Channel'] || 'channel'})`, `by ${d.SubjectUserName || d['SubjectUserName'] || d['LogFileCleared.SubjectUserName'] || '?'}`, ['T1070.001'], 'Defense Evasion');
      if (id === 7045 && /service control manager/i.test(prov)) {
        ev(r, 'Service installed', `${d.ServiceName}: ${d.ImagePath} (${d.AccountName})`);
        const stdLoc = /^"?(system32\\|%systemroot%\\|%windir%\\|\\systemroot\\|c:\\windows\\(system32|syswow64|microsoft\.net)\\|c:\\program files( \(x86\))?\\|%programfiles%)/i.test(d.ImagePath || '');
        ctx.persist({ mechanism: 'Service installed (7045)', name: d.ServiceName, command: d.ImagePath || '', time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, alwaysReport: stdLoc ? null : 'low', mitre: ['T1543.003'] });
        if (/psexesvc|paexec|remcom|csexec|btobto/i.test((d.ServiceName || '') + (d.ImagePath || '')) || (/^%?comspec%?|cmd(\.exe)?\s+\/c|\\\\127\.0\.0\.1\\admin\$|echo .{0,60}\\\\\.\\pipe\\/i.test(d.ImagePath || '')) || /^[A-Za-z]{16}$|^[a-z0-9]{7,8}$/.test(d.ServiceName || '') && /\\(windows|temp)\\[a-z0-9]{6,16}\.exe$/i.test(d.ImagePath || ''))
          note(r, 'critical', `Remote execution / Cobalt Strike style service: ${d.ServiceName}`, d.ImagePath, ['T1569.002', 'T1543.003'], 'Lateral Movement');
        else if (/^cmd(\.exe)?$/i.test((d.ImagePath || '').trim())) note(r, 'high', `Service with bare cmd.exe image: ${d.ServiceName}`, 'Pattern used by exploitation tools (e.g. SpoolFool, service-based privesc).', ['T1543.003'], 'Privilege Escalation');
      }
      if (id === 7040 && /windows defender|microsoft defender|windows event log|eventlog|sense|wdnissvc|windefend/i.test(d.param1 || '') && /disabled|demand/i.test(d.param3 || '')) note(r, 'high', `Security service start type changed: ${d.param1} -> ${d.param3}`, '', ['T1562.001'], 'Defense Evasion');
      if (id === 7036 && /windows defender|microsoft defender antivirus|windows event log|sysmon|sense/i.test(d.param1 || '') && /stopped/i.test(d.param2 || '')) note(r, /event log/i.test(d.param1) ? 'low' : 'medium', `Security service stopped: ${d.param1}`, '', ['T1562.001'], 'Defense Evasion');
      if ([6005, 6006, 6008, 1074].includes(id)) ev(r, { 6005: 'Event log started (boot)', 6006: 'Clean shutdown', 6008: 'Unexpected shutdown', 1074: 'Shutdown initiated' }[id], payloadString(r, 200));
    }

    // ---------------------------------------------------------- PowerShell
    if (/powershell/.test(ch) || /powershell/.test(prov)) {
      if (id === 4104) {
        const sb = d.ScriptBlockText || '';
        const cc = classifyCommand(sb);
        ctx.text(sb, f.name); ctx.domains(sb, f.name);
        const kw = KEYWORD_RULES.filter((k) => k.rx.test(sb));
        const sev = kw.some((k) => k.sev === 'critical') ? 'critical' : kw.length || cc.sev === 'high' || cc.sev === 'critical' ? (cc.sev === 'critical' ? 'critical' : 'high') : r.Level === 3 ? 'medium' : cc.sev;
        if (sev) note(r, sev, `PowerShell script block: ${kw[0]?.title || cc.reasons[0] || 'flagged as suspicious by PowerShell (Level Warning)'}`, [...kw.map((k) => k.title), ...cc.reasons].join('; '), ['T1059.001', ...cc.mitre], 'Execution', sb.slice(0, 1500));
        if (sev) ev(r, 'PowerShell script block', sb.slice(0, 300));
      } else if (id === 4103) {
        const p = (d.Payload || '') + ' ' + (d.ContextInfo || '');
        const cc = classifyCommand(p); ctx.text(p, f.name);
        if (cc.sev && cc.score >= 4) note(r, cc.sev, `PowerShell module logging: ${cc.reasons[0]}`, cc.reasons.join('; '), ['T1059.001', ...cc.mitre], 'Execution', p.slice(0, 1500));
      } else if (id === 400 || id === 800 || id === 403 || id === 600) {
        const blob = r.DataList.join('\n') + Object.values(d).join('\n');
        const host = (blob.match(/HostApplication=([^\r\n]+)/) || [])[1] || '';
        if (host) { const cc = classifyCommand(host); ctx.text(host, f.name); if (cc.sev) note(r, cc.sev, `PowerShell engine start: ${cc.reasons[0]}`, cc.reasons.join('; '), ['T1059.001', ...cc.mitre], 'Execution', host.slice(0, 1500)); }
        if (/EngineVersion=2\./.test(blob) && id === 400) note(r, 'medium', 'PowerShell v2 engine started (downgrade attack bypasses logging/AMSI)', host, ['T1562.010'], 'Defense Evasion', host);
      }
    }

    // ---------------------------------------------------------- Sysmon
    if (prov === 'microsoft-windows-sysmon') sysmon(r, d, f, ctx, note, ev);

    // ---------------------------------------------------------- Defender
    if (/windows defender|microsoft defender/i.test(prov)) {
      if (id === 1116 || id === 1117 || id === 1006 || id === 1015) {
        const tn = d['Threat Name'] || d.ThreatName || '';
        const sev = /hacktool|mimikatz|cobalt|meterpreter|ransom|powersploit|sliver|bruteratel|lsass|credentialdump|exploit|webshell|backdoor/i.test(tn) ? 'critical' : 'high';
        note(r, sev, `Defender ${id === 1117 ? 'action taken' : 'detection'}: ${tn}`, `Path: ${d.Path || ''} | Process: ${d['Process Name'] || ''} | User: ${d['Detection User'] || ''} | Action: ${d['Action Name'] || ''}`, ['T1204'], 'Malware');
        const pth = (d.Path || '').split(/;\s*/)[0].replace(/^(container)?file:_/i, '').replace(/->.*$/, ''); if (pth) ctx.indicators.add('file_path', pth, f.name, tn);
        ctx.indicators.add('av_detection', tn, f.name, d.Path || '');
      }
      if (id === 1118 || id === 1119) note(r, 'critical', `Defender remediation FAILED: ${d['Threat Name'] || ''}`, d.Path || '', ['T1562.001'], 'Malware');
      if (id === 5001) note(r, 'high', 'Defender real-time protection disabled', '', ['T1562.001'], 'Defense Evasion');
      if (id === 5010 || id === 5012) note(r, 'high', `Defender ${id === 5010 ? 'antispyware' : 'antivirus'} scanning disabled`, '', ['T1562.001'], 'Defense Evasion');
      if (id === 5007 && /exclusions|DisableRealtimeMonitoring|DisableAntiSpyware|TamperProtection|SpyNetReporting/i.test(d['New Value'] || d.NewValue || '')) note(r, /exclusions/i.test(d['New Value'] || '') ? 'high' : 'medium', 'Defender configuration changed', `${d['Old Value'] || ''} -> ${d['New Value'] || ''}`, ['T1562.001'], 'Defense Evasion');
      if (id === 1121 || id === 1122) note(r, id === 1121 ? 'medium' : 'low', `Attack Surface Reduction rule ${id === 1121 ? 'blocked' : 'audited'} activity`, `${d.Path || ''} by ${d['Process Name'] || ''}`, ['T1204'], 'Execution');
    }

    // ---------------------------------------------------------- RDP / TerminalServices
    if (/terminalservices-remoteconnectionmanager/i.test(ch) && id === 1149) {
      const src = d['EventXML.Param3'] || d.Param3 || r.DataList[2] || '';
      const user = d['EventXML.Param1'] || d.Param1 || r.DataList[0] || '';
      ev(r, 'RDP authentication succeeded', `${user} from ${src}`);
      if (ip(src)) { ctx.indicators.add(isPrivateIp(src) ? 'internal_ip' : 'ipv4', src, f.name, `RDP 1149 ${user}`); if (!isPrivateIp(src)) note(r, 'high', `RDP authentication from public IP ${src}`, user, ['T1021.001', 'T1133'], 'Initial Access'); else note(r, 'low', `RDP authentication from ${src}`, user, ['T1021.001'], 'Lateral Movement'); }
      if (/^(127\.0\.0\.1|::1|localhost)$/i.test(src)) note(r, 'high', 'RDP from localhost (RDP tunnelling via plink/ngrok/port forward)', user, ['T1572', 'T1021.001'], 'Command and Control');
    }
    if (/terminalservices-localsessionmanager/i.test(ch) && [21, 22, 24, 25].includes(id)) {
      const addr = d.Address || d['EventXML.Address'] || ''; const user = d.User || d['EventXML.User'] || '';
      ev(r, { 21: 'RDP session logon', 22: 'RDP shell start', 24: 'RDP session disconnected', 25: 'RDP session reconnect' }[id], `${user} from ${addr}`);
      if (ip(addr) && addr !== 'LOCAL') ctx.indicators.add(isPrivateIp(addr) ? 'internal_ip' : 'ipv4', addr, f.name, `RDP session ${user}`);
      if (/^(127\.0\.0\.1|::1)$/.test(addr)) note(r, 'high', 'RDP session from localhost (tunnelled RDP)', user, ['T1572'], 'Command and Control');
    }
    if (/terminalservices-rdpclient/i.test(ch) && (id === 1024 || id === 1102)) { const v = d.Value || r.DataList[0] || ''; ev(r, 'Outbound RDP', v); if (v) ctx.indicators.add('rdp_target', v, f.name); }

    // ---------------------------------------------------------- Task Scheduler / WMI / BITS / misc
    if (/taskscheduler\/operational/i.test(ch)) {
      if (id === 106 || id === 140) { ev(r, id === 106 ? 'Task registered' : 'Task updated', `${d.TaskName} by ${d.UserContext || d.UserName || ''}`); if (!/^\\Microsoft\\/i.test(d.TaskName || '')) note(r, 'low', `Scheduled task ${id === 106 ? 'registered' : 'updated'}: ${d.TaskName}`, d.UserContext || d.UserName || '', ['T1053.005'], 'Persistence'); }
      if (id === 141) ev(r, 'Task deleted', d.TaskName);
      if (id === 200 || id === 129) { const a = d.ActionName || d.Path || ''; ev(r, 'Task action launched', `${d.TaskName} -> ${a}`); if (a) ctx.exec_({ path: a, time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, source: `Task ${d.TaskName}` }); }
    }
    if (/wmi-activity/i.test(ch) && id === 5861) note(r, 'critical', 'WMI permanent event subscription created', payloadString(r, 600), ['T1546.003'], 'Persistence');
    if (/bits-client/i.test(ch) && (id === 59 || id === 60)) { const url = d.url || d.Url || ''; ctx.text(url, f.name); const cc = classifyCommand(url); const pc = classifyPath(d.name || ''); if (cc.sev || /\.(exe|dll|ps1|hta|bat|zip|7z|rar)(\?|$)/i.test(url) && !/microsoft|windowsupdate|office|adobe|google|mozilla/i.test(url)) note(r, 'medium', `BITS job transfer: ${d.name || ''}`, url, ['T1197'], 'Command and Control', url); }
    if (/windows firewall with advanced security/i.test(ch) && (id === 2004 || id === 2005 || id === 2097) && /allow/i.test(payloadString(r)) && /3389|any|4444|5985|5986|445/i.test(payloadString(r))) note(r, 'low', `Firewall rule added/changed: ${d.RuleName || ''}`, payloadString(r, 400), ['T1562.004'], 'Defense Evasion');
    if (/applocker/i.test(ch) && (id === 8004 || id === 8007 || id === 8022 || id === 8025)) note(r, 'medium', 'AppLocker blocked execution', d.FullFilePath || d.FilePath || payloadString(r, 300), ['T1204'], 'Execution');
    if (/openssh/i.test(ch) && id === 4) { const m = (r.DataList.join(' ') + JSON.stringify(d)).match(/Accepted \w+ for (\S+) from ([\d.:a-f]+)/i); if (m) { ev(r, 'SSH logon', `${m[1]} from ${m[2]}`); if (!isPrivateIp(m[2])) note(r, 'medium', `SSH logon from public IP ${m[2]}`, m[1], ['T1021.004'], 'Initial Access'); } }
    if (ch === 'application' && /mssql/i.test(prov) && /xp_cmdshell/i.test(payloadString(r))) note(r, 'high', 'SQL Server xp_cmdshell configuration changed', payloadString(r, 300), ['T1505.001'], 'Execution');
    if (ch === 'application' && id === 1000 && /lsass\.exe/i.test(payloadString(r))) note(r, 'high', 'LSASS crashed (possible credential dumping attempt)', payloadString(r, 300), ['T1003.001'], 'Credential Access');
  }

  // ---------------------------------------------------------- aggregations
  for (const [src, e] of fails) {
    const users = [...e.users].filter(Boolean);
    if (e.count >= 10 && users.length >= 5) ctx.finding({ sev: 'high', category: 'Credential Access', tool: 'EvtxECmd', file: f.name, time: e.first, title: `Password spray: ${e.count} failed logons for ${users.length} accounts from ${src}`, detail: `${e.first} → ${e.last}; logon types ${[...e.types].join(',')}`, evidence: users.slice(0, 40).join(', '), mitre: ['T1110.003'] });
    else if (e.count >= 20) ctx.finding({ sev: 'high', category: 'Credential Access', tool: 'EvtxECmd', file: f.name, time: e.first, title: `Brute force: ${e.count} failed logons from ${src}`, detail: `${e.first} → ${e.last}`, evidence: users.join(', '), mitre: ['T1110.001'] });
    else if (e.count >= 5) ctx.finding({ sev: 'low', category: 'Credential Access', tool: 'EvtxECmd', file: f.name, time: e.first, title: `${e.count} failed logons from ${src}`, evidence: users.join(', '), mitre: ['T1110'] });
    const s = src.replace(/^NTLM:/, '');
    if (ip(s) && /\d+\.\d+\.\d+\.\d+/.test(s)) ctx.indicators.add(isPrivateIp(s) ? 'internal_ip' : 'ipv4', s, f.name, `${e.count} failed logons`);
  }
  for (const [src, e] of kerbFail) if (e.users.size >= 5) ctx.finding({ sev: 'high', category: 'Credential Access', tool: 'EvtxECmd', file: f.name, time: e.first, title: `Kerberos password spray: ${e.count} pre-auth failures (0x18) for ${e.users.size} users from ${src}`, evidence: [...e.users].slice(0, 40).join(', '), mitre: ['T1110.003'] });
  for (const [k, e] of rc4) {
    const [user, from] = k.split('|');
    ctx.finding({ sev: e.svcs.size >= 3 ? 'high' : 'medium', category: 'Credential Access', tool: 'EvtxECmd', file: f.name, time: e.first, title: `Kerberoasting indicator: ${user} requested RC4 service tickets for ${e.svcs.size} SPN(s)`, detail: `from ${from}`, evidence: [...e.svcs].join(', '), mitre: ['T1558.003'] });
  }

  // ---------------------------------------------------------- record number gaps / clock anomalies (selective deletion)
  const byNum = recs.filter((r) => Number.isFinite(r.RecordNumber)).sort((a, b) => a.RecordNumber - b.RecordNumber);
  const chan = (recs[0]?.Channel || '').toLowerCase();
  let gapCount = 0, backCount = 0;
  for (let i = 1; i < byNum.length; i++) {
    const a = byNum[i - 1], b = byNum[i]; const miss = b.RecordNumber - a.RecordNumber - 1;
    if (miss > 0 && gapCount < 10) {
      gapCount++;
      ctx.finding({ sev: parsed.errors ? 'low' : chan === 'security' ? 'high' : 'medium', category: 'Defense Evasion', tool: 'EvtxECmd', file: f.name, time: a.TimeCreated, title: `${miss} event record(s) missing: EventRecordID ${a.RecordNumber + 1}${miss > 1 ? '-' + (b.RecordNumber - 1) : ''} (${r0(a.TimeCreated)} to ${r0(b.TimeCreated)})`, detail: parsed.errors ? 'Some records failed to decode, so this gap may be a parsing artifact.' : 'Record numbers are sequential; a hole in the middle of a log means records were removed selectively (e.g. EventCleaner, Danderspritz eventlogedit) rather than by a full clear.', mitre: ['T1070.001'] });
      ctx.event({ time: a.TimeCreated, tool: 'EvtxECmd', file: f.name, type: 'Event record gap', desc: `${miss} records missing after ${a.RecordNumber}` });
    }
    const dt = Date.parse(b.TimeCreated) - Date.parse(a.TimeCreated);
    if (dt < -3600000 && backCount < 5 && chan === 'security' && -dt < 30 * 86400000) { backCount++; ctx.finding({ sev: 'medium', category: 'Defense Evasion', tool: 'EvtxECmd', file: f.name, time: b.TimeCreated, title: `Event time clock moved backwards by ${Math.round(-dt / 60000)} min between records ${a.RecordNumber} and ${b.RecordNumber}`, detail: 'Either the system clock was changed (check 4616 and System Kernel-General 1) or records were altered. Small jumps right after boot can be a CMOS or time zone correction.', mitre: ['T1070.006'] }); }
  }

  const tables = [];
  tables.push({ title: 'Notable events', columns: ['Time', 'Severity', 'EventId', 'Channel', 'Rule', 'Payload'], rows: notable });
  if (logons.size) tables.push({ title: 'Successful logons (4624) summary', columns: ['Account', 'Source', 'LogonType', 'Count', 'First', 'Last'], rows: [...logons].map(([k, e]) => { const [a, s, t] = k.split('|'); return [a, s, `${t} ${LOGON_TYPES[t] || ''}`, e.count, e.first, e.last]; }).sort((a, b) => b[3] - a[3]) });
  if (fails.size) tables.push({ title: 'Failed logons (4625/4776) by source', columns: ['Source', 'Count', 'DistinctUsers', 'Users', 'First', 'Last'], rows: [...fails].map(([s, e]) => [s, e.count, e.users.size, [...e.users].slice(0, 20).join(', '), e.first, e.last]).sort((a, b) => b[1] - a[1]) });
  tables.push({ title: 'Event ID counts', columns: ['Channel', 'EventId', 'Count'], rows: [...eventIds].map(([k, n]) => [...k.split('|'), n]).sort((a, b) => b[2] - a[2]) });
  tables.push({ title: 'All events (EvtxECmd normalised)', columns: ['TimeCreated', 'EventId', 'Level', 'Provider', 'Channel', 'Computer', 'UserId', 'RecordNumber', 'PayloadData'], rows: recs.map((r) => [r.TimeCreated, r.EventId, r.Level, r.Provider, r.Channel, r.Computer, r.UserId, r.RecordNumber, payloadString(r, 800)]) });
  const notes = [];
  if (parsed.errors) notes.push(`${parsed.errors} record(s) could not be decoded (${parsed.errorSamples[0] || ''}).`);
  if (parsed.dirty) notes.push('Log header marked dirty (file was in use when copied). Records were still recovered chunk by chunk.');
  if (parsed.truncated) notes.push('Record limit reached; remaining records were not analysed.');
  const chans = [...channels.keys()].join(', ');
  return { tool: 'EvtxECmd', artifact: `Event log (${chans || 'empty'})`, summary: `${recs.length} records in ${parsed.chunks} chunks, ${notable.length} notable`, tables, notes };
}

function parentChild(r, parent, img, cmd, note) {
  if (!parent || !img) return;
  const exp = expectedParents(baseName(img));
  const pn = baseName(parent).toLowerCase();
  if (exp && pn && !exp.includes(pn) && exp.some(Boolean)) note(r, /^(lsass|services|wininit|smss)\.exe$/i.test(baseName(img)) ? 'critical' : 'high', `${baseName(img)} started by unexpected parent ${baseName(parent)}`, `Expected parent: ${exp.filter(Boolean).join(' or ')}. ${cmd || img}`, ['T1036.005', 'T1055'], 'Defense Evasion');
  if (OFFICE.test(parent) && SCRIPTY.test(img)) note(r, 'high', `Office application spawned ${baseName(img)}`, `${baseName(parent)} -> ${cmd || img}`, ['T1204.002', 'T1566.001'], 'Initial Access');
  else if (BROWSER.test(parent) && /\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$/i.test(img)) note(r, 'high', `Browser spawned ${baseName(img)}`, `${baseName(parent)} -> ${cmd || img}`, ['T1189', 'T1204'], 'Initial Access');
  else if (/\\wmiprvse\.exe$/i.test(parent) && /\\(cmd|powershell|pwsh|rundll32|mshta)\.exe$/i.test(img)) note(r, 'high', `WMI provider host spawned ${baseName(img)} (remote WMI execution)`, cmd || img, ['T1047'], 'Lateral Movement');
  else if (/\\services\.exe$/i.test(parent) && /\\(cmd|powershell)\.exe$/i.test(img)) note(r, 'high', `services.exe spawned ${baseName(img)} (service-based execution)`, cmd || img, ['T1569.002'], 'Execution');
  else if (/\\(w3wp|httpd|nginx|tomcat\d*|php-cgi|sqlservr|java)\.exe$/i.test(parent) && /\\(cmd|powershell|pwsh|whoami|net1?|certutil|wscript|cscript)\.exe$/i.test(img)) note(r, 'critical', `Server process ${baseName(parent)} spawned ${baseName(img)} (web shell / SQL injection)`, cmd || img, ['T1505.003', 'T1190'], 'Persistence');
  else if (/\\(mshta|wscript|cscript|rundll32|regsvr32)\.exe$/i.test(parent) && /\\(powershell|pwsh|cmd)\.exe$/i.test(img)) note(r, 'medium', `${baseName(parent)} spawned ${baseName(img)}`, cmd || img, ['T1218'], 'Defense Evasion');
}

function sysmon(r, d, f, ctx, note, ev) {
  const id = r.EventId;
  switch (id) {
    case 1: {
      ev(r, 'Process create', `${d.Image} ${d.CommandLine || ''} (parent ${d.ParentImage || ''})`);
      const res = ctx.exec_({ path: d.Image, args: d.CommandLine, time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, source: 'Sysmon 1', sha1: (String(d.Hashes || '').match(/SHA1=([0-9A-Fa-f]{40})/) || [])[1], extraDetail: `parent ${d.ParentCommandLine || d.ParentImage || ''} | user ${d.User || ''}` });
      parentChild(r, d.ParentImage, d.Image, d.CommandLine, note);
      if (d.OriginalFileName && d.Image && !/^-$|^\?$/.test(d.OriginalFileName)) {
        const on = d.OriginalFileName.toLowerCase().replace(/\.mui$/, ''), bn = baseName(d.Image).toLowerCase();
        if (on !== bn && isLolbin(on) && !/^(powershell\.exe\.mui)$/.test(on)) note(r, 'high', `Renamed system binary: ${d.OriginalFileName} running as ${baseName(d.Image)}`, d.Image, ['T1036.003'], 'Defense Evasion');
      }
      if (d.Hashes) for (const m of d.Hashes.matchAll(/(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)/g)) if (res?.sev || /SHA256/.test(m[1])) ctx.indicators.add(m[1].toLowerCase() === 'imphash' ? 'imphash' : m[1].toLowerCase(), m[2].toLowerCase(), f.name, d.Image);
      break;
    }
    case 3: {
      const dst = d.DestinationIp || '', host = d.DestinationHostname || '', port = d.DestinationPort || '';
      if (ip(dst) && !isPrivateIp(dst)) ctx.indicators.add('ipv4', dst, f.name, `${baseName(d.Image)} -> ${host}:${port}`);
      if (host && !/\.(local|lan|internal|arpa)$/i.test(host)) ctx.domains(host, f.name);
      if (/\\(powershell|pwsh|rundll32|regsvr32|mshta|certutil|bitsadmin|msbuild|installutil|wscript|cscript|msiexec|cmstp|wmic|notepad|calc)\.exe$/i.test(d.Image || '') && d.Initiated === 'true' && ip(dst) && !isPrivateIp(dst)) note(r, 'high', `${baseName(d.Image)} made an outbound connection to ${dst}:${port}`, host, ['T1071', 'T1218'], 'Command and Control');
      if (port === '3389' && d.Initiated === 'true') ev(r, 'Outbound RDP connection', `${d.Image} -> ${dst}`);
      if (/^(4444|1337|31337|8888|9001|9050|6667|5555)$/.test(port) && d.Initiated === 'true') note(r, 'medium', `Connection to suspicious port ${port}`, `${d.Image} -> ${dst}`, ['T1571'], 'Command and Control');
      break;
    }
    case 6: if (d.Signed === 'false' || /\\(temp|users)\\/i.test(d.ImageLoaded || '')) note(r, 'high', 'Driver loaded unsigned / from user path', d.ImageLoaded, ['T1014'], 'Defense Evasion'); break;
    case 7: if ((d.Signed === 'false' && /\\(temp|users\\public|appdata|programdata)\\/i.test(d.ImageLoaded || '')) || /\\(dbghelp|dbgcore)\.dll$/i.test(d.ImageLoaded || '') && /\\(rundll32|powershell|cmd|wmic)\.exe$/i.test(d.Image || '')) note(r, 'medium', `Suspicious module load into ${baseName(d.Image)}`, `${d.ImageLoaded} signed=${d.Signed}`, ['T1574.002'], 'Defense Evasion'); break;
    case 8: note(r, 'high', `CreateRemoteThread into ${baseName(d.TargetImage)}`, `${d.SourceImage} -> ${d.TargetImage} StartFunction ${d.StartFunction || ''}`, ['T1055'], 'Defense Evasion'); break;
    case 10: {
      if (/\\lsass\.exe$/i.test(d.TargetImage || '') && !/\\(wininit|csrss|services|svchost|lsm|msmpeng|mrt|wmiprvse|taskmgr|vmtoolsd|sense\w*|mssense|csfalcon\w*|cyserver|sentinel\w*|cb|repux|elastic-agent|osqueryd|procexp64?)\.exe$/i.test(d.SourceImage || '') && LSASS_ACCESS.test(d.GrantedAccess || '')) note(r, 'critical', `LSASS memory access by ${baseName(d.SourceImage)}`, `GrantedAccess ${d.GrantedAccess} CallTrace ${(d.CallTrace || '').slice(0, 200)}`, ['T1003.001'], 'Credential Access');
      break;
    }
    case 11: {
      const t = d.TargetFilename || '';
      if (/\\start menu\\programs\\startup\\/i.test(t)) ctx.persist({ mechanism: 'Startup folder file (Sysmon 11)', name: baseName(t), command: t, time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, alwaysReport: 'high', mitre: ['T1547.001'] });
      else { const pc = classifyPath(t); if (pc.sev && /\.(exe|dll|scr|ps1|bat|vbs|js|hta|lnk|sys)$/i.test(t)) note(r, pc.sev, `File dropped: ${baseName(t)}`, `${pc.reasons.join('; ')} by ${d.Image}`, ['T1105'], 'Execution', t); }
      if (/\.(dmp)$/i.test(t) && /lsass/i.test(t)) note(r, 'critical', 'LSASS dump file written', t, ['T1003.001'], 'Credential Access');
      break;
    }
    case 12: case 13: case 14: {
      const o = d.TargetObject || '';
      if (/\\currentversion\\(run|runonce|policies\\explorer\\run)\\|\\winlogon\\(shell|userinit)|\\image file execution options\\[^\\]+\\debugger|\\services\\[^\\]+\\imagepath|\\environment\\userinitmprlogonscript|\\silentprocessexit\\|inprocserver32\\\(default\)|\\shell\\open\\command/i.test(o))
        ctx.persist({ mechanism: `Registry ${id === 13 ? 'value set' : 'key change'} (Sysmon ${id})`, name: o, command: d.Details || '', time: r.TimeCreated, tool: 'EvtxECmd', file: f.name, alwaysReport: 'medium', mitre: ['T1547.001', 'T1112'] });
      if (/fdenytsconnections|uselogoncredential|disableantispyware|disablerealtimemonitoring|\\exclusions\\|enablelua|consentpromptbehavioradmin|localaccounttokenfilterpolicy/i.test(o)) note(r, 'high', `Security-relevant registry change: ${o.split('\\').pop()}`, `${o} = ${d.Details || ''} by ${d.Image}`, ['T1112', 'T1562.001'], 'Defense Evasion');
      break;
    }
    case 15: { const c = d.Contents || ''; const m = c.match(/HostUrl=(\S+)/); if (m) { ctx.indicators.add('url', m[1], f.name, `download of ${d.TargetFilename}`); ev(r, 'File downloaded (Zone.Identifier)', `${d.TargetFilename} from ${m[1]}`); } break; }
    case 17: case 18: {
      const g = classifyPipe(d.PipeName, { name: baseName(d.Image || ''), path: d.Image, pid: d.ProcessId });
      if (g) { note(r, g.sev, `Sysmon ${id}: ${g.title}`, `${id === 17 ? 'created' : 'connected'} by ${d.Image || '?'} (PID ${d.ProcessId || '?'})${d.User ? ' as ' + d.User : ''}. ${g.detail}`, g.mitre, g.category); ctx.indicators.add('named_pipe', '\\\\.\\pipe\\' + normPipe(d.PipeName), f.name, g.tool || g.title); }
      break;
    }
    case 22: { const q = d.QueryName || ''; if (q && !/\.(local|lan|arpa|internal)$/i.test(q)) ctx.domains(q, f.name); if (/(ngrok|trycloudflare|duckdns|no-ip|pastebin|transfer\.sh|anonfiles|mega\.nz|portmap|serveo|\.onion|discord\.gg|api\.telegram\.org|raw\.githubusercontent)/i.test(q)) note(r, 'medium', `DNS query to tunnelling/file-share service: ${q}`, d.Image, ['T1102', 'T1572'], 'Command and Control'); break; }
    case 25: note(r, 'high', 'Process tampering (hollowing/herpaderping)', `${d.Image} ${d.Type || ''}`, ['T1055.012'], 'Defense Evasion'); break;
  }
}
