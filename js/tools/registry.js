// RECmd (batch style plugins) + AppCompatCacheParser + AmcacheParser + SBECmd.
import { Reader, filetimeToIso, utf16, guidStr } from '../core/bytes.js';
import { Hive, guessHiveType } from '../parsers/regf.js';
import { decodeShellItem } from '../parsers/shellitems.js';
import { classifyPath, baseName, expandPath } from '../ioc/heuristics.js';

const rot13 = (s) => s.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26));
const FOLDER_GUIDS = {
  '1AC14E77-02E7-4E5D-B744-2EB1AE5198B7': 'C:\\Windows\\System32', '6D809377-6AF0-444B-8957-A3773F02200E': 'C:\\Program Files',
  '7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E': 'C:\\Program Files (x86)', 'F38BF404-1D43-42F2-9305-67DE0B28FC23': 'C:\\Windows',
  'D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27': 'C:\\Windows\\SysWOW64', '0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8': '%CommonPrograms%',
  'A77F5D77-2E2B-44C3-A6A2-ABA601054A51': '%Programs%', '9E3995AB-1F9C-4F13-B827-48B24B6C7174': '%UserPinned%',
  '374DE290-123F-4565-9164-39C4925E467B': '%Downloads%', 'B4BFCC3A-DB2C-424C-B029-7FE99A87C641': '%Desktop%',
  'F1B32785-6FBA-4FCF-9D55-7B8E7F157091': '%LocalAppData%', '3EB685DB-65F9-4CF6-A03A-E3EF65729F3D': '%AppData%',
  '62AB5D82-FDC1-4DC3-A9DD-070D1D495D97': 'C:\\ProgramData',
};
const expandGuidPath = (p) => p.replace(/^\{([0-9A-F-]{36})\}/i, (m, g) => FOLDER_GUIDS[g.toUpperCase()] || m);

function currentControlSet(root) {
  const sel = root.sub('Select');
  const n = sel ? sel.get('Current') || 1 : 1;
  return root.sub(`ControlSet${String(n).padStart(3, '0')}`) || root.subkeys().find((k) => /^ControlSet\d+/i.test(k.name));
}

const T = (title, columns, rows, note) => ({ title, columns, rows, note });
const binStr = (b) => { try { return utf16(b).replace(/\0.*$/s, ''); } catch { return ''; } };

// ---------------------------------------------------------------- SYSTEM
function shimcache(raw) {
  const r = new Reader(raw);
  const rows = [];
  const sig = r.u32(0);
  if (sig === 0x30 || sig === 0x34) { // Windows 10/11
    let p = sig;
    while (p + 12 < r.length && r.ascii(p, 4) === '10ts') {
      const entSize = r.u32(p + 8), q = p + 12;
      const pl = r.u16(q);
      rows.push({ path: r.utf16(q + 2, pl / 2), modified: r.filetime(q + 2 + pl), executed: null });
      p = q + entSize;
    }
    return { format: 'Windows 10/11', rows };
  }
  if (sig === 0x80) { // Windows 8/8.1
    let p = 0x80;
    while (p + 12 < r.length && /^(00|10)ts$/.test(r.ascii(p, 4))) {
      const entSize = r.u32(p + 8), q = p + 12;
      const pl = r.u16(q); let o = q + 2 + pl;
      const pkl = r.u16(o); o += 2 + pkl;
      const flags = r.u32(o);
      rows.push({ path: r.utf16(q + 2, pl / 2), modified: r.filetime(o + 8), executed: !!(flags & 2) });
      p = q + entSize;
    }
    return { format: 'Windows 8.x', rows };
  }
  if (sig === 0xbadc0fee) { // Windows 7 / 2008 R2
    const n = r.u32(4);
    const x64 = r.u32(128 + 8) === 0 || r.u32(128 + 4) === 0 ? true : r.u32(128 + 4) > r.length;
    const es = x64 ? 48 : 32;
    for (let i = 0; i < n; i++) {
      const e = 128 + i * es;
      if (e + es > r.length) break;
      const len = r.u16(e);
      const off = x64 ? r.u32(e + 8) : r.u32(e + 4);
      const mod = r.filetime(x64 ? e + 16 : e + 8);
      const ins = r.u32(x64 ? e + 24 : e + 16);
      if (off + len > r.length) continue;
      rows.push({ path: r.utf16(off, len / 2), modified: mod, executed: !!(ins & 2) });
    }
    return { format: 'Windows 7', rows };
  }
  if (sig === 0xdeadbeef) return { format: 'Windows XP (not decoded)', rows };
  return { format: `unknown header 0x${sig.toString(16)}`, rows };
}

function systemPlugins(root, f, ctx, tables) {
  const cs = currentControlSet(root);
  if (!cs) return;
  const info = [];
  const cn = cs.path('Control\\ComputerName\\ComputerName')?.get('ComputerName');
  if (cn) { info.push(['ComputerName', cn]); ctx.hosts.add(cn); }
  const tz = cs.path('Control\\TimeZoneInformation');
  if (tz) info.push(['TimeZone', tz.get('TimeZoneKeyName') || tz.get('StandardName') || '']);
  const sd = cs.path('Control\\Windows')?.value('ShutdownTime');
  if (sd && sd.raw.length >= 8) info.push(['Last shutdown', filetimeToIso(new Reader(sd.raw).u64(0))]);
  info.push(['Current ControlSet', cs.name]);

  // RDP / credential settings
  const ts = cs.path('Control\\Terminal Server');
  if (ts) {
    const deny = ts.get('fDenyTSConnections');
    info.push(['RDP (fDenyTSConnections)', deny === 0 ? 'ENABLED' : String(deny ?? 'n/a')]);
    if (deny === 0) ctx.finding({ sev: 'low', category: 'Configuration', tool: 'RECmd', file: f.name, time: ts.lastWritten, title: 'Remote Desktop is enabled', detail: 'fDenyTSConnections = 0. Expected on servers; on workstations correlate with 4624 type 10 / 1149 events.', mitre: ['T1021.001'] });
    const port = ts.path('WinStations\\RDP-Tcp')?.get('PortNumber');
    if (port && port !== 3389) ctx.finding({ sev: 'medium', category: 'Configuration', tool: 'RECmd', file: f.name, title: `RDP listening on non-standard port ${port}`, detail: 'Port changes are used to hide RDP exposure.', mitre: ['T1021.001'] });
    const sticky = ts.path('WinStations\\RDP-Tcp')?.get('UserAuthentication');
    if (sticky === 0) ctx.finding({ sev: 'medium', category: 'Configuration', tool: 'RECmd', file: f.name, title: 'RDP Network Level Authentication disabled', detail: 'UserAuthentication = 0 lets anyone reach the logon screen (sticky keys / utilman backdoors).', mitre: ['T1021.001'] });
  }
  const wd = cs.path('Control\\SecurityProviders\\WDigest')?.get('UseLogonCredential');
  if (wd === 1) ctx.finding({ sev: 'high', category: 'Credential Access', tool: 'RECmd', file: f.name, title: 'WDigest UseLogonCredential = 1', detail: 'Forces cleartext passwords in LSASS memory. Classic pre-Mimikatz setup.', mitre: ['T1112', 'T1003.001'] });
  const lsa = cs.path('Control\\Lsa');
  if (lsa) {
    const defaults = { 'Security Packages': ['kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', ''], 'Authentication Packages': ['msv1_0', ''], 'Notification Packages': ['scecli', 'rassfm', ''] };
    for (const [vn, ok] of Object.entries(defaults)) {
      const v = lsa.get(vn);
      const list = Array.isArray(v) ? v : v ? [v] : [];
      const extra = list.filter((x) => !ok.includes(String(x).toLowerCase().replace(/"/g, '')));
      if (extra.length) ctx.finding({ sev: 'high', category: 'Persistence', tool: 'RECmd', file: f.name, time: lsa.lastWritten, title: `Non-default LSA ${vn}: ${extra.join(', ')}`, detail: 'LSA packages load into lsass.exe. Unknown entries can be password filters or SSP credential stealers (e.g. mimilib, memssp).', mitre: ['T1547.002', 'T1547.005', 'T1556.002'] });
    }
    if (lsa.get('DisableRestrictedAdmin') === 0) ctx.finding({ sev: 'medium', category: 'Lateral Movement', tool: 'RECmd', file: f.name, title: 'RestrictedAdmin mode enabled (DisableRestrictedAdmin = 0)', detail: 'Enables pass-the-hash over RDP.', mitre: ['T1550.002'] });
    info.push(['LSA RunAsPPL', String(lsa.get('RunAsPPL') ?? 'not set')]);
  }
  // Port proxy
  const pp = cs.path('Services\\PortProxy');
  if (pp) for (const k of pp.subkeys()) for (const kk of k.subkeys()) for (const v of kk.values()) {
    ctx.finding({ sev: 'high', category: 'Command and Control', tool: 'RECmd', file: f.name, time: kk.lastWritten, title: `netsh PortProxy rule ${k.name}/${kk.name}: ${v.name} -> ${v.data}`, detail: 'Port forwarding is used to tunnel RDP/SMB through a pivot host.', mitre: ['T1090'] });
    ctx.text(String(v.data), f.name);
  }

  // Services
  const svcRows = [];
  const svcs = cs.sub('Services');
  if (svcs) for (const s of svcs.subkeys()) {
    const img = s.get('ImagePath'); if (!img) continue;
    const start = s.get('Start'), type = s.get('Type');
    const dll = s.path('Parameters')?.get('ServiceDll') || '';
    svcRows.push([s.lastWritten, s.name, String(img), dll, start, type, s.get('ObjectName') || '', s.get('DisplayName') || '']);
    const cmd = String(img) + (dll ? ` [ServiceDll: ${dll}]` : '');
    const isDriver = type === 1 || type === 2;
    const sev = ctx.persist({ mechanism: isDriver ? 'Driver service' : 'Service', name: s.name, command: String(img), time: s.lastWritten, tool: 'RECmd', file: f.name, mitre: ['T1543.003'] });
    if (dll) ctx.persist({ mechanism: 'Service DLL', name: s.name, command: dll, time: s.lastWritten, tool: 'RECmd', file: f.name, mitre: ['T1543.003'] });
    const imgX = expandPath(String(img).replace(/^"([^"]+)".*$/, '$1').replace(/\s+-.*$/, ''));
    if (!sev && /\.(exe|sys)/i.test(imgX) && /^[a-z]:\\/i.test(imgX) && !/^c:\\(windows|program files|program files \(x86\)|programdata\\(microsoft|package cache))\\/i.test(imgX)) {
      ctx.finding({ sev: 'low', category: 'Persistence', tool: 'RECmd', file: f.name, time: s.lastWritten, title: `Service binary outside Windows/Program Files: ${s.name}`, detail: 'Review publisher and signature.', evidence: cmd, mitre: ['T1543.003'] });
    }
    if (/^psexesvc|^paexec|^remcom|^csexec|^btobto|^[a-z]{8}$/i.test(s.name) && /\\windows\\[^\\]+\.exe$/i.test(String(img)) && /psexe|paexec|remcom|csexec/i.test(String(img) + s.name)) {
      ctx.finding({ sev: 'high', category: 'Lateral Movement', tool: 'RECmd', file: f.name, time: s.lastWritten, title: `Remote execution service installed: ${s.name}`, evidence: String(img), mitre: ['T1569.002'] });
    }
  }
  tables.push(T('Services', ['KeyLastWrite', 'Name', 'ImagePath', 'ServiceDll', 'Start', 'Type', 'Account', 'DisplayName'], svcRows));

  // ShimCache
  const acc = cs.path('Control\\Session Manager\\AppCompatCache')?.value('AppCompatCache') || cs.path('Control\\Session Manager\\AppCompatibility')?.value('AppCompatCache');
  if (acc) {
    try {
      const sc = shimcache(acc.raw);
      const rows = sc.rows.map((e, i) => [i, e.modified, e.path, e.executed === null ? 'n/a' : e.executed ? 'Yes' : 'No']);
      tables.push(T(`AppCompatCache / ShimCache (${sc.format})`, ['Position', 'LastModified', 'Path', 'Executed'], rows, 'Position 0 is the most recent entry. On Win10+ presence means the file was seen by the shim engine, not proof of execution.'));
      for (const e of sc.rows) {
        ctx.event({ time: e.modified, tool: 'AppCompatCacheParser', file: f.name, type: 'ShimCache (file mtime)', desc: e.path });
        const pc = classifyPath(e.path);
        if (pc.sev) ctx.exec_({ path: e.path, time: e.modified, tool: 'AppCompatCacheParser', file: f.name, source: 'ShimCache' });
      }
    } catch (e) { tables.push(T('AppCompatCache', ['Error'], [[e.message]])); }
  }

  // BAM / DAM
  const bamRows = [];
  for (const base of ['Services\\bam\\State\\UserSettings', 'Services\\bam\\UserSettings', 'Services\\dam\\State\\UserSettings', 'Services\\dam\\UserSettings']) {
    const k = cs.path(base); if (!k) continue;
    for (const sid of k.subkeys()) for (const v of sid.values()) {
      if (v.raw.length < 8 || /^(version|sequencenumber)$/i.test(v.name)) continue;
      const t = filetimeToIso(new Reader(v.raw).u64(0));
      bamRows.push([t, sid.name, v.name, base.includes('dam') ? 'DAM' : 'BAM']);
      ctx.event({ time: t, tool: 'RECmd (BAM)', file: f.name, type: 'Program execution (BAM)', desc: `${v.name} [${sid.name}]` });
      ctx.exec_({ path: v.name.replace(/^\\Device\\HarddiskVolume\d+/i, 'C:'), time: t, tool: 'RECmd', file: f.name, source: 'BAM', user: sid.name });
    }
  }
  if (bamRows.length) tables.push(T('BAM / DAM (background activity, last execution per user)', ['LastExecution', 'UserSID', 'Program', 'Source'], bamRows.sort((a, b) => (b[0] || '').localeCompare(a[0] || ''))));

  // USB devices
  const usbRows = [];
  const usb = cs.path('Enum\\USBSTOR');
  if (usb) for (const dev of usb.subkeys()) for (const ser of dev.subkeys()) {
    usbRows.push([ser.lastWritten, dev.name, ser.name, ser.get('FriendlyName') || '']);
    ctx.event({ time: ser.lastWritten, tool: 'RECmd (USBSTOR)', file: f.name, type: 'USB device', desc: `${ser.get('FriendlyName') || dev.name} serial ${ser.name}` });
  }
  if (usbRows.length) {
    tables.push(T('USB storage devices (USBSTOR)', ['KeyLastWrite', 'Device', 'Serial', 'FriendlyName'], usbRows));
    ctx.finding({ sev: 'info', category: 'Exfiltration', tool: 'RECmd', file: f.name, title: `${usbRows.length} USB mass storage device(s) connected historically`, detail: usbRows.map((r) => r[3] || r[1]).slice(0, 10).join('; '), mitre: ['T1052.001'] });
  }
  // network interfaces
  const ifs = cs.path('Services\\Tcpip\\Parameters\\Interfaces');
  if (ifs) {
    const rows = [];
    for (const i of ifs.subkeys()) {
      const ip = i.get('DhcpIPAddress') || i.get('IPAddress'); if (!ip || (Array.isArray(ip) && !ip.length)) continue;
      rows.push([i.lastWritten, i.name, Array.isArray(ip) ? ip.join(', ') : ip, i.get('DhcpServer') || '', Array.isArray(i.get('DefaultGateway')) ? i.get('DefaultGateway').join(', ') : i.get('DhcpDefaultGateway')?.join?.(', ') || '', i.get('DhcpDomain') || i.get('Domain') || '']);
    }
    if (rows.length) tables.push(T('Network interfaces', ['KeyLastWrite', 'Interface', 'IP', 'DHCP server', 'Gateway', 'Domain'], rows));
  }
  tables.unshift(T('System information', ['Field', 'Value'], info));
}

// ---------------------------------------------------------------- SOFTWARE
function scanRunKey(k, label, f, ctx, rows, hive) {
  if (!k) return;
  for (const v of k.values()) {
    const cmd = v.data instanceof Uint8Array ? binStr(v.data) : String(v.data ?? '');
    rows.push([k.lastWritten, label, v.name, cmd]);
    ctx.event({ time: k.lastWritten, tool: 'RECmd', file: f.name, type: 'Run key (key last write)', desc: `${label}\\${v.name} = ${cmd}` });
    ctx.persist({ mechanism: `${hive} ${label}`, name: v.name, command: cmd, time: k.lastWritten, tool: 'RECmd', file: f.name, mitre: ['T1547.001'] });
  }
}

const ACCESSIBILITY = /^(sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)\.exe$/i;

function softwarePlugins(root, f, ctx, tables) {
  const info = [];
  const cv = root.path('Microsoft\\Windows NT\\CurrentVersion');
  if (cv) {
    info.push(['ProductName', cv.get('ProductName') || ''], ['DisplayVersion', cv.get('DisplayVersion') || cv.get('ReleaseId') || ''], ['Build', `${cv.get('CurrentBuild') || ''}.${cv.get('UBR') ?? ''}`], ['RegisteredOwner', cv.get('RegisteredOwner') || '']);
    const inst = cv.get('InstallDate'); if (inst) info.push(['InstallDate', new Date(inst * 1000).toISOString()]);
  }
  tables.push(T('OS information', ['Field', 'Value'], info));

  const runRows = [];
  for (const p of ['Microsoft\\Windows\\CurrentVersion\\Run', 'Microsoft\\Windows\\CurrentVersion\\RunOnce', 'Microsoft\\Windows\\CurrentVersion\\RunOnceEx', 'Microsoft\\Windows\\CurrentVersion\\RunServices', 'Microsoft\\Windows\\CurrentVersion\\RunServicesOnce', 'Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run', 'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', 'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'Microsoft\\Active Setup\\Installed Components']) {
    if (p.endsWith('Installed Components')) {
      const ac = root.path(p); if (!ac) continue;
      for (const c of ac.subkeys()) { const sp = c.get('StubPath'); if (sp) { runRows.push([c.lastWritten, 'Active Setup', c.name, String(sp)]); ctx.persist({ mechanism: 'Active Setup', name: c.get('(default)') || c.name, command: String(sp), time: c.lastWritten, tool: 'RECmd', file: f.name, mitre: ['T1547.014'] }); } }
      continue;
    }
    scanRunKey(root.path(p), p.replace('Microsoft\\Windows\\CurrentVersion\\', ''), f, ctx, runRows, 'HKLM');
  }
  // Winlogon
  const wl = root.path('Microsoft\\Windows NT\\CurrentVersion\\Winlogon');
  if (wl) {
    const shell = String(wl.get('Shell') ?? ''), ui = String(wl.get('Userinit') ?? '');
    runRows.push([wl.lastWritten, 'Winlogon', 'Shell', shell], [wl.lastWritten, 'Winlogon', 'Userinit', ui]);
    if (shell && !/^explorer\.exe,?$/i.test(shell.trim())) ctx.finding({ sev: 'critical', category: 'Persistence', tool: 'RECmd', file: f.name, time: wl.lastWritten, title: 'Winlogon Shell modified', evidence: shell, detail: 'Expected "explorer.exe".', mitre: ['T1547.004'] });
    if (ui && !/^c:\\windows\\system32\\userinit\.exe,?$/i.test(ui.trim())) ctx.finding({ sev: 'critical', category: 'Persistence', tool: 'RECmd', file: f.name, time: wl.lastWritten, title: 'Winlogon Userinit modified', evidence: ui, detail: 'Expected "C:\\Windows\\system32\\userinit.exe,".', mitre: ['T1547.004'] });
    const notify = wl.sub('Notify');
    if (notify) for (const n of notify.subkeys()) { const dll = n.get('DLLName'); if (dll) runRows.push([n.lastWritten, 'Winlogon Notify', n.name, String(dll)]); }
    for (const vn of ['Taskman', 'AppSetup', 'GinaDLL']) { const v = wl.get(vn); if (v) { runRows.push([wl.lastWritten, 'Winlogon', vn, String(v)]); ctx.persist({ mechanism: 'Winlogon ' + vn, name: vn, command: String(v), time: wl.lastWritten, tool: 'RECmd', file: f.name, alwaysReport: 'medium', mitre: ['T1547.004'] }); } }
  }
  // AppInit
  const win = root.path('Microsoft\\Windows NT\\CurrentVersion\\Windows');
  for (const k of [win, root.path('Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows')]) {
    const ai = k?.get('AppInit_DLLs');
    if (ai && String(ai).trim()) { runRows.push([k.lastWritten, 'AppInit_DLLs', 'AppInit_DLLs', String(ai)]); ctx.finding({ sev: k.get('LoadAppInit_DLLs') === 1 ? 'high' : 'medium', category: 'Persistence', tool: 'RECmd', file: f.name, time: k.lastWritten, title: `AppInit_DLLs set (LoadAppInit_DLLs=${k.get('LoadAppInit_DLLs')})`, evidence: String(ai), mitre: ['T1546.010'] }); }
  }
  // IFEO
  const ifeoRows = [];
  for (const base of ['Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options', 'Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options']) {
    const ifeo = root.path(base); if (!ifeo) continue;
    for (const e of ifeo.subkeys()) {
      const dbg = e.get('Debugger'); const gf = e.get('GlobalFlag');
      if (dbg) {
        ifeoRows.push([e.lastWritten, e.name, 'Debugger', String(dbg)]);
        const crit = ACCESSIBILITY.test(e.name);
        ctx.finding({ sev: crit ? 'critical' : /vsjitdebugger|windbg|devenv/i.test(String(dbg)) ? 'low' : 'high', category: 'Persistence', tool: 'RECmd', file: f.name, time: e.lastWritten, title: `IFEO Debugger on ${e.name}${crit ? ' (accessibility backdoor)' : ''}`, evidence: String(dbg), detail: 'Image File Execution Options Debugger hijacks process launch.', mitre: ['T1546.012', ...(crit ? ['T1546.008'] : [])] });
      }
      if (gf && (gf & 0x200)) ifeoRows.push([e.lastWritten, e.name, 'GlobalFlag', '0x' + gf.toString(16)]);
    }
  }
  const spe = root.path('Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit');
  if (spe) for (const e of spe.subkeys()) { const mp = e.get('MonitorProcess'); if (mp) { ifeoRows.push([e.lastWritten, e.name, 'SilentProcessExit MonitorProcess', String(mp)]); ctx.finding({ sev: /lsass/i.test(e.name) ? 'critical' : 'high', category: /lsass/i.test(e.name) ? 'Credential Access' : 'Persistence', tool: 'RECmd', file: f.name, time: e.lastWritten, title: `SilentProcessExit monitor on ${e.name}`, evidence: String(mp), detail: /lsass/i.test(e.name) ? 'Used to dump LSASS via WER (LsassSilentProcessExit).' : 'Runs a program when the target exits.', mitre: ['T1546.012', 'T1003.001'] }); } }
  if (ifeoRows.length) tables.push(T('Image File Execution Options / SilentProcessExit', ['KeyLastWrite', 'Image', 'Value', 'Data'], ifeoRows));
  tables.push(T('Autoruns (HKLM)', ['KeyLastWrite', 'Location', 'Name', 'Command'], runRows));

  // Defender
  const defRows = [];
  const pol = root.path('Policies\\Microsoft\\Windows Defender');
  if (pol) {
    for (const [k, vn] of [[pol, 'DisableAntiSpyware'], [pol, 'DisableAntiVirus'], [pol.sub('Real-Time Protection'), 'DisableRealtimeMonitoring'], [pol.sub('Real-Time Protection'), 'DisableBehaviorMonitoring'], [pol.sub('Real-Time Protection'), 'DisableIOAVProtection'], [pol.sub('Spynet'), 'SpynetReporting'], [pol.sub('Spynet'), 'SubmitSamplesConsent']]) {
      const v = k?.get(vn); if (v === undefined) continue;
      defRows.push([k.lastWritten, 'Policy', vn, v]);
      if (/^Disable/.test(vn) && v === 1) ctx.finding({ sev: 'high', category: 'Defense Evasion', tool: 'RECmd', file: f.name, time: k.lastWritten, title: `Defender policy ${vn} = 1`, mitre: ['T1562.001'] });
    }
  }
  for (const base of ['Microsoft\\Windows Defender\\Exclusions', 'Policies\\Microsoft\\Windows Defender\\Exclusions']) {
    const ex = root.path(base); if (!ex) continue;
    for (const t of ex.subkeys()) for (const v of t.values()) {
      defRows.push([t.lastWritten, `Exclusion ${t.name}`, v.name, v.data]);
      const broad = /^[a-z]:\\?$|\\(temp|users\\public|programdata|appdata|downloads|perflogs)\\?$|^\.?(exe|dll|ps1|bat|vbs|js|tmp)$|^(powershell|rundll32|regsvr32|cmd|mshta)\.exe$/i.test(v.name);
      ctx.finding({ sev: broad ? 'high' : 'medium', category: 'Defense Evasion', tool: 'RECmd', file: f.name, time: t.lastWritten, title: `Defender ${t.name} exclusion: ${v.name}`, detail: broad ? 'Broad exclusion covering a common malware staging location or type.' : 'Review whether this exclusion is sanctioned.', mitre: ['T1562.001'] });
    }
  }
  if (defRows.length) tables.push(T('Microsoft Defender configuration', ['KeyLastWrite', 'Area', 'Name', 'Value'], defRows));

  // Scheduled tasks (TaskCache)
  const tcRows = [];
  const tree = root.path('Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree');
  const tasks = root.path('Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks');
  // Win8+ stores an SD value on every Tree key; only then is a missing SD meaningful.
  let withSd = 0, total = 0;
  const count = (k) => { for (const s of k.subkeys()) { if (s.value('Id')) { total++; if (s.value('SD')) withSd++; } if (s.nSub) count(s); } };
  if (tree) count(tree);
  const sdTracked = total > 0 && withSd / total > 0.5;
  const walk = (k, prefix) => {
    for (const s of k.subkeys()) {
      const id = s.get('Id');
      const full = `${prefix}\\${s.name}`;
      if (id) {
        const t = tasks?.sub(String(id));
        let action = '';
        const a = t?.value('Actions');
        if (a) action = (a.raw.length ? (String.fromCharCode(...a.raw.subarray(0, Math.min(a.raw.length, 4096))).replace(/\0/g, '').match(/[\x20-\x7e]{3,}/g) || []).join(' ') : '').replace(/^\S{1,4}\s/, '');
        const hidden = sdTracked && !s.value('SD');
        tcRows.push([s.lastWritten, full, action, t?.get('Author') || '', hidden ? 'YES (no SD)' : '']);
        ctx.event({ time: s.lastWritten, tool: 'RECmd (TaskCache)', file: f.name, type: 'Scheduled task (key last write)', desc: `${full} -> ${action}` });
        if (hidden) ctx.finding({ sev: 'critical', category: 'Defense Evasion', tool: 'RECmd', file: f.name, time: s.lastWritten, title: `Hidden scheduled task (SD value removed): ${full}`, evidence: action, detail: 'Tasks without a security descriptor are invisible to schtasks/Task Scheduler (Tarrask technique).', mitre: ['T1053.005', 'T1564'] });
        if (/^\\At\d+$/i.test(full)) ctx.finding({ sev: 'medium', category: 'Persistence', tool: 'RECmd', file: f.name, time: s.lastWritten, title: `Legacy AT job: ${full}`, evidence: action, detail: 'Created with at.exe, a common lateral movement/persistence method on older systems.', mitre: ['T1053.002'] });
        else if (!hidden && !/^\\Microsoft\\/i.test(full)) ctx.persist({ mechanism: 'Scheduled task', name: full, command: action, time: s.lastWritten, tool: 'RECmd', file: f.name, mitre: ['T1053.005'] });
      }
      if (s.nSub) walk(s, full);
    }
  };
  if (tree) walk(tree, '');
  if (tcRows.length) tables.push(T('Scheduled tasks (TaskCache)', ['KeyLastWrite', 'Task', 'Action (strings)', 'Author', 'Hidden'], tcRows));

  // Installed software
  const insRows = [];
  for (const base of ['Microsoft\\Windows\\CurrentVersion\\Uninstall', 'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall']) {
    const u = root.path(base); if (!u) continue;
    for (const a of u.subkeys()) {
      const name = a.get('DisplayName'); if (!name) continue;
      const loc = a.get('InstallLocation') || '';
      insRows.push([a.lastWritten, name, a.get('DisplayVersion') || '', a.get('Publisher') || '', a.get('InstallDate') || '', loc]);
      if (/anydesk|teamviewer|screenconnect|connectwise control|splashtop|atera|rustdesk|meshagent|netsupport|ammyy|remote utilities|logmein|supremo|zoho assist|simplehelp|dwservice|ngrok|advanced ip scanner|advanced port scanner|softperfect network scanner|angry ip|rclone|megasync|wireshark|nmap|mimikatz|cobalt|process hacker|system informer/i.test(name))
        ctx.finding({ sev: /mimikatz|cobalt/i.test(name) ? 'critical' : 'medium', category: 'Installed Tools', tool: 'RECmd', file: f.name, time: a.lastWritten, title: `Dual-use / remote access software installed: ${name}`, detail: `Publisher ${a.get('Publisher') || 'n/a'}; ${loc}`, mitre: ['T1219'] });
    }
  }
  if (insRows.length) tables.push(T('Installed programs (Uninstall)', ['KeyLastWrite', 'Name', 'Version', 'Publisher', 'InstallDate', 'InstallLocation'], insRows));

  // Network profiles
  const np = root.path('Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles');
  if (np) {
    const st = (b) => { if (!(b instanceof Uint8Array) || b.length < 16) return ''; const r = new Reader(b); const d = Date.UTC(r.u16(0), r.u16(2) - 1, r.u16(6), r.u16(8), r.u16(10), r.u16(12)); return isNaN(d) ? '' : new Date(d).toISOString().replace('Z', ' (local)'); };
    const rows = np.subkeys().map((p) => [p.lastWritten, p.get('ProfileName') || '', p.get('Description') || '', st(p.get('DateCreated')), st(p.get('DateLastConnected')), { 6: 'Wired', 71: 'Wireless', 23: 'VPN', 243: 'Mobile' }[p.get('NameType')] || p.get('NameType')]);
    tables.push(T('Network profiles (networks this host joined)', ['KeyLastWrite', 'ProfileName', 'Description', 'Created', 'LastConnected', 'Type'], rows));
  }
}

// ---------------------------------------------------------------- NTUSER
function shellbags(root, f, ctx, tables, basePath) {
  const bm = root.path(basePath); if (!bm) return;
  const rows = [];
  const walk = (k, parent, depth) => {
    if (depth > 40) return;
    for (const v of k.values()) {
      if (!/^\d+$/.test(v.name) || !(v.raw instanceof Uint8Array) || v.raw.length < 3) continue;
      const item = decodeShellItem(new Reader(v.raw));
      const path = parent ? `${parent}\\${item.name}` : item.name;
      const sub = k.sub(v.name);
      rows.push([sub?.lastWritten || '', path.replace(/^(My Computer|Users Files)\\/, ''), item.type, item.created || '', item.modified || '', item.accessed || '', item.mft ? `${item.mft.entry}-${item.mft.seq}` : '']);
      if (sub) walk(sub, path, depth + 1);
    }
  };
  walk(bm, '', 0);
  if (!rows.length) return;
  tables.push(T(`ShellBags (${basePath.split('\\').slice(-2).join('\\')})`, ['KeyLastWrite', 'Path', 'Type', 'Created', 'Modified', 'Accessed', 'MFT'], rows, 'Folders the user browsed in Explorer, including removable, network and since deleted folders.'));
  for (const r of rows) {
    if (r[0]) ctx.event({ time: r[0], tool: 'SBECmd', file: f.name, type: 'ShellBag (folder interaction)', desc: r[1] });
    if (/\\\\|^network|\\(admin|c)\$/i.test(r[1]) || r[2] === 'network') ctx.indicators.add('unc', r[1], f.name, 'ShellBag');
    if (/mimikatz|bloodhound|sharphound|\\tools?\\|hacktool|exploit|payload|\\loot\\|\\exfil|\\dump|\\staging|rubeus|cobalt|psexec|\\perflogs\\/i.test(r[1]))
      ctx.finding({ sev: 'medium', category: 'Discovery', tool: 'SBECmd', file: f.name, time: r[0], title: 'User browsed a folder with attacker-tooling name', evidence: r[1], mitre: ['T1083'] });
  }
}

function ntuserPlugins(root, f, ctx, tables) {
  const runRows = [];
  for (const p of ['Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run', 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\Run']) {
    scanRunKey(root.path(p), p.replace('Software\\Microsoft\\Windows\\CurrentVersion\\', ''), f, ctx, runRows, 'HKCU');
  }
  const winK = root.path('Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows');
  const load = winK?.get('Load'); if (load) { runRows.push([winK.lastWritten, 'Windows\\Load', 'Load', String(load)]); ctx.persist({ mechanism: 'HKCU Windows Load', name: 'Load', command: String(load), time: winK.lastWritten, tool: 'RECmd', file: f.name, alwaysReport: 'high', mitre: ['T1547.001'] }); }
  const env = root.sub('Environment');
  const ls = env?.get('UserInitMprLogonScript'); if (ls) { runRows.push([env.lastWritten, 'Environment', 'UserInitMprLogonScript', String(ls)]); ctx.persist({ mechanism: 'Logon script (UserInitMprLogonScript)', name: 'UserInitMprLogonScript', command: String(ls), time: env.lastWritten, tool: 'RECmd', file: f.name, alwaysReport: 'high', mitre: ['T1037.001'] }); }
  const wl = root.path('Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon');
  const shell = wl?.get('Shell'); if (shell) { runRows.push([wl.lastWritten, 'Winlogon (user)', 'Shell', String(shell)]); ctx.finding({ sev: 'critical', category: 'Persistence', tool: 'RECmd', file: f.name, time: wl.lastWritten, title: 'Per-user Winlogon Shell value set', evidence: String(shell), mitre: ['T1547.004'] }); }
  // UAC bypass / COM hijack via HKCU Classes
  for (const p of ['Software\\Classes\\ms-settings\\Shell\\Open\\command', 'Software\\Classes\\mscfile\\shell\\open\\command', 'Software\\Classes\\exefile\\shell\\open\\command', 'Software\\Classes\\Folder\\shell\\open\\command', 'Software\\Classes\\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\\Shell\\open\\command', 'Software\\Classes\\Launcher.SystemSettings\\Shell\\Open\\command']) {
    const k = root.path(p); if (!k) continue;
    const cmd = String(k.get('(default)') ?? '');
    runRows.push([k.lastWritten, 'HKCU shell open command', p.split('\\')[2], cmd]);
    ctx.finding({ sev: 'critical', category: 'Privilege Escalation', tool: 'RECmd', file: f.name, time: k.lastWritten, title: `UAC bypass hijack: HKCU\\${p}`, evidence: cmd || '(DelegateExecute set)', detail: 'Auto-elevating binaries (fodhelper, eventvwr, sdclt, computerdefaults) read these keys.', mitre: ['T1548.002'] });
  }
  const clsid = root.path('Software\\Classes\\CLSID');
  if (clsid) for (const c of clsid.subkeys()) {
    for (const sub of ['InprocServer32', 'LocalServer32']) {
      const s = c.sub(sub); if (!s) continue;
      const dll = String(s.get('(default)') ?? '');
      if (dll) { const pc = classifyPath(dll); runRows.push([s.lastWritten, `HKCU CLSID ${sub}`, c.name, dll]); if (pc.sev || /\\(temp|public|appdata\\roaming|programdata)\\/i.test(dll)) ctx.finding({ sev: 'high', category: 'Persistence', tool: 'RECmd', file: f.name, time: s.lastWritten, title: `Possible COM hijack: HKCU CLSID ${c.name}`, evidence: dll, mitre: ['T1546.015'] }); }
    }
  }
  tables.push(T('Autoruns (HKCU)', ['KeyLastWrite', 'Location', 'Name', 'Command'], runRows));

  // UserAssist
  const ua = root.path('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist');
  const uaRows = [];
  if (ua) for (const g of ua.subkeys()) {
    const cnt = g.sub('Count'); if (!cnt) continue;
    for (const v of cnt.values()) {
      const name = expandGuidPath(rot13(v.name));
      const b = v.raw; let runs = null, focus = null, last = null;
      if (b.length >= 72) { const r = new Reader(b); runs = r.u32(4); focus = r.u32(12); last = r.filetime(60); }
      else if (b.length >= 16) { const r = new Reader(b); runs = Math.max(0, r.u32(4) - 5); last = r.filetime(8); }
      if (/^UEME_/.test(name)) continue;
      uaRows.push([last, name, runs, focus != null ? Math.round(focus / 1000) + 's' : '', g.name]);
      if (last) {
        ctx.event({ time: last, tool: 'RECmd (UserAssist)', file: f.name, type: 'Program execution (UserAssist GUI)', desc: `${name} (runs ${runs})` });
        ctx.exec_({ path: name, time: last, tool: 'RECmd', file: f.name, source: 'UserAssist' });
      }
    }
  }
  if (uaRows.length) tables.push(T('UserAssist (GUI program execution)', ['LastExecuted', 'Program', 'RunCount', 'FocusTime', 'GUID'], uaRows.sort((a, b) => (b[0] || '').localeCompare(a[0] || ''))));

  // MRUs
  const mru = [];
  const exp = root.path('Software\\Microsoft\\Windows\\CurrentVersion\\Explorer');
  const runMru = exp?.sub('RunMRU');
  if (runMru) for (const v of runMru.values()) if (v.name !== 'MRUList') {
    const cmd = String(v.data).replace(/\\1$/, '');
    mru.push([runMru.lastWritten, 'RunMRU (Win+R)', cmd]);
    const cc = ctx.exec_({ path: cmd.split(' ')[0], args: cmd, time: runMru.lastWritten, tool: 'RECmd', file: f.name, source: 'RunMRU' });
  }
  const tp = exp?.sub('TypedPaths');
  if (tp) for (const v of tp.values()) { mru.push([tp.lastWritten, 'TypedPaths (Explorer bar)', String(v.data)]); if (/^\\\\/.test(String(v.data))) ctx.indicators.add('unc', String(v.data), f.name, 'TypedPaths'); }
  const ww = exp?.sub('WordWheelQuery');
  if (ww) for (const v of ww.values()) if (/^\d+$/.test(v.name)) { const q = binStr(v.raw); mru.push([ww.lastWritten, 'WordWheelQuery (search)', q]); if (/password|passwd|creds|credential|vpn|wallet|\.kdbx|secret|backup|admin/i.test(q)) ctx.finding({ sev: 'medium', category: 'Credential Access', tool: 'RECmd', file: f.name, time: ww.lastWritten, title: `User searched for: ${q}`, mitre: ['T1552.001'] }); }
  const rd = exp?.sub('RecentDocs');
  if (rd) for (const v of rd.values()) if (/^\d+$/.test(v.name)) mru.push([rd.lastWritten, 'RecentDocs', binStr(v.raw)]);
  const tu = root.path('Software\\Microsoft\\Internet Explorer\\TypedURLs');
  if (tu) for (const v of tu.values()) { mru.push([tu.lastWritten, 'TypedURLs', String(v.data)]); ctx.text(String(v.data), f.name); }
  const lv = exp?.path('ComDlg32\\LastVisitedPidlMRU');
  if (lv) for (const v of lv.values()) if (/^\d+$/.test(v.name)) mru.push([lv.lastWritten, 'LastVisitedPidlMRU (app used file dialog)', binStr(v.raw)]);
  const mp = exp?.sub('MountPoints2');
  if (mp) for (const k of mp.subkeys()) { mru.push([k.lastWritten, 'MountPoints2', k.name]); if (/^##/.test(k.name)) ctx.indicators.add('unc', k.name.replace(/#/g, '\\'), f.name, 'MountPoints2'); }
  tables.push(T('MRU lists and user activity', ['KeyLastWrite', 'Source', 'Value'], mru));
  for (const m of mru) if (m[0]) ctx.event({ time: m[0], tool: 'RECmd', file: f.name, type: m[1] + ' (key last write)', desc: m[2] });

  // RDP client history
  const tsc = root.path('Software\\Microsoft\\Terminal Server Client');
  if (tsc) {
    const rows = [];
    for (const s of tsc.sub('Servers')?.subkeys() || []) { rows.push([s.lastWritten, s.name, s.get('UsernameHint') || '']); ctx.indicators.add('rdp_target', s.name, f.name, `user ${s.get('UsernameHint') || ''}`); ctx.event({ time: s.lastWritten, tool: 'RECmd', file: f.name, type: 'Outbound RDP (Terminal Server Client)', desc: `${s.name} as ${s.get('UsernameHint') || '?'}` }); }
    for (const v of tsc.sub('Default')?.values() || []) if (/^MRU/.test(v.name)) rows.push([tsc.sub('Default').lastWritten, String(v.data), '(Default MRU)']);
    if (rows.length) {
      tables.push(T('Outbound RDP connections (Terminal Server Client)', ['KeyLastWrite', 'Host', 'UsernameHint'], rows));
      ctx.finding({ sev: 'low', category: 'Lateral Movement', tool: 'RECmd', file: f.name, title: `User initiated RDP to ${rows.length} host(s)`, detail: rows.map((r) => r[1]).join(', ').slice(0, 400), mitre: ['T1021.001'] });
    }
  }
  // Sysinternals EULA = tool was run
  const si = root.path('Software\\Sysinternals');
  if (si) {
    const rows = si.subkeys().map((k) => [k.lastWritten, k.name, k.get('EulaAccepted')]);
    tables.push(T('Sysinternals tools run (EulaAccepted)', ['KeyLastWrite', 'Tool', 'EulaAccepted'], rows));
    for (const r of rows) {
      ctx.event({ time: r[0], tool: 'RECmd', file: f.name, type: 'Sysinternals EULA accepted (tool first run)', desc: r[1] });
      if (/psexec|procdump|pskill|psloggedon|sdelete|psservice|accesschk|psgetsid|psinfo|pspasswd/i.test(r[1]))
        ctx.finding({ sev: /psexec|procdump|sdelete/i.test(r[1]) ? 'medium' : 'low', category: 'Execution', tool: 'RECmd', file: f.name, time: r[0], title: `Sysinternals ${r[1]} was run by this user`, detail: /procdump/i.test(r[1]) ? 'ProcDump is frequently used to dump LSASS.' : /sdelete/i.test(r[1]) ? 'SDelete securely wipes files (anti-forensics).' : 'Remote execution / admin tooling.', mitre: [/psexec/i.test(r[1]) ? 'T1569.002' : /procdump/i.test(r[1]) ? 'T1003.001' : 'T1070.004'] });
    }
  }
  // Putty / WinSCP saved sessions
  const putty = root.path('Software\\SimonTatham\\PuTTY\\SshHostKeys');
  if (putty) { const rows = putty.values().map((v) => [putty.lastWritten, v.name]); tables.push(T('PuTTY known SSH hosts', ['KeyLastWrite', 'Host'], rows)); for (const r of rows) ctx.indicators.add('ssh_target', r[1].replace(/^[^@]*@/, ''), f.name); }

  shellbags(root, f, ctx, tables, 'Software\\Microsoft\\Windows\\Shell\\BagMRU');
  shellbags(root, f, ctx, tables, 'Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU');
}

function usrclassPlugins(root, f, ctx, tables) {
  shellbags(root, f, ctx, tables, 'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU');
  // COM hijacks also land in UsrClass (HKCU\Software\Classes)
  const rows = [];
  const clsid = root.sub('CLSID');
  if (clsid) for (const c of clsid.subkeys()) for (const sub of ['InprocServer32', 'LocalServer32']) {
    const s = c.sub(sub); if (!s) continue;
    const dll = String(s.get('(default)') ?? ''); if (!dll) continue;
    rows.push([s.lastWritten, c.name, sub, dll]);
    const pc = classifyPath(dll);
    if (pc.sev || /\\(temp|public|appdata\\roaming|programdata)\\[^\\]+\.(dll|exe)$/i.test(dll)) ctx.finding({ sev: 'high', category: 'Persistence', tool: 'RECmd', file: f.name, time: s.lastWritten, title: `Possible COM hijack (per-user CLSID ${c.name})`, evidence: dll, mitre: ['T1546.015'] });
  }
  for (const p of ['ms-settings\\Shell\\Open\\command', 'mscfile\\shell\\open\\command', 'exefile\\shell\\open\\command', 'Folder\\shell\\open\\command']) {
    const k = root.path(p); if (!k) continue;
    ctx.finding({ sev: 'critical', category: 'Privilege Escalation', tool: 'RECmd', file: f.name, time: k.lastWritten, title: `UAC bypass hijack: HKCU\\Software\\Classes\\${p}`, evidence: String(k.get('(default)') ?? '(DelegateExecute)'), mitre: ['T1548.002'] });
  }
  if (rows.length) tables.push(T('Per-user COM registrations', ['KeyLastWrite', 'CLSID', 'Type', 'Server'], rows));
}

// ---------------------------------------------------------------- AMCACHE
function amcachePlugins(root, f, ctx, tables) {
  const R = root.sub('Root') || root;
  const rows = [];
  const iaf = R.sub('InventoryApplicationFile');
  if (iaf) for (const k of iaf.subkeys()) {
    const path = k.get('LowerCaseLongPath') || ''; if (!path) continue;
    const sha1 = String(k.get('FileId') || '').replace(/^0000/, '');
    rows.push([k.lastWritten, path, sha1, k.get('Publisher') || '', k.get('ProductName') || '', k.get('Version') || '', k.get('LinkDate') || '', k.get('IsOsComponent') ? 'Y' : '', k.get('Size') ?? '']);
  }
  const old = R.sub('File');
  if (old) for (const vol of old.subkeys()) for (const k of vol.subkeys()) {
    const path = k.get('15') || ''; if (!path) continue;
    rows.push([k.lastWritten, path, String(k.get('101') || '').replace(/^0000/, ''), k.get('1') || '', k.get('0') || '', '', '', '', k.get('6') ?? '']);
  }
  tables.push(T('Amcache file entries', ['KeyLastWrite (≈first run/install)', 'Path', 'SHA1', 'Publisher', 'Product', 'Version', 'LinkDate', 'OSComponent', 'Size'], rows, 'SHA1 values are the most useful pivot for threat intel lookups.'));
  for (const r of rows) {
    ctx.event({ time: r[0], tool: 'AmcacheParser', file: f.name, type: 'Amcache entry (program present/executed)', desc: `${r[1]} SHA1 ${r[2]}` });
    const res = ctx.exec_({ path: r[1], time: r[0], tool: 'AmcacheParser', file: f.name, source: 'Amcache', sha1: r[2] || null });
    if (/\.(exe|dll|sys|scr|com)$/i.test(r[1])) ctx.sign({ path: r[1], sha1: r[2], publisher: r[3], osComponent: !!r[7], kind: /\.sys$/i.test(r[1]) ? 'driver' : /\.dll$/i.test(r[1]) ? 'dll' : 'exe', source: 'Amcache', file: f.name, time: r[0] });
    if (res?.sev) { /* sha1 indicator added by exec_ */ }
    else if (r[2] && !r[7] && !r[3] && /\.exe$/i.test(r[1]) && !/\\(program files|windows)\\/i.test(r[1])) ctx.indicators.add('sha1_unsigned_review', r[2], f.name, r[1]);
  }
  const drv = R.sub('InventoryDriverBinary');
  if (drv) {
    const drows = drv.subkeys().map((k) => [k.lastWritten, k.name, k.get('DriverName') || '', k.get('DriverCompany') || '', k.get('DriverSigned'), k.get('Service') || '', String(k.get('DriverId') || '').replace(/^0000/, '')]);
    tables.push(T('Amcache drivers', ['KeyLastWrite', 'Path', 'Name', 'Company', 'Signed', 'Service', 'SHA1'], drows));
    for (const d of drows) {
      ctx.sign({ path: d[1], sha1: d[6], signed: d[4] === 1 || d[4] === true ? true : d[4] === 0 || d[4] === false ? false : null, publisher: d[3], kind: 'driver', source: 'Amcache drivers', file: f.name, time: d[0] });
      if (d[4] === 0) ctx.finding({ sev: 'high', category: 'Defense Evasion', tool: 'AmcacheParser', file: f.name, time: d[0], title: `Unsigned driver loaded: ${d[2] || d[1]}`, evidence: `${d[1]} SHA1 ${d[6]}`, mitre: ['T1014', 'T1068'] });
      if (/(^|\\)(rtcore64|dbutil_2_3|gdrv|aswarpot|zam64|zamguard64|procexp152|kprocesshacker|mhyprot2?|iqvw64e|asio64|asrdrv10[0-9]|winring0x?6?4?|truesight|gmer64|rentdrv2|cpuz141|wnbios|ene|amifldrv64|physmem|semav6msr|speedfan|viragt64|nvflash|kevp64|hw64)\.sys$/i.test(d[1]) || /^(rtcore64|dbutil_2_3|gdrv|aswarpot|mhyprot2?|iqvw64e|kprocesshacker|truesight|rentdrv2)\.sys$/i.test(d[2])) ctx.finding({ sev: 'critical', category: 'Defense Evasion', tool: 'AmcacheParser', file: f.name, time: d[0], title: `Known vulnerable driver (BYOVD): ${d[2] || d[1]}`, evidence: `${d[1]} SHA1 ${d[6]}`, mitre: ['T1068', 'T1562.001'] });
    }
  }
  const ia = R.sub('InventoryApplication');
  if (ia) tables.push(T('Amcache installed applications', ['KeyLastWrite', 'Name', 'Publisher', 'Version', 'InstallDate', 'RootDir', 'Source'], ia.subkeys().map((k) => [k.lastWritten, k.get('Name') || '', k.get('Publisher') || '', k.get('Version') || '', k.get('InstallDate') || '', k.get('RootDirPath') || '', k.get('Source') || ''])));
}

// ---------------------------------------------------------------- SAM
function samPlugins(root, f, ctx, tables) {
  const users = root.path('SAM\\Domains\\Account\\Users');
  if (!users) return;
  const rows = [];
  const names = users.sub('Names');
  const byRid = new Map();
  for (const n of names?.subkeys() || []) { const v = n.values()[0]; byRid.set(v ? v.type : -1, { name: n.name, created: n.lastWritten }); }
  for (const u of users.subkeys()) {
    if (!/^[0-9A-F]{8}$/i.test(u.name)) continue;
    const rid = parseInt(u.name, 16);
    const F = u.value('F')?.raw;
    let lastLogon = '', pwdSet = '', lastFail = '', logons = '', fails = '', disabled = '';
    if (F && F.length >= 0x44) { const r = new Reader(F); lastLogon = r.filetime(8); pwdSet = r.filetime(24); lastFail = r.filetime(40); disabled = (r.u16(56) & 1) ? 'Yes' : 'No'; fails = r.u16(64); logons = r.u16(66); }
    const nm = byRid.get(rid)?.name || '?';
    rows.push([byRid.get(rid)?.created || '', nm, rid, lastLogon, pwdSet, lastFail, logons, fails, disabled]);
    ctx.users.add(nm);
    if (byRid.get(rid)?.created) ctx.event({ time: byRid.get(rid).created, tool: 'RECmd (SAM)', file: f.name, type: 'Local account (Names key last write ≈ created)', desc: `${nm} RID ${rid}` });
    if (lastLogon) ctx.event({ time: lastLogon, tool: 'RECmd (SAM)', file: f.name, type: 'Local account last logon', desc: nm });
    if (/\$$/.test(nm)) ctx.finding({ sev: 'high', category: 'Persistence', tool: 'RECmd', file: f.name, title: `Local account name ends with $: ${nm}`, detail: 'Hides from "net user" output. Local SAM should not hold machine-style accounts.', mitre: ['T1136.001', 'T1564.002'] });
    if (rid === 500 && disabled === 'No') ctx.finding({ sev: 'low', category: 'Configuration', tool: 'RECmd', file: f.name, title: 'Built-in Administrator (RID 500) is enabled', mitre: ['T1078.003'] });
  }
  tables.push(T('Local user accounts (SAM)', ['Created (Names key)', 'User', 'RID', 'LastLogon', 'PasswordSet', 'LastFailed', 'Logons', 'FailedCount', 'Disabled'], rows));
}

export function runRegistry(u8, f, ctx) {
  const hive = new Hive(u8);
  const type = guessHiveType(hive, f.name);
  const root = hive.key();
  const tables = [];
  const notes = [];
  if (hive.dirty) notes.push('Hive is dirty (primary/secondary sequence numbers differ). Uncommitted changes live in .LOG1/.LOG2; replay with RLA on Windows for full fidelity.');
  switch (type) {
    case 'SYSTEM': systemPlugins(root, f, ctx, tables); break;
    case 'SOFTWARE': softwarePlugins(root, f, ctx, tables); break;
    case 'NTUSER': ntuserPlugins(root, f, ctx, tables); break;
    case 'USRCLASS': usrclassPlugins(root, f, ctx, tables); break;
    case 'AMCACHE': amcachePlugins(root, f, ctx, tables); break;
    case 'SAM': samPlugins(root, f, ctx, tables); break;
    default: notes.push('Hive type not recognised; only the top-level key list is shown.');
  }
  tables.push(T('Hive header', ['Field', 'Value'], [['Detected type', type], ['Embedded name', hive.embeddedName], ['Last written', hive.lastWritten], ['Dirty', hive.dirty ? 'Yes' : 'No'], ['Root subkeys', root.subkeys().map((k) => k.name).join(', ')]]));
  return { tool: type === 'AMCACHE' ? 'AmcacheParser' : type === 'SYSTEM' ? 'RECmd + AppCompatCacheParser' : /NTUSER|USRCLASS/.test(type) ? 'RECmd + SBECmd' : 'RECmd', artifact: `Registry hive (${type})`, summary: `${type} hive, ${tables.reduce((n, t) => n + t.rows.length, 0)} rows across ${tables.length} plugins`, tables, notes };
}
