// Known-good Windows process baseline. Used to catch misspelled / lookalike
// names (scvhost.exe, expl0rer.exe, lsass64.exe, Cyrillic homoglyphs),
// known names running from the wrong folder, and wrong parent processes.
//
// dirs:   where the binary legitimately lives
//         sys = System32 / SysWOW64 / WinSxS / servicing, win = C:\Windows root,
//         pf = Program Files (x86), pd = ProgramData vendor dirs, user = per-user app dirs, any = no path rule
// parent: expected parent image(s) when known (null = parent normally exited)
// single: only one instance should run per system (per session for csrss/winlogon)

export const BASELINE = {
  // core OS
  'system': { dirs: ['any'], desc: 'Kernel' },
  'registry': { dirs: ['any'], desc: 'Registry process' },
  'memcompression': { dirs: ['any'], desc: 'Memory compression' },
  'smss.exe': { dirs: ['sys'], parent: ['system', 'smss.exe'], desc: 'Session Manager' },
  'csrss.exe': { dirs: ['sys'], parent: ['smss.exe', null], desc: 'Client/Server Runtime' },
  'wininit.exe': { dirs: ['sys'], parent: ['smss.exe', null], single: true, desc: 'Windows Start-Up Application' },
  'winlogon.exe': { dirs: ['sys'], parent: ['smss.exe', null], desc: 'Windows Logon' },
  'services.exe': { dirs: ['sys'], parent: ['wininit.exe'], single: true, desc: 'Service Control Manager' },
  'lsass.exe': { dirs: ['sys'], parent: ['wininit.exe'], single: true, desc: 'Local Security Authority' },
  'lsaiso.exe': { dirs: ['sys'], parent: ['wininit.exe'], single: true, desc: 'Credential Guard isolated LSA' },
  'lsm.exe': { dirs: ['sys'], parent: ['wininit.exe'], single: true, desc: 'Local Session Manager (Win7)' },
  'svchost.exe': { dirs: ['sys'], parent: ['services.exe', 'msmpeng.exe', 'svchost.exe'], desc: 'Service Host' },
  'fontdrvhost.exe': { dirs: ['sys'], parent: ['wininit.exe', 'winlogon.exe'], desc: 'Font Driver Host' },
  'dwm.exe': { dirs: ['sys'], parent: ['winlogon.exe'], desc: 'Desktop Window Manager' },
  'userinit.exe': { dirs: ['sys'], parent: ['winlogon.exe', 'dwm.exe'], desc: 'Userinit Logon' },
  'explorer.exe': { dirs: ['win'], parent: ['userinit.exe', null, 'explorer.exe'], desc: 'Windows Explorer' },
  'taskhostw.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Task Host' },
  'taskhost.exe': { dirs: ['sys'], parent: ['services.exe', 'svchost.exe'], desc: 'Task Host (Win7)' },
  'taskeng.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Task Scheduler Engine (Win7)' },
  'sihost.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Shell Infrastructure Host' },
  'ctfmon.exe': { dirs: ['sys'], desc: 'CTF Loader' },
  'runtimebroker.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Runtime Broker' },
  'conhost.exe': { dirs: ['sys'], desc: 'Console Window Host' },
  'dllhost.exe': { dirs: ['sys'], parent: ['svchost.exe', 'services.exe'], desc: 'COM Surrogate' },
  'wmiprvse.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'WMI Provider Host' },
  'wmiapsrv.exe': { dirs: ['sys'], parent: ['services.exe'], desc: 'WMI Performance Adapter' },
  'spoolsv.exe': { dirs: ['sys'], parent: ['services.exe'], single: true, desc: 'Print Spooler' },
  'audiodg.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Audio Device Graph Isolation' },
  'dashost.exe': { dirs: ['sys'], desc: 'Device Association Framework' },
  'backgroundtaskhost.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Background Task Host' },
  'applicationframehost.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Application Frame Host' },
  'searchindexer.exe': { dirs: ['sys'], parent: ['services.exe'], desc: 'Windows Search Indexer' },
  'searchprotocolhost.exe': { dirs: ['sys'], parent: ['searchindexer.exe'], desc: 'Search Protocol Host' },
  'searchfilterhost.exe': { dirs: ['sys'], parent: ['searchindexer.exe'], desc: 'Search Filter Host' },
  'searchapp.exe': { dirs: ['win'], desc: 'Search (SystemApps)' },
  'searchhost.exe': { dirs: ['win'], desc: 'Search host (SystemApps)' },
  'startmenuexperiencehost.exe': { dirs: ['win'], desc: 'Start Menu' },
  'shellexperiencehost.exe': { dirs: ['win'], desc: 'Shell Experience Host' },
  'textinputhost.exe': { dirs: ['win'], desc: 'Text Input Host' },
  'lockapp.exe': { dirs: ['win'], desc: 'Lock screen' },
  'systemsettings.exe': { dirs: ['win'], desc: 'Settings' },
  'smartscreen.exe': { dirs: ['sys'], desc: 'Windows Defender SmartScreen' },
  'securityhealthservice.exe': { dirs: ['sys'], parent: ['services.exe'], desc: 'Windows Security Health Service' },
  'securityhealthsystray.exe': { dirs: ['sys'], desc: 'Windows Security tray' },
  'msmpeng.exe': { dirs: ['pf', 'pd'], parent: ['services.exe'], desc: 'Microsoft Defender Antivirus' },
  'nissrv.exe': { dirs: ['pf', 'pd'], parent: ['services.exe'], desc: 'Defender Network Inspection' },
  'mpcmdrun.exe': { dirs: ['pf', 'pd'], desc: 'Defender command line' },
  'msmpengcp.exe': { dirs: ['pf', 'pd'], desc: 'Defender core process' },
  'mssense.exe': { dirs: ['pf'], desc: 'Defender for Endpoint sensor' },
  'trustedinstaller.exe': { dirs: ['win'], parent: ['services.exe'], desc: 'Windows Modules Installer' },
  'tiworker.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'Windows Modules Installer Worker' },
  'wuauclt.exe': { dirs: ['sys'], desc: 'Windows Update' },
  'usocoreworker.exe': { dirs: ['sys'], desc: 'Update Orchestrator worker' },
  'mousocoreworker.exe': { dirs: ['sys'], desc: 'Update Orchestrator worker' },
  'musnotification.exe': { dirs: ['sys'], desc: 'Update notifications' },
  'sppsvc.exe': { dirs: ['sys'], parent: ['services.exe'], desc: 'Software Protection' },
  'vssvc.exe': { dirs: ['sys'], parent: ['services.exe'], desc: 'Volume Shadow Copy service' },
  'msdtc.exe': { dirs: ['sys'], parent: ['services.exe'], desc: 'Distributed Transaction Coordinator' },
  'wlanext.exe': { dirs: ['sys'], desc: 'WLAN extensibility' },
  'compattelrunner.exe': { dirs: ['sys'], desc: 'Compatibility telemetry' },
  'werfault.exe': { dirs: ['sys'], desc: 'Windows Error Reporting' },
  'wermgr.exe': { dirs: ['sys'], desc: 'Windows Error Reporting manager' },
  'consent.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'UAC consent' },
  'logonui.exe': { dirs: ['sys'], parent: ['winlogon.exe'], desc: 'Logon UI' },
  'winver.exe': { dirs: ['sys'], desc: 'Windows version' },
  'wsmprovhost.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'PowerShell remoting host' },
  'winrshost.exe': { dirs: ['sys'], parent: ['svchost.exe'], desc: 'WinRM remote shell host' },
  'sdiagnhost.exe': { dirs: ['sys'], desc: 'Scripted diagnostics host' },
  'msiexec.exe': { dirs: ['sys'], desc: 'Windows Installer' },
  'rundll32.exe': { dirs: ['sys'], desc: 'Run DLL' },
  'regsvr32.exe': { dirs: ['sys'], desc: 'Register server' },
  'cmd.exe': { dirs: ['sys'], desc: 'Command prompt' },
  'powershell.exe': { dirs: ['sys'], desc: 'Windows PowerShell' },
  'powershell_ise.exe': { dirs: ['sys'], desc: 'PowerShell ISE' },
  'pwsh.exe': { dirs: ['pf', 'user'], desc: 'PowerShell 7' },
  'notepad.exe': { dirs: ['sys', 'win'], desc: 'Notepad' },
  'regedit.exe': { dirs: ['win'], desc: 'Registry Editor' },
  'mmc.exe': { dirs: ['sys'], desc: 'Management Console' },
  'taskmgr.exe': { dirs: ['sys'], desc: 'Task Manager' },
  'schtasks.exe': { dirs: ['sys'], desc: 'Scheduled tasks CLI' },
  'reg.exe': { dirs: ['sys'], desc: 'Registry CLI' },
  'certutil.exe': { dirs: ['sys'], desc: 'Certificate utility' },
  'bitsadmin.exe': { dirs: ['sys'], desc: 'BITS admin' },
  'wscript.exe': { dirs: ['sys'], desc: 'Windows Script Host' },
  'cscript.exe': { dirs: ['sys'], desc: 'Console Script Host' },
  'mshta.exe': { dirs: ['sys'], desc: 'HTML Application host' },
  'mstsc.exe': { dirs: ['sys'], desc: 'Remote Desktop client' },
  'sdclt.exe': { dirs: ['sys'], desc: 'Backup and Restore' },
  'fodhelper.exe': { dirs: ['sys'], desc: 'Features on Demand helper' },
  'eventvwr.exe': { dirs: ['sys'], desc: 'Event Viewer' },
  'calc.exe': { dirs: ['sys'], desc: 'Calculator' },
  'wordpad.exe': { dirs: ['pf'], desc: 'WordPad' },
  'hh.exe': { dirs: ['win'], desc: 'HTML Help' },
  'splwow64.exe': { dirs: ['win'], desc: 'Print driver host' },
  'wininit': { dirs: ['sys'] },
  // common applications (name checks only; installed in many places)
  'chrome.exe': { dirs: ['pf', 'user'], desc: 'Google Chrome' },
  'msedge.exe': { dirs: ['pf'], desc: 'Microsoft Edge' },
  'firefox.exe': { dirs: ['pf', 'user'], desc: 'Mozilla Firefox' },
  'iexplore.exe': { dirs: ['pf'], desc: 'Internet Explorer' },
  'outlook.exe': { dirs: ['pf'], desc: 'Microsoft Outlook' },
  'winword.exe': { dirs: ['pf'], desc: 'Microsoft Word' },
  'excel.exe': { dirs: ['pf'], desc: 'Microsoft Excel' },
  'powerpnt.exe': { dirs: ['pf'], desc: 'Microsoft PowerPoint' },
  'onenote.exe': { dirs: ['pf'], desc: 'Microsoft OneNote' },
  'msaccess.exe': { dirs: ['pf'], desc: 'Microsoft Access' },
  'onedrive.exe': { dirs: ['pf', 'user'], desc: 'OneDrive' },
  'teams.exe': { dirs: ['user', 'pf'], desc: 'Microsoft Teams (classic)' },
  'ms-teams.exe': { dirs: ['pf'], desc: 'Microsoft Teams' },
  'acrord32.exe': { dirs: ['pf'], desc: 'Adobe Reader' },
  'acrobat.exe': { dirs: ['pf'], desc: 'Adobe Acrobat' },
  'java.exe': { dirs: ['pf', 'any'], desc: 'Java' },
  'javaw.exe': { dirs: ['pf', 'any'], desc: 'Java' },
  'sqlservr.exe': { dirs: ['pf'], desc: 'SQL Server' },
  'w3wp.exe': { dirs: ['sys'], desc: 'IIS worker' },
  'inetinfo.exe': { dirs: ['sys'], desc: 'IIS' },
  'vmtoolsd.exe': { dirs: ['pf'], desc: 'VMware Tools' },
  'vboxservice.exe': { dirs: ['sys'], desc: 'VirtualBox Guest Additions' },
  'zoom.exe': { dirs: ['user', 'pf'], desc: 'Zoom' },
  'slack.exe': { dirs: ['user'], desc: 'Slack' },
  'discord.exe': { dirs: ['user'], desc: 'Discord' },
  'code.exe': { dirs: ['user', 'pf'], desc: 'VS Code' },
};

// Real names that sit within edit distance of a baseline name (never flag these).
const LEGIT_NEAR = new Set(['taskhost.exe', 'taskhostw.exe', 'taskhostex.exe', 'lsass.exe', 'lsaiso.exe', 'lsm.exe', 'searchapp.exe', 'searchhost.exe', 'searchui.exe', 'dllhost.exe', 'conhost.exe', 'sihost.exe', 'svchost.exe', 'wsmprovhost.exe', 'smss.exe', 'mmc.exe', 'reg.exe', 'calc.exe', 'cmd.exe', 'csrss.exe', 'excel.exe', 'mspaint.exe', 'msinfo32.exe', 'msedgewebview2.exe', 'msedge_proxy.exe', 'chrome_proxy.exe', 'firefox_proxy.exe', 'powershell_ise.exe', 'pwsh.exe', 'werfault.exe', 'wermgr.exe', 'werfaultsecure.exe', 'regsvr32.exe', 'regedt32.exe', 'regini.exe', 'rundll32.exe', 'wininit.exe', 'winlogon.exe', 'wlanext.exe', 'dwm.exe', 'notepad.exe', 'notepad++.exe', 'wordpad.exe', 'write.exe', 'winver.exe', 'winword.exe', 'explorer.exe', 'iexplore.exe', 'mstsc.exe', 'msra.exe', 'mshta.exe', 'msiexec.exe', 'msdt.exe', 'msdtc.exe', 'sdclt.exe', 'sdbinst.exe', 'tiworker.exe', 'tasklist.exe', 'taskkill.exe', 'taskmgr.exe', 'taskeng.exe', 'schtasks.exe', 'onedrive.exe', 'onenote.exe', 'onenotem.exe', 'teams.exe', 'ms-teams.exe', 'java.exe', 'javaw.exe', 'javaws.exe', 'outlook.exe', 'consent.exe', 'conhost.exe', 'certutil.exe', 'certreq.exe', 'cscript.exe', 'wscript.exe', 'smartscreen.exe', 'services.exe', 'spoolsv.exe', 'audiodg.exe', 'vssvc.exe', 'vssadmin.exe', 'sppsvc.exe', 'osppsvc.exe', 'ospprearm.exe', 'mpcmdrun.exe', 'msmpeng.exe', 'nissrv.exe', 'mssense.exe', 'sensecncproxy.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe', 'code.exe', 'zoom.exe', 'slack.exe', 'discord.exe', 'dashost.exe', 'fodhelper.exe', 'hh.exe', 'logonui.exe', 'userinit.exe', 'ctfmon.exe', 'w3wp.exe', 'wuauclt.exe', 'wusa.exe', 'usoclient.exe', 'wmiprvse.exe', 'wmiapsrv.exe', 'wmic.exe', 'splwow64.exe', 'eventvwr.exe', 'systeminfo.exe', 'systemsettings.exe', 'runtimebroker.exe', 'regedit.exe']);

// Unicode lookalikes (Cyrillic / Greek) and digit / letter swaps used in masquerading.
const HOMO = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'ј': 'j', 'ԁ': 'd', 'ӏ': 'l', 'һ': 'h', 'ո': 'n', 'α': 'a', 'ο': 'o', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'ρ': 'p', 'υ': 'u', 'χ': 'x', 'ᴠ': 'v' };
const LEET = [[/0/g, 'o'], [/1/g, 'l'], [/3/g, 'e'], [/5/g, 's'], [/4/g, 'a'], [/7/g, 't'], [/\$/g, 's'], [/rn/g, 'm'], [/vv/g, 'w'], [/cl/g, 'd']];

function damerau(a, b, max) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      const c = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length][b.length];
}

const NAMES = Object.keys(BASELINE).filter((n) => n.endsWith('.exe'));
const STEMS = NAMES.map((n) => n.slice(0, -4));

/**
 * Lookalike check for an executable name.
 * Returns null, or { target, kind, detail } where kind is homoglyph | typo | suffix | spacing.
 */
export function lookalike(nameRaw) {
  if (!nameRaw) return null;
  const name = String(nameRaw).toLowerCase().trim();
  if (!/\.(exe|scr|com|pif)(\s*)$/.test(name) && !/\.exe\./.test(name)) return null;
  if (BASELINE[name] || LEGIT_NEAR.has(name)) return null;
  // whitespace / double extension tricks: "svchost .exe", "svchost.exe.exe"
  const squashed = name.replace(/\s+(?=\.exe$)/, '').replace(/(\.exe)+$/, '.exe');
  if (squashed !== name && BASELINE[squashed]) return { target: squashed, kind: 'spacing', detail: `"${nameRaw}" pads or repeats the extension of ${squashed}` };
  // homoglyphs (non-ASCII letters that look like Latin)
  if (/[^\x00-\x7f]/.test(name)) {
    const latin = [...name].map((c) => HOMO[c] || c).join('');
    if (BASELINE[latin] || LEGIT_NEAR.has(latin)) return { target: latin, kind: 'homoglyph', detail: `"${nameRaw}" uses non-Latin lookalike characters to imitate ${latin}` };
  }
  const stem = name.replace(/\.(exe|scr|com|pif)$/, '');
  // digit / letter swaps: expl0rer, 1sass, svch0st
  let leet = stem; for (const [rx, r] of LEET) leet = leet.replace(rx, r);
  if (leet !== stem && STEMS.includes(leet)) return { target: leet + '.exe', kind: 'typo', detail: `"${nameRaw}" swaps characters to imitate ${leet}.exe` };
  // appended digits / words: svchost32.exe, lsass64.exe, explorer_.exe, svchost-update.exe
  const suf = stem.match(/^([a-z_-]+?)[-_ .]?(\d{1,3}|x64|x86|32|64|_|-|new|update|svc|srv|old|bak)$/);
  if (suf && STEMS.includes(suf[1]) && suf[1].length >= 4) return { target: suf[1] + '.exe', kind: 'suffix', detail: `"${nameRaw}" adds "${stem.slice(suf[1].length)}" to ${suf[1]}.exe` };
  // edit distance (1 for short names, 2 for long ones); only against names of 5+ characters
  if (stem.length < 4) return null;
  let best = null;
  for (const s of STEMS) {
    if (s.length < 5) continue;
    const max = s.length >= 9 ? 2 : 1;
    const dist = damerau(stem, s, max);
    if (dist <= max && (!best || dist < best.dist)) best = { s, dist };
  }
  if (best) return { target: best.s + '.exe', kind: 'typo', detail: `"${nameRaw}" is ${best.dist} edit${best.dist > 1 ? 's' : ''} away from ${best.s}.exe` };
  return null;
}

const DIR_RX = {
  sys: /^(?:[a-z]:|<vol>)?\\windows\\(system32|syswow64|winsxs|servicing|sysnative|ccmsetup|softwaredistribution|temp\\[^\\]*\\(amd64|x86)|systemapps|immersivecontrolpanel|microsoft\.net|uus|systemtemp)\\/i,
  win: /^(?:[a-z]:|<vol>)?\\windows\\([^\\]+\.exe$|systemapps\\|explorer\.exe|regedit\.exe|hh\.exe|notepad\.exe|splwow64\.exe|servicing\\trustedinstaller\.exe|winsxs\\|system32\\|syswow64\\)/i,
  pf: /^(?:[a-z]:|<vol>)?\\program files( \(x86\))?\\|\\windowsapps\\/i,
  pd: /^(?:[a-z]:|<vol>)?\\programdata\\microsoft\\(windows defender|windows defender advanced threat protection)\\/i,
  user: /^(?:[a-z]:|<vol>)?\\users\\[^\\]+\\appdata\\local\\(programs|microsoft|google|mozilla|discord|slack|zoom|teams)\\|\\appdata\\roaming\\zoom\\/i,
};

/** Is a known baseline process in an allowed folder? Returns null when fine or unknown. */
export function wrongLocation(path) {
  if (!path || !/[\\/]/.test(path)) return null;
  const p = String(path).replace(/\//g, '\\').replace(/^\\\?\?\\/, '').replace(/^\\device\\harddiskvolume\d+/i, 'C:').replace(/^%systemroot%|^\\systemroot/i, 'C:\\Windows');
  const name = p.split('\\').pop().toLowerCase();
  const b = BASELINE[name];
  if (!b || b.dirs.includes('any')) return null;
  if (!/^(?:[a-z]:|<vol>)?\\/i.test(p)) return null;
  if (b.dirs.some((d) => DIR_RX[d]?.test(p))) return null;
  return { name, expected: b.dirs.map((d) => ({ sys: 'C:\\Windows\\System32', win: 'C:\\Windows', pf: 'Program Files', pd: 'ProgramData\\Microsoft', user: 'user AppData app folder' }[d])).join(' or '), desc: b.desc };
}

export const expectedParents = (name) => BASELINE[String(name).toLowerCase()]?.parent || null;
export const isSingleton = (name) => !!BASELINE[String(name).toLowerCase()]?.single;
