// The five core execution artifacts read side by side: Prefetch, ShimCache,
// Amcache, UserAssist and SRUM. Each one answers a different question, and
// most of what analysts miss shows up where they disagree.
import { baseName, classifyPath, SEV_RANK } from './heuristics.js';
import { normKey } from './context.js';

export const EXEC_ARTIFACTS = {
  Prefetch: {
    expected: 'C:\\Windows\\Prefetch\\*.pf', kape: 'Prefetch', tool: 'PECmd',
    proves: 'The program ran: run count, up to 8 last run times (Win8+), and the files and folders it touched in its first seconds.',
    limits: 'Disabled by default on Windows Server and when EnablePrefetcher is 0. Win8+ keeps about 1024 programs. Deleting .pf files is a common cleanup step.',
  },
  ShimCache: {
    expected: 'C:\\Windows\\System32\\config\\SYSTEM (AppCompatCache value)', kape: 'RegistryHives', tool: 'AppCompatCacheParser',
    proves: 'The file existed on this machine and was seen by the application compatibility engine, with its last-modified time and order.',
    limits: 'On Windows 10/11 it does not prove execution and has no run time. Written to the hive at shutdown, so the newest entries are only in memory.',
  },
  Amcache: {
    expected: 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve (+ .LOG1/.LOG2)', kape: 'Amcache', tool: 'AmcacheParser',
    proves: 'The program was present (usually run or installed): full path, SHA1 of the file, publisher and version details.',
    limits: 'Inventory tasks also create entries, so presence alone is not execution. The key time is when the entry was written.',
  },
  UserAssist: {
    expected: 'C:\\Users\\<user>\\NTUSER.DAT (one per user)', kape: 'RegistryHives', tool: 'RECmd',
    proves: 'A specific user launched it from the GUI (Explorer, Start menu, shortcut): run count, last run, time in focus.',
    limits: 'GUI launches only. Command line, service and scheduled task starts are not recorded. One hive per user is needed.',
  },
  SRUM: {
    expected: 'C:\\Windows\\System32\\sru\\SRUDB.dat (+ SOFTWARE hive for names)', kape: 'SRUM', tool: 'SrumECmd',
    proves: 'The program ran and used resources, per user and per hour, for roughly the last 30 to 60 days, including network bytes sent and received.',
    limits: 'Written to disk about once an hour, so the last hour may be missing. No command lines or paths of files touched.',
  },
};
const ORDER = Object.keys(EXEC_ARTIFACTS);
const RUN_SOURCES = /^(Prefetch|UserAssist|SRUM|BAM|Sysmon 1|Security 4688|Security 592|Memory process|Memory cmdline|Windows Timeline|RunMRU|RADAR|Task )/;
const PSEUDO = /^(system|registry|memcompression|secure system|idle|smss\.exe|csrss\.exe|wininit\.exe|services\.exe|lsass\.exe|lsaiso\.exe|fontdrvhost\.exe|dwm\.exe|winlogon\.exe|svchost\.exe)$/i;
const fmtB = (n) => (n >= 1024 ** 3 ? (n / 1024 ** 3).toFixed(1) + ' GB' : n >= 1024 ** 2 ? (n / 1024 ** 2).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(0) + ' KB' : (n || 0) + ' B');
const short = (t) => String(t || '').replace('T', ' ').slice(0, 16);

/** Short per-artifact summary for one program. */
function cell(a, list) {
  if (!list?.length) return '';
  if (a === 'Prefetch') { const runs = list.flatMap((x) => x.lastRuns || [x.time]).filter(Boolean).sort(); const cnt = list.reduce((n, x) => n + (+x.runCount || 0), 0); return `ran ${cnt || '?'}x, last ${short(runs[runs.length - 1])}${list.length > 1 ? ` (${list.length} .pf)` : ''}`; }
  if (a === 'ShimCache') { const x = list[0]; return `#${x.position ?? '?'} mtime ${short(x.time)}${list.some((y) => y.executed === true) ? ', executed flag' : ''}`; }
  if (a === 'Amcache') { const sh = [...new Set(list.map((x) => x.sha1).filter(Boolean))]; return `${sh.length ? 'SHA1 ' + sh.map((h) => h.slice(0, 10)).join(' / ') : 'no hash'}, ${short(list[0].time)}`; }
  if (a === 'UserAssist') return list.map((x) => `${x.runCount ?? '?'}x by ${x.user || '?'}, last ${short(x.time)}`).join('; ');
  if (a === 'SRUM') { const s = list.reduce((n, x) => n + (x.sent || 0), 0), r = list.reduce((n, x) => n + (x.recv || 0), 0); const f = list.map((x) => x.first).filter(Boolean).sort()[0]; const l = list.map((x) => x.last).filter(Boolean).sort().pop(); return `${fmtB(s)} sent / ${fmtB(r)} recv, ${short(f)} to ${short(l)}`; }
  return '';
}

/** Per program: what each artifact says, whether execution is proven, first and last known run. */
export function executionFor(ctx, key) {
  const e = ctx.evid.get(key); const ex = ctx.exec.get(key) || [];
  const out = {};
  for (const a of ORDER) out[a] = cell(a, e?.[a]);
  const runTimes = [];
  for (const x of e?.Prefetch || []) runTimes.push(...(x.lastRuns || [x.time]));
  for (const x of e?.UserAssist || []) runTimes.push(x.time);
  for (const x of e?.SRUM || []) runTimes.push(x.first, x.last);
  for (const x of ex) if (RUN_SOURCES.test(x.source || '')) runTimes.push(x.time);
  const t = runTimes.filter((x) => x && /^\d{4}-/.test(x) && x > '1990').sort();
  const ran = !!(e?.Prefetch || e?.UserAssist || e?.SRUM || ex.some((x) => RUN_SOURCES.test(x.source || '')) || e?.ShimCache?.some((x) => x.executed === true));
  const present = !!(e?.ShimCache || e?.Amcache);
  out.executed = ran ? 'Yes' : present ? 'Present, not proven run' : '';
  out.firstRun = t[0] || ''; out.lastRun = t[t.length - 1] || '';
  out.artifacts = ORDER.filter((a) => e?.[a]).length;
  return out;
}

/** Coverage table and cross-artifact findings. files = report file records. */
export function analyseExecution(ctx, files, window) {
  const add = (sev, title, detail, evidence, mitre, file, category = 'Defense Evasion') => ctx.finding({ sev, category, tool: 'Sudo-Z', file: file || '', title, detail, evidence, mitre });
  const paths = files.map((f) => f.name.toLowerCase());
  const triage = paths.some((p) => /windows\/system32\/(config|winevt)|\$mft|ntuser\.dat|amcache\.hve/.test(p));
  // ------------------------------------------------------------- coverage
  const usersSeen = new Set();
  for (const [, list] of ctx.exec) for (const x of list) { const m = String(x.path || '').match(/^[a-z]:\\(?:users|documents and settings)\\([^\\]+)\\/i); if (m && !/^(public|default|all users|default user)$/i.test(m[1])) usersSeen.add(m[1].toLowerCase()); }
  for (const p of paths) { const m = p.match(/(?:^|\/)users\/([^/]+)\//); if (m && !/^(public|default|all users|default user)$/.test(m[1])) usersSeen.add(m[1]); }
  const uaUsers = new Set([...(ctx.coverage.UserAssist?.files || [])].map((f) => (String(f).match(/users[\\/]([^\\/]+)[\\/]/i) || [])[1]).filter(Boolean).map((u) => u.toLowerCase()));
  const coverage = ORDER.map((a) => {
    const c = ctx.coverage[a]; const d = EXEC_ARTIFACTS[a];
    let state = c ? (c.entries ? 'Collected' : 'Collected, empty') : 'Missing';
    let note = '';
    if (a === 'Prefetch' && ctx.settings.enablePrefetcher?.value === 0) note = 'EnablePrefetcher = 0: Prefetch is turned off on this system.';
    const uaFiles = [...(ctx.coverage.UserAssist?.files || [])]; const unknownOwner = uaFiles.filter((f) => !/users[\\/][^\\/]+[\\/]/i.test(String(f))).length;
    if (a === 'UserAssist' && c && !unknownOwner) { const missing = [...usersSeen].filter((u) => !uaUsers.has(u)); if (missing.length) note = `No NTUSER.DAT for: ${missing.join(', ')}`; }
    if (a === 'UserAssist' && c && unknownOwner) note = `${unknownOwner} hive(s) not under Users\\<name>, so their owner is unknown`;
    return { artifact: a, state, files: c ? c.files.size : 0, entries: c ? c.entries : 0, first: c?.first || '', last: c?.last || '', users: c ? [...c.users].join(', ') : '', expected: d.expected, kape: d.kape, proves: d.proves, limits: d.limits, note };
  });
  const missing = coverage.filter((c) => c.state === 'Missing');
  if (triage && missing.length && missing.length < ORDER.length) add('info', `Execution evidence not collected: ${missing.map((c) => c.artifact).join(', ')}`, 'These artifacts each prove something the others cannot. Without them, programs can look like they never ran.', missing.map((c) => `${c.artifact}: ${c.expected}  (KAPE target: ${c.kape})`).join('\n'), [], '', 'Coverage');
  const uaGap = coverage.find((c) => c.artifact === 'UserAssist' && /^No NTUSER/.test(c.note));
  if (triage && uaGap) add('info', `User hives missing for ${uaGap.note.replace('No NTUSER.DAT for: ', '')}`, 'Programs ran from these profiles, but their NTUSER.DAT was not submitted, so their UserAssist, RunMRU, typed paths and shellbags are unseen.', uaGap.note, [], '', 'Coverage');

  // ------------------------------------------------------------- Prefetch turned off
  const epf = ctx.settings.enablePrefetcher;
  if (epf && epf.value === 0) {
    const inWindow = window?.attackFirst && epf.time && epf.time >= window.attackFirst.slice(0, 10);
    add(inWindow ? 'high' : 'medium', 'Prefetch is disabled (EnablePrefetcher = 0)', `Windows will not record program execution in Prefetch. This is the default on Windows Server; on a workstation it is usually done to hide execution.${inWindow ? ' The key was last written during the attack window.' : ''} Key last written ${epf.time || '?'}.`, 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\\EnablePrefetcher = 0', ['T1562', 'T1070'], epf.file);
  }
  // ------------------------------------------------------------- Prefetch empty while other artifacts show many runs
  const pfc = ctx.coverage.Prefetch;
  const ranElsewhere = [...ctx.evid].filter(([, e]) => e.UserAssist || e.SRUM).length + [...ctx.exec].filter(([, l]) => l.some((x) => /^(BAM|Sysmon 1|Security 4688)/.test(x.source || ''))).length;
  const multiHost = ctx.hosts.size > 1;
  if (triage && (!epf || epf.value !== 0) && (!pfc || pfc.entries < 10) && ranElsewhere >= 20) {
    add(multiHost ? 'low' : pfc ? 'high' : 'low', pfc ? `Only ${pfc.entries} Prefetch file(s) although ${ranElsewhere} programs show execution elsewhere` : `No Prefetch files submitted although ${ranElsewhere} programs show execution elsewhere`, pfc ? 'A workstation normally holds hundreds of .pf files. A nearly empty Prefetch folder with execution evidence everywhere else means the folder was wiped.' : 'Either the Prefetch folder was not collected or it was emptied. Collect C:\\Windows\\Prefetch to tell which.', `Prefetch entries: ${pfc?.entries || 0}\nPrograms with UserAssist / SRUM / BAM / Sysmon / 4688 execution: ${ranElsewhere}${multiHost ? `\nNote: the evidence names ${ctx.hosts.size} hosts (${[...ctx.hosts].slice(0, 5).join(', ')}), so these may not be from the same machine.` : ''}`, ['T1070.004'], [...(pfc?.files || [])][0]);
  }
  // ------------------------------------------------------------- ran, but its Prefetch file is gone
  if (pfc && pfc.entries >= 10 && (!epf || epf.value !== 0)) {
    const oldest = [...ctx.evid.values()].flatMap((e) => (e.Prefetch || []).map((x) => (x.lastRuns || [x.time]).filter(Boolean).sort().pop())).filter(Boolean).sort()[0] || '';
    const gone = [];
    const pfNames = new Set([...ctx.evid.values()].filter((e) => e.Prefetch).map((e) => baseName(e.path).toLowerCase()));
    for (const [key, e] of ctx.evid) {
      if (e.Prefetch) continue;
      const name = baseName(e.path); if (!/\.exe$/i.test(name) || PSEUDO.test(name) || pfNames.has(name.toLowerCase())) continue;
      const ex = ctx.exec.get(key) || [];
      const proofs = [...(e.UserAssist || []).map((x) => ['UserAssist', x.time]), ...(e.SRUM || []).map((x) => ['SRUM', x.last || x.first]), ...ex.filter((x) => /^(BAM|Sysmon 1|Security 4688)/.test(x.source || '')).map((x) => [x.source, x.time])].filter(([, t]) => t && t >= oldest);
      if (!proofs.length) continue;
      if (/^\\\\/.test(e.path)) continue; // network share launches still get Prefetch, but paths differ too much to match reliably
      const pc = classifyPath(String(e.path));
      gone.push({ e, proofs, sev: pc.sev && pc.sev !== 'low' ? 'high' : 'medium' });
    }
    if (gone.length) {
      const worst = gone.some((g) => g.sev === 'high') ? 'high' : 'medium';
      add(multiHost && worst === 'high' ? 'medium' : worst, `${gone.length} program(s) ran but have no Prefetch file`, `Each of these shows execution after ${short(oldest)} (the oldest run still covered by the Prefetch set), so its .pf should still exist. Missing .pf files for programs that ran are a sign of targeted Prefetch deletion. Programs run from user-writable folders are listed first.`, gone.sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev]).slice(0, 40).map((g) => `${g.e.path}  <- ${g.proofs.slice(0, 3).map(([s, t]) => `${s} ${short(t)}`).join(', ')}`).join('\n'), ['T1070.004'], [...pfc.files][0]);
    }
  }
  // ------------------------------------------------------------- same path, different SHA1 (file swapped in place)
  const swapped = [];
  for (const [, e] of ctx.evid) {
    const hs = [...new Set((e.Amcache || []).map((x) => x.sha1).filter((h) => h && /^[0-9a-f]{40}$/i.test(h)))];
    if (hs.length > 1) swapped.push(`${e.path}\n   ${(e.Amcache || []).filter((x) => x.sha1).map((x) => `${x.sha1} at ${short(x.time)}`).join('\n   ')}`);
  }
  if (swapped.length) add(swapped.length > 10 ? 'low' : 'medium', `${swapped.length} program path(s) recorded with different SHA1s in Amcache`, 'The same file path held different binaries at different times. Software updates do this, but so does replacing a legitimate binary with a trojanised one (DLL or EXE planting).', swapped.slice(0, 20).join('\n'), ['T1036', 'T1574'], [...(ctx.coverage.Amcache?.files || [])][0], 'Persistence');
  // ------------------------------------------------------------- present in user-writable places but never proven to run
  const unproven = [];
  for (const [key, e] of ctx.evid) {
    if (e.Prefetch || e.UserAssist || e.SRUM) continue;
    if ((ctx.exec.get(key) || []).some((x) => RUN_SOURCES.test(x.source || ''))) continue;
    const pc = classifyPath(String(e.path)); if (!pc.sev || !/\.(exe|scr|com|bat|ps1)$/i.test(e.path) || /\\(unins\d+|.*setup.*|.*install.*)\.exe$/i.test(e.path)) continue;
    unproven.push(`${e.path}  (${ORDER.filter((a) => e[a]).join(', ')}) ${pc.reasons.join('; ')}`);
  }
  if (unproven.length) add('low', `${unproven.length} suspicious program(s) present but not proven to have run`, 'ShimCache or Amcache saw these files, but Prefetch, UserAssist and SRUM have no record of them running. They may have been staged and not run, run before Prefetch rolled over, or their Prefetch was deleted. Check $MFT and the event logs around their timestamps.', unproven.slice(0, 40).join('\n'), ['T1105'], '', 'Execution');
  return { coverage };
}
