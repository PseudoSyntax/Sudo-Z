// KAPE-style triage targets: the files Sudo-Z pulls out of an NTFS volume.
// Paths are matched case-insensitively against the path from the volume root.
// Each entry: [label, regex, options]. options.max caps bytes; options.stream picks an ADS.

const U = '(?:users|documents and settings)/[^/]+';
export const TARGETS = [
  ['$MFT', /^\$mft$/, { max: 1.5 * 1024 ** 3 }],
  ['$UsnJrnl:$J', /^\$extend\/\$usnjrnl$/, { stream: '$J', dropSparse: true, max: 1024 ** 3, as: '$J' }],
  ['$Boot', /^\$boot$/, { max: 64 * 1024 }],
  ['Registry hives', /^windows\/system32\/config\/(system|software|sam|security|default)(\.log[12]?)?$/],
  ['RegBack', /^windows\/system32\/config\/regback\/(system|software|sam|security|default)$/],
  ['Event logs', /^windows\/system32\/winevt\/logs\/[^/]+\.evtx$/],
  ['Legacy event logs', /^windows\/system32\/config\/[^/]+\.evt$/],
  ['Prefetch', /^windows\/prefetch\/[^/]+\.pf$/],
  ['Amcache', /^windows\/appcompat\/programs\/(amcache\.hve(\.log[12])?|recentfilecache\.bcf)$/],
  ['Scheduled tasks', /^windows\/(system32\/tasks\/.+|tasks\/[^/]+\.job|syswow64\/tasks\/.+)$/, { max: 4 * 1024 ** 2 }],
  ['SRUM', /^windows\/system32\/sru\/srudb\.dat$/],
  ['SUM / UAL', /^windows\/system32\/logfiles\/sum\/[^/]+\.mdb$/],
  ['IIS logs', /^(windows\/system32\/logfiles\/w3svc\d+|inetpub\/logs\/logfiles\/w3svc\d+)\/[^/]+\.log$/],
  ['Shim databases', /^windows\/apppatch\/custom\/(custom64\/)?[^/]+\.sdb$/],
  ['WMI repository', /^windows\/system32\/wbem\/repository\/objects\.data$/, { max: 512 * 1024 ** 2 }],
  ['PowerShell profiles', /^windows\/system32\/windowspowershell\/v1\.0\/[^/]*profile\.ps1$/],
  ['User hives', new RegExp(`^${U}/(ntuser\\.dat(\\.log[12]?)?)$`)],
  ['UsrClass', new RegExp(`^${U}/appdata/local/microsoft/windows/usrclass\\.dat(\\.log[12]?)?$`)],
  ['LNK and jump lists', new RegExp(`^${U}/(appdata/roaming/microsoft/(windows|office)/recent/.+\\.(lnk|automaticdestinations-ms|customdestinations-ms)|recent/[^/]+\\.lnk|desktop/[^/]+\\.lnk)$`)],
  ['Startup folders', new RegExp(`^(${U}/appdata/roaming/microsoft/windows/start menu/programs/startup/[^/]+|programdata/microsoft/windows/start menu/programs/startup/[^/]+)$`), { max: 64 * 1024 ** 2 }],
  ['PowerShell history', new RegExp(`^${U}/appdata/roaming/microsoft/windows/powershell/psreadline/[^/]+\\.txt$`)],
  ['PowerShell transcripts', new RegExp(`^${U}/documents/(powershell_transcript[^/]*\\.txt|\\d{8}/powershell_transcript[^/]*\\.txt)$`)],
  ['Browser history', new RegExp(`^${U}/appdata/(local/(google/chrome|microsoft/edge|bravesoftware/brave-browser)/user data/[^/]+/history(-wal)?|roaming/mozilla/firefox/profiles/[^/]+/places\\.sqlite(-wal)?)$`)],
  ['WebCache', new RegExp(`^${U}/appdata/local/microsoft/windows/webcache/webcachev01\\.dat$`)],
  ['Windows Timeline', new RegExp(`^${U}/appdata/local/connecteddevicesplatform/[^/]+/activitiescache\\.db(-wal)?$`)],
  ['Recycle Bin', /^(\$recycle\.bin\/[^/]+\/\$i[^/]+|recycler\/[^/]+\/info2)$/],
  ['Defender logs', /^programdata\/microsoft\/windows defender\/support\/mplog-[^/]+\.log$/],
];

const TOTAL_CAP = 3 * 1024 ** 3;   // stop extracting after 3 GB
const FILE_CAP = 1024 ** 3;        // 1 GB per file unless the target says otherwise

/** Pick target files from an Ntfs volume. Returns [{label, file, stream, opts}] */
export function selectTargets(ntfs) {
  const picks = [];
  for (const f of ntfs.files()) {
    if (f.dir) continue;
    const lp = f.path.toLowerCase();
    for (const [label, rx, opts = {}] of TARGETS) {
      if (!rx.test(lp)) continue;
      const stream = f.streams[opts.stream || ''];
      if (stream) picks.push({ label, file: f, stream, opts });
      break;
    }
  }
  return picks;
}

export { TOTAL_CAP, FILE_CAP };
