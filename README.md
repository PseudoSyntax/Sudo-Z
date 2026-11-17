# Sudo-Z

**One console for the Eric Zimmerman toolset, rebuilt for the browser and focused on spotting IOCs.**

Drop Windows artifacts (one file, many files, a folder, or a KAPE triage zip) and Sudo-Z identifies each file, routes it to the parser that would handle it in Eric Zimmerman's toolset [1], runs shared detection logic across everything, and hands back an IOC report: verdict, prioritised findings with MITRE ATT&CK mapping, an indicator list, a super timeline and per-artifact tables.

Nothing is uploaded. Files are read with the browser File API and parsed in a Web Worker on your own machine. Sudo-Z is a static site, so it runs from GitHub Pages and keeps working offline once loaded.

## Quick start

**Option 1: just use it.** Open **https://pseudosyntax.github.io/Sudo-Z/**, drop your files, press EXECUTE ANALYSIS. Nothing to install, always the latest version.

**Option 2: install it locally** (works offline, one command, the same command updates it).

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/PseudoSyntax/Sudo-Z/main/install.ps1 | iex
```

Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/PseudoSyntax/Sudo-Z/main/install.sh | bash
```

Then:

| Command | What it does |
|---|---|
| `sudo-z` | Starts the console on `http://localhost:8765` and opens your browser |
| `sudo-z update` | Pulls the newest version from GitHub and replaces the old code |
| `sudo-z version` | Shows the installed version and whether an update is out |
| `sudo-z cli triage.zip -o out` | Runs the analysis headless (needs Node 18+) |
| `sudo-z uninstall` | Removes it |

On Windows open a new terminal after installing so `sudo-z` is on your PATH, or use the Start Menu shortcut. The launcher also tells you when an update is available.

The installer downloads the latest commit from this repo, checks it is a complete copy, swaps it in and deletes the old one. If anything fails the old version stays in place. It installs to `%LOCALAPPDATA%\Sudo-Z` on Windows and `~/.local/share/sudo-z` on Linux/macOS and needs no admin rights.

Opening `index.html` straight from disk will not work, because browsers block ES modules and Web Workers on `file://`. That is why the launcher runs a small web server bound to localhost only.

## Why I built it

Eric Zimmerman's tools are the standard for Windows artifact parsing [1], but each tool covers one artifact type and produces CSV that still has to be filtered and correlated by hand in Timeline Explorer. During an investigation or a CTF that means running a dozen tools, opening a dozen CSVs and remembering which columns matter.

Sudo-Z collapses that into one step. The aim is not just parsing but hunting: the same path and command-line heuristics run against Prefetch, Amcache, ShimCache, BAM, UserAssist, services, Run keys, scheduled tasks, LNKs, jump lists, the $MFT, browser history and every event log. A malicious binary gets graded the same way whether it shows up in a Sysmon event or a ShimCache entry, and when two independent artifacts agree that a suspicious program ran, Sudo-Z raises a correlation finding.

## Using it

**Web:** open the GitHub Pages site, drop files on the INTAKE panel, press EXECUTE ANALYSIS.

**Many files:** zip them first, or drag a whole folder in. KAPE Targets output (for example `!SANS_Triage` or `KapeTriage`) works as is. Nested zips are opened up to three levels deep.

**Headless:** the same engine runs in Node 18 or later, either through `sudo-z cli` or directly from a clone.

```
node cli/sudo-z.mjs triage.zip -o out/
node cli/sudo-z.mjs C:\kape\out\C -o out/ --no-defang
```

The CLI writes `report.md`, `report.json`, `findings.csv`, `indicators.csv` and `timeline.csv`.

**Hosting your own copy on GitHub Pages:** fork the repo, then Settings, Pages, Source "GitHub Actions". The included `pages.yml` workflow publishes on every push to `main`. There is no build step.

## The console

| Tab | What it shows |
|---|---|
| 01 SITREP | Verdict, severity counts, the high/critical activity window, hosts and accounts seen, activity by tactic, ATT&CK techniques, indicator types, priority findings and per-tool coverage |
| 02 FINDINGS | Every finding with severity, category, tool, source file, the reason it fired, ATT&CK links and the raw evidence. Filter by severity, category or free text |
| 03 INDICATORS | Atomic IOCs grouped by type with counts, sources and context. Defang toggle and copy-all |
| 04 TIMELINE | Super timeline across all artifacts in UTC with 100ns precision where the source has it |
| 05 ARTIFACTS | One entry per parsed file: hashes, notes and every table the parser produced, each exportable to CSV |
| 06 REJECTED | Files no tool accepts, with the reason and what was done instead, plus guidance on inputs that cannot be accepted |
| 07 TOOLS | Every Eric Zimmerman tool, what it does, what it accepts and how Sudo-Z covers it |

Exports: Markdown IOC report, full JSON, findings CSV, indicators CSV and a timeline CSV that opens directly in Timeline Explorer.

## How a file is routed

Each file is identified by its signature first and its name second, so a renamed hive or event log still lands on the right parser.

| Signature / name | Tool |
|---|---|
| `ElfFile` | EvtxECmd |
| `SCCA` or `MAM\x04` | PECmd |
| Shell link header | LECmd |
| `*.automaticDestinations-ms` (OLE) / `*.customDestinations-ms` | JLECmd |
| `regf` | RECmd, AppCompatCacheParser, AmcacheParser, SBECmd (picked by hive type) |
| `FILE` records / `$J` / `NTFS` boot sector | MFTECmd |
| `$I*` / `INFO2` | RBCmd |
| `RecentFileCache.bcf` | RecentFileCacheParser |
| `SQLite format 3` | SQLECmd, or WxTCmd for ActivitiesCache.db |
| IIS W3C header | iisGeolocate (parse and hunt, no geolocation) |
| ESE `0x89ABCDEF` | Recognised as SrumECmd / SumECmd input, strings only |
| Task XML, `ConsoleHost_history.txt`, scripts | Sudo-Z extras |
| Anything else | Hasher + bstrings, listed under REJECTED with a reason |

Every file, accepted or not, is hashed with MD5, SHA1 and SHA256.

## What counts as an IOC

I wanted the report to be something I could act on, so findings come from explicit rules rather than "unusual" scoring. The main groups:

* **Execution from places programs should not live:** Users\Public, Temp, ProgramData root, Recycle Bin, PerfLogs, AppData roots, browser and Outlook caches, admin shares.
* **Masquerading:** system binary names (svchost, lsass, rundll32...) outside System32, typosquats like `scvhost.exe`, double extensions, right-to-left override characters, renamed system binaries (Sysmon OriginalFileName mismatch).
* **Known tooling by name or strings:** Mimikatz, Rubeus, SharpHound, Cobalt Strike, Sliver, PsExec and clones, ProcDump, rclone, ngrok, chisel, network scanners, remote access tools, EDR killers, vulnerable drivers (BYOVD).
* **Command lines:** encoded PowerShell (decoded and re-scanned), download cradles, hidden windows, certutil/bitsadmin/mshta/regsvr32/rundll32 proxy execution, LSASS dumping, shadow copy and backup deletion, hive and NTDS theft, log clearing, account creation and privileged group changes, Defender and firewall tampering, port proxies, RDP and WDigest changes, WMI and PsExec style remote execution, archive staging and exfil uploads, paste and tunnelling services, raw IP URLs.
* **Persistence:** Run/RunOnce, Active Setup, Winlogon Shell/Userinit, AppInit_DLLs, IFEO debuggers and accessibility backdoors, SilentProcessExit, LSA packages, services and service DLLs, scheduled tasks (including hidden tasks with the SD value removed), startup folder drops, UAC bypass and COM hijack keys, logon scripts, shim databases, WMI event subscriptions. Persistence entries are graded one level higher than the same path seen in plain execution.
* **Event log behaviour:** brute force and password spraying (NTLM and Kerberos), pass-the-hash logon pattern, Kerberoasting and AS-REP roasting, explicit credential use against remote hosts, admin share and named pipe access (svcctl, atsvc, PsExec pipes), RDP from public or tunnelled sources, Office, browser, WMI and web server processes spawning shells, LSASS memory access, CreateRemoteThread, suspicious DNS and outbound connections from LOLBins, Defender detections and failed remediation, PowerShell v2 downgrade.
* **File system:** Mark-of-the-Web downloads (HostUrl / ReferrerUrl from Zone.Identifier), timestomping candidates, ransom note spread, mass extension changes, bulk Prefetch deletion.
* **Web servers:** web shell commands, SQL injection (including leaked database errors), known Exchange and SharePoint exploitation paths, scanners and 404 floods.

Severity runs from INFO to CRITICAL. The verdict is "COMPROMISE LIKELY" when any critical finding exists, "SUSPICIOUS ACTIVITY" for high, "REVIEW RECOMMENDED" for medium.

## Tools in detail

Status shows how Sudo-Z covers each tool from the site [1]. The original tools are Windows .NET executables and cannot run in a browser, so every parser here is an independent JavaScript implementation of the same file format.

### EvtxECmd

**Status:** Implemented  
**Accepts:** *.evtx (Security, System, Sysmon, PowerShell, Defender, TerminalServices, TaskScheduler, WMI, BITS, AppLocker, OpenSSH...)

Parses Windows event logs into normalised CSV/JSON/XML using per-event "maps" that pull the useful fields into PayloadData columns.

**In Sudo-Z:** Full chunk + Binary XML decoder with template caching. Every record is normalised like EvtxECmd output, then run through 80+ detection rules: log clearing, brute force / spray, pass-the-hash, Kerberoasting / AS-REP roasting, PsExec and service-based lateral movement, admin share and named pipe abuse, malicious services and tasks, Sysmon process / network / LSASS access / registry / pipe / DNS events, PowerShell script blocks, Defender detections and tampering, RDP from public or tunnelled sources, WMI persistence.

### PECmd

**Status:** Implemented  
**Accepts:** *.pf (Prefetch v17 XP, v23 Vista/7, v26 8.x, v30/31 Win10/11 incl. MAM compressed)

Parses Prefetch: executable name, run count, last 8 run times, volumes, and the files/directories the program touched in its first ~10 seconds.

**In Sudo-Z:** Native LZXpress Huffman decompressor plus every Prefetch version. Grades the executable path and every referenced file (DLL side loading from Temp, credential material) and adds each run time to the timeline.

### LECmd

**Status:** Implemented  
**Accepts:** *.lnk

Parses shortcut files: target path, arguments, MAC times of the target, volume serial/type, network share, and the tracker block (machine NetBIOS name, MAC address).

**In Sudo-Z:** Full Shell Link parser including LinkInfo, shell item ID lists, string data and extra blocks. Flags malicious LNKs (script interpreters with hidden arguments, padded arguments, removable media launches) and extracts machine ID / MAC indicators.

### JLECmd

**Status:** Implemented  
**Accepts:** *.automaticDestinations-ms, *.customDestinations-ms

Parses Jump Lists, which hold embedded LNK records plus a DestList with last-used time, access count, pin status and host name per entry.

**In Sudo-Z:** OLE compound file reader, DestList v1-v4, embedded LNK parsing and AppID mapping (RDP client jump lists become RDP target indicators).

### RECmd

**Status:** Implemented  
**Accepts:** SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat, SAM, Amcache.hve (any regf hive)

Command line registry engine. Normally run with batch files (e.g. Kroll_Batch) that extract autoruns, execution evidence, user activity and system info.

**In Sudo-Z:** regf reader with big-data cell support and batch-style plugins: Run/RunOnce/Active Setup/Winlogon/AppInit/IFEO/SilentProcessExit, services and service DLLs, LSA packages, WDigest, RDP settings, PortProxy, Defender policies and exclusions, TaskCache (incl. hidden tasks with no SD), installed software, network profiles, USBSTOR, BAM/DAM, UserAssist, RunMRU, TypedPaths, WordWheelQuery, RecentDocs, Terminal Server Client, Sysinternals EULA, UAC bypass / COM hijacks, SAM accounts.

### AppCompatCacheParser

**Status:** Implemented  
**Accepts:** SYSTEM hive

Extracts ShimCache (AppCompatCache) entries: file paths seen by the application compatibility engine with their last-modified time.

**In Sudo-Z:** Decodes Windows 7, 8.x and 10/11 formats with position order and the Win7/8 executed flag, then grades every path.

### AmcacheParser

**Status:** Implemented  
**Accepts:** Amcache.hve

Parses Amcache: program file entries with full path and SHA1, installed applications, drivers and shortcuts.

**In Sudo-Z:** New (InventoryApplicationFile / InventoryDriverBinary / InventoryApplication) and legacy (Root\File) layouts. SHA1s become indicators, unsigned and known-vulnerable (BYOVD) drivers are flagged.

### SBECmd

**Status:** Implemented  
**Accepts:** NTUSER.DAT, UsrClass.dat

Exports ShellBags: folders a user opened in Explorer, including on removable, network and since-deleted locations.

**In Sudo-Z:** Walks BagMRU recursively, decodes root/volume/file-entry/network/URI shell items (with BEEF0004 long names and MFT references).

### MFTECmd

**Status:** Partial  
**Accepts:** $MFT, $J ($UsnJrnl:$J), $Boot  ($SDS, $I30, $LogFile accepted but strings only)

Parses NTFS metadata files into CSV / bodyfile with full paths, $SI and $FN timestamps and alternate data streams.

**In Sudo-Z:** FILE record fix-ups, $SI/$FN, ADS (reads Zone.Identifier HostUrl / ReferrerUrl), path resolution, timestomp heuristics, ransom note and mass-extension detection, files in suspicious locations. $J paths resolve when the $MFT is in the same submission. $SDS, $I30 and $LogFile are not decoded yet.

### RBCmd

**Status:** Implemented  
**Accepts:** $I* files (Vista+), INFO2 (XP)

Parses Recycle Bin metadata: original path, size and deletion time.

**In Sudo-Z:** Both formats. Flags deleted tools, scripts, dumps and large archives (exfil staging clean-up).

### RecentFileCacheParser

**Status:** Implemented  
**Accepts:** RecentFileCache.bcf (Windows 7)

Lists executables recently run on Windows 7 (predecessor of Amcache).

**In Sudo-Z:** Parsed and graded like other execution evidence.

### SQLECmd

**Status:** Partial  
**Accepts:** SQLite databases (*.db, *.sqlite, History, places.sqlite...)

Finds SQLite files and processes them with maps (browser history, Windows notification DB, etc.).

**In Sudo-Z:** Pure JS SQLite reader (b-trees, overflow pages). Maps for Chromium history + downloads and Firefox places + downloads; unknown databases get a table inventory and indicator sweep. -wal files are not merged and freelist records are not recovered.

### WxTCmd

**Status:** Implemented  
**Accepts:** ActivitiesCache.db

Parses the Windows 10/11 Timeline database (application use, files opened, focus time).

**In Sudo-Z:** Activity table with AppId/Payload JSON decoding; Win32 application paths become execution evidence.

### SrumECmd

**Status:** Strings only  
**Accepts:** SRUDB.dat (+ SOFTWARE)

Parses the System Resource Usage Monitor ESE database: per-app network bytes, CPU, energy, push notifications.

**In Sudo-Z:** Recognised, but ESE (JET Blue) parsing is not implemented in-browser. The file is string-scanned so executable paths and SIDs are still graded. Run SrumECmd for byte counts.

### SumECmd

**Status:** Strings only  
**Accepts:** SUM folder (Current.mdb, {GUID}.mdb, SystemIdentity.mdb)

Parses User Access Logging on Windows Server: which users/IPs accessed which roles per day.

**In Sudo-Z:** Recognised (ESE) and string-scanned only; IPs and user names found in strings still reach the indicator table.

### bstrings

**Status:** Implemented  
**Accepts:** Any file

Finds ASCII and Unicode strings with built-in regex patterns (URLs, IPs, emails, paths, base64...).

**In Sudo-Z:** ASCII + UTF-16LE extraction on every unrecognised file, URL/IP/email/UNC/encoded PowerShell/wallet patterns, offensive tooling keyword rules (Mimikatz, Cobalt Strike, PowerSploit, ransom notes, shadow copy deletion, web shells).

### Hasher

**Status:** Implemented  
**Accepts:** Any file

Computes file hashes.

**In Sudo-Z:** MD5, SHA1 and SHA256 for every submitted and extracted file (WebCrypto + local MD5).

### iisGeolocate

**Status:** Partial  
**Accepts:** IIS W3C logs (u_ex*.log)

Geolocates client IPs in IIS logs with a MaxMind database and records malformed lines.

**In Sudo-Z:** Parses the logs and hunts for web shell commands, SQL injection, known Exchange/SharePoint/ProxyShell exploit paths, scanners and 404 floods. Geolocation is left to you: client IPs are listed for offline lookup.

### RLA

**Status:** Not implemented  
**Accepts:** Dirty hives + .LOG1/.LOG2

Replays registry transaction logs into dirty hives.

**In Sudo-Z:** Not implemented. Dirty hives are still parsed and flagged; .LOG1/.LOG2 files are listed as not accepted.

### EZViewer

**Status:** GUI / not applicable  
**Accepts:** Documents, text, PDF

Standalone viewer for many document formats; unknown files open in a hex editor.

**In Sudo-Z:** Viewer, not an analyser. Sudo-Z hashes and string-scans documents instead.

### Timeline Explorer

**Status:** GUI / not applicable  
**Accepts:** CSV / XLSX

Spreadsheet-style viewer for the CSVs the other tools produce.

**In Sudo-Z:** Replaced by the built-in super timeline and table views. Every table and the timeline export to CSV that Timeline Explorer opens.

### Registry Explorer

**Status:** GUI / not applicable  
**Accepts:** Registry hives

GUI registry viewer with bookmarks and plugins.

**In Sudo-Z:** GUI. Its plugins are covered by the RECmd section above.

### MFTExplorer

**Status:** GUI / not applicable  
**Accepts:** $MFT

GUI for browsing $MFT.

**In Sudo-Z:** GUI. See MFTECmd.

### JumpList Explorer

**Status:** GUI / not applicable  
**Accepts:** Jump lists

GUI for Jump Lists.

**In Sudo-Z:** GUI. See JLECmd.

### ShellBags Explorer

**Status:** GUI / not applicable  
**Accepts:** NTUSER.DAT / UsrClass.dat

GUI for ShellBags.

**In Sudo-Z:** GUI. See SBECmd.

### SDB Explorer

**Status:** Strings only  
**Accepts:** *.sdb shim databases

GUI for application compatibility shim databases.

**In Sudo-Z:** Custom .sdb files are flagged (shim persistence, T1546.011) and string-scanned for target executables and DLLs.

### VSCMount

**Status:** GUI / not applicable  
**Accepts:** Live volume

Mounts every Volume Shadow Copy to a folder.

**In Sudo-Z:** Needs a live Windows volume. Mount shadow copies on Windows, collect the artifacts with KAPE and submit the zip.

### KAPE

**Status:** GUI / not applicable  
**Accepts:** Live system / image

Triage collection (Targets) and processing (Modules) framework that drives the tools above.

**In Sudo-Z:** Sudo-Z is built to take a KAPE Targets zip (e.g. !SANS_Triage / KapeTriage output) and run every applicable parser on it in the browser.

### Get-ZimmermanTools

**Status:** GUI / not applicable  
**Accepts:** -

PowerShell script that downloads and updates all the tools.

**In Sudo-Z:** Not applicable.

### TimeApp

**Status:** GUI / not applicable  
**Accepts:** -

Clock, stopwatch and timestamp converter.

**In Sudo-Z:** Not applicable; all times in Sudo-Z are UTC ISO-8601 with 100ns precision.

### XWFIM

**Status:** GUI / not applicable  
**Accepts:** -

X-Ways Forensics installation manager.

**In Sudo-Z:** Not applicable.

## What cannot be accepted

| Input | What happens |
|---|---|
| Registry transaction logs (*.LOG, *.LOG1, *.LOG2) | Need RLA to replay into the hive; replay on Windows and submit the clean hive. |
| ESE databases (SRUDB.dat, SUM *.mdb, WebCacheV01.dat, Windows.edb) | Recognised and string-scanned only; full table parsing needs SrumECmd / SumECmd / ESEDatabaseView. |
| Disk / memory images (E01, VMDK, VHD(X), raw dd, .mem, .dmp) | Too large for the browser and not EZ tool inputs. Collect artifacts with KAPE first. |
| Encrypted / password-protected zip entries, RAR, 7z, tar | Only standard and ZIP64 zips with stored/deflate entries are opened. Re-zip without a password. |
| Executables and DLLs (PE files) | Not an EZ tool input. They are hashed and string-scanned; submit hashes to your sandbox / threat intel. |
| $LogFile, $SDS, $I30 | Accepted by MFTECmd on Windows; Sudo-Z only string-scans them for now. |

## Project layout

```
index.html              the console
assets/sudo-z.css       styling
js/app.js               UI controller
js/worker.js            runs the engine off the UI thread
js/engine.js            intake, zip expansion, routing, report assembly
js/catalog.js           tool catalog shown on the TOOLS tab
js/report.js            Markdown / CSV exporters, defanging
js/core/                bytes, zip (DecompressionStream), hashes, strings, CFB, LZXpress Huffman
js/parsers/             evtx, prefetch, lnk, shellitems, jumplist, regf, ntfs, sqlite, misc
js/tools/               tool level logic: evtx rules, registry plugins, artifact wrappers
js/ioc/                 shared heuristics, indicator extraction, analysis context
cli/sudo-z.mjs          headless runner
install.ps1 / install.sh  installers and updaters
tools/                  local launchers (launch.ps1, sudo-z.sh) and a fallback web server
.github/workflows/      CI checks, installer tests on Windows and Linux, Pages deploy
```

No dependencies, no build step, no network calls with your data.

## Validation

I tested the parsers against public sample corpora rather than synthetic files: the plaso project test data [2] (event logs, Prefetch v17 to v31 including MAM compressed files, LNKs, jump lists, SYSTEM / SOFTWARE / NTUSER / Amcache hives, $MFT, USN journal, Recycle Bin, Chrome, Firefox, ActivitiesCache, IIS logs) and attack-scenario event logs from EVTX-ATTACK-SAMPLES [3]. Every sample parsed with zero record errors, and the attack logs produced the expected detections (log clearing, Squiblydoo, rundll32 and mshta proxy execution, pass-the-hash logons, svcctl lateral movement, malicious services, Defender hits, LSASS dumping via PowerShell).

## Limits

* Findings are heuristics. Treat them as leads and confirm anything that matters with the original tools.
* Browser memory caps practical input size around 1.5 GB per file.
* Not decoded yet: ESE databases (SRUM, SUM, WebCache), $LogFile, $SDS, $I30, legacy .evt, .job files, SQLite WAL merging and deleted record recovery, RLA style transaction log replay.
* iisGeolocate's geolocation needs a MaxMind database, so Sudo-Z lists client IPs for offline lookup instead.

## Credits

All credit for the original tools and the research behind them goes to Eric Zimmerman [1]. Sample data from the plaso project [2] and EVTX-ATTACK-SAMPLES by Samir Bousseaden [3] was used for testing only and is not shipped.

[1] https://ericzimmerman.github.io/
[2] https://github.com/log2timeline/plaso/tree/main/test_data
[3] https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
