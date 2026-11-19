# Sudo-Z

**One console for the Eric Zimmerman toolset, rebuilt for the browser and focused on spotting IOCs.**

Drop Windows artifacts (one file, many files, a folder, a KAPE triage zip or a Velociraptor collection) and Sudo-Z identifies each file, routes it to the parser that would handle it in Eric Zimmerman's toolset [1], runs shared detection logic across everything, and hands back an IOC report: verdict, prioritised findings with MITRE ATT&CK mapping, an indicator list, a super timeline and per-artifact tables. Volatility 3 memory analysis is part of the line-up too: on the website it grades Volatility's JSON output, and the home install runs Volatility itself against a memory image.

Nothing is uploaded. Files are read with the browser File API and parsed in a Web Worker on your own machine. Sudo-Z is a static site, so it runs from GitHub Pages and keeps working offline once loaded.

## Quick start

**Option 1: just use it.** Open **https://pseudosyntax.github.io/Sudo-Z/**, drop your files, a KAPE zip, or a disk image (E01, VHD, VHDX, raw, QCOW2), press EXECUTE ANALYSIS. Nothing to install, always the latest version.

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
| `sudo-z setup` | Downloads the requirements for the home-only extras: a private .NET 10 runtime, the original Eric Zimmerman tools and Volatility 3 (`sudo-z setup status` shows what is installed) |
| `sudo-z cli triage.zip -o out` | Runs the analysis headless (needs Node 18+) |
| `sudo-z uninstall` | Removes it |

Want everything in one go? Add the requirements to the install command:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/PseudoSyntax/Sudo-Z/main/install.ps1))) -Full
```

```bash
curl -fsSL https://raw.githubusercontent.com/PseudoSyntax/Sudo-Z/main/install.sh | SUDOZ_FULL=1 bash
```

On Windows open a new terminal after installing so `sudo-z` is on your PATH, or use the Start Menu shortcut. The launcher also tells you when an update is available.

The installer downloads the latest commit from this repo, checks it is a complete copy, swaps it in and deletes the old one. If anything fails the old version stays in place. It installs to `%LOCALAPPDATA%\Sudo-Z` on Windows and `~/.local/share/sudo-z` on Linux/macOS and needs no admin rights.

Opening `index.html` straight from disk will not work, because browsers block ES modules and Web Workers on `file://`. That is why the launcher runs a small web server bound to localhost only.


For every workflow, the cross-artifact checks that run after it, and the follow-on triage when one comes back positive, see [docs/WORKFLOWS.md](docs/WORKFLOWS.md).

## Website vs home install

The website runs everything Sudo-Z rebuilt in JavaScript, in your browser. A browser cannot run Python or Windows programs, so a few things only work in the home install, where `sudo-z` starts a small local server (Python 3.8+, standard library only) next to the console:

* **Volatility 3 on memory images.** Type the image path into the LOCAL ENGINE panel. The image is read in place, so multi-GB dumps never pass through the browser, and the results feed straight into the same report.
* **KAPE collection (Windows).** Give the LOCAL ENGINE panel a drive (`C:`), a folder, or a VHD/VHDX, pick a target (`!SANS_Triage` by default) and press RUN KAPE. It runs as a background job, asking for admin rights through UAC if `sudo-z` is not elevated. A VHD/VHDX is mounted read-only first and dismounted after. You can add `!EZParser` modules and shadow copies. When it finishes, the collection loads into the console automatically. KAPE is free from Kroll but not redistributable, so `sudo-z setup kape` opens the download page, finds `kape.exe` once you unzip it, and runs `kape --sync` to update its targets.
* **Disk images by path.** Type an image path into ANALYSE IMAGE and the local server streams only the bytes the reader asks for, so a 500 GB E01 on an external drive never gets copied. Sibling segments (`.E02`, `.002` ...) are picked up automatically.
* **The original Eric Zimmerman tools.** Point the LOCAL ENGINE panel at an artifact folder and Sudo-Z runs the matching tools the way KAPE's EZParser module does, writing their CSVs for Timeline Explorer. Useful for checking Sudo-Z's findings against the originals.

### Requirements download

`sudo-z setup` fetches everything these need, privately inside the Sudo-Z folder: no admin rights, nothing installed system-wide, and `sudo-z uninstall` removes it all.

| Requirement | Where it comes from | Notes |
|---|---|---|
| .NET 10 runtime | Microsoft's official `dotnet-install` script | Skipped if .NET 10 is already installed. Windows also gets the Desktop runtime for the GUI tools |
| Eric Zimmerman tools | Eric's own `Get-ZimmermanTools` on Windows; `tools/ez_fetch.py` (same download list, no PowerShell needed) on Linux/macOS | The command-line tools run on Windows, Linux and macOS. SrumECmd and SumECmd are Windows-only, and so are the GUI tools |
| Python 3 + Volatility 3 | Your Python if you have 3.8+, otherwise a private Python 3.12 installed with `uv` | Installed into its own venv. If the optional extras will not build on a very new Python, the core installs and the extras are tried one by one |

Run `sudo-z setup ez`, `sudo-z setup vol` or `sudo-z setup dotnet` to install just one, and `sudo-z setup status` to check. `sudo-z setup kape` (Windows) finds your KAPE copy and syncs its targets; KAPE itself has to be downloaded from Kroll [7] because its license does not allow redistribution (free for internal company, government, educational and research use).

The local server only listens on localhost, rejects other Host headers and requires a custom header on its API, so other websites open in your browser cannot drive it. Without Python the launcher falls back to serving the console only.

| Tool | Website (GitHub Pages) | Home install |
|---|---|---|
| EvtxECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| PECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| LECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| JLECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| RECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| AppCompatCacheParser | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| AmcacheParser | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| SBECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| MFTECmd | Partial (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| RBCmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| RecentFileCacheParser | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| SQLECmd | Partial (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| WxTCmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| Volatility 3 | JSON output only | Full: runs vol on the image |
| Velociraptor | Collections accepted | Same; run Velociraptor itself separately |
| SrumECmd | Yes (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| SumECmd | Partial (Sudo-Z parser) | Same, plus the original tool via the EZ runner (sudo-z setup ez) |
| bstrings | Yes (Sudo-Z parser) | Same; the original bstrings is fetched by sudo-z setup ez |
| Hasher | Yes (Sudo-Z hashes every file) | Same; the Hasher GUI is fetched by sudo-z setup ez (Windows) |
| iisGeolocate | Parse + hunt (no geolocation) | Same, plus the original tool via sudo-z setup ez (needs a MaxMind GeoLite2 database) |
| RLA | Yes (Sudo-Z replays logs) | Same; the original RLA is fetched by sudo-z setup ez (Windows) |
| EZViewer | No (Windows GUI) | Downloaded by sudo-z setup ez (Windows); open it yourself |
| Timeline Explorer | Replaced by built-in tables; CSV exports open in it | Downloaded by sudo-z setup ez (Windows); open the exported CSVs in it |
| Registry Explorer | No (Windows GUI); RECmd logic built in | Downloaded by sudo-z setup ez (Windows) |
| MFTExplorer | No (Windows GUI); MFTECmd logic built in | Downloaded by sudo-z setup ez (Windows) |
| JumpList Explorer | No (Windows GUI); JLECmd logic built in | Downloaded by sudo-z setup ez (Windows) |
| ShellBags Explorer | No (Windows GUI); SBECmd logic built in | Downloaded by sudo-z setup ez (Windows) |
| SDB Explorer | Flag + strings only | Downloaded by sudo-z setup ez (Windows) for full shim inspection |
| VSCMount | No (needs a live volume) | Downloaded by sudo-z setup ez; run as admin on the live Windows host |
| KAPE | KAPE output zips accepted | Not redistributable: get it from Kroll, then point the EZ runner or Sudo-Z at its output |
| Get-ZimmermanTools | Not applicable | Used by sudo-z setup ez to fetch every tool |
| TimeApp | Not applicable | Not needed |
| XWFIM | Not applicable | Not needed |

## Disk images

Drop an E01, VHD, VHDX, raw/dd (single or split `.001`), or QCOW2 image on the website or the home install, and Sudo-Z triages it the way KAPE would. Nothing is uploaded and the image is never loaded whole: the browser reads only the clusters it needs.

1. The container is opened: E01 chunks are inflated, VHD/VHDX block tables and QCOW2 cluster tables are followed, and split segments are joined.
2. MBR (including extended partitions) and GPT partition tables are read and every volume's file system is identified.
3. Each NTFS volume is opened from its boot sector. The full $MFT is read, records are rebuilt into paths, and file contents are read from their data runs, including sparse and LZNT1 compressed files and named streams like `$UsnJrnl:$J`.
4. A KAPE-style target set is pulled out (plus executables sitting in user-writable folders, so their signatures can be checked): $MFT, $J, $Boot, registry hives with their .LOG1/.LOG2, user NTUSER.DAT and UsrClass.dat, event logs, Prefetch, Amcache, scheduled tasks, SRUM, SUM, IIS logs, shim databases, LNK files and jump lists, startup folders, PowerShell history and transcripts, Chrome, Edge, Brave and Firefox history, WebCache, Windows Timeline, Recycle Bin and Defender logs.
5. Those files run through the normal parsers, rules and leads, exactly as if a KAPE zip had been dropped in. The ARTIFACTS tab shows the image, its volumes and every file pulled out with its MFT timestamps.

Not read yet: BitLocker volumes (reported, unlock and re-image them), file systems other than NTFS, VMDK, VDI, AFF4, differencing VHD/VHDX, and volume shadow copies inside an image. On Windows, the home install's KAPE job covers shadow copies for VHD/VHDX and live drives.

## Velociraptor

Velociraptor [4] is a collection and hunting platform (an agent and server running VQL queries across many machines), not a parser of offline artifacts, so it does not fit as another engine inside Sudo-Z. It fits as an input source, the same role KAPE plays. Drop an offline collector or collection zip and Sudo-Z decodes its URL-encoded upload paths (so `uploads/ntfs/%5C%5C.%5CC%3A/%24MFT` is treated as the `$MFT`), runs the normal parsers on the raw files and grades the artifact results in `results/*.json`. Hayabusa, Sigma and YARA hits from Velociraptor become findings at their own severity. For live hunting across a fleet, keep using Velociraptor itself.

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

**Hosting your own copy on GitHub Pages:** fork the repo, then Settings, Pages, Source "Deploy from a branch", branch `main`, folder `/ (root)`. Every push to `main` republishes automatically. There is no build step.

## The console

| Tab | What it shows |
|---|---|
| 01 SITREP | Verdict, severity counts, the high/critical activity window, hosts and accounts seen, activity by tactic, ATT&CK techniques, indicator types, the top leads, the programs to review, priority findings and per-tool coverage |
| 02 INVESTIGATE | Leads built by correlating artifacts, each with why it matters, what to do next, the evidence and the related timeline events. A pivot box searches findings, indicators, the timeline and leads at once for any name, hash, user, IP or path |
| 03 GRID | A Timeline Explorer style grid over any table: the Programs view (default), findings, the super timeline, indicators, leads, the MACB views, and every parsed artifact or tool CSV. Click a header to sort, type under it to filter (`text`, `!not`, `=exact`, `>n`, `<n`, `/regex/`), group by any column, tag rows, hide columns, resize them, open a row's details and export the current view |
| 04 STRINGS | bstrings search over every loaded file (and, if you tick it, the raw bytes of whole disk and memory images): find text (`--ls`), a regex (`--lr`), any of bstrings' 27 built-in patterns by name plus CTF flags, encoded PowerShell, NTLM hashes and private keys, a list of strings (`--fs`) or every string. Min/max length, ASCII or Unicode only, case sensitivity, only-the-match, file filter and max file size. Hits show file, byte offset and encoding in a sortable, filterable grid. On the home install it can also run the real bstrings.exe on any folder and load its output into the same grid |
| 05 FINDINGS | Every finding with severity, category, tool, source file, the reason it fired, a NEXT step, ATT&CK links and the raw evidence. Filter by severity, category or free text |
| 06 INDICATORS | Atomic IOCs grouped by type with counts, sources and context. Defang toggle and copy-all |
| 07 TIMELINE | Super timeline across all artifacts in UTC with 100ns precision where the source has it |
| 08 ARTIFACTS | One entry per parsed file: hashes, notes and every table the parser produced, each exportable to CSV |
| 09 REJECTED | Files no tool accepts, with the reason and what was done instead, plus guidance on inputs that cannot be accepted |
| 10 TOOLS | Every Eric Zimmerman tool plus Volatility 3 and Velociraptor: what it does, what it accepts, how Sudo-Z covers it, and whether it works on the website or needs the home install |

Exports: Markdown IOC report (with Leads to investigate, Programs to review, MACB file times, and a Next line per finding), full JSON, programs CSV, leads CSV, findings CSV, indicators CSV, a timeline CSV that opens directly in Timeline Explorer, MACB anomalies CSV and a Sleuth Kit body file (feed it to `mactime`).

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
| ESE `0x89ABCDEF` | SrumECmd (SRUDB.dat), WebCache history, SumECmd, generic ESE inventory |
| Hive + `.LOG1` / `.LOG2` in the same folder | RLA (logs replayed before parsing) |
| SQLite database + `-wal` in the same folder | WAL merged before parsing |
| `LfLe` legacy event log / `.job` / `INDX` | `.evt` parser / Task Scheduler 1.0 / MFTECmd ($I30) |
| Volatility 3 JSON (`__children` rows) | Volatility 3 |
| Velociraptor collection zip | Velociraptor (uploads decoded, results graded) |
| E01 / VHD / VHDX / QCOW2 / raw disk with MBR or GPT | Disk image reader, then every parser on the extracted triage files |
| Memory image (crash dump, hiberfil, LiME, large raw) | Home install only (Volatility 3) |
| Office documents (OOXML zip or OLE) and PDF | Sudo-Z docmeta (embedded times, macros, remote templates, PDF actions) |
| Task XML, `ConsoleHost_history.txt`, scripts | Sudo-Z extras |
| Anything else | Hasher + bstrings, listed under REJECTED with a reason |

Every file, accepted or not, is hashed with MD5, SHA1 and SHA256.

## Timeline Explorer CSVs

If you already ran the EZ tools (by hand, through KAPE's `!EZParser` module, or with the home install's EZ runner), drop their CSVs in. Each CSV is recognised by its header and analysed with the same rules as the raw artifacts, so it feeds findings, programs, leads and the super timeline instead of only being displayed:

| CSV | What Sudo-Z does with it |
|---|---|
| EvtxECmd | Rebuilds each event from the Payload column and runs the full event log rules, per source log |
| PECmd, AmcacheParser, AppCompatCacheParser, RECmd UserAssist / RunMRU / RADAR, WxTCmd, SrumECmd | Execution evidence: programs, run counts, SHA1s, publishers, network bytes |
| RECmd batch and plugin CSVs (Services, TaskCache, firewall rules ...) | Persistence and defence evasion checks |
| MFTECmd $MFT / $J, RBCmd, SBECmd, LECmd, JLECmd | Suspicious locations, timestomping, downloads (Zone.Identifier), deletions, shortcut targets and arguments |
| SQLECmd browser downloads and history | Risky downloads and URL indicators |
| Autoruns, Sigcheck | Signature status (verified, not verified, unsigned) for every autostart entry or scanned file |
| Hayabusa, Chainsaw | Sigma detections become findings at their own level |

On the home install, finished EZ runner and KAPE module jobs load their CSVs into the console automatically.

## Execution evidence: Prefetch, ShimCache, Amcache, UserAssist, SRUM

These five artifacts are where Windows records that a program existed or ran, and each one proves something different, so Sudo-Z reads them side by side instead of one at a time.

| Artifact | Expected file (KAPE target) | Proves | Does not prove |
|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` (Prefetch) | The program ran: run count, up to 8 last run times, files it touched at start | Off on Windows Server and when EnablePrefetcher = 0; about 1024 entries on Win8+ |
| ShimCache | `SYSTEM` hive, AppCompatCache value (RegistryHives) | The file existed and was seen by the compatibility engine, with its last-modified time | Execution on Windows 10/11; newest entries are only written at shutdown |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` + logs (Amcache) | The program was present: full path, SHA1, publisher, version | Execution on its own; inventory tasks also add entries |
| UserAssist | `C:\Users\<user>\NTUSER.DAT`, one per user (RegistryHives) | A named user launched it from the GUI: run count, last run, focus time | Command line, service and task starts |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` + SOFTWARE (SRUM) | The program ran, per user and hour, for 30 to 60 days, with network bytes sent and received | The last hour (flushed hourly) and command lines |

What you get:

* **Coverage** on SITREP and in the report: which of the five were collected, how many entries, the time range they cover, and which are missing with the file to collect. User profiles whose NTUSER.DAT was not submitted are named.
* **A matrix** in the GRID Programs view: one column per artifact (run counts, last runs, ShimCache position, Amcache SHA1, UserAssist user, SRUM bytes), plus **Executed?** (proven to run, or only present), **First run** and **Last run** across all of them. One-click filters: ran, ran with no Prefetch, present but never proven to run.
* **Cross-artifact findings**, the things single tools do not show:
  * **Ran, but no Prefetch file:** UserAssist, SRUM, BAM, Sysmon or 4688 show a run after the oldest run still covered by the Prefetch set, yet the program has no .pf. That is what targeted Prefetch deletion looks like.
  * **Prefetch nearly empty** while dozens of programs show execution elsewhere (folder wiped), and **Prefetch disabled** (`EnablePrefetcher = 0` read from the SYSTEM hive, high when the key changed during the attack window).
  * **Same path, different SHA1** in Amcache: the binary at that path was replaced (updates, or a trojanised copy).
  * **Present, never proven to run:** suspicious files only ShimCache or Amcache saw. Staged tools, or programs whose other traces were removed.
  * When the evidence names several hosts, the Prefetch checks say so and are toned down, since the artifacts may not be from the same machine.

## MACB: file times, and the times inside files

Every file has four times on NTFS, and they live in two places. MACB is Modified, Accessed, Changed (the $MFT record change, not the creation time) and Born. `$STANDARD_INFORMATION` ($SI) holds the four times Explorer shows and any program can rewrite with one API call. `$FILE_NAME` ($FN) holds another four that only the kernel sets. Files also carry times of their own that move with them: a document's created and last saved times, a program's compile time. And other artifacts keep copies: a shortcut remembers its target's B, M and A from the day it was opened. Sudo-Z puts all of these side by side.

| Source | Times | Comes from |
|---|---|---|
| $MFT (native or MFTECmd CSV) | $SI B M A C and $FN B M A C, all eight, plus Copied | MFTECmd |
| Disk image | $SI B M A C of each extracted file | the image reader |
| Archive entry | M, A, B from the NTFS extra field (7-Zip, WinRAR), M from the extended timestamp, or the DOS time (local, no zone, shown but not compared) | ZIP central directory |
| Office documents | created, last saved, last printed, author, last saved by, application | docx/docm/xlsx/pptx `docProps/core.xml` and `app.xml`, doc/xls/ppt `SummaryInformation` |
| PDF | /CreationDate, /ModDate (last incremental update), XMP dates, author, producer | the PDF itself |
| Programs | PE header compile time; Amcache LinkDate | the PE file; Amcache.hve |
| Shortcuts and jump lists | the target's B, M, A when it was opened, and its $MFT entry and sequence | LNK header and shell items |

Checks on the $MFT itself:

* **$SI born before $FN born.** The visible born time was moved back.
* **B or M later than C.** Every change updates C, so a born or modified time after it was set forward by a tool.
* **All four $SI times identical with no sub-second part.** What a timestomp tool writes when given one value.
* **Born before the volume was formatted** (`$MFT` record 0), for files in user folders.
* **Times in the future.**
* **Bursts:** 50+ files born in one minute in user-writable folders (extraction, installer or dropper), and 200+ user files modified in one minute, high when one new extension dominates (ransomware encrypting in place).

Checks against the times inside files and copies kept elsewhere:

* **Compiled after the file system says the file was born and last modified** (not for Microsoft-signed or Windows folder binaries, where reproducible builds put a hash in the compile time).
* **Document saved after its file system M, or authored after its file system B.** M or B was set back.
* **Document created after last saved.** Typical of documents built by scripts.
* **A shortcut's copy of the target's B or M is later than the current $MFT.** The times went back after the user opened it. A different $MFT entry or sequence means the file was **replaced** with a new one of the same name.

To keep the noise down, $MFT checks outside user-writable folders count only for programs, the same anomaly on 10 or more files in one folder is marked bulk and kept low (installers and archive extractions keep the archive's times), and a rule that fires on more than 2% of the volume is capped at medium with a note to check for a clock change. The Accessed time comes with a caveat read from the SYSTEM hive (`NtfsDisableLastAccessUpdate`): on most systems A is not updated or is updated lazily, so it is weak evidence.

Where it shows: a MACB box on SITREP, four GRID views (anomalies, content vs file system times, bursts, and a mactime style MACB timeline of every $SI and $FN time with `macb` flags), a section in the report, `macb.csv`, and a body file for `mactime`. Documents also get their own findings: VBA macros, remote template injection (T1221), external OLE links, and PDF JavaScript, auto actions, Launch and embedded files.

## Signatures and the Programs view

Every program seen anywhere (Prefetch, Amcache, ShimCache, BAM, UserAssist, SRUM, Sysmon, memory, persistence entries, files pulled out of a disk image) becomes one row in the Programs view, with what is known about its code signature:

* **Sysmon 6 and 7** report whether a driver or DLL was signed and whether the signature was valid. Revoked signatures are flagged high (a common sign of a vulnerable driver being abused).
* **Autoruns and Sigcheck CSVs** give verified, not verified or unsigned for each file.
* **PE files** submitted directly, or pulled out of a disk image from user-writable folders, are read for an embedded Authenticode signature and its signer. This finds the signature and who signed it, but does not re-verify it, so treat it as "carries a signature".
* **Amcache** only records the publisher from the version information. That is shown separately and never counted as a signature.

Each program gets a risk score (location, name tricks, unsigned or invalid signature, persistence, linked findings) and the GRID opens on them sorted by risk, with one-click filters for unsigned, user-writable, persisting, LOLBins and programs with findings. Windows binaries are mostly catalog-signed (their signature lives in a catalog file, not in the binary), so "no embedded signature" on a file in System32 is normal; the score only weighs it heavily for files in user-writable places.

## What counts as an IOC

I wanted the report to be something I could act on, so findings come from explicit rules rather than "unusual" scoring. The main groups:

* **Execution from places programs should not live:** Users\Public, Temp, ProgramData root, Recycle Bin, PerfLogs, AppData roots, browser and Outlook caches, admin shares.
* **Masquerading:** checked against a baseline of about 120 common Windows and application processes (explorer.exe, svchost.exe, lsass.exe, csrss.exe, chrome.exe, OneDrive.exe and so on) with their normal folders and parents. It catches misspellings and transpositions (`scvhost.exe`, `explorer.exe` vs `exp1orer.exe`), lookalike Unicode letters (Cyrillic `о` in `svchоst.exe`), digit and letter swaps (`lsas5.exe`), extra suffixes (`svchost32.exe`), spaces, genuine names running from the wrong folder, and wrong parents (lsass not started by wininit). Real near-names like `taskhostw.exe`, `lsaiso.exe` and `osppsvc.exe` are allowlisted. Also double extensions, right-to-left override characters, and renamed system binaries (Sysmon OriginalFileName mismatch).
* **Known tooling by name or strings:** Mimikatz, Rubeus, SharpHound, Cobalt Strike, Sliver, PsExec and clones, ProcDump, rclone, ngrok, chisel, network scanners, remote access tools, EDR killers, vulnerable drivers (BYOVD).
* **Command lines:** encoded PowerShell (decoded and re-scanned), download cradles, hidden windows, certutil/bitsadmin/mshta/regsvr32/rundll32 proxy execution, LSASS dumping, shadow copy and backup deletion, hive and NTDS theft, log clearing, account creation and privileged group changes, Defender and firewall tampering, port proxies, RDP and WDigest changes, WMI and PsExec style remote execution, archive staging and exfil uploads, paste and tunnelling services, raw IP URLs.
* **Persistence:** Run/RunOnce, Active Setup, Winlogon Shell/Userinit, AppInit_DLLs, IFEO debuggers and accessibility backdoors, SilentProcessExit, LSA packages, services and service DLLs, scheduled tasks (including hidden tasks with the SD value removed), startup folder drops, UAC bypass and COM hijack keys, logon scripts, shim databases, WMI event subscriptions. Persistence entries are graded one level higher than the same path seen in plain execution.
* **Event log behaviour:** brute force and password spraying (NTLM and Kerberos), pass-the-hash logon pattern, Kerberoasting and AS-REP roasting, explicit credential use against remote hosts, admin share and named pipe access (svcctl, atsvc, PsExec pipes), RDP from public or tunnelled sources, Office, browser, WMI and web server processes spawning shells, LSASS memory access, CreateRemoteThread, suspicious DNS and outbound connections from LOLBins, Defender detections and failed remediation, PowerShell v2 downgrade.
* **File system:** Mark-of-the-Web downloads (HostUrl / ReferrerUrl from Zone.Identifier), timestomping candidates, ransom note spread, mass extension changes, bulk Prefetch deletion.
* **Memory (Volatility 3):** hidden processes (psscan vs pslist, psxview), unexpected parents for lsass / services / svchost, duplicate singleton processes, Office, web server and WMI processes spawning shells, malicious command lines, LOLBins connected to public IPs, malfind regions with PE headers or shellcode, unlinked DLLs, process hollowing and ghosting, suspicious threads, console history, rootkit drivers and syscall hooks.
* **Code injection (Volatility 3):** ldrmodules, malfind, pstree, dlllist, suspicious_threads and hollowprocesses are read together, per process. Flagged: a module in the loader lists with MappedPath N/A (nothing on disk behind it: reflective DLL injection, manual mapping, hollowing); image memory with no file and no loader entry; a main module that maps a different file than the process name, or a PEB path that disagrees with the mapped file; DLLs unlinked from one or all loader lists; LSASS and other core processes loading DLLs from outside the Windows and Program Files folders (malicious security packages and password filters); PE images in private memory with the MZ header wiped; and any executable private memory in LSASS. When two or more of these hit the same process, a correlation finding says injection is confirmed.
* **Kernel rootkits (Volatility 3):** the home install runs windows.ssdt, a Sudo-Z plugin for per-thread service tables (`windows.kthread_ssdt`, in `tools/volplugins`), modules and modscan, driverscan, unloadedmodules, callbacks, driverirp, timers and orphan_kernel_threads, and the console grades them:
  * **Global SSDT hooks:** entries that point outside ntoskrnl/win32k, plus gaps in the index list (windows.ssdt prints nothing for an entry that points outside every module, so a gap is an entry redirected into hidden memory).
  * **Per-thread SSDT hooks from KTHREAD:** every thread's `KTHREAD.ServiceTable` must point at `KeServiceDescriptorTable` or `...Shadow`. A rootkit can give chosen threads a private, hooked copy so the global SSDT still looks clean. The plugin walks process thread lists and pool-scanned threads, reports any other table, its owner module and how many of its entries point outside the kernel. Kernels whose `_KTHREAD` has no ServiceTable field (newer x64 builds dispatch from the global tables only) say so in one row.
  * **DKOM:** processes missing from ActiveProcessLinks but found by psscan, thrdscan or csrss (psxview); drivers found by modscan but unlinked from PsLoadedModuleList; driver objects whose code is in no listed module; threads found by pool scan but missing from their process; kernel threads running from memory no driver owns.
  * **Other kernel hooks:** callbacks, IRP dispatch routines and timer DPCs that point into unknown memory, IRP handlers taken over by an unrelated driver, and drivers loaded from user-writable folders.
* **Named pipes:** Sysmon 17/18 and Volatility 3 (handles, filescan, command lines) share one pipe checker. It knows the default pipes of Cobalt Strike, PsExec, RemCom/Impacket, PAExec, Covenant and PoshC2, catches Potato and PrintSpoofer impersonation pipes (`\\.\pipe\x\pipe\spoolss`), spots PowerShell running inside another process from its `PSHost.*` pipe, and flags random-looking pipes held by rundll32, dllhost and other processes beacons spawn into, or by programs in user folders. Common browser, .NET, Office and Windows pipes are allowlisted.
* **Exfiltration (SRUM):** large or upload-heavy network use by non-browser programs, LOLBins with network traffic, network use by programs in suspicious paths.
* **Web servers:** web shell commands, SQL injection (including leaked database errors), known Exchange and SharePoint exploitation paths, scanners and 404 floods.

## Leads: what an analyst might miss

Single-tool rules catch the obvious. I added a second pass that reads across every artifact and builds **leads**, the things that only show up when the evidence is put side by side. Each lead says why it matters and what to do next, and lists the evidence it used.

| Lead | How it is found |
|---|---|
| Attack chain | The same file name appears as Delivered (download, Zone.Identifier, BITS), Executed (Prefetch, Amcache, ShimCache, BAM, Sysmon), Persisted (Run key, service, task), Network (C2 or exfil finding) and Deleted. Three or more stages, or two with a strong finding, become a lead |
| Executed then deleted | A program in a user-writable folder has execution evidence but is gone from the $MFT or marked deleted |
| Renamed binary | One SHA1 (Amcache, Sysmon, Velociraptor) under two or more names, such as psexec.exe and svcupdate.exe. Installer temp copies and DLL pairs are skipped |
| Masquerading | Every lookalike or wrong-folder hit from the process baseline gathered in one place |
| Activity window | Events within 15 minutes of a high or critical finding that did not trip a rule themselves: the dropper, the logon before, the tool run next |
| Unflagged new programs | Programs in user folders that ran within 2 hours of the attack window and were not flagged (one per folder, installers filtered) |
| New account used | An account created (4720 or `net user /add`) and then used for logons |
| Log tampering | Cleared logs plus gaps in EventRecordID, which reveal selective record deletion that a full clear check misses |

Event logs are also checked for missing record numbers and for the clock jumping backwards in the Security log. Every finding gets a NEXT line from a playbook keyed on its ATT&CK technique, so the report reads as a to-do list rather than a pile of alerts.

Severity runs from INFO to CRITICAL. The verdict is "COMPROMISE LIKELY" when any critical finding exists, "SUSPICIOUS ACTIVITY" for high, "REVIEW RECOMMENDED" for medium.

## Tools in detail

Status shows how Sudo-Z covers each tool from the site [1], plus Volatility 3 and Velociraptor. The original EZ tools are Windows .NET executables and cannot run in a browser, so every parser here is an independent JavaScript implementation of the same file format; the home install can additionally run the originals.

### EvtxECmd

**Status:** Implemented  
**Accepts:** *.evtx (Security, System, Sysmon, PowerShell, Defender, TerminalServices, TaskScheduler, WMI, BITS, AppLocker, OpenSSH...)  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses Windows event logs into normalised CSV/JSON/XML using per-event "maps" that pull the useful fields into PayloadData columns.

**In Sudo-Z:** Full chunk + Binary XML decoder with template caching. Every record is normalised like EvtxECmd output, then run through 80+ detection rules: log clearing, brute force / spray, pass-the-hash, Kerberoasting / AS-REP roasting, PsExec and service-based lateral movement, admin share and named pipe abuse, malicious services and tasks, Sysmon process / network / LSASS access / registry / pipe / DNS events, PowerShell script blocks, Defender detections and tampering, RDP from public or tunnelled sources, WMI persistence.

### PECmd

**Status:** Implemented  
**Accepts:** *.pf (Prefetch v17 XP, v23 Vista/7, v26 8.x, v30/31 Win10/11 incl. MAM compressed)  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses Prefetch: executable name, run count, last 8 run times, volumes, and the files/directories the program touched in its first ~10 seconds.

**In Sudo-Z:** Native LZXpress Huffman decompressor plus every Prefetch version. Grades the executable path and every referenced file (DLL side loading from Temp, credential material) and adds each run time to the timeline.

### LECmd

**Status:** Implemented  
**Accepts:** *.lnk  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses shortcut files: target path, arguments, MAC times of the target, volume serial/type, network share, and the tracker block (machine NetBIOS name, MAC address).

**In Sudo-Z:** Full Shell Link parser including LinkInfo, shell item ID lists, string data and extra blocks. Flags malicious LNKs (script interpreters with hidden arguments, padded arguments, removable media launches) and extracts machine ID / MAC indicators.

### JLECmd

**Status:** Implemented  
**Accepts:** *.automaticDestinations-ms, *.customDestinations-ms  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses Jump Lists, which hold embedded LNK records plus a DestList with last-used time, access count, pin status and host name per entry.

**In Sudo-Z:** OLE compound file reader, DestList v1-v4, embedded LNK parsing and AppID mapping (RDP client jump lists become RDP target indicators).

### RECmd

**Status:** Implemented  
**Accepts:** SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat, SAM, Amcache.hve (any regf hive)  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Command line registry engine. Normally run with batch files (e.g. Kroll_Batch) that extract autoruns, execution evidence, user activity and system info.

**In Sudo-Z:** regf reader with big-data cell support and batch-style plugins: Run/RunOnce/Active Setup/Winlogon/AppInit/IFEO/SilentProcessExit, services and service DLLs, LSA packages, WDigest, RDP settings, PortProxy, Defender policies and exclusions, TaskCache (incl. hidden tasks with no SD), installed software, network profiles, USBSTOR, BAM/DAM, UserAssist, RunMRU, TypedPaths, WordWheelQuery, RecentDocs, Terminal Server Client, Sysinternals EULA, UAC bypass / COM hijacks, SAM accounts.

### AppCompatCacheParser

**Status:** Implemented  
**Accepts:** SYSTEM hive  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Extracts ShimCache (AppCompatCache) entries: file paths seen by the application compatibility engine with their last-modified time.

**In Sudo-Z:** Decodes Windows 7, 8.x and 10/11 formats with position order and the Win7/8 executed flag, then grades every path.

### AmcacheParser

**Status:** Implemented  
**Accepts:** Amcache.hve  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses Amcache: program file entries with full path and SHA1, installed applications, drivers and shortcuts.

**In Sudo-Z:** New (InventoryApplicationFile / InventoryDriverBinary / InventoryApplication) and legacy (Root\File) layouts. SHA1s become indicators, unsigned and known-vulnerable (BYOVD) drivers are flagged.

### SBECmd

**Status:** Implemented  
**Accepts:** NTUSER.DAT, UsrClass.dat  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Exports ShellBags: folders a user opened in Explorer, including on removable, network and since-deleted locations.

**In Sudo-Z:** Walks BagMRU recursively, decodes root/volume/file-entry/network/URI shell items (with BEEF0004 long names and MFT references).

### MFTECmd

**Status:** Partial  
**Accepts:** $MFT, $J ($UsnJrnl:$J), $Boot, $I30 ($SDS and $LogFile strings only)  
**Website:** Partial (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses NTFS metadata files into CSV / bodyfile with full paths, $SI and $FN timestamps and alternate data streams.

**In Sudo-Z:** FILE record fix-ups, $SI/$FN, ADS (reads Zone.Identifier HostUrl / ReferrerUrl), path resolution, MACB analysis of all eight $SI/$FN times (B before $FN, B or M after C, identical whole-second times, born before the volume, future times, mass born/modified bursts) with a mactime style timeline and a TSK bodyfile export, timestomp heuristics, ransom note and mass-extension detection, files in suspicious locations. $J and $I30 paths resolve when the $MFT is in the same submission. $I30 INDX records are parsed including deleted entries recovered from slack. $SDS and $LogFile are not decoded yet.

### RBCmd

**Status:** Implemented  
**Accepts:** $I* files (Vista+), INFO2 (XP)  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses Recycle Bin metadata: original path, size and deletion time.

**In Sudo-Z:** Both formats. Flags deleted tools, scripts, dumps and large archives (exfil staging clean-up).

### RecentFileCacheParser

**Status:** Implemented  
**Accepts:** RecentFileCache.bcf (Windows 7)  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Lists executables recently run on Windows 7 (predecessor of Amcache).

**In Sudo-Z:** Parsed and graded like other execution evidence.

### SQLECmd

**Status:** Partial  
**Accepts:** SQLite databases (*.db, *.sqlite, History, places.sqlite...)  
**Website:** Partial (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Finds SQLite files and processes them with maps (browser history, Windows notification DB, etc.).

**In Sudo-Z:** Pure JS SQLite reader (b-trees, overflow pages). Maps for Chromium history + downloads, Firefox places + downloads and WebCacheV01.dat (ESE); unknown databases get a table inventory and indicator sweep. A -wal file submitted next to its database is merged first (committed frames only). Freelist / deleted records are not recovered.

### WxTCmd

**Status:** Implemented  
**Accepts:** ActivitiesCache.db  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses the Windows 10/11 Timeline database (application use, files opened, focus time).

**In Sudo-Z:** Activity table with AppId/Payload JSON decoding; Win32 application paths become execution evidence.

### Volatility 3

**Status:** Partial  
**Accepts:** Memory images (raw, crash dumps, hiberfil, LiME, VMware) or vol3 JSON output  
**Website:** JSON output only  
**Home install:** Full: runs vol on the image

The Volatility Foundation's memory forensics framework (not an EZ tool, added to the line-up). Extracts processes, command lines, network connections, injected code, services, DLLs and more from RAM.

**In Sudo-Z:** GitHub Pages: drop JSON from "vol -r json -f mem windows.<plugin>" and it is graded: hidden processes (psscan vs pslist, psxview), unexpected parents (lsass, services, svchost), duplicate singletons, Office/web server/WMI spawning shells, malicious command lines, LOLBin connections to public IPs, malfind injected PE/shellcode, code injection correlated per process (loader-listed modules with MappedPath N/A, main image mismatches, unlinked DLLs, LSASS loading DLLs from odd folders, wiped PE headers), hollowing and ghosting, suspicious threads, services, console history, rootkit drivers and syscall hooks, and named pipes from windows.handles, windows.filescan and command lines (Cobalt Strike, PsExec/RemCom, Covenant and PoshC2 default pipes, Potato/PrintSpoofer impersonation pipes, PowerShell loaded inside non-PowerShell processes via PSHost pipes, random pipes held by rundll32-type processes or user-folder programs). Home install: point it at the image and it runs the plugin set itself (sudo-z setup vol).

### Velociraptor

**Status:** Partial  
**Accepts:** Offline collector / collection .zip (uploads/ + results/*.json)  
**Website:** Collections accepted  
**Home install:** Same; run Velociraptor itself separately

Rapid7's endpoint visibility and DFIR platform: an agent/server that collects files and runs VQL artifacts across many machines, or as a standalone offline collector.

**In Sudo-Z:** Used as an input source, like KAPE. Collection zips are detected, their URL-encoded upload paths decoded so raw files ($MFT, hives, event logs...) route to the normal parsers, and VQL result JSON is graded: Hayabusa / Sigma / YARA detections become findings with their own severity, process and persistence artifacts go through the shared heuristics, remote addresses become indicators. Velociraptor itself (server, agents, VQL hunts) is not embedded.

### SrumECmd

**Status:** Implemented  
**Accepts:** SRUDB.dat  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses the System Resource Usage Monitor ESE database: per-app network bytes, CPU, energy, push notifications.

**In Sudo-Z:** Native ESE (JET Blue) reader. Decodes the ID map (apps, services, user SIDs), NetworkUsages, AppResourceUseInfo and NetworkConnections. Flags upload-heavy or very large transfers by non-browser programs, LOLBins with network traffic and network use by programs in suspicious paths (exfiltration).

### SumECmd

**Status:** Partial  
**Accepts:** SUM folder (Current.mdb, {GUID}.mdb, SystemIdentity.mdb)  
**Website:** Partial (Sudo-Z parser)  
**Home install:** Same, plus the original tool via the EZ runner (sudo-z setup ez)

Parses User Access Logging on Windows Server: which users/IPs accessed which roles per day.

**In Sudo-Z:** Opened with the native ESE reader: CLIENTS table (user, address, access counts, last access) plus a table inventory and indicator sweep. Role GUIDs are not resolved to names.

### bstrings

**Status:** Implemented  
**Accepts:** Any file  
**Website:** Yes (Sudo-Z parser)  
**Home install:** Same; the original bstrings is fetched by sudo-z setup ez

Finds ASCII and Unicode strings with built-in regex patterns (URLs, IPs, emails, paths, base64...).

**In Sudo-Z:** ASCII + UTF-16LE extraction on every unrecognised file, URL/IP/email/UNC/encoded PowerShell/wallet patterns, offensive tooling keyword rules (Mimikatz, Cobalt Strike, PowerSploit, ransom notes, shadow copy deletion, web shells).

### Hasher

**Status:** Implemented  
**Accepts:** Any file  
**Website:** Yes (Sudo-Z hashes every file)  
**Home install:** Same; the Hasher GUI is fetched by sudo-z setup ez (Windows)

Computes file hashes.

**In Sudo-Z:** MD5, SHA1 and SHA256 for every submitted and extracted file (WebCrypto + local MD5).

### iisGeolocate

**Status:** Partial  
**Accepts:** IIS W3C logs (u_ex*.log)  
**Website:** Parse + hunt (no geolocation)  
**Home install:** Same, plus the original tool via sudo-z setup ez (needs a MaxMind GeoLite2 database)

Geolocates client IPs in IIS logs with a MaxMind database and records malformed lines.

**In Sudo-Z:** Parses the logs and hunts for web shell commands, SQL injection, known Exchange/SharePoint/ProxyShell exploit paths, scanners and 404 floods. Geolocation is left to you: client IPs are listed for offline lookup.

### RLA

**Status:** Implemented  
**Accepts:** Dirty hives + .LOG / .LOG1 / .LOG2  
**Website:** Yes (Sudo-Z replays logs)  
**Home install:** Same; the original RLA is fetched by sudo-z setup ez (Windows)

Replays registry transaction logs into dirty hives.

**In Sudo-Z:** Submit a hive with its logs in the same folder and they are replayed before parsing: new format (HvLE, Windows 8.1+) with Marvin32 hash checks and sequence handling across LOG1/LOG2, and the old DIRT bitmap format. Tested byte-identical to Windows 10 recovery on msuhanov's test hives.

### EZViewer

**Status:** GUI / not applicable  
**Accepts:** Documents, text, PDF  
**Website:** No (Windows GUI)  
**Home install:** Downloaded by sudo-z setup ez (Windows); open it yourself

Standalone viewer for many document formats; unknown files open in a hex editor.

**In Sudo-Z:** Viewer, not an analyser. Sudo-Z reads Office (docx/docm/xlsx/pptx and 97-2003 doc/xls/ppt) and PDF metadata itself: created, last saved, last printed, author, application, VBA macros, remote templates, external links, PDF JavaScript and auto actions. Those embedded times are compared with the file system times (MACB). RTF, OneNote and mail are hashed and string-scanned.

### Timeline Explorer

**Status:** GUI / not applicable  
**Accepts:** CSV / XLSX  
**Website:** Replaced by built-in tables; CSV exports open in it  
**Home install:** Downloaded by sudo-z setup ez (Windows); open the exported CSVs in it

Spreadsheet-style viewer for the CSVs the other tools produce.

**In Sudo-Z:** Replaced by the built-in super timeline and table views. Every table and the timeline export to CSV that Timeline Explorer opens.

### Registry Explorer

**Status:** GUI / not applicable  
**Accepts:** Registry hives  
**Website:** No (Windows GUI); RECmd logic built in  
**Home install:** Downloaded by sudo-z setup ez (Windows)

GUI registry viewer with bookmarks and plugins.

**In Sudo-Z:** GUI. Its plugins are covered by the RECmd section above.

### MFTExplorer

**Status:** GUI / not applicable  
**Accepts:** $MFT  
**Website:** No (Windows GUI); MFTECmd logic built in  
**Home install:** Downloaded by sudo-z setup ez (Windows)

GUI for browsing $MFT.

**In Sudo-Z:** GUI. See MFTECmd.

### JumpList Explorer

**Status:** GUI / not applicable  
**Accepts:** Jump lists  
**Website:** No (Windows GUI); JLECmd logic built in  
**Home install:** Downloaded by sudo-z setup ez (Windows)

GUI for Jump Lists.

**In Sudo-Z:** GUI. See JLECmd.

### ShellBags Explorer

**Status:** GUI / not applicable  
**Accepts:** NTUSER.DAT / UsrClass.dat  
**Website:** No (Windows GUI); SBECmd logic built in  
**Home install:** Downloaded by sudo-z setup ez (Windows)

GUI for ShellBags.

**In Sudo-Z:** GUI. See SBECmd.

### SDB Explorer

**Status:** Strings only  
**Accepts:** *.sdb shim databases  
**Website:** Flag + strings only  
**Home install:** Downloaded by sudo-z setup ez (Windows) for full shim inspection

GUI for application compatibility shim databases.

**In Sudo-Z:** Custom .sdb files are flagged (shim persistence, T1546.011) and string-scanned for target executables and DLLs.

### VSCMount

**Status:** GUI / not applicable  
**Accepts:** Live volume  
**Website:** No (needs a live volume)  
**Home install:** Downloaded by sudo-z setup ez; run as admin on the live Windows host

Mounts every Volume Shadow Copy to a folder.

**In Sudo-Z:** Needs a live Windows volume. Mount shadow copies on Windows, collect the artifacts with KAPE and submit the zip.

### KAPE

**Status:** GUI / not applicable  
**Accepts:** Live system / image  
**Website:** KAPE output zips accepted  
**Home install:** Not redistributable: get it from Kroll, then point the EZ runner or Sudo-Z at its output

Triage collection (Targets) and processing (Modules) framework that drives the tools above.

**In Sudo-Z:** Sudo-Z is built to take a KAPE Targets zip (e.g. !SANS_Triage / KapeTriage output) and run every applicable parser on it in the browser.

### Get-ZimmermanTools

**Status:** GUI / not applicable  
**Accepts:** -  
**Website:** Not applicable  
**Home install:** Used by sudo-z setup ez to fetch every tool

PowerShell script that downloads and updates all the tools.

**In Sudo-Z:** Not applicable.

### TimeApp

**Status:** GUI / not applicable  
**Accepts:** -  
**Website:** Not applicable  
**Home install:** Not needed

Clock, stopwatch and timestamp converter.

**In Sudo-Z:** Not applicable; all times in Sudo-Z are UTC ISO-8601 with 100ns precision.

### XWFIM

**Status:** GUI / not applicable  
**Accepts:** -  
**Website:** Not applicable  
**Home install:** Not needed

X-Ways Forensics installation manager.

**In Sudo-Z:** Not applicable.

## What cannot be accepted

| Input | What happens |
|---|---|
| Memory images (raw, .mem, .vmem, crash dumps, hiberfil, LiME) | Volatility 3 cannot run in a browser. Home install: run sudo-z setup vol, then give the image path in the LOCAL ENGINE panel. On the website: drop the JSON from "vol -r json" instead. |
| Registry transaction logs (.LOG1 / .LOG2) or SQLite -wal on their own | Submit them in the same folder as their hive / database and they are replayed / merged automatically. Alone they are string-scanned only. |
| Disk images in VMDK, VDI, AFF4 or DMG, differencing VHD/VHDX, BitLocker volumes, non-NTFS file systems | E01, VHD, VHDX, raw/dd, split raw and QCOW2 with NTFS are triaged directly (see Disk images). For the rest, convert to raw (`qemu-img convert -O raw`), unlock BitLocker first, or collect with KAPE. |
| Encrypted / password-protected zip entries, RAR, 7z, tar | Only standard and ZIP64 zips with stored/deflate entries are opened. Re-zip without a password. |
| Executables and DLLs (PE files) | Not an EZ tool input. They are hashed and string-scanned; submit hashes to your sandbox / threat intel. |
| $LogFile, $SDS | Accepted by MFTECmd on Windows (home install: EZ runner); Sudo-Z only string-scans them for now. |

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
js/parsers/             evtx, prefetch, lnk, shellitems, jumplist, regf, reglog (RLA), ntfs, sqlite, ese, legacy (.evt, .job, $I30, WAL), misc
js/tools/               tool level logic: evtx rules, registry plugins, artifacts, ese (SRUM / WebCache), volatility, velociraptor
js/image/               disk images: lazy sources, E01/VHD/VHDX/QCOW2 containers, MBR/GPT, NTFS reader, KAPE-style targets
js/grid.js              Timeline Explorer style grid (virtual scrolling, filters, grouping, tags)
js/ioc/                 shared heuristics, indicator extraction, analysis context,
                        process baseline (baseline.js), leads (leads.js), next-step playbook (playbook.js)
cli/sudo-z.mjs          headless runner
install.ps1 / install.sh  installers and updaters
tools/server.py         home install companion server (console, Volatility 3, EZ tool runner, KAPE jobs, image reads by path)
tools/                  launchers (launch.ps1, sudo-z.sh) and a fallback web server (serve.mjs)
.github/workflows/      CI checks and installer tests on Windows and Linux
```

No dependencies, no build step, no network calls with your data.

## Validation

I tested the parsers against public sample corpora rather than synthetic files: the plaso project test data [2] (event logs, Prefetch v17 to v31 including MAM compressed files, LNKs, jump lists, SYSTEM / SOFTWARE / NTUSER / Amcache hives, $MFT, USN journal, Recycle Bin, Chrome, Firefox, ActivitiesCache, IIS logs) and attack-scenario event logs from EVTX-ATTACK-SAMPLES [3]. Every sample parsed with zero record errors, and the attack logs produced the expected detections (log clearing, Squiblydoo, rundll32 and mshta proxy execution, pass-the-hash logons, svcctl lateral movement, malicious services, Defender hits, LSASS dumping via PowerShell).

Transaction log replay was checked against msuhanov's dirty test hives [5]: new-format replay is byte-identical to Windows 10's own recovery, and old-format replay matches apart from a hive bin timestamp Windows rewrites. The ESE reader was tested on the plaso SRUDB.dat, WebCacheV01.dat and Windows.edb samples, and the Volatility 3 module against output in the exact column layout of Volatility 3.28's plugins, with the local runner driving a real Volatility 3.28.3 install.

### Checked against the original tools

Every pull request and push to `main` runs the real-tools workflow. A Windows runner installs Sudo-Z with `-Full` (private .NET 10, all EZ tools, Volatility 3), runs the original tools through the Sudo-Z runner on public sample evidence laid out like a KAPE collection, and compares their output with Sudo-Z's own parsers. Latest results:

| Original tool | Compared | Result |
|---|---|---|
| EvtxECmd | records per log (4 logs, 5,136 records) | identical |
| PECmd | run count per Prefetch file (8 files) | identical |
| AppCompatCacheParser | ShimCache entries | 330 = 330 |
| AmcacheParser | SHA1s | 1,102 = 1,102, all in common |
| MFTECmd | file records | 13,060 = 13,060 |
| RBCmd, JLECmd, SBECmd, WxTCmd, SrumECmd | rows per artifact | identical |
| LECmd | resolved target per shortcut | identical |

All 13 EZ tools the runner uses completed on Windows. On Linux 11 of 13 ran under .NET 10; SrumECmd and SumECmd stop with "Non-Windows platforms not supported" because they need Windows ESE libraries, which is where Sudo-Z's own ESE parser earns its keep. Volatility 3 (2.28.2 from pip) was checked to contain every plugin the runner uses on both platforms.

## Limits

* Findings are heuristics. Treat them as leads and confirm anything that matters with the original tools (the home install can run them for you).
* Browser memory caps practical input size around 1.5 GB per file. Disk images are the exception: they are read in place and only the triage files are loaded (up to 3 GB in total). Memory images go through the home install instead.
* Not decoded yet: $LogFile, $SDS, deleted SQLite records, ESE dirty-shutdown log replay (esentutl /r), SRUM tables beyond network, app and connection usage.
* iisGeolocate's geolocation needs a MaxMind database, so Sudo-Z lists client IPs for offline lookup instead.

## Credits

All credit for the original tools and the research behind them goes to Eric Zimmerman [1]. Volatility 3 is by the Volatility Foundation [6] and Velociraptor by Rapid7 [4]. The registry log replay follows Maxim Suhanov's format specification [5]. KAPE is by Kroll [7]. Disk image test images come from the dfvfs project [8]. Sample data from the plaso project [2], EVTX-ATTACK-SAMPLES by Samir Bousseaden [3] and msuhanov's yarp test hives [5] was used for testing only and is not shipped.

[1] https://ericzimmerman.github.io/
[2] https://github.com/log2timeline/plaso/tree/main/test_data
[3] https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
[4] https://www.rapid7.com/products/velociraptor/
[5] https://github.com/msuhanov/regf
[6] https://github.com/volatilityfoundation/volatility3
[7] https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape
[8] https://github.com/log2timeline/dfvfs/tree/main/test_data
