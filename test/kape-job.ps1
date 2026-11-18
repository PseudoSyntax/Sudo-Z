# End-to-end check of the KAPE background job on a Windows runner (admin).
# KAPE itself cannot be downloaded in CI (Kroll registration), so a stand-in
# kape.exe is compiled that copies event logs the way a target would. What is
# tested is everything around it: VHDX read-only mount, drive letter discovery,
# the generated job script, log tailing, results listing, dismount, and that
# the collection parses.
$ErrorActionPreference = 'Stop'
$t = Join-Path $env:RUNNER_TEMP 'kapetest'; New-Item -ItemType Directory -Force -Path $t | Out-Null

# 1. stand-in kape.exe
$cs = @'
using System; using System.IO;
class K { static int Main(string[] a) {
  string s = null, d = null;
  for (int i = 0; i < a.Length - 1; i++) { if (a[i] == "--tsource") s = a[i + 1]; if (a[i] == "--tdest") d = a[i + 1]; }
  Console.WriteLine("stand-in KAPE " + string.Join(" ", a));
  if (s == null || d == null) return 2;
  string root = s.EndsWith(":") ? s + "\\" : s; int n = 0;
  foreach (var f in Directory.EnumerateFiles(Path.Combine(root, "Windows\\System32\\winevt\\Logs"), "*.evtx")) {
    var rel = f.Substring(root.Length).TrimStart('\\'); var o = Path.Combine(d, s.Substring(0, 1), rel);
    Directory.CreateDirectory(Path.GetDirectoryName(o)); File.Copy(f, o, true); n++; Console.WriteLine("Copied " + rel);
  }
  Console.WriteLine("Found " + n + " files"); return 0; } }
'@
Set-Content (Join-Path $t 'k.cs') $cs
$csc = Get-ChildItem "$env:WINDIR\Microsoft.NET\Framework64" -Recurse -Filter csc.exe | Sort-Object FullName -Descending | Select-Object -First 1
New-Item -ItemType Directory -Force -Path (Join-Path $t 'kape') | Out-Null
$exe = Join-Path $t 'kape\kape.exe'
& $csc.FullName /nologo "/out:$exe" (Join-Path $t 'k.cs')
if (-not (Test-Path (Join-Path $t 'kape\kape.exe'))) { throw 'stand-in kape.exe did not build' }

# 2. a small NTFS VHDX holding an exported event log
$vhd = Join-Path $t 'case.vhdx'
@"
create vdisk file="$vhd" maximum=64 type=expandable
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=CASE
assign letter=T
"@ | Set-Content (Join-Path $t 'dp1.txt') -Encoding ascii
diskpart /s (Join-Path $t 'dp1.txt') | Out-Host
New-Item -ItemType Directory -Force -Path 'T:\Windows\System32\winevt\Logs' | Out-Null
wevtutil epl System 'T:\Windows\System32\winevt\Logs\System.evtx'
@"
select vdisk file="$vhd"
detach vdisk
"@ | Set-Content (Join-Path $t 'dp2.txt') -Encoding ascii
diskpart /s (Join-Path $t 'dp2.txt') | Out-Host

# 3. run the job through the server
$env:SUDOZ_KAPE = Join-Path $t 'kape\kape.exe'
$srv = Start-Process python -ArgumentList 'tools/server.py', '8794', '--no-browser' -PassThru -WindowStyle Hidden
Start-Sleep 4
$h = @{ 'X-Sudo-Z' = '1' }
$caps = Invoke-RestMethod -Headers $h http://localhost:8794/api/caps
if (-not $caps.kape.available) { throw 'server did not find the stand-in kape.exe' }
Write-Host "kape caps: available=$($caps.kape.available) admin=$($caps.kape.admin)"
$job = Invoke-RestMethod -Headers $h -Method Post -ContentType 'application/json' -Body (@{ source = $vhd; target = '!SANS_Triage' } | ConvertTo-Json) http://localhost:8794/api/kape/run
$deadline = (Get-Date).AddMinutes(5)
do { Start-Sleep 2; $j = Invoke-RestMethod -Headers $h "http://localhost:8794/api/job/$($job.id)" } while ($j.status -eq 'running' -and (Get-Date) -lt $deadline)
$j.log | ForEach-Object { Write-Host "  | $_" }
if ($j.status -ne 'done') { throw "KAPE job ended as $($j.status): $($j.error)" }
if (-not ($j.results | Where-Object { $_.file -like '*System.evtx' })) { throw 'System.evtx was not collected' }
if (Get-DiskImage -ImagePath $vhd | Where-Object Attached) { throw 'image was left mounted' }
Write-Host "collected: $($j.results.file -join ', ')"

# 4. the collection parses
node cli/sudo-z.mjs (Join-Path $j.dir 'tout') -o (Join-Path $t 'out')
if (-not (Select-String -Path (Join-Path $t 'out\report.md') -Pattern '\| parsed \| EvtxECmd' -Quiet)) { throw 'collected event log was not parsed' }
Stop-Process -Id $srv.Id -Force
Write-Host 'KAPE job test passed'
