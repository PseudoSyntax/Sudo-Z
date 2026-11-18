<#
  Sudo-Z requirements (Windows). Everything installs inside the Sudo-Z folder;
  no admin rights, nothing system-wide.

    sudo-z setup            all of the below
    sudo-z setup dotnet     private .NET 10 runtime (+ Windows Desktop runtime for the GUI tools)
    sudo-z setup ez         original Eric Zimmerman tools (Eric's Get-ZimmermanTools, .NET 10 builds); implies dotnet
    sudo-z setup vol        Python venv + Volatility 3 (bootstraps Python with uv if none is installed)
    sudo-z setup status     show what is installed
#>
param([string]$What = 'all', [string]$Dir = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent))
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
$What = $What.ToLower()
function Say($m, $c = 'Gray') { Write-Host "[sudo-z] $m" -ForegroundColor $c }

$dotnetDir = Join-Path $Dir 'dotnet'
$ezDir = Join-Path $Dir 'ez'
$venv = Join-Path $Dir 'venv'

function Test-Runtime([string]$dotnet, [string]$name) {
  if (-not $dotnet) { return $false }
  $exists = (Test-Path $dotnet -PathType Leaf -ErrorAction SilentlyContinue) -or [bool](Get-Command $dotnet -CommandType Application -ErrorAction SilentlyContinue)
  if (-not $exists) { return $false }
  try { return ((& $dotnet --list-runtimes 2>$null) -join "`n") -match "Microsoft\.$name\.App 10\." } catch { return $false }
}

function Install-DotNet {
  $private = Join-Path $dotnetDir 'dotnet.exe'
  $haveCore = (Test-Runtime $private 'NETCore') -or (Test-Runtime 'dotnet' 'NETCore')
  $haveDesk = (Test-Runtime $private 'WindowsDesktop') -or (Test-Runtime 'dotnet' 'WindowsDesktop')
  if ($haveCore -and $haveDesk) { Say '.NET 10 runtimes already present' 'Green'; return }
  $script = Join-Path ([IO.Path]::GetTempPath()) 'dotnet-install.ps1'
  Say 'downloading Microsoft dotnet-install script'
  Invoke-WebRequest 'https://dot.net/v1/dotnet-install.ps1' -OutFile $script -UseBasicParsing
  foreach ($rt in @(@('dotnet', $haveCore), @('windowsdesktop', $haveDesk))) {
    if ($rt[1]) { continue }
    Say "installing .NET 10 runtime ($($rt[0])) to $dotnetDir"
    & $script -Channel 10.0 -Runtime $rt[0] -InstallDir $dotnetDir -NoPath | Out-Host
  }
  if (Test-Runtime $private 'NETCore') { Say '.NET 10 ready (private copy, used only by Sudo-Z)' 'Green' } else { throw '.NET 10 runtime install failed' }
}

function Install-EZ {
  Install-DotNet
  New-Item -ItemType Directory -Force -Path $ezDir | Out-Null
  $gzt = Join-Path $ezDir 'Get-ZimmermanTools.ps1'
  Say "downloading the original Eric Zimmerman tools to $ezDir (Eric's Get-ZimmermanTools, .NET 10 builds)"
  Invoke-WebRequest 'https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1' -OutFile $gzt -UseBasicParsing
  & powershell -NoProfile -ExecutionPolicy Bypass -File $gzt -Dest $ezDir -NetVersion 10 -NoUpdate | Out-Host
  $n = @(Get-ChildItem $ezDir -Recurse -Filter '*.exe' -ErrorAction SilentlyContinue).Count
  if ($n -eq 0) { throw 'no EZ tools were downloaded' }
  Say "$n EZ tool executables installed" 'Green'
}

function Find-SystemPython {
  foreach ($c in @(@('py', '-3'), @('python'), @('python3'))) {
    if (-not (Get-Command $c[0] -ErrorAction SilentlyContinue)) { continue }
    try { $o = & $c[0] @($c[1..($c.Length)] | Where-Object { $_ }) -c 'import sys; print(sys.version_info >= (3, 8))' 2>$null; if ("$o".Trim() -eq 'True') { return ,@($c) } } catch { }
  }
  return $null
}

function Install-Vol {
  $vpy = Join-Path $venv 'Scripts\python.exe'
  if (-not (Test-Path $vpy)) {
    $py = Find-SystemPython
    if ($py) {
      Say "creating $venv with $($py -join ' ')"
      & $py[0] @($py[1..($py.Length)] | Where-Object { $_ }) -m venv $venv
    } else {
      # No Python: bootstrap a private one with uv (single binary from GitHub releases)
      $uvDir = Join-Path $Dir 'uv'; New-Item -ItemType Directory -Force -Path $uvDir | Out-Null
      $zip = Join-Path $uvDir 'uv.zip'
      Say 'no Python found: downloading uv to install a private Python 3.12'
      Invoke-WebRequest 'https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip' -OutFile $zip -UseBasicParsing
      Expand-Archive $zip -DestinationPath $uvDir -Force; Remove-Item $zip
      $env:UV_PYTHON_INSTALL_DIR = Join-Path $Dir 'python'
      & (Join-Path $uvDir 'uv.exe') venv --python 3.12 --seed $venv | Out-Host
    }
  }
  if (-not (Test-Path $vpy)) { throw "could not create $venv" }
  Say 'installing Volatility 3 into the venv'
  & $vpy -m pip install -q -U pip 2>$null
  & $vpy -m pip install -U 'volatility3[full]'
  if ($LASTEXITCODE -ne 0) {
    Say 'full extras failed to build; installing core Volatility 3 and the extras one by one' 'Yellow'
    & $vpy -m pip install -U volatility3
    foreach ($x in 'capstone', 'pycryptodome', 'yara-python') { & $vpy -m pip install -q $x; if ($LASTEXITCODE -ne 0) { Say "optional extra $x unavailable on this Python (some plugins lose features)" 'Yellow' } }
  }
  $vol = Join-Path $venv 'Scripts\vol.exe'
  if (Test-Path $vol) { Say "Volatility 3 ready ($((& $vol -h 2>&1 | Select-String 'Framework [0-9.]+').Matches.Value))" 'Green' } else { throw 'Volatility 3 install failed' }
}

function Find-Kape {
  $c = @($env:SUDOZ_KAPE, (Join-Path $Dir 'kape\kape.exe'), 'C:\KAPE\kape.exe', 'C:\Tools\KAPE\kape.exe', "$env:USERPROFILE\Downloads\KAPE\kape.exe") | Where-Object { $_ -and (Test-Path $_) }
  if ($c) { return $c[0] }
  $k = Get-ChildItem (Join-Path $Dir 'kape') -Recurse -Filter 'kape.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($k) { return $k.FullName }
  return $null
}
function Install-Kape {
  # KAPE is free but licensed by Kroll behind a registration form, so it cannot be downloaded silently.
  $k = Find-Kape
  if (-not $k) {
    $dest = Join-Path $Dir 'kape'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Say "KAPE not found. Opening the Kroll download page. Unzip the KAPE folder into $dest (so $dest\kape.exe exists) or C:\KAPE, then run: sudo-z setup kape" Yellow
    Start-Process 'https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape'
    return
  }
  Say "KAPE found: $k" Green
  Say 'updating KAPE targets and modules from GitHub (kape --sync)'
  Push-Location (Split-Path $k); try { & $k --sync | Out-Host } finally { Pop-Location }
}

function Show-Status {
  $private = Join-Path $dotnetDir 'dotnet.exe'
  $core = (Test-Runtime $private 'NETCore') -or (Test-Runtime 'dotnet' 'NETCore')
  $ez = @(Get-ChildItem $ezDir -Recurse -Filter '*.exe' -ErrorAction SilentlyContinue).Count
  $vol = Test-Path (Join-Path $venv 'Scripts\vol.exe')
  Write-Host ("  .NET 10 runtime : {0}" -f $(if ($core) { 'yes' } else { 'no  (sudo-z setup dotnet)' }))
  Write-Host ("  EZ tools        : {0}" -f $(if ($ez) { "$ez executables in $ezDir" } else { 'no  (sudo-z setup ez)' }))
  Write-Host ("  Volatility 3    : {0}" -f $(if ($vol) { 'yes' } else { 'no  (sudo-z setup vol)' }))
  $k = Find-Kape
  Write-Host ("  KAPE            : {0}" -f $(if ($k) { $k } else { 'no  (sudo-z setup kape)' }))
}

switch ($What) {
  'dotnet' { Install-DotNet }
  'ez' { Install-EZ }
  'vol' { Install-Vol }
  'kape' { Install-Kape }
  'status' { Show-Status }
  'all' {
    $failed = @()
    try { Install-EZ } catch { $failed += "EZ tools: $($_.Exception.Message)" }
    try { Install-Vol } catch { $failed += "Volatility 3: $($_.Exception.Message)" }
    Show-Status
    if ($failed) { $failed | ForEach-Object { Say $_ 'Red' }; exit 1 }
  }
  default { throw "unknown setup target '$What' (use all, dotnet, ez, vol, status)" }
}
