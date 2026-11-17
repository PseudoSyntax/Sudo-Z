<#
  Sudo-Z installer and updater for Windows.

  Install or update (same command):
    irm https://raw.githubusercontent.com/PseudoSyntax/Sudo-Z/main/install.ps1 | iex

  Then run:  sudo-z            start the console in your browser
             sudo-z update     pull the latest version from GitHub
             sudo-z version    show the installed commit
             sudo-z uninstall  remove Sudo-Z

  Each update downloads the newest commit, checks it, swaps it in and deletes
  the old copy. Nothing outside the install folder is touched apart from your
  user PATH (one entry) and an optional Start Menu shortcut.
#>
param(
  [string]$Dir = "$env:LOCALAPPDATA\Sudo-Z",
  [string]$Branch = "main",
  [string]$Repo = "PseudoSyntax/Sudo-Z",
  [switch]$Force,
  [switch]$NoShortcut,
  [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

function Say($msg, $color = 'Gray') { if (-not $Quiet) { Write-Host $msg -ForegroundColor $color } }

$App      = Join-Path $Dir 'app'
$VerFile  = Join-Path $Dir 'version.txt'

function Get-LatestSha([string]$Repo, [string]$Branch, [int]$Timeout = 30) {
  # 1) GitHub API (uses GITHUB_TOKEN if set)  2) git ref advertisement, which is not API rate limited
  $h = @{ 'User-Agent' = 'sudo-z' }
  if ($env:GITHUB_TOKEN) { $h['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
  try { $s = (Invoke-RestMethod "https://api.github.com/repos/$Repo/commits/$Branch" -Headers $h -TimeoutSec $Timeout).sha; if ($s -match '^[0-9a-f]{40}$') { return $s } } catch { }
  try {
    $r = Invoke-WebRequest "https://github.com/$Repo.git/info/refs?service=git-upload-pack" -UseBasicParsing -UserAgent 'git/2.40' -TimeoutSec $Timeout
    $txt = if ($r.Content -is [byte[]]) { [Text.Encoding]::ASCII.GetString($r.Content) } else { [string]$r.Content }
    $m = [regex]::Match($txt, "([0-9a-f]{40}) refs/heads/$([regex]::Escape($Branch))(?![\w/.-])")
    if ($m.Success) { return $m.Groups[1].Value }
  } catch { }
  return $null
}

Say "[sudo-z] checking $Repo@$Branch" 'DarkYellow'
$latest = Get-LatestSha $Repo $Branch 30
if (-not $latest) { throw 'Could not reach GitHub to find the latest version (check your connection or proxy).' }
$current = if (Test-Path $VerFile) { (Get-Content $VerFile -Raw).Trim() } else { '' }

if (-not $Force -and $current -eq $latest -and (Test-Path (Join-Path $App 'index.html'))) {
  Say "[sudo-z] already up to date ($($latest.Substring(0,7)))" 'Green'
} else {
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("sudo-z-" + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $zip = Join-Path $tmp 'src.zip'
    Say "[sudo-z] downloading $($latest.Substring(0,7))"
    Invoke-WebRequest "https://codeload.github.com/$Repo/zip/$latest" -OutFile $zip -UseBasicParsing -TimeoutSec 300
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    $src = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
    if (-not $src -or -not (Test-Path (Join-Path $src.FullName 'index.html')) -or -not (Test-Path (Join-Path $src.FullName 'js\engine.js'))) {
      throw 'Downloaded archive does not look like Sudo-Z (index.html or js\engine.js missing). Old version left in place.'
    }
    # swap: old -> app.old, new -> app, then delete old
    $old = "$App.old"
    if (Test-Path $old) { Remove-Item $old -Recurse -Force }
    if (Test-Path $App) { Rename-Item $App $old }
    try { Move-Item $src.FullName $App }
    catch { if (Test-Path $old) { Rename-Item $old $App }; throw }
    if (Test-Path $old) { Remove-Item $old -Recurse -Force -ErrorAction SilentlyContinue }
    Set-Content -Path $VerFile -Value $latest -NoNewline
    if ($current) { Say "[sudo-z] updated $($current.Substring(0,7)) -> $($latest.Substring(0,7))" 'Green' }
    else { Say "[sudo-z] installed $($latest.Substring(0,7)) to $App" 'Green' }
  } finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# launcher on PATH
$cmd = Join-Path $Dir 'sudo-z.cmd'
Set-Content -Path $cmd -Encoding ASCII -Value "@echo off`r`npowershell -NoProfile -ExecutionPolicy Bypass -File `"%~dp0app\tools\launch.ps1`" -Dir `"%~dp0.`" %*`r`n"
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not (($userPath -split ';') -contains $Dir)) {
  [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ";$Dir").TrimStart(';'), 'User')
  Say "[sudo-z] added $Dir to your PATH (open a new terminal to use 'sudo-z')"
}
if (-not (($env:Path -split ';') -contains $Dir)) { $env:Path = "$env:Path;$Dir" }

if (-not $NoShortcut) {
  try {
    $lnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'Sudo-Z.lnk'
    $ws = New-Object -ComObject WScript.Shell
    $s = $ws.CreateShortcut($lnk)
    $s.TargetPath = $cmd; $s.WorkingDirectory = $Dir; $s.Description = 'Sudo-Z DFIR triage console'
    $s.Save()
  } catch { }
}

Say ""
Say "  Start:   sudo-z            (or Start Menu > Sudo-Z)" 'White'
Say "  Update:  sudo-z update" 'White'
Say ""
