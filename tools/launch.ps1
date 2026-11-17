<#
  Sudo-Z launcher for Windows (installed as 'sudo-z').
    sudo-z [start] [-Port 8765] [-NoBrowser]   serve the console on localhost and open it
    sudo-z update                              pull the latest version from GitHub
    sudo-z version                             show installed commit and check for updates
    sudo-z cli <args>                          run the headless analyser (needs Node 18+)
    sudo-z uninstall                           remove Sudo-Z
  The console uses ES modules and a Web Worker, which browsers block on file://,
  so it is served from a tiny local web server bound to localhost only.
#>
param(
  [Parameter(Position = 0)][string]$Command = 'start',
  [int]$Port = 8765,
  [switch]$NoBrowser,
  [string]$Dir = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
  [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)
$ErrorActionPreference = 'Stop'
$Repo = 'PseudoSyntax/Sudo-Z'
$App = Join-Path $Dir 'app'
$VerFile = Join-Path $Dir 'version.txt'
$installed = if (Test-Path $VerFile) { (Get-Content $VerFile -Raw).Trim() } else { 'unknown' }

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
function Get-Latest { Get-LatestSha $Repo 'main' 4 }

switch ($Command.ToLower()) {
  'update' {
    # run a copy so the installer can replace the folder it lives in
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "sudo-z-install-$PID.ps1"
    Copy-Item (Join-Path $App 'install.ps1') $tmp -Force
    try { & powershell -NoProfile -ExecutionPolicy Bypass -File $tmp -Dir $Dir -NoShortcut @Rest } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
    return
  }
  'version' {
    $l = Get-Latest
    Write-Host "installed $($installed.Substring(0, [Math]::Min(7, $installed.Length)))  in $App"
    if ($l -and $l -ne $installed) { Write-Host "update available: $($l.Substring(0,7))  (run: sudo-z update)" -ForegroundColor Yellow }
    elseif ($l) { Write-Host 'up to date' -ForegroundColor Green }
    return
  }
  'cli' {
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'The headless analyser needs Node.js 18 or newer (https://nodejs.org).' }
    & node (Join-Path $App 'cli\sudo-z.mjs') @Rest
    return
  }
  'uninstall' {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    [Environment]::SetEnvironmentVariable('Path', (($userPath -split ';') | Where-Object { $_ -and $_ -ne $Dir }) -join ';', 'User')
    Remove-Item (Join-Path ([Environment]::GetFolderPath('Programs')) 'Sudo-Z.lnk') -ErrorAction SilentlyContinue
    Write-Host "Removing $Dir"
    Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile -Command Start-Sleep 2; Remove-Item -Recurse -Force '$Dir'"
    return
  }
}

# ---------------------------------------------------------------- start: local static server
$latest = Get-Latest
if ($latest -and $installed -ne $latest) { Write-Host "[sudo-z] update available ($($latest.Substring(0,7))). Run: sudo-z update" -ForegroundColor Yellow }

$mime = @{
  '.html' = 'text/html; charset=utf-8'; '.js' = 'text/javascript; charset=utf-8'; '.mjs' = 'text/javascript; charset=utf-8'
  '.css' = 'text/css; charset=utf-8'; '.json' = 'application/json'; '.svg' = 'image/svg+xml'; '.png' = 'image/png'
  '.ico' = 'image/x-icon'; '.md' = 'text/markdown; charset=utf-8'; '.txt' = 'text/plain; charset=utf-8'
}
$root = [IO.Path]::GetFullPath($App)
$listener = $null
for ($p = $Port; $p -lt $Port + 20; $p++) {
  try {
    $l = New-Object Net.HttpListener
    $l.Prefixes.Add("http://localhost:$p/")
    $l.Start(); $listener = $l; $Port = $p; break
  } catch { }
}
if (-not $listener) { throw "No free port between $Port and $($Port + 19)." }
$url = "http://localhost:$Port/"
Write-Host "[sudo-z] serving $root"
Write-Host "[sudo-z] open $url   (Ctrl+C to stop)" -ForegroundColor Green
if (-not $NoBrowser) { Start-Process $url }
try {
  while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    $res = $ctx.Response
    try {
      $rel = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath).TrimStart('/')
      if (-not $rel) { $rel = 'index.html' }
      $full = [IO.Path]::GetFullPath((Join-Path $root $rel))
      if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path $full -PathType Leaf)) {
        $res.StatusCode = 404; $b = [Text.Encoding]::UTF8.GetBytes('not found')
      } else {
        $ext = [IO.Path]::GetExtension($full).ToLower()
        $res.ContentType = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' }
        $res.Headers.Add('Cache-Control', 'no-cache')
        $b = [IO.File]::ReadAllBytes($full)
      }
      $res.ContentLength64 = $b.Length
      $res.OutputStream.Write($b, 0, $b.Length)
    } catch { } finally { $res.Close() }
  }
} finally { $listener.Stop() }
