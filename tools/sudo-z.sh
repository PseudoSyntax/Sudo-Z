#!/usr/bin/env bash
# Sudo-Z launcher for Linux/macOS (installed as 'sudo-z').
#   sudo-z [start] [port]   serve the console on localhost and open it
#   sudo-z update           pull the latest version from GitHub
#   sudo-z version          show installed commit and check for updates
#   sudo-z cli <args>       run the headless analyser (needs Node 18+)
#   sudo-z setup [vol|ez]   install home-only extras: Volatility 3 (memory) and the original EZ tools
#   sudo-z uninstall        remove Sudo-Z
set -euo pipefail
APP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$(dirname "$APP")"
REPO="PseudoSyntax/Sudo-Z"
INSTALLED="$(cat "$DIR/version.txt" 2>/dev/null || echo unknown)"

latest() {
  local s b="${SUDOZ_BRANCH:-main}"
  s="$(curl -fsS -m 4 -H 'User-Agent: sudo-z' -H 'Accept: application/vnd.github.sha' "https://api.github.com/repos/$REPO/commits/$b" 2>/dev/null | tr -d '[:space:]')" || true
  printf '%s' "$s" | grep -qE '^[0-9a-f]{40}$' || s="$(curl -fsS -m 4 -A 'git/2.40' "https://github.com/$REPO.git/info/refs?service=git-upload-pack" 2>/dev/null | grep -aoE "[0-9a-f]{40} refs/heads/$b" | head -n1 | cut -c1-40)" || true
  printf '%s' "$s" | grep -qE '^[0-9a-f]{40}$' && printf '%s' "$s" || true
}

cmd="${1:-start}"; shift || true
case "$cmd" in
  update)
    tmp="$(mktemp)"; cp "$APP/install.sh" "$tmp"
    SUDOZ_DIR="$DIR" bash "$tmp" "$@"; rm -f "$tmp"; exit ;;
  version)
    l="$(latest)"; echo "installed ${INSTALLED:0:7} in $APP"
    if [ -n "$l" ] && [ "$l" != "$INSTALLED" ]; then echo "update available: ${l:0:7} (run: sudo-z update)"; elif [ -n "$l" ]; then echo "up to date"; fi
    exit ;;
  cli)
    command -v node >/dev/null || { echo "The headless analyser needs Node.js 18 or newer." >&2; exit 1; }
    exec node "$APP/cli/sudo-z.mjs" "$@" ;;
  setup)
    what="${1:-all}"
    if [ "$what" = all ] || [ "$what" = vol ]; then
      command -v python3 >/dev/null || { echo "Volatility 3 needs Python 3.8+ (install python3 first)." >&2; exit 1; }
      echo "[sudo-z] creating $DIR/venv and installing Volatility 3"
      python3 -m venv "$DIR/venv" || { echo "python3 -m venv failed (on Debian/Ubuntu: sudo apt install python3-venv)" >&2; exit 1; }
      "$DIR/venv/bin/pip" install -q -U pip >/dev/null 2>&1 || true
      "$DIR/venv/bin/pip" install -U "volatility3[full]" || "$DIR/venv/bin/pip" install -U volatility3
      "$DIR/venv/bin/vol" -h >/dev/null 2>&1 && echo "[sudo-z] Volatility 3 ready: $("$DIR/venv/bin/vol" -h 2>&1 | grep -oE 'Framework [0-9.]+')"
    fi
    if [ "$what" = all ] || [ "$what" = ez ]; then
      if command -v pwsh >/dev/null && command -v dotnet >/dev/null; then
        mkdir -p "$DIR/ez"
        curl -fsSL -o "$DIR/ez/Get-ZimmermanTools.ps1" https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1
        pwsh -NoProfile -File "$DIR/ez/Get-ZimmermanTools.ps1" -Dest "$DIR/ez" -NetVersion 10
        dotnet --list-runtimes | grep -q "Microsoft.NETCore.App 10\." || echo "[sudo-z] note: the EZ tools need the .NET 10 runtime (https://dotnet.microsoft.com/download)"
      else
        echo "[sudo-z] The original EZ tools are .NET programs built for Windows. On Linux/macOS they need PowerShell (pwsh) and the .NET 10 runtime;"
        echo "         install both, then run: sudo-z setup ez   (Sudo-Z's own parsers work without them)."
      fi
    fi
    exit ;;
  uninstall)
    rm -rf "$DIR"; rm -f "${SUDOZ_BIN:-$HOME/.local/bin}/sudo-z"; echo "removed $DIR"; exit ;;
  start|[0-9]*) ;;
  *) echo "unknown command: $cmd (use start, update, version, setup, cli, uninstall)" >&2; exit 1 ;;
esac

PORT="${1:-8765}"; [ "$cmd" != start ] && PORT="$cmd"
l="$(latest)"; if [ -n "$l" ] && [ "$l" != "$INSTALLED" ]; then echo "[sudo-z] update available (${l:0:7}). Run: sudo-z update"; fi
URL="http://localhost:$PORT/"
echo "[sudo-z] serving $APP"
echo "[sudo-z] open $URL   (Ctrl+C to stop)"
PY=""
[ -x "$DIR/venv/bin/python" ] && PY="$DIR/venv/bin/python"
[ -z "$PY" ] && command -v python3 >/dev/null && PY="$(command -v python3)"
if [ -n "$PY" ]; then exec "$PY" "$APP/tools/server.py" "$PORT" ${SUDOZ_NO_BROWSER:+--no-browser}
elif command -v node >/dev/null; then
  echo "[sudo-z] python3 not found: serving the console only (memory analysis and EZ tool runner need Python)"
  ( sleep 1; { command -v xdg-open >/dev/null && xdg-open "$URL"; } || { command -v open >/dev/null && open "$URL"; } || true ) >/dev/null 2>&1 &
  exec node "$APP/tools/serve.mjs" "$PORT"
else echo "Need python3 (or node) to serve the console locally, or use the hosted site: https://pseudosyntax.github.io/Sudo-Z/" >&2; exit 1; fi
