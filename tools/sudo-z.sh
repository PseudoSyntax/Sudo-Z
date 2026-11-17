#!/usr/bin/env bash
# Sudo-Z launcher for Linux/macOS (installed as 'sudo-z').
#   sudo-z [start] [port]   serve the console on localhost and open it
#   sudo-z update           pull the latest version from GitHub
#   sudo-z version          show installed commit and check for updates
#   sudo-z cli <args>       run the headless analyser (needs Node 18+)
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
  uninstall)
    rm -rf "$DIR"; rm -f "${SUDOZ_BIN:-$HOME/.local/bin}/sudo-z"; echo "removed $DIR"; exit ;;
  start|[0-9]*) ;;
  *) echo "unknown command: $cmd (use start, update, version, cli, uninstall)" >&2; exit 1 ;;
esac

PORT="${1:-8765}"; [ "$cmd" != start ] && PORT="$cmd"
l="$(latest)"; if [ -n "$l" ] && [ "$l" != "$INSTALLED" ]; then echo "[sudo-z] update available (${l:0:7}). Run: sudo-z update"; fi
URL="http://localhost:$PORT/"
echo "[sudo-z] serving $APP"
echo "[sudo-z] open $URL   (Ctrl+C to stop)"
( sleep 1; { command -v xdg-open >/dev/null && xdg-open "$URL"; } || { command -v open >/dev/null && open "$URL"; } || true ) >/dev/null 2>&1 &
if command -v python3 >/dev/null; then exec python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$APP"
elif command -v node >/dev/null; then exec node "$APP/tools/serve.mjs" "$PORT"
else echo "Need python3 or node to serve the console locally, or use the hosted site: https://pseudosyntax.github.io/Sudo-Z/" >&2; exit 1; fi
