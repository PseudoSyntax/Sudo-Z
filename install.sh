#!/usr/bin/env bash
# Sudo-Z installer and updater for Linux and macOS.
#
#   Install or update (same command):
#     curl -fsSL https://raw.githubusercontent.com/PseudoSyntax/Sudo-Z/main/install.sh | bash
#
#   Then:  sudo-z            start the console in your browser
#          sudo-z update     pull the latest version from GitHub
#          sudo-z version    show the installed commit
#          sudo-z uninstall  remove Sudo-Z
#
# Options (env vars): SUDOZ_DIR (default ~/.local/share/sudo-z), SUDOZ_BIN
# (default ~/.local/bin), SUDOZ_BRANCH (default main), SUDOZ_FORCE=1.
set -euo pipefail

REPO="${SUDOZ_REPO:-PseudoSyntax/Sudo-Z}"
BRANCH="${SUDOZ_BRANCH:-main}"
DIR="${SUDOZ_DIR:-$HOME/.local/share/sudo-z}"
BIN="${SUDOZ_BIN:-$HOME/.local/bin}"
APP="$DIR/app"
VER="$DIR/version.txt"

say() { printf '\033[33m[sudo-z]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[sudo-z] %s\033[0m\n' "$*" >&2; exit 1; }
command -v curl >/dev/null || die "curl is required"
command -v tar >/dev/null || die "tar is required"

say "checking $REPO@$BRANCH"
sha_of() {
  # 1) GitHub API as plain text (uses GITHUB_TOKEN if set)
  # 2) git ref advertisement, which is not subject to the API rate limit
  local s auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  s="$(curl -fsSL -m "${2:-30}" -H 'User-Agent: sudo-z' -H 'Accept: application/vnd.github.sha' ${auth[@]+"${auth[@]}"} "https://api.github.com/repos/$REPO/commits/$1" 2>/dev/null | tr -d '[:space:]')" || true
  if ! printf '%s' "$s" | grep -qE '^[0-9a-f]{40}$'; then
    s="$(curl -fsSL -m "${2:-30}" -A 'git/2.40' "https://github.com/$REPO.git/info/refs?service=git-upload-pack" 2>/dev/null | grep -aoE "[0-9a-f]{40} refs/heads/$1\$|[0-9a-f]{40} refs/heads/$1[^a-zA-Z0-9_./-]" | head -n1 | cut -c1-40)" || true
  fi
  printf '%s' "$s"
}
LATEST="$(sha_of "$BRANCH")"
[ -n "$LATEST" ] || die "could not read the latest commit from GitHub"
CURRENT="$(cat "$VER" 2>/dev/null || true)"

if [ "${SUDOZ_FORCE:-0}" != "1" ] && [ "$CURRENT" = "$LATEST" ] && [ -f "$APP/index.html" ]; then
  say "already up to date (${LATEST:0:7})"
else
  mkdir -p "$DIR"
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  say "downloading ${LATEST:0:7}"
  curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$LATEST" | tar -xz -C "$TMP"
  SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  [ -f "$SRC/index.html" ] && [ -f "$SRC/js/engine.js" ] || die "download does not look like Sudo-Z; old version left in place"
  rm -rf "$APP.old"
  [ -d "$APP" ] && mv "$APP" "$APP.old"
  if ! mv "$SRC" "$APP"; then [ -d "$APP.old" ] && mv "$APP.old" "$APP"; die "could not move new version into place"; fi
  rm -rf "$APP.old"
  printf '%s' "$LATEST" > "$VER"
  if [ -n "$CURRENT" ]; then say "updated ${CURRENT:0:7} -> ${LATEST:0:7}"; else say "installed ${LATEST:0:7} to $APP"; fi
fi

mkdir -p "$BIN"
cat > "$BIN/sudo-z" <<EOF
#!/usr/bin/env bash
exec bash "$APP/tools/sudo-z.sh" "\$@"
EOF
chmod +x "$BIN/sudo-z" "$APP/tools/sudo-z.sh" 2>/dev/null || true
case ":$PATH:" in *":$BIN:"*) ;; *) say "add $BIN to your PATH, e.g.: echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.bashrc";; esac

echo
echo "  Start:   sudo-z"
echo "  Update:  sudo-z update"
echo
