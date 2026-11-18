#!/usr/bin/env bash
# Sudo-Z requirements (Linux/macOS). Everything installs inside the Sudo-Z
# folder; no sudo, nothing system-wide.
#   sudo-z setup            all of the below
#   sudo-z setup dotnet     private .NET 10 runtime (Microsoft dotnet-install.sh)
#   sudo-z setup ez         original Eric Zimmerman tools (.NET 10 builds); implies dotnet
#   sudo-z setup vol        Python venv + Volatility 3 (bootstraps Python with uv if needed)
#   sudo-z setup status     show what is installed
set -euo pipefail
WHAT="${1:-all}"
APP="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${SUDOZ_DIR:-$(dirname "$APP")}"
DOTNET_DIR="$DIR/dotnet"; EZ_DIR="$DIR/ez"; VENV="$DIR/venv"
say() { printf '\033[33m[sudo-z]\033[0m %s\n' "$*"; }

have_net10() { local d="$1"; [ -x "$d" ] || command -v "$d" >/dev/null 2>&1 || return 1; "$d" --list-runtimes 2>/dev/null | grep -q "Microsoft.NETCore.App 10\."; }

install_dotnet() {
  if have_net10 "$DOTNET_DIR/dotnet" || have_net10 dotnet; then say ".NET 10 runtime already present"; return; fi
  say "installing a private .NET 10 runtime to $DOTNET_DIR"
  curl -fsSL https://dot.net/v1/dotnet-install.sh -o "/tmp/dotnet-install-$$.sh"
  bash "/tmp/dotnet-install-$$.sh" --channel 10.0 --runtime dotnet --install-dir "$DOTNET_DIR" --no-path
  rm -f "/tmp/dotnet-install-$$.sh"
  have_net10 "$DOTNET_DIR/dotnet" && say ".NET 10 ready (private copy, used only by Sudo-Z)"
}

find_python() {
  for p in python3 python; do
    command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys,venv; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null && { command -v "$p"; return; }
  done
  return 1
}

install_ez() {
  install_dotnet
  PY="$(find_python || true)"; [ -x "$VENV/bin/python" ] && PY="$VENV/bin/python"
  [ -n "$PY" ] || install_vol_python
  [ -x "$VENV/bin/python" ] && PY="$VENV/bin/python"
  say "downloading the original Eric Zimmerman tools to $EZ_DIR (.NET 10 builds)"
  "$PY" "$APP/tools/ez_fetch.py" "$EZ_DIR"
  say "note: the command-line EZ tools ship as cross-platform .NET 10 builds and run here under the .NET runtime; the GUI tools (Timeline Explorer, Registry Explorer...) are Windows-only."
}

install_vol_python() {
  [ -x "$VENV/bin/python" ] && return
  PY="$(find_python || true)"
  if [ -n "$PY" ] && "$PY" -m venv "$VENV" 2>/dev/null; then return; fi
  rm -rf "$VENV"
  say "no usable Python venv: downloading uv to install a private Python 3.12"
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) T=uv-x86_64-unknown-linux-gnu ;; Linux-aarch64) T=uv-aarch64-unknown-linux-gnu ;;
    Darwin-arm64) T=uv-aarch64-apple-darwin ;; Darwin-x86_64) T=uv-x86_64-apple-darwin ;;
    *) echo "unsupported platform for uv bootstrap; install Python 3.8+ and rerun" >&2; exit 1 ;;
  esac
  mkdir -p "$DIR/uv"
  curl -fsSL "https://github.com/astral-sh/uv/releases/latest/download/$T.tar.gz" | tar -xz -C "$DIR/uv" --strip-components=1
  UV_PYTHON_INSTALL_DIR="$DIR/python" "$DIR/uv/uv" venv --python 3.12 --seed "$VENV"
}

install_vol() {
  install_vol_python
  say "installing Volatility 3 into $VENV"
  "$VENV/bin/python" -m pip install -q -U pip >/dev/null 2>&1 || true
  "$VENV/bin/python" -m pip install -U "volatility3[full]" || "$VENV/bin/python" -m pip install -U volatility3
  "$VENV/bin/vol" -h >/dev/null 2>&1 && say "Volatility 3 ready: $("$VENV/bin/vol" -h 2>&1 | grep -oE 'Framework [0-9.]+')"
}

status() {
  if have_net10 "$DOTNET_DIR/dotnet" || have_net10 dotnet; then n=yes; else n="no  (sudo-z setup dotnet)"; fi
  c=$( { find "$EZ_DIR" \( -name '*.exe' -o -name '*.dll' \) 2>/dev/null || true; } | wc -l | tr -d ' ')
  [ -x "$VENV/bin/vol" ] && v=yes || v="no  (sudo-z setup vol)"
  echo "  .NET 10 runtime : $n"; echo "  EZ tools        : ${c} files in $EZ_DIR"; echo "  Volatility 3    : $v"
}

case "$WHAT" in
  dotnet) install_dotnet ;;
  ez) install_ez ;;
  vol) install_vol ;;
  status) status ;;
  all) rc=0; install_ez || { say "EZ tools step failed"; rc=1; }; install_vol || { say "Volatility 3 step failed"; rc=1; }; status; exit $rc ;;
  *) echo "unknown setup target '$WHAT' (use all, dotnet, ez, vol, status)" >&2; exit 1 ;;
esac
