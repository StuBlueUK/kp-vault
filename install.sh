#!/usr/bin/env bash
# Install KP Vault for the current user (no root needed).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

cargo build --release

bindir="$HOME/.local/bin"
icondir="$HOME/.local/share/icons/hicolor"
appdir="$HOME/.local/share/applications"

install -Dm755 target/release/kp-vault "$bindir/kp-vault"
install -Dm644 assets/icon.png "$icondir/256x256/apps/kp-vault.png"
install -Dm644 assets/icon.svg "$icondir/scalable/apps/kp-vault.svg"
install -Dm644 kp-vault.desktop "$appdir/kp-vault.desktop"

gtk-update-icon-cache -f -t "$icondir" >/dev/null 2>&1 || true
update-desktop-database "$appdir" >/dev/null 2>&1 || true

echo "Installed KP Vault."
echo "  binary : $bindir/kp-vault"
echo "  menu   : $appdir/kp-vault.desktop"
case ":$PATH:" in
  *":$bindir:"*) ;;
  *) echo "  note   : add $bindir to your PATH to run 'kp-vault' from a terminal" ;;
esac
