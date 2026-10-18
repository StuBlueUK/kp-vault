#!/usr/bin/env bash
# Build a Debian package for KP Vault. Output: dist/kp-vault_<ver>_<arch>.deb
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"

version="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
arch="$(dpkg --print-architecture)"
maintainer="${MAINTAINER:-Stuart <root@localhost>}"
root="$here/target/deb/kp-vault_${version}_${arch}"

cargo build --release

rm -rf "$root"
install -Dm755 target/release/kp-vault "$root/usr/bin/kp-vault"
install -Dm644 kp-vault.desktop "$root/usr/share/applications/kp-vault.desktop"
install -Dm644 assets/icon.png "$root/usr/share/icons/hicolor/256x256/apps/kp-vault.png"
install -Dm644 assets/icon.svg "$root/usr/share/icons/hicolor/scalable/apps/kp-vault.svg"
mkdir -p "$root/usr/share/doc/kp-vault"
install -Dm644 packaging/copyright "$root/usr/share/doc/kp-vault/copyright"

size="$(du -sk "$root/usr" | cut -f1)"

mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: kp-vault
Version: $version
Section: utils
Priority: optional
Architecture: $arch
Maintainer: $maintainer
Depends: libc6 (>= 2.31)
Recommends: libgl1, libxkbcommon0, libx11-6
Installed-Size: $size
Description: encrypted local vault for passwords, notes and email records
 KP Vault stores passwords, notes and email records in a single file
 encrypted with Argon2id and ChaCha20-Poly1305. It is a desktop app with
 a system-tray icon and copy-to-clipboard helpers for each field.
EOF

cat > "$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
EOF
chmod 755 "$root/DEBIAN/postinst"

mkdir -p "$here/dist"
out="$here/dist/kp-vault_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$root" "$out" >/dev/null
echo "Built $out"
