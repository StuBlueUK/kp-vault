# kp-vault agent notes (read before touching)

## Scope
- **This project dir only**: `~/Desktop/Projects/kp-vault/`. Never touch
  anything outside it (no Hosting Panel, no system PHP, no other vhosts).
- **Dev:** this host (Linux Mint). Plain files, Rust 1.99+, no CI.
- **Runtime target:** the owner's Linux Mint desktop (Cinnamon). Not a server
  app — no prod box, no deploy. A `.deb` is the delivery format.

## What it is
A single-window desktop vault: passwords, notes and email records, all stored
in **one encrypted file**. Rust + egui/eframe (immediate mode), no framework,
no build step beyond cargo, no web assets.

- Vault file: `~/.local/share/kp-vault/vault.kpv` — atomic write, mode `0600`,
  parent dir `0700`.
- Crypto: Argon2id (m=64 MiB, t=3, p=1) → ChaCha20-Poly1305.
  File layout: `"KPVLT01\0"` | m u32 | t u32 | p u32 | salt 16 | nonce 12 | ct+tag.
  Key cached in `EncKey` while unlocked so saves re-run only the AEAD step;
  fresh nonce per save.
- Records: `Record::{Secret,Email}` (serde internally tagged `kind`).
  - `SecretRecord`: id, label, description, `entries: Vec<PasswordEntry>`
    (each = name/Title + username + value/password + non-glossed `revealed`),
    notes. Old single-`password` field is folded in by `Vault::migrate`.
  - `EmailRecord`: id, label, name, email, phone, website, subject, message.
  - Secrets are `zeroize`d on Drop (i.e. on lock).
- Clipboard auto-clears after 30 s (`CLIP_CLEAR_SECS`).
- System tray via `ksni` (pure-Rust SNI, no GTK/appindicator deps): Show/Lock/Quit.
  Closing the window hides to tray; Quit sets the `quitting` AtomicBool.
  Needs Cinnamon's XApp Status Applet to show the icon.

## eframe/egui 0.37 API gotchas (these bit us)
- `eframe::App` requires `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame)`
  (NOT `update`); put background work in `fn logic(&mut self, ctx, frame)`.
- Panels take `ui`, not `ctx`: `egui::Panel::left(id)` (`SidePanel` was renamed
  to `Panel`), `egui::CentralPanel::default().show(ui, …)`.
- Copy: `ctx.copy_text(String)`. Use `Id::unique("…")`, not deprecated `Id::new`.
- Modals: `egui::Modal::new(id).show(ctx, …)` → `ModalResponse` with
  `.should_close()` / `.inner`.
- `TextEdit::margin(Margin::symmetric(x, y))` takes `i8`.

## Build / verify
- `cargo build` (debug) and `cargo build --release` must be warning-free.
- `cargo test` — 8 crypto tests (roundtrip, tampered, wrong-pw, fresh nonce,
  `open_with` key reuse + foreign-key reject, generated length).
- Clippy is **not installed**; don't assume it.
- Smoke test (runs headless-ish on X11): `DISPLAY=:0 timeout 3 cargo run` →
  exit 124 is healthy. Only benign output is
  `MESA-INTEL: warning: Haswell Vulkan support is incomplete`.
- Dev host has no GTK dev headers; winit/glutin dlopen X11/GL at runtime, so
  `cargo build` works even though GUI dev headers are absent.
- `ldd target/release/kp-vault` shows only libc/libgcc/libm — GL/X11/Wayland
  are dlopen'd. That's why the `.deb` only needs `libc6`.

## File dialogs
- `rfd` with `default-features = false, features = ["xdg-portal", "tokio"]`.
  The portal feature **requires** tokio (or async-std) — build.rs fails otherwise.
  Backend `xdg-desktop-portal` (+ `-xapp`/`-gtk`) must be running at runtime.

## Packaging (Debian)
- `./packaging/build-deb.sh` → `dist/kp-vault_<ver>_<arch>.deb`.
  Version is read from `Cargo.toml`; `--root-owner-group`; `postinst` refreshes
  icon cache + desktop DB. Depends `libc6`, Recommends `libgl1 libxkbcommon0 libx11-6`.
- Maintainer defaults to `Stuart <root@localhost>`; override with the
  `MAINTAINER` env var or edit the script.
- `packaging/copyright` is a placeholder until a license is chosen.
- `install.sh` is the no-root user-local install (binary + icons + desktop file
  under `~/.local`).

## Conventions
- Terse comments: why, not what. No narrator comments, no comments on obvious
  code. Small diffs; match surrounding idioms.
- No JS/HTML/CSS here — it's all Rust.
- Never commit the vault data or any secret/key. `.gitignore` excludes
  `/target` and `/dist`.
- Exports are encrypted `.kpv` copies; imports may be decrypted with the cached
  session key (own backups share the salt) or a prompted master password.
