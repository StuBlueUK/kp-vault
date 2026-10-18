# KP Vault

A single-file, encrypted desktop vault for **passwords, notes and email records**,
built in Rust with [egui/eframe](https://github.com/emilk/egui). No accounts, no
sync, no network — everything lives in one encrypted file on your machine.

![KP Vault icon](assets/icon.png)

## Features

- **One encrypted file** — `~/.local/share/kp-vault/vault.kpv`.
- Multiple **named credential groups** per record: each group is a
  **Title → username → password** block, with its own copy / show-hide /
  generate buttons.
- Email records with name, address, phone, website, subject and message.
- **Copy-to-clipboard** buttons that clear the clipboard after 30 seconds.
- **Generate** strong passwords; won't overwrite a field that already has content.
- Free-form notes on every record, plus a searchable record list.
- **System tray** (Show / Lock / Quit) — closing the window hides to the tray.
- **Encrypted export / import** for backups and moving between machines.
- Auto-save on change; the vault is re-encrypted with a fresh nonce each save.

## Install

### Debian / Ubuntu / Linux Mint (`.deb`)

Download the latest `.deb` from [Releases](../../releases) and install it:

```sh
sudo apt install ./kp-vault_0.1.0_amd64.deb
```

### From source

Requires a recent Rust toolchain (1.99+) and Linux with X11 or Wayland.

```sh
git clone https://github.com/StuBlueUK/kp-vault.git
cd kp-vault
cargo build --release
./target/release/kp-vault
```

Or install for the current user (no root):

```sh
./install.sh
```

## Usage

1. On first launch, choose a **master password** (at least 8 characters). It
   derives the key and is never stored.
2. **＋ Password** adds a credential record; **＋ Email** adds a contact record.
3. Click **＋ Add field** inside a password record to add more credential groups
   (Title, username, password).
4. `⧉` copies a field, `👁` reveals it, `🎲` generates a password.
5. **Lock** wipes the decrypted data from memory. Closing the window keeps the
   app in the tray.

### Export / import

- **Export…** writes an encrypted copy of the vault to a location you choose.
- **Import…** reads a `.kpv` file. Files exported by the current session open
  directly; anything else prompts for that file's master password. Import
  **replaces** the current records and re-encrypts with your current master
  password.

## Security

- Key derivation: **Argon2id** (m = 64 MiB, t = 3, p = 1).
- Encryption: **ChaCha20-Poly1305** (AEAD) with a fresh random nonce per save.
- Vault file is written atomically and forced to mode `0600`; the parent
  directory is `0700`.
- Decrypted secrets are held in memory only and zeroized on lock/exit.
- Clipboard contents are cleared automatically after 30 seconds.

File layout:

```
"KPVLT01\0" | m_cost u32 | t_cost u32 | p_cost u32 | salt (16) | nonce (12) | ciphertext + tag
```

> The cryptographic design is implemented but has **not** been independently
> audited. Review it before trusting it with anything important.

## Build

```sh
cargo build            # debug
cargo build --release  # optimized
cargo test             # crypto unit tests
```

### Debian package

```sh
./packaging/build-deb.sh     # -> dist/kp-vault_<version>_<arch>.deb
```

The version is read from `Cargo.toml`. Override the package maintainer with the
`MAINTAINER` environment variable.

## Notes

- Linux only (X11 / Wayland). The tray icon needs a StatusNotifier host — on
  Cinnamon that is the XApp Status Applet.
- The `.deb` depends only on `libc6`; OpenGL / X11 / Wayland libraries are
  loaded at runtime.

## License

No license has been chosen yet — all rights reserved by the author.
