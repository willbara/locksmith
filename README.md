# Locksmith

![Locksmith's Encrypt page in the dark theme](example.png)

A minimalist black-and-white desktop app to encrypt, decrypt and share files on Linux and Windows.
Build it yourself as a single AppImage or a single Windows .exe.

## Build

Needs `curl`, `tar`, `xz` and binutils (`ar`, `objdump`), plus internet access on the first build. No system
Python is needed.

```sh
./packaging/build_appimage.sh
./dist/Locksmith-x86_64.AppImage
```

The script downloads pinned, checksum-verified tools into `build/` (uv, a standalone Python 3.14, appimagetool),
installs dependencies from the hash-locked `packaging/requirements.lock`, runs the tests, freezes the app with
PyInstaller, refuses to package if anything would need a newer system than the targets below, and finally runs
the AppImage's self-test. Set `SKIP_TESTS=1` to skip the tests and the self-test. Works on x86_64 and aarch64.

**Compatibility:** the AppImage runs on any Linux with glibc 2.34+ and a standard desktop: Ubuntu 22.04+,
Debian 12+, Linux Mint 21+, Fedora 35+, RHEL/Rocky/Alma 9+, Arch. On older systems it exits with a clear
message. `./packaging/test_distros.sh` checks this in podman containers of several distros.

**Check a build:** `./dist/Locksmith-x86_64.AppImage --self-test` round-trips every cipher, compression method and
key-derivation function, checks public-key encryption and memory protection, and builds the window offscreen.
It uses a throwaway config and never touches your keys.

Files passed on the command line, or dropped anywhere on the window, are routed automatically: `.locked`
files go to Decrypt, everything else to Encrypt.

## Build for Windows

```sh
./packaging/build_windows.sh      # on Linux; needs wine (64-bit), curl, python3
```

Produces `dist/Locksmith-windows-x64.exe` (one file, runs on Windows 10 1903+ and 11) plus a `.sha256`
file to send with it. The script uses the real Windows builds of Python 3.14, Qt, `cryptography` and
PyInstaller, pinned and hash-verified like the Linux build. Wine only hosts the build: it runs the test suite
with Windows Python, then the `.exe`'s self-test. Wine lacks the ICU library that Windows provides, so the
build installs a small stand-in into its own Wine prefix (never into the `.exe`).

Files are fully compatible between the Windows and Linux versions. Differences on Windows:

- **Protections:** only those that can be applied and verified are attempted. DLL-injection protection (process
  mitigation policies, read back after being set) and keeping copied secrets out of clipboard history.
  Crash-dump and memory-reading protection and the network block have no reliable unprivileged equivalent
  and are shown as unavailable in Settings → About. TPM sealing is shown greyed out as not available.
- **Email** opens a new message and shows the file in Explorer to attach (Windows has no standard way to
  attach automatically). Settings and keys live in `%APPDATA%\locksmith`.
- **Sharing the .exe:** it is not code-signed, so Windows SmartScreen warns on first run ("More info → Run
  anyway"). Check the SHA-256 against the `.sha256` file you sent alongside it.

## Develop

```sh
python3 -m venv .venv        # Python 3.12+; older than 3.14 installs backports.zstd automatically
.venv/bin/pip install -e ".[dev]"
.venv/bin/python run.py      # run from source
.venv/bin/pytest             # tests
.venv/bin/ruff check         # lint
LOCKSMITH_FUZZ=20000 .venv/bin/pytest tests/test_fuzz.py   # a longer fuzzing run
```

```
locksmith/
  core/      encryption engine, no Qt: ciphers, KDFs, compression, file format, keys, tools
  ui/        PySide6 interface: theme, custom widgets, dialogs, worker threads, pages/
  assets/    app icon and bundled Inter font (OFL, see fonts/Inter-LICENSE.txt)
packaging/   build script, PyInstaller spec, dependency lock, distro tests, .desktop file, MIME type
tests/       tests, fuzzing (test_fuzz.py) and format test vectors (vectors/)
docs/        file-format specification and threat model
```

## Features

- **Ciphers:** AES-256-GCM, ChaCha20-Poly1305, AES-256-GCM-SIV, AES-256-OCB3, AES-256-SIV, and cascades
  (AES + ChaCha20, AES + ChaCha20 + OCB3) with an independent key per layer.
- **Key derivation:** Argon2id, scrypt or PBKDF2-SHA512, with four strength presets (Fast → Paranoid).
- **Protection:** a password, a keyfile (second factor), public keys for any number of recipients, or any
  combination. Each one wraps the same random file key.
- **Keys:** identities (your key pairs) and contacts (other people's public keys). New identities are hybrid
  post-quantum (X25519 + ML-KEM-768), and older classical ones can be upgraded. An identity can be protected
  with a passphrase, sealed to the machine's TPM, exported as a backup, written down as backup words, split
  into Shamir shares, and shared as text or a QR code. Recipients stay anonymous: a file doesn't say who it
  was encrypted for, and decoy slots can hide how many recipients there are.
- **Privacy:** optional lossless removal of photo metadata (JPEG, PNG, WebP: location, camera, dates), file
  times and archive owner names.
- **Extras:** streaming chunked encryption with parallel per-chunk compression (Zstandard, zlib, LZMA,
  bzip2, or automatic), size padding (Padmé, block or power-of-two), hidden file names, encrypted notes,
  folders and multi-item bundles, ASCII armor, verify-only mode, shredding of originals.
- **Share:** copy a file to the clipboard, email it, copy it as pasteable text, split it into size-limited
  parts and join them, send encrypted text messages, show a password as a QR code, split a password among
  people with Shamir secret sharing, publish your public key.
- **Tools:** password and passphrase generator, strength tester, checksums, file comparison, folder
  manifests (`sha256sum --tag` compatible), minisign signature verification, keyfile generator, shredder.
- **Interface:** dark, light or system theme, monochrome throughout.

## File format

```
"LOCKED\x00\x01" | u32 header_len | header JSON | { u32 len | AEAD frame }*
```

The full specification is [docs/FORMAT.md](docs/FORMAT.md), with test vectors in
[tests/vectors](tests/vectors). What Locksmith does and doesn't protect against is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

Locksmith 2.0 replaced the format of Cryptor 1.x (the app's former name). Cryptor files and keys are not read.

- A random 256-bit data key (DEK) is wrapped with AES-256-GCM once per slot. A password slot uses KDF
  output, mixed with SHA-512(keyfile) through HKDF when a keyfile is set. A classical recipient slot uses
  an ephemeral X25519 exchange plus HKDF. A hybrid slot also
  encapsulates to the recipient's ML-KEM-768 key and derives its key from both shared secrets plus the
  transcript, so breaking X25519 alone is not enough.
- Layer keys, the metadata key and a key-commitment value are derived from the DEK with HKDF-SHA512.
  A slot only counts as opened when its key matches the commitment; a mismatch reads as a wrong key.
- Frame `i` uses nonce `prefix(7) ‖ i(u32) ‖ final(u8)` and the SHA-256 of the header as associated data.
  Reordering, truncation, appended data and header tampering all fail authentication.
- File name, size, type, compression method and note are stored in an encrypted metadata blob.
- Output is written to a temporary file and moved into place only after every frame authenticates.

## Runtime protection

- **Memory:** core dumps are disabled and the process is non-dumpable. A crash cannot write keys to disk,
  and other programs running as you cannot read its memory.
- **No network:** a seccomp filter on every thread stops Locksmith from creating any internet or other
  non-local socket. Programs it opens (file manager, mail) are started by systemd, outside the sandbox.
- **Auto-lock and panic:** after inactivity (default 10 minutes), or with Ctrl+L, secrets are cleared from
  the window and it is covered. Ctrl+Shift+L also minimizes it.
- **Clipboard:** copied passwords and decrypted text are hidden from clipboard managers and cleared after
  30 seconds, on lock and on quit.

The desktop portal refuses requests from a non-dumpable process, so Locksmith uses its own file dialogs and
reads the system dark/light setting through a short-lived helper process. Settings → About shows the status.

## Your data

Settings and keys live in `~/.config/locksmith/` (`keys.json` is mode 0600). Identities can optionally be
protected with a passphrase (Argon2id + AES-GCM).

## Caveats

- Shredding is best effort. SSDs and copy-on-write filesystems such as btrfs can keep old copies.
- Losing the password, keyfile or private key means losing the data. There is no recovery.
- Senders are not authenticated. Decrypting proves a file was not changed after it was made, not who made
  it: anyone with your public key can send you a file, and its name and note can claim anything.
