# Locksmith

PySide6 desktop app for file encryption, packaged as an AppImage. It is built locally to be used, not released.

## Commands

- Run from source: `.venv/bin/python run.py`
- Tests: `.venv/bin/pytest`. Lint: `.venv/bin/ruff check`
- Fuzzing: `tests/test_fuzz.py` runs a short budget with the suite; `LOCKSMITH_FUZZ=20000` for a long run. New parsers
  of outside input get a target there.
- `tests/vectors` are committed files checked by the engine and by `tests/spec_reader.py` (written from
  `docs/FORMAT.md`). Never regenerate them to make a test pass: a failure means old files no longer open. A format
  change adds new vectors and updates `docs/FORMAT.md`.
- Build: `./packaging/build_appimage.sh` → `dist/Locksmith-<arch>.AppImage` (pinned uv + Python 3.14, hash-locked deps)
- Check a build: `dist/Locksmith-x86_64.AppImage --self-test`; other distros: `./packaging/test_distros.sh` (podman)
- Windows build (from Linux, via Wine): `./packaging/build_windows.sh` → `dist/Locksmith-windows-x64.exe`.
  Run the suite with Windows Python: `WINEPREFIX=$PWD/build/wine wine build/win/python/tools/python.exe -X utf8 -m pytest`
- Update dependencies: edit `pyproject.toml`, then
  `build/tools/uv pip compile pyproject.toml --extra dev --universal --python-version 3.14 --generate-hashes --no-header -o packaging/requirements.lock`
- Update a pinned tool: change its version and SHA-256 at the top of `packaging/build_appimage.sh`
- UI flows are tested in `tests/test_ui_flows.py` (offscreen). TPM tests skip on machines without a TPM.
- Screenshots or UI checks without a display: `QT_QPA_PLATFORM=offscreen` and `widget.grab().save(...)`.
  Point `XDG_CONFIG_HOME` at a temp dir so the real `~/.config/locksmith` is untouched.

## Architecture

- `locksmith/core` is pure Python with no Qt imports. Keep it that way. Errors raised to the UI must subclass
  `LocksmithError` (`core/errors.py`) with a user-facing message.
- `core/engine.py` owns the on-disk format (documented in its docstring and the README). Changing frame layout,
  nonce construction, HKDF labels or header fields breaks existing files: bump the magic version byte and keep
  reading v1.
- Cipher suites (`core/ciphers.py`), KDFs and presets (`core/kdf.py`) and codecs (`core/compress.py`) are
  registries. Add entries there and the dropdowns pick them up.
- UI: `ui/theme.py` holds the monochrome palettes, stylesheet and inline SVG icons. `ui/widgets.py` holds
  custom-painted animated widgets. Colors come from `theme.c(...)` at paint time, so theme switches just repaint.
  Durations go through `theme.ms()` so the animations toggle works.
- Blocking work goes through `ui/workers.run_task`. Read widget values on the UI thread before starting the
  task, never inside it.
- Dialogs are in-window sheets (`ui/dialogs.py`), not native windows.
- Use `widgets.Label` / `widgets.label()`, never a bare `QLabel`: file names, notes and messages come from
  whoever made the file, and a bare `QLabel` renders text that looks like HTML as markup.
- The process is hardened (`locksmith/hardening.py`: no core dumps, non-dumpable). The desktop portal rejects
  non-dumpable processes, so never call it directly: go through a child process in `ui/host.py`. Native file
  dialogs are disabled for the same reason.
- The process has no network (seccomp, installed in `app.py` after Qt connects). Never add in-process
  networking. Start host programs with `ui/host.launch`, which runs them via systemd outside the sandbox.
- Any widget that can hold a secret must be cleared on lock: `PasswordField` is automatic; mark other text
  widgets with `lock.mark_sensitive`, or give a page a `clear_secrets()` method. Copy secrets with
  `widgets.copy_secret`, and compare them with `tools.same_secret` (constant time).
- Keys: raw public keys are 32 bytes (X25519) or 1216 (X25519 + ML-KEM-768); raw private keys 32 or 96
  (X25519 + ML-KEM seed). Classical and hybrid slots share one format. TPM sealing goes through `systemd-creds`.
- `core/metadata.py` strips images with allowlists. Keep it that way: unknown data is dropped, not kept.

## Format and versioning

- Files start with `LOCKED\x00\x01` and use `.locked`. `engine.Format` bundles a format's signature and its
  key-derivation labels (`locksmith/v1/…`); a new format version adds a profile and keeps reading the old ones.
- The app was called Cryptor before 2.0. Version 2.0 deliberately dropped Cryptor compatibility.
- Versioning is SemVer: a major bump when files or keys made by the new version can't be read by older ones.

## Portability

- The AppImage targets glibc 2.34 / libstdc++ 3.4.29. The build fails if anything bundled needs newer.
- `packaging/locksmith.spec` bundles only files from the build Python and venv, plus a short allowlist. Host
  desktop libraries (GL, Wayland, X11, fonts, D-Bus, GLib) must come from the user's system.
- Zstandard is required: `compression.zstd` on 3.14+, `backports.zstd` below. Every build must read every file.

## Windows

- Platform differences live in `core/osutil.py` (file creation flags, config folder, safe file names) and
  `ui/host.py` (Explorer, default apps, email). Never use Linux-only `os` flags or paths directly.
- Always pass `encoding="utf-8"` for text files: Windows Python otherwise uses the legacy code page.
- Windows hardening only attempts protections that are verified by reading them back (`hardening._harden_windows`).
  Don't add protections that can't be confirmed; report them as unavailable instead.
- Tests that rely on POSIX modes or symlinks must skip on Windows (`needs_symlinks` fixture in `tests/conftest.py`).

## Style

Monochrome only (black, white, greys). No accent colors.
