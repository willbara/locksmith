# Build and develop

## Build the AppImage

You need `curl`, `tar`, `xz` and binutils (`ar`, `objdump`). The first build also needs internet
access. You do not need a system Python.

```sh
./packaging/build_appimage.sh
./dist/Locksmith-x86_64.AppImage
```

The script does these steps:

1. It downloads pinned tools into `build/` and verifies their checksums: uv, a standalone Python 3.14
   and appimagetool.
2. It installs the dependencies from the hash-locked `packaging/requirements.lock`.
3. It runs the tests.
4. It freezes the app with PyInstaller.
5. It stops if the app needs a newer system than the targets below.
6. It runs the self-test of the AppImage.

To skip the tests and the self-test, set `SKIP_TESTS=1`. The script works on x86_64 and aarch64.

**Compatibility:** the AppImage runs on all Linux systems with glibc 2.34 or later and a standard
desktop: Ubuntu 22.04+, Debian 12+, Linux Mint 21+, Fedora 35+, RHEL/Rocky/Alma 9+ and Arch. On an
older system, it stops and shows a clear message. `./packaging/test_distros.sh` checks this in podman
containers of different distributions.

**Reproducible build:** the same source and pinned inputs give the same AppImage, byte for byte.
`./packaging/check_reproducible.sh` builds two times and compares the results.

**Check a build:** `./dist/Locksmith-x86_64.AppImage --self-test` encrypts and decrypts with each
cipher, compression method and key-derivation function. It also checks public-key encryption and memory
protection, and builds the window offscreen. It uses a temporary configuration and does not touch your
keys.

When you give files on the command line or drop them on the window, Locksmith sends `.locked` files to
Decrypt. It sends all other files to Encrypt.

## Build for Windows

On Linux, with 64-bit Wine, `curl` and `python3`:

```sh
./packaging/build_windows.sh
```

The script makes `dist/Locksmith-windows-x64.exe`, one file that runs on Windows 10 1903 or later and
Windows 11. It also makes a `.sha256` file to send with the `.exe`.

The script uses the real Windows builds of Python 3.14, Qt, `cryptography` and PyInstaller. These are
pinned and verified by hash, as in the Linux build. Wine only hosts the build. It runs the test suite
with Windows Python, and then the self-test of the `.exe`. Wine does not have the ICU library that
Windows supplies. Thus the build installs a small replacement into its own Wine prefix. This
replacement is not in the `.exe`.

## Differences on Windows

The files are fully compatible between the Windows and Linux versions. These are the differences:

- **Protections:** Locksmith uses only the protections that it can apply and verify. It applies
  protection against DLL injection (process mitigation policies, which it reads back after it sets
  them). It also keeps copied secrets out of the clipboard history. Windows has no reliable
  unprivileged equivalent of the crash-dump protection, the memory-reading protection or the network
  block. Settings → About shows these as not available. TPM sealing is not available and shows grey.
- **Email:** Locksmith opens a new message and shows the file in Explorer. You attach the file
  yourself, because Windows has no standard way to attach a file automatically.
- **Settings and keys:** these are in `%LOCALAPPDATA%\locksmith` (the local profile, which does not
  roam). Locksmith 4 kept them in `%APPDATA%`. Locksmith 5 moves them when it starts for the first time.
- **Code signing:** the `.exe` is not code-signed. Thus Windows SmartScreen shows a warning when the
  `.exe` runs for the first time ("More info → Run anyway"). Compare the SHA-256 of the `.exe` with the
  `.sha256` file that you sent with it.

## Develop

Use Python 3.12.11 or later, or 3.13.4 or later. Versions older than 3.14 install `backports.zstd`
automatically.

```sh
python3 -m venv .venv
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
packaging/   build scripts, PyInstaller spec, dependency lock, distro tests, .desktop file, MIME type
tests/       tests, fuzzing (test_fuzz.py) and format test vectors (vectors/)
docs/        documentation and the file-format specification
```
