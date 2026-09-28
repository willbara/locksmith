#!/usr/bin/env bash
# Build dist/Locksmith-windows-x64.exe from Linux, using Windows Python under Wine.
#
# The .exe is produced by the real Windows builds of Python, Qt, cryptography and
# PyInstaller (pinned and checksum/hash verified), so it is a genuine Windows program.
# Wine only hosts the build. The test suite and the .exe's self-test run under Wine too;
# a final check on real Windows is still recommended before sharing.
#
# Host requirements: wine (64-bit), curl, python3, sha256sum.
# Environment: SKIP_TESTS=1 skips the test suite and the self-test.
set -euo pipefail

PYTHON_VERSION="3.14.7"
PYTHON_NUPKG_SHA=46a4da5529a92d18ff894911f6e6033a8253198d705b8161bf28c9123c87d46b

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
TOOLS="$BUILD/tools"
WINPY_DIR="$BUILD/win/python"
export WINEPREFIX="$BUILD/wine" WINEDEBUG=-all WINEARCH=win64
cd "$ROOT"

for tool in wine curl python3 sha256sum; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done
mkdir -p "$TOOLS"

NUPKG="$TOOLS/python-$PYTHON_VERSION.nupkg"
if [ ! -f "$NUPKG" ] || ! echo "$PYTHON_NUPKG_SHA  $NUPKG" | sha256sum -c --status; then
    echo "==> Downloading Windows Python $PYTHON_VERSION"
    curl -fsSL -o "$NUPKG.part" "https://api.nuget.org/v3-flatcontainer/python/$PYTHON_VERSION/python.$PYTHON_VERSION.nupkg"
    echo "$PYTHON_NUPKG_SHA  $NUPKG.part" | sha256sum -c --status || { rm -f "$NUPKG.part"; echo "Checksum mismatch" >&2; exit 1; }
    mv "$NUPKG.part" "$NUPKG"
fi

if [ ! -x "$WINPY_DIR/tools/python.exe" ] || ! grep -q "$PYTHON_VERSION" "$WINPY_DIR/.version" 2>/dev/null; then
    echo "==> Preparing Windows Python $PYTHON_VERSION"
    rm -rf "$WINPY_DIR" && mkdir -p "$WINPY_DIR"
    python3 -c "import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); [z.extract(n, sys.argv[2]) for n in z.namelist() if n.startswith('tools/')]" "$NUPKG" "$WINPY_DIR"
    echo "$PYTHON_VERSION" > "$WINPY_DIR/.version"
fi
wineboot -i >/dev/null 2>&1 || true
PY=(wine "$WINPY_DIR/tools/python.exe" -X utf8)

echo "==> Installing locked dependencies (Windows wheels)"
"${PY[@]}" -m pip install -q --disable-pip-version-check --no-warn-script-location \
    --require-hashes --only-binary=:all: -r packaging/requirements.lock

# Qt needs icuuc.dll, which Windows 10 1903+ provides and Wine does not. Install a stub
# into the Wine prefix only (see packaging/windows/icu_stub.py); it is never bundled.
SYS32="$WINEPREFIX/drive_c/windows/system32"
python3 packaging/windows/icu_stub.py "$SYS32/icuuc.dll" \
    ucnv_cbFromUWriteUChars ucnv_cbToUWriteUChars ucnv_close ucnv_countAvailable ucnv_fromUCountPending \
    ucnv_fromUnicode ucnv_getAvailableName ucnv_getFromUCallBack ucnv_getMaxCharSize ucnv_getName \
    ucnv_getStandardName ucnv_getToUCallBack ucnv_open ucnv_reset ucnv_setFromUCallBack ucnv_setToUCallBack \
    ucnv_toUCountPending ucnv_toUnicode UCNV_FROM_U_CALLBACK_SUBSTITUTE UCNV_TO_U_CALLBACK_SUBSTITUTE

if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "==> Running tests with Windows Python"
    QT_QPA_PLATFORM=offscreen "${PY[@]}" -m pytest -q -p no:cacheprovider tests 2>/dev/null | tail -1
    [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "Tests failed under Windows Python." >&2; exit 1; }
fi

echo "==> Generating icon and version resource"
"${PY[@]}" packaging/windows/make_resources.py 2>/dev/null

echo "==> Freezing with PyInstaller"
"${PY[@]}" -m PyInstaller --noconfirm --clean --log-level WARN \
    --distpath "$BUILD/win/dist" --workpath "$BUILD/win/work" packaging/windows/locksmith-windows.spec 2>&1 \
    | grep -vE "MESA|pci id|dri2|^\s*$" || true

EXE="$BUILD/win/dist/Locksmith.exe"
[ -f "$EXE" ] || { echo "PyInstaller did not produce Locksmith.exe" >&2; exit 1; }
# Inspect what is actually inside the finished .exe.
"${PY[@]}" -c "
import sys
from PyInstaller.archive.readers import CArchiveReader
names = [n.lower() for n in CArchiveReader(sys.argv[1]).toc]
bad = [n for n in names if n.rsplit('\\\\', 1)[-1].rsplit('/', 1)[-1] in ('icuuc.dll', 'icuin.dll', 'icu.dll')]
sys.exit('The Wine-only ICU stub ended up in the bundle: ' + ', '.join(bad) if bad else 0)
" "$EXE"

mkdir -p dist
OUT="dist/Locksmith-windows-x64.exe"
cp "$EXE" "$OUT"
(cd dist && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")

if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "==> Self-testing the .exe (under Wine)"
    QT_QPA_PLATFORM=offscreen wine "$OUT" --self-test 2>/dev/null | grep -vE "MESA|pci id|dri2" | tail -3
    [ "${PIPESTATUS[0]}" -eq 0 ] || { echo "Self-test failed." >&2; exit 1; }
fi
echo "==> Built $OUT ($(du -h "$OUT" | cut -f1)), SHA-256 in $OUT.sha256"
