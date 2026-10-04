#!/usr/bin/env bash
# Build dist/Locksmith-<arch>.AppImage.
#
# Portable by design: a pinned standalone Python (installed by uv) replaces the
# system Python, dependencies are installed from a hash-locked file, only our own
# libraries are bundled, and the build fails if anything inside would need a glibc
# newer than GLIBC_TARGET. Every downloaded tool is pinned and checksum-verified.
#
# Reproducible: the same source and pinned inputs make a byte-identical AppImage
# (packaging/check_reproducible.sh builds twice and compares). File times come from
# SOURCE_DATE_EPOCH (by default the last commit's time) and Python's hash seed is fixed.
#
# Host requirements: curl, tar, xz, sha256sum, ar and objdump (binutils).
# Environment: SKIP_TESTS=1 skips the test suite and the final self-test;
#              SOURCE_DATE_EPOCH overrides the timestamp stored in the build.
set -euo pipefail

PYTHON_VERSION="3.14.7"
GLIBC_TARGET="2.34"
GLIBCXX_TARGET="3.4.29"   # libstdc++ from GCC 11, shipped by every glibc 2.34+ distro
UV_VERSION="0.12.19"
APPIMAGETOOL_VERSION="1.9.1"
RUNTIME_VERSION="20251108"
XCB_CURSOR_DEB="libxcb-cursor0_0.1.1-4"   # Debian 12; needs only glibc 2.8

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
TOOLS="$BUILD/tools"
APPDIR="$BUILD/Locksmith.AppDir"
VENV="$BUILD/venv"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64)
        DEB_ARCH=amd64
        UV_SHA=db7278c9f57981338fddff1fb250e11964bc0a4fafcb9eed8303fdb117dc067b
        APPIMAGETOOL_SHA=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
        RUNTIME_SHA=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
        XCB_CURSOR_SHA=bab731cd0143303f77461dd0a03ad20807bd3d767d5d6af6a11ff99c3b7aeac3 ;;
    aarch64)
        DEB_ARCH=arm64
        UV_SHA=ad8d8448a2ff642ba62c2f684d7dd22a03f8eb3fc9918c2c3e8ec975f4ed6710
        APPIMAGETOOL_SHA=f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158
        RUNTIME_SHA=00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444
        XCB_CURSOR_SHA=2b68b4c41535b241b3e51dfc9f6e783f6160b4ed005dd422dceadc5a42e84382 ;;
    *)
        echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

for tool in curl tar xz sha256sum ar objdump; do
    command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 1; }
done

# fetch URL FILE SHA256: download once into build/tools and verify the checksum.
fetch() {
    local url="$1" file="$TOOLS/$2" sha="$3"
    if [ ! -f "$file" ] || ! echo "$sha  $file" | sha256sum -c --status; then
        echo "==> Downloading $2"
        curl -fsSL -o "$file.part" "$url"
        if ! echo "$sha  $file.part" | sha256sum -c --status; then
            rm -f "$file.part"
            echo "Checksum mismatch for $2. Refusing to continue." >&2
            exit 1
        fi
        mv "$file.part" "$file"
    fi
}

cd "$ROOT"
mkdir -p "$TOOLS"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 1767225600)}"
export SOURCE_DATE_EPOCH PYTHONHASHSEED=0 TZ=UTC LC_ALL=C.UTF-8
export UV_PYTHON_INSTALL_DIR="$BUILD/python" UV_CACHE_DIR="$BUILD/uv-cache" UV_PYTHON_PREFERENCE=only-managed

fetch "https://github.com/astral-sh/uv/releases/download/$UV_VERSION/uv-$ARCH-unknown-linux-musl.tar.gz" \
      "uv-$UV_VERSION.tar.gz" "$UV_SHA"
if [ ! -x "$TOOLS/uv" ] || [ "$("$TOOLS/uv" --version | cut -d' ' -f2)" != "$UV_VERSION" ]; then
    tar -xzf "$TOOLS/uv-$UV_VERSION.tar.gz" -C "$TOOLS" --strip-components=1
fi
UV="$TOOLS/uv"

echo "==> Preparing Python $PYTHON_VERSION"
"$UV" python install -q "$PYTHON_VERSION"
if [ ! -x "$VENV/bin/python" ] || [ "$("$VENV/bin/python" -c 'import platform; print(platform.python_version())')" != "$PYTHON_VERSION" ]; then
    rm -rf "$VENV"
    "$UV" venv -q --python "$PYTHON_VERSION" "$VENV"
fi
PY="$VENV/bin/python"
"$UV" pip sync -q --python "$PY" --require-hashes packaging/requirements.lock

if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "==> Running tests"
    "$PY" -m pytest -q -p no:cacheprovider tests
fi

echo "==> Fetching libxcb-cursor ($XCB_CURSOR_DEB, $DEB_ARCH)"
fetch "https://deb.debian.org/debian/pool/main/x/xcb-util-cursor/${XCB_CURSOR_DEB}_$DEB_ARCH.deb" \
      "${XCB_CURSOR_DEB}_$DEB_ARCH.deb" "$XCB_CURSOR_SHA"
XCB_DIR="$BUILD/xcb-cursor"
rm -rf "$XCB_DIR" && mkdir -p "$XCB_DIR"
(cd "$XCB_DIR" && ar x "$TOOLS/${XCB_CURSOR_DEB}_$DEB_ARCH.deb" && tar -xf data.tar.*)
LOCKSMITH_XCB_CURSOR="$(find "$XCB_DIR" -name 'libxcb-cursor.so.0.*' -type f | head -1)"
export LOCKSMITH_XCB_CURSOR

echo "==> Freezing with PyInstaller"
rm -rf "$BUILD/pyinstaller" "$BUILD/work"   # nothing left over from an earlier build
"$PY" -m PyInstaller --noconfirm --clean --log-level WARN \
    --distpath "$BUILD/pyinstaller" --workpath "$BUILD/work" packaging/locksmith.spec

echo "==> Checking compatibility (glibc $GLIBC_TARGET, libstdc++ $GLIBCXX_TARGET)"
# highest PREFIX: the newest versioned symbol any bundled file needs, e.g. GLIBC_2.34.
highest() {
    local prefix="$1" best="0" v
    while IFS= read -r -d '' f; do
        v="$(objdump -T "$f" 2>/dev/null | grep -o "${prefix}_[0-9][0-9.]*" | sed "s/${prefix}_//" | sort -uV | tail -1 || true)"
        [ -n "$v" ] && best="$(printf '%s\n%s\n' "$best" "$v" | sort -V | tail -1)"
    done < <(find "$BUILD/pyinstaller/locksmith" -type f \( -name '*.so*' -o -name locksmith \) -print0)
    echo "$best"
}
newer_than() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }
FLOOR="$(highest GLIBC)"
CXX_FLOOR="$(highest GLIBCXX)"
echo "    Needs glibc $FLOOR+ and libstdc++ $CXX_FLOOR+"
if newer_than "$FLOOR" "$GLIBC_TARGET" || newer_than "$CXX_FLOOR" "$GLIBCXX_TARGET"; then
    echo "The build needs a newer system than the targets above. Refusing to package." >&2
    exit 1
fi

echo "==> Assembling AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps" "$APPDIR/usr/share/icons/hicolor/scalable/apps" \
         "$APPDIR/usr/share/mime/packages"
cp -a "$BUILD/pyinstaller/locksmith" "$APPDIR/usr/lib/locksmith"
ln -s ../lib/locksmith/locksmith "$APPDIR/usr/bin/locksmith"
cp packaging/locksmith.desktop "$APPDIR/locksmith.desktop"
cp packaging/locksmith.desktop "$APPDIR/usr/share/applications/"
cp packaging/locksmith-mime.xml "$APPDIR/usr/share/mime/packages/locksmith.xml"
cp locksmith/assets/locksmith.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/locksmith.svg"
QT_QPA_PLATFORM=offscreen "$PY" - "$APPDIR/locksmith.png" <<'EOF'
import sys
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer
app = QGuiApplication(sys.argv[:1])
img = QImage(256, 256, QImage.Format.Format_ARGB32)
img.fill(Qt.GlobalColor.transparent)
p = QPainter(img)
p.setRenderHint(QPainter.RenderHint.Antialiasing)
QSvgRenderer("locksmith/assets/locksmith.svg").render(p)
p.end()
img.save(sys.argv[1])
EOF
cp "$APPDIR/locksmith.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/locksmith.png"
ln -sf locksmith.png "$APPDIR/.DirIcon"

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
NEED="@GLIBC_TARGET@"
HAVE="$(getconf GNU_LIBC_VERSION 2>/dev/null | cut -d' ' -f2)"
if [ -n "$HAVE" ] && [ "$(printf '%s\n%s\n' "$NEED" "$HAVE" | sort -V | head -1)" != "$NEED" ]; then
    MSG="Locksmith needs a newer Linux system (glibc $NEED or later, this one has $HAVE)."
    echo "$MSG" >&2
    command -v notify-send >/dev/null 2>&1 && notify-send -i dialog-error "Locksmith" "$MSG"
    exit 1
fi
exec "$HERE/usr/lib/locksmith/locksmith" "$@"
EOF
sed -i "s/@GLIBC_TARGET@/$GLIBC_TARGET/" "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun"

# Every file in the AppDir gets the same time, so the squashfs image doesn't record when it was built.
find "$APPDIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

fetch "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$ARCH.AppImage" \
      "appimagetool-$APPIMAGETOOL_VERSION-$ARCH.AppImage" "$APPIMAGETOOL_SHA"
fetch "https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_VERSION/runtime-$ARCH" \
      "runtime-$RUNTIME_VERSION-$ARCH" "$RUNTIME_SHA"
chmod +x "$TOOLS/appimagetool-$APPIMAGETOOL_VERSION-$ARCH.AppImage"

echo "==> Packing AppImage"
mkdir -p dist
OUT="dist/Locksmith-$ARCH.AppImage"
rm -f "$OUT"   # appimagetool refuses to overwrite an existing image
ARCH="$ARCH" APPIMAGE_EXTRACT_AND_RUN=1 "$TOOLS/appimagetool-$APPIMAGETOOL_VERSION-$ARCH.AppImage" \
    --no-appstream --runtime-file "$TOOLS/runtime-$RUNTIME_VERSION-$ARCH" -n "$APPDIR" "$OUT" >/dev/null
chmod +x "$OUT"

if [ "${SKIP_TESTS:-0}" != "1" ]; then
    echo "==> Self-testing the AppImage"
    "$OUT" --self-test | tail -1
fi
echo "==> Built $OUT ($(du -h "$OUT" | cut -f1), needs glibc $FLOOR+ and libstdc++ $CXX_FLOOR+)"
