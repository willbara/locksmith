#!/usr/bin/env bash
# Run the built AppImage's self-test inside clean containers of other distros,
# with only standard desktop libraries installed. Requires podman.
#   ./packaging/test_distros.sh [image ...]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APPIMAGE="$ROOT/dist/Locksmith-$(uname -m).AppImage"
[ -f "$APPIMAGE" ] || { echo "Build the AppImage first: $APPIMAGE" >&2; exit 1; }

# image => expected result (pass or fail)
DEFAULT=(ubuntu:22.04=pass ubuntu:24.04=pass debian:12=pass rockylinux:9=pass fedora:41=pass
         archlinux:latest=pass debian:11=fail)
[ $# -gt 0 ] && DEFAULT=("$@")

DEB_LIBS="libgl1 libegl1 libfontconfig1 libfreetype6 libdbus-1-3 libxkbcommon0 libxkbcommon-x11-0
  libwayland-client0 libwayland-cursor0 libwayland-egl1 libx11-6 libx11-xcb1 libxcb1 libxcb-glx0
  libxcb-randr0 libxcb-render0 libxcb-shape0 libxcb-shm0 libxcb-sync1 libxcb-xfixes0 libxcb-xkb1
  zlib1g libzstd1 fonts-dejavu-core"
RPM_LIBS="mesa-libGL mesa-libEGL fontconfig freetype glib2 dbus-libs libxkbcommon libxkbcommon-x11
  libwayland-client libwayland-cursor libwayland-egl libX11 libX11-xcb libxcb zlib libzstd dejavu-sans-fonts"
ARCH_LIBS="libglvnd mesa fontconfig freetype2 glib2 dbus libxkbcommon libxkbcommon-x11 wayland libx11
  libxcb zlib zstd ttf-dejavu"

# Collapse the multi-line lists so they expand onto a single command line.
DEB_LIBS="$(echo $DEB_LIBS)"; RPM_LIBS="$(echo $RPM_LIBS)"; ARCH_LIBS="$(echo $ARCH_LIBS)"

# Package installation is allowed to fail (e.g. end-of-life repos); missing
# libraries are still caught by the ldd check below.
read -r -d '' INSIDE <<EOF
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq $DEB_LIBS >/dev/null
    apt-get install -y -qq libglib2.0-0t64 >/dev/null 2>&1 || apt-get install -y -qq libglib2.0-0 >/dev/null
elif command -v dnf >/dev/null; then
    dnf install -y -q $RPM_LIBS >/dev/null
elif command -v pacman >/dev/null; then
    pacman -Sy --noconfirm --needed $ARCH_LIBS >/dev/null 2>&1
fi
echo "glibc: \$(ldd --version | head -1 | grep -o '[0-9.]*\$')"
cd /tmp && /dist/app.AppImage --appimage-extract >/dev/null
missing=\$(find squashfs-root/usr/lib/locksmith -name '*.so*' -type f -exec ldd {} \; 2>/dev/null | grep 'not found' | sort -u || true)
[ -z "\$missing" ] || echo "missing host libraries: \$missing"
squashfs-root/AppRun --self-test 2>&1 | tail -3
EOF

status=0
for entry in "${DEFAULT[@]}"; do
    image="${entry%%=*}"; expect="${entry#*=}"
    [ "$expect" = "$image" ] && expect=pass
    printf '%-18s ' "$image"
    out="$(podman run --rm -v "$APPIMAGE:/dist/app.AppImage:ro,Z" "docker.io/library/$image" \
           bash -c "$INSIDE" 2>&1 || true)"
    [ "$image" = "rockylinux:9" ] && out="$(podman run --rm -v "$APPIMAGE:/dist/app.AppImage:ro,Z" \
           "docker.io/rockylinux/rockylinux:9" bash -c "$INSIDE" 2>&1 || true)"
    glibc="$(grep -o 'glibc: [0-9.]*' <<<"$out" | head -1)"
    if grep -q "SELF-TEST PASSED" <<<"$out"; then got=pass; else got=fail; fi
    # A system that is too old must be turned away with a clear message, not a crash.
    if [ "$got" = fail ] && [ "$expect" = fail ] && ! grep -q "needs a newer Linux system" <<<"$out"; then
        got="crash"
    fi
    if [ "$got" = "$expect" ]; then verdict="ok"; else verdict="UNEXPECTED"; status=1; fi
    printf '%-14s %-5s (expected %s) %s\n' "$glibc" "$got" "$expect" "$verdict"
    if [ "$verdict" != ok ] || [ "$got" = fail ]; then
        grep -E "missing host|GLIBC|FAIL|rror" <<<"$out" | head -3 | sed 's/^/    /'
    fi
done
exit $status
