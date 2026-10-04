#!/usr/bin/env bash
# Build the AppImage twice from the same source and check the results are byte-identical.
#
#     ./packaging/check_reproducible.sh
#
# Both builds use the pinned tools and hash-locked dependencies of build_appimage.sh and the
# same SOURCE_DATE_EPOCH (the last commit's time). Tests are skipped: they don't affect the output.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="$(uname -m)"
OUT="$ROOT/dist/Locksmith-$ARCH.AppImage"
KEEP="$(mktemp -d)"
# An AppImage already in dist/ is put back afterwards: this check shouldn't replace it.
if [ -f "$OUT" ]; then cp -p "$OUT" "$KEEP/previous.AppImage"; fi
restore() {
    if [ -f "$KEEP/previous.AppImage" ]; then cp -p "$KEEP/previous.AppImage" "$OUT"; fi
    rm -rf "$KEEP"
}
trap restore EXIT

for run in 1 2; do
    echo "==> Build $run of 2"
    SKIP_TESTS=1 "$ROOT/packaging/build_appimage.sh" >"$KEEP/build-$run.log" 2>&1 || {
        tail -20 "$KEEP/build-$run.log" >&2; exit 1; }
    cp "$OUT" "$KEEP/build-$run.AppImage"
done
A="$(sha256sum <"$KEEP/build-1.AppImage" | cut -d' ' -f1)"
B="$(sha256sum <"$KEEP/build-2.AppImage" | cut -d' ' -f1)"
if [ "$A" = "$B" ]; then
    echo "Reproducible: both builds are $A"
    exit 0
fi
echo "Not reproducible: $A and $B differ." >&2
for run in 1 2; do
    (cd "$KEEP" && "./build-$run.AppImage" --appimage-extract >/dev/null 2>&1 && mv squashfs-root "tree-$run")
done
diff -rq "$KEEP/tree-1" "$KEEP/tree-2" | head -20 >&2 || true
exit 1
