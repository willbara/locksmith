#!/usr/bin/env bash
# Copy the age test kit (C2SP CCTV, age/testdata) into testdata/ here (run from the repository root):
#
#     tests/interop/age-cctv/fetch.sh [commit]
#
# The vectors were made by the age authors with the reference implementation; they are
# available under 0BSD, CC0 1.0 or the Unlicense (see the kit's README). The commit they came
# from is recorded in commit.txt. Only update them deliberately.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone -q https://github.com/C2SP/CCTV "$TMP/cctv"
if [ $# -gt 0 ]; then git -C "$TMP/cctv" checkout -q "$1"; fi
rm -rf "$HERE/testdata"
cp -r "$TMP/cctv/age/testdata" "$HERE/testdata"
git -C "$TMP/cctv" rev-parse HEAD >"$HERE/commit.txt"
echo "ok: $(ls "$HERE/testdata" | wc -l) vectors from $(cat "$HERE/commit.txt")"
