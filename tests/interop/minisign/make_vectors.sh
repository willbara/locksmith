#!/usr/bin/env bash
# Make the minisign interop vectors in this folder with the real minisign
# (run from the repository root):
#
#     MINISIGN=/path/to/minisign tests/interop/minisign/make_vectors.sh
#
# Only do this deliberately: the committed files are evidence that Locksmith reads
# signatures made by minisign. Secret keys are made in a temporary folder without a
# password and deleted; only public keys, the signed files and the signatures are kept.
set -euo pipefail

MINISIGN="${MINISIGN:-minisign}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

"$MINISIGN" -v >"$HERE/tool-version.txt"
printf 'Signed by minisign for the Locksmith interop tests.\n\xe2\x9c\x93 \x00\xff\n' >"$HERE/message.bin"
: >"$HERE/empty.bin"

for name in key other; do
    "$MINISIGN" -G -W -p "$HERE/$name.pub" -s "$TMP/$name.key" >/dev/null
done

sign() {  # output, file, options...
    local out="$1" file="$2"; shift 2
    "$MINISIGN" -S -s "$TMP/key.key" -m "$HERE/$file" -x "$HERE/$out" "$@" >/dev/null
}

sign default.minisig message.bin
sign comment.minisig message.bin -c "<b>untrusted</b>" -t $'release 1.0\tfile:message.bin \xe2\x9c\x93'
sign not-utf8.minisig message.bin -t $'latin-1 caf\xe9'
sign legacy.minisig message.bin -l -t "legacy"
sign empty.minisig empty.bin -t "empty"

# minisign's own verdicts, for the record.
for sig in "$HERE"/*.minisig; do
    file=message.bin; [[ "$sig" == */empty.minisig ]] && file=empty.bin
    "$MINISIGN" -V -q -p "$HERE/key.pub" -m "$HERE/$file" -x "$sig"
done
echo "ok: minisign verifies every signature"
