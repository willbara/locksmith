#!/usr/bin/env bash
# Make the OpenPGP signature interop vectors in this folder with the real GnuPG (run from the
# repository root):
#
#     tests/interop/openpgp/make_vectors.sh
#
# Keys are made in a temporary GNUPGHOME and deleted; only public keys, the signed files and the
# detached signatures are kept. Only do this deliberately: the committed files are evidence that
# Locksmith reads signatures made by GnuPG.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
export GNUPGHOME="$(mktemp -d)"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
G=(gpg --batch --quiet --pinentry-mode loopback --passphrase "")

gpg --version | head -2 >"$HERE/tool-version.txt"
rm -f "$HERE"/*.asc "$HERE"/*.sig "$HERE"/*.gpg
printf 'Signed by GnuPG for the Locksmith interop tests.\n\xe2\x9c\x93 \x00\xff\n' >"$HERE/message.bin"
printf 'Text mode:\nline two\r\nline three without a newline' >"$HERE/message.txt"

key() {   # name, algo, usage, expiry
    "${G[@]}" --quick-gen-key "Locksmith interop $1 <$1@example.invalid>" "$2" "$3" "${4:-never}"
    "${G[@]}" --list-keys --with-colons "$1@example.invalid" | awk -F: '/^fpr/{print $10; exit}'
}
export_key() { "${G[@]}" --armor --export "$2" >"$HERE/$1.asc"; "${G[@]}" --export "$2" >"$HERE/$1.gpg"; }
sign() {  # key fingerprint, file, output, extra options...
    local fpr="$1" file="$2" out="$3"; shift 3
    "${G[@]}" --local-user "$fpr" "$@" --output "$HERE/$out" --detach-sign "$HERE/$file"
}

ED=$(key ed25519 ed25519 sign)
sign "$ED" message.bin ed25519.sig
sign "$ED" message.bin ed25519.sig.asc --armor
sign "$ED" message.bin ed25519-sha512.sig --digest-algo SHA512
sign "$ED" message.txt ed25519-text.sig --textmode
export_key ed25519 "$ED"

RSA=$(key rsa rsa3072 cert)
"${G[@]}" --quick-add-key "$RSA" rsa3072 sign
SUB=$("${G[@]}" --list-keys --with-colons "$RSA" | awk -F: '/^fpr/{n++} /^fpr/ && n==2 {print $10}')
sign "$SUB!" message.bin rsa-subkey.sig
export_key rsa "$RSA"

EC=$(key p256 nistp256 sign)
sign "$EC" message.bin p256.sig
export_key p256 "$EC"

# Made (and signed with) in 2020 with a one-day expiry: a good signature from a key that has expired since.
OLD=$("${G[@]}" --faked-system-time 20200101T000000 --quick-gen-key \
      "Locksmith interop expired <expired@example.invalid>" ed25519 sign 1d >/dev/null 2>&1;
      "${G[@]}" --list-keys --with-colons expired@example.invalid | awk -F: '/^fpr/{print $10; exit}')
sign "$OLD" message.bin expired.sig --faked-system-time 20200101T120000
export_key expired "$OLD"

# Revoked with the revocation certificate GnuPG writes when it makes a key.
REV=$(key revoked ed25519 sign)
sign "$REV" message.bin revoked.sig
sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$REV.rev" | "${G[@]}" --import
export_key revoked "$REV"

# GnuPG's own verdicts, for the record.
for sig in ed25519.sig ed25519.sig.asc ed25519-sha512.sig rsa-subkey.sig p256.sig; do
    "${G[@]}" --verify "$HERE/$sig" "$HERE/message.bin"
done
"${G[@]}" --verify "$HERE/ed25519-text.sig" "$HERE/message.txt"
echo "ok: GnuPG verifies every signature"
