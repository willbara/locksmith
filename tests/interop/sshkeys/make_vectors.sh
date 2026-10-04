#!/usr/bin/env bash
# Make the SSH key pairs in this folder with the real ssh-keygen (run from the repository root):
#
#     tests/interop/sshkeys/make_vectors.sh
#
# They are test keys, made only for these tests and never used for anything else: their private
# halves are committed on purpose, so the tests can open files encrypted to them (FORMAT.md §3,
# "SSH Ed25519 recipients" and "SSH RSA recipient slot"). Protected copies use the passphrase in
# passphrase.txt. Only do this deliberately: tests/vectors/v2-ssh-recipients.locked is encrypted
# to these keys and must be made again with tests/vectors/make_ssh_vectors.py afterwards.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PASS="locksmith interop"
printf '%s\n' "$PASS" >"$HERE/passphrase.txt"
ssh -V 2>"$HERE/tool-version.txt"
rm -f "$HERE"/id_* "$HERE"/*.pub

ssh-keygen -q -t ed25519 -N '' -C locksmith-interop-ed25519 -f "$HERE/id_ed25519"
ssh-keygen -q -t rsa -b 3072 -N '' -C locksmith-interop-rsa3072 -f "$HERE/id_rsa3072"
ssh-keygen -q -t ecdsa -b 256 -N '' -C locksmith-interop-ecdsa -f "$HERE/id_ecdsa"
# The same keys protected by a passphrase: OpenSSH's own format (bcrypt-pbkdf) and, for RSA, PEM.
cp "$HERE/id_ed25519" "$HERE/id_ed25519_protected"
ssh-keygen -q -p -a 8 -N "$PASS" -P '' -f "$HERE/id_ed25519_protected"
cp "$HERE/id_rsa3072" "$HERE/id_rsa3072_protected"
ssh-keygen -q -p -a 8 -N "$PASS" -P '' -f "$HERE/id_rsa3072_protected"
cp "$HERE/id_rsa3072" "$HERE/id_rsa3072_protected.pem"
ssh-keygen -q -p -m PEM -N "$PASS" -P '' -f "$HERE/id_rsa3072_protected.pem"
rm -f "$HERE"/*_protected.pub "$HERE"/*_protected.pem.pub
echo "ok"
