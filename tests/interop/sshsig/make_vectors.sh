#!/usr/bin/env bash
# Make the SSH signature interop vectors in this folder with the real ssh-keygen
# (run from the repository root):
#
#     tests/interop/sshsig/make_vectors.sh
#
# Only do this deliberately: the committed files are evidence that Locksmith reads
# signatures made by OpenSSH. Private keys are made in a temporary folder and deleted;
# only public keys, the signed files and the signatures are kept.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ssh -V 2>"$HERE/tool-version.txt"
printf 'Signed by ssh-keygen for the Locksmith interop tests.\n\xe2\x9c\x93 \x00\xff\n' >"$HERE/message.bin"
: >"$HERE/empty.bin"

key() {   # name, ssh-keygen type options...
    local name="$1"; shift
    ssh-keygen -q -N '' -C "locksmith-interop-$name" -f "$TMP/$name" "$@"
    cp "$TMP/$name.pub" "$HERE/$name.pub"
}

sign() {  # key name, file, output, extra options...
    local name="$1" file="$2" out="$3"; shift 3
    ssh-keygen -q -Y sign -f "$TMP/$name" "$@" <"$HERE/$file" >"$HERE/$out"
}

key ed25519 -t ed25519
key rsa3072 -t rsa -b 3072
key rsa1024 -t rsa -b 1024
key ecdsa256 -t ecdsa -b 256
key ecdsa384 -t ecdsa -b 384
key ecdsa521 -t ecdsa -b 521

sign ed25519 message.bin ed25519.sig -n file
sign ed25519 message.bin ed25519-sha256.sig -n file -O hashalg=sha256
sign ed25519 message.bin ed25519-git.sig -n git
sign ed25519 empty.bin ed25519-empty.sig -n file
sign rsa3072 message.bin rsa3072.sig -n file
sign rsa1024 message.bin rsa1024.sig -n file
sign ecdsa256 message.bin ecdsa256.sig -n file
sign ecdsa384 message.bin ecdsa384.sig -n file
sign ecdsa521 message.bin ecdsa521.sig -n file

# ssh-keygen's own verdicts, for the record.
for sig in "$HERE"/*.sig; do
    name="$(basename "$sig" .sig)"
    keyname="${name%%-*}"
    file=message.bin; [[ "$name" == *-empty ]] && file=empty.bin
    ns=file; [[ "$name" == *-git ]] && ns=git
    printf 'locksmith %s\n' "$(cat "$HERE/$keyname.pub")" >"$TMP/allowed"
    ssh-keygen -Y verify -f "$TMP/allowed" -I locksmith -n "$ns" -s "$sig" <"$HERE/$file" >/dev/null
done
echo "ok: ssh-keygen verifies every signature"
