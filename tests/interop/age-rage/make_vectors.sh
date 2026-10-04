#!/usr/bin/env bash
# Make age files with rage (through its Python bindings, pyrage) for the SSH test keys in
# tests/interop/sshkeys (run from the repository root):
#
#     tests/interop/age-rage/make_vectors.sh
#
# pyrage is installed into a temporary virtual environment and removed afterwards; it is not a
# Locksmith dependency. The age test kit (age-cctv) has no SSH vectors, so these show that
# Locksmith reads ssh-ed25519 and ssh-rsa stanzas as another implementation writes them. Only do
# this deliberately: the committed files are the evidence.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
KEYS="$HERE/../sshkeys"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
python3 -m venv "$TMP/venv"
"$TMP/venv/bin/pip" install -q "pyrage==1.3.0"
"$TMP/venv/bin/python" - "$HERE" "$KEYS" <<'PY'
import sys
from pathlib import Path

import pyrage

here, keys = Path(sys.argv[1]), Path(sys.argv[2])
(here / "message.txt").write_bytes(b"Encrypted by rage for the Locksmith interop tests.\n" * 2000)
data = (here / "message.txt").read_bytes()
for name in ("ed25519", "rsa3072"):
    recipient = pyrage.ssh.Recipient.from_str((keys / f"id_{name}.pub").read_text().strip())
    (here / f"{name}.age").write_bytes(pyrage.encrypt(data, [recipient]))
    identity = pyrage.ssh.Identity.from_buffer((keys / f"id_{name}").read_bytes())
    assert pyrage.decrypt((here / f"{name}.age").read_bytes(), [identity]) == data
(here / "tool-version.txt").write_text("pyrage 1.3.0 (rage)\n")
print("ok")
PY
