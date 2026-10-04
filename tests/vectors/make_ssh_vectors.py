"""Make the SSH recipient test vector in this folder (run from the repository root):

    .venv/bin/python tests/vectors/make_ssh_vectors.py

One file encrypted to the SSH Ed25519 and RSA test keys in tests/interop/sshkeys (made by the
real ssh-keygen) and to the password of vectors.json, signed by its hybrid identity. The second
reader (spec_reader.py) records what it must decrypt to. Every other vector is left untouched.
Only do this deliberately: the committed file is the evidence that later versions still read it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_ssh_private_key

HERE = Path(__file__).resolve().parent
KEYS = HERE.parent / "interop" / "sshkeys"
sys.path[:0] = [str(HERE.parent.parent), str(HERE.parent)]

import spec_reader  # noqa: E402

from locksmith.core import engine, sshkeys  # noqa: E402
from locksmith.core.engine import EncryptOptions  # noqa: E402

NAME = "v2-ssh-recipients"
TEXT = b"Encrypted to two SSH keys made by ssh-keygen.\n"


def main():
    base = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
    password, hybrid = base["password"], bytes.fromhex(base["identities"]["hybrid"])
    ed = sshkeys.parse_recipient((KEYS / "id_ed25519.pub").read_text(encoding="utf-8"))
    rsa = sshkeys.parse_recipient((KEYS / "id_rsa3072.pub").read_text(encoding="utf-8"))
    blob = engine.encrypt_bytes(TEXT, EncryptOptions(
        password=password, recipients=[ed.raw, rsa.raw], kdf="pbkdf2-sha512", preset="fast", signer=hybrid,
        suite="chacha20-poly1305"), name=f"{NAME}.txt", kind="text")
    (HERE / f"{NAME}.locked").write_bytes(blob)

    signer = (spec_reader.public3(hybrid),)
    ed_key = load_ssh_private_key((KEYS / "id_ed25519").read_bytes(), None)
    rsa_key = load_ssh_private_key((KEYS / "id_rsa3072").read_bytes(), None)
    ed_identity = spec_reader.ssh_ed25519_identity(ed_key.private_bytes_raw())
    by_ed = spec_reader.read(blob, identity=ed_identity, verifiers=signer)
    by_rsa = spec_reader.read(blob, rsa_key=rsa_key, verifiers=signer)
    by_pw = spec_reader.read(blob, password, verifiers=signer)
    assert by_ed["dek"] == by_rsa["dek"] == by_pw["dek"] and by_ed["content"] == TEXT
    assert by_ed["opened_with"] == b"x25519" and by_rsa["opened_with"] == b"ssh-rsa"
    vector = {
        "name": NAME, "file": f"{NAME}.locked", "signer": "hybrid", "dek": by_pw["dek"].hex(),
        "slot_types": sorted(s["t"] for s in by_pw["slots"]),
        "ed25519_x25519_public": spec_reader.ssh_ed25519_to_x25519(ed_key.public_key().public_bytes_raw()).hex(),
        "rsa_blob_sha256": hashlib.sha256(spec_reader.ssh_rsa_blob(rsa_key.public_key())).hexdigest(),
        "rsa_blob": base64.b64encode(spec_reader.ssh_rsa_blob(rsa_key.public_key())).decode(),
        "content_sha256": hashlib.sha256(TEXT).hexdigest(),
    }
    (HERE / "ssh-vectors.json").write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
