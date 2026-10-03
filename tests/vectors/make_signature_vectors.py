"""Make the signing test vectors in this folder (run from the repository root):

    .venv/bin/python tests/vectors/make_signature_vectors.py

Written from docs/FORMAT.md sections 9, 13 and 14 with the independent reader, never
Locksmith's code. It signs with the "hybrid" identity already in vectors.json and leaves
every other vector untouched. Only do this deliberately: ML-DSA signing is randomised, so
each run makes different signatures, and the committed ones are the evidence that later
versions still verify signatures made to this specification.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent)]

import spec_reader  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey  # noqa: E402

SIGNED = b"Signed for the Locksmith test vectors.\n\xe2\x9c\x93 \x00\xff\n" * 3
CASES = [  # (signed file, its content, comment)
    ("signed.bin", SIGNED, "Release 1.0 ✓ — café"),
    ("signed-empty.bin", b"", ""),
]


def sign(raw: bytes, data: bytes, comment: str, created: int) -> str:
    ed_seed, ml_seed = spec_reader.signing_seeds(raw)
    key_id = hashlib.sha256(spec_reader.public3(raw)).digest()
    c = comment.encode()
    head = spec_reader.SIG_MAGIC + b"\x01" + struct.pack(">Q32sH", created, key_id, len(c)) + c
    m = spec_reader.signed_message(head, data)
    blob = (head + Ed25519PrivateKey.from_private_bytes(ed_seed).sign(m)
            + MLDSA65PrivateKey.from_seed_bytes(ml_seed).sign(m, spec_reader.LABEL + b"sig"))
    body = base64.b64encode(blob).decode()
    return "\n".join([spec_reader.SIG_BEGIN, *(body[i:i + 64] for i in range(0, len(body), 64)),
                      spec_reader.SIG_END]) + "\n"


def main():
    identities = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))["identities"]
    raw = bytes.fromhex(identities["hybrid"])
    ed_seed, ml_seed = spec_reader.signing_seeds(raw)
    public = spec_reader.public3(raw)
    created = int(time.time())
    out = {"signer": "hybrid", "ed25519_seed": ed_seed.hex(), "ml_dsa_65_seed": ml_seed.hex(),
           "ed25519_public": public[1216:1248].hex(),
           "ml_dsa_65_public_sha256": hashlib.sha256(public[1248:]).hexdigest(),
           "public_key": spec_reader.encode_public(public), "fingerprint": spec_reader.fingerprint(public),
           "qr": spec_reader.qr_payload(public), "signatures": []}
    for name, data, comment in CASES:
        (HERE / name).write_bytes(data)
        text = sign(raw, data, comment, created)
        (HERE / f"{name}.lsig").write_text(text, encoding="utf-8")
        key, sig = spec_reader.verify_signature(text, data, [public])
        assert key == public and sig.comment == comment
        out["signatures"].append({"file": name, "signature": f"{name}.lsig", "created": created,
                                  "comment": comment})
    (HERE / "signatures.json").write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
