"""Make the recipient-list ("to", FORMAT.md §7) test vector in this folder (run from the
repository root):

    .venv/bin/python tests/vectors/make_addressed_vectors.py

One signed file, addressed to the classical identity of vectors.json and then given a slot for
the hybrid identity, as someone forwarding it would. The second reader (spec_reader.py)
records what each reader is told. Every other vector is left untouched. Only do this
deliberately: the committed file is the evidence that later versions read it the same way.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent.parent), str(HERE.parent)]

import spec_reader  # noqa: E402

from locksmith.core import engine, keys  # noqa: E402
from locksmith.core.engine import AccessChange, DecryptKeys, EncryptOptions  # noqa: E402

NAME = "v2-signed-addressed-forwarded"
TEXT = b"Addressed to one person, then forwarded to another.\n"


def main():
    base = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
    password = base["password"]
    classical, hybrid = (bytes.fromhex(base["identities"][k]) for k in ("classical", "hybrid"))
    pub = keys.public_from_private
    blob = engine.encrypt_bytes(TEXT, EncryptOptions(
        password=password, recipients=[pub(classical)], kdf="pbkdf2-sha512", preset="fast", signer=hybrid,
        address_to=True), name=f"{NAME}.txt", kind="text")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "f.locked"
        path.write_bytes(blob)
        engine.change_access(path, DecryptKeys(identities=[classical]), AccessChange(add_recipients=[pub(hybrid)]))
        blob = path.read_bytes()
    (HERE / f"{NAME}.locked").write_bytes(blob)

    signer = spec_reader.public3(hybrid)
    readers = []
    for who, unlock in (("classical", {"identity": "classical"}), ("hybrid", {"identity": "hybrid"}),
                        ("password", {"password": password})):
        ident = {"classical": classical, "hybrid": hybrid}.get(unlock.get("identity"))
        r = spec_reader.read(blob, unlock.get("password"), None, ident, verifiers=(signer,))
        own = [pub(ident)] if ident else []
        assert r["content"] == TEXT and r["signature"]["status"] == "valid"
        readers.append({"reader": who, "unlock": unlock, "intent": spec_reader.addressed(r, own)})
    r = spec_reader.read(blob, password, verifiers=(signer,))
    vector = {"name": NAME, "file": f"{NAME}.locked", "signer": "hybrid", "slots": len(r["slots"]),
              "to": [base64.b64decode(e).hex() for e in r["meta"]["to"]],
              "content_sha256": hashlib.sha256(TEXT).hexdigest(), "readers": readers}
    assert [x["intent"] for x in readers] == ["listed", "not_listed", "password"]
    (HERE / "addressed-vectors.json").write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
