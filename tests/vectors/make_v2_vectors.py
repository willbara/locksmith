"""Make the format version 2 test vectors in this folder (run from the repository root):

    .venv/bin/python tests/vectors/make_v2_vectors.py

The engine writes them; the second reader (spec_reader.py) records what they must
decrypt to, including each file's data key and, for signed files, the signature. The
password, keyfile and identities come from vectors.json, whose version 1 files this
leaves untouched. Only do this deliberately: encryption and ML-DSA signing are
randomised, so each run makes different files, and the committed ones are the evidence
that later versions still read files made by this one.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent.parent), str(HERE.parent)]

import spec_reader  # noqa: E402

from locksmith.core import engine, keys  # noqa: E402
from locksmith.core.engine import EncryptOptions  # noqa: E402

TEXT = b"Hello from the Locksmith version 2 test vectors.\n" * 3
DATA = bytes(range(256)) * 12   # 3072 bytes: several 1 KiB chunks


def main():
    base = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))
    password, keyfile = base["password"], bytes.fromhex(base["keyfile"])
    classical, hybrid = (bytes.fromhex(base["identities"][k]) for k in ("classical", "hybrid"))
    signer_public = spec_reader.public3(hybrid)
    pub = keys.public_from_private
    cases = [  # name, options, content, kind, unlock, signed
        ("v2-password-aes256gcm-zstd", dict(password=password, kdf="argon2id", preset="fast", compression="zstd"),
         TEXT, "text", {"password": password}, False),
        ("v2-signed-password-keyfile-chacha20-padme", dict(
            password=password, keyfile=True, kdf="scrypt", preset="fast", suite="chacha20-poly1305",
            compression="none", padding="padme", chunk_size=1024),
         DATA, "file", {"password": password, "keyfile": True}, True),
        ("v2-keyfile-only-aessiv-bz2", dict(keyfile=True, kdf="pbkdf2-sha512", preset="fast", suite="aes-256-siv",
                                            compression="bz2"),
         DATA, "file", {"keyfile": True}, False),
        ("v2-signed-x25519-aesgcmsiv-zlib", dict(recipients=[pub(classical)], suite="aes-256-gcm-siv",
                                                 compression="zlib", chunk_size=1024),
         DATA, "file", {"identity": "classical"}, True),
        ("v2-hybrid-ocb3-lzma-hidden-recipients", dict(recipients=[pub(hybrid)], suite="aes-256-ocb3",
                                                       compression="lzma", hide_recipients=True),
         TEXT, "text", {"identity": "hybrid"}, False),
        ("v2-signed-cascade2-password-and-recipient-64k", dict(
            password=password, recipients=[pub(classical)], kdf="pbkdf2-sha512", preset="fast", suite="cascade-2",
            compression="none", padding="64k", note="Signed note ✓"),
         TEXT, "text", {"identity": "classical"}, True),
    ]
    vectors = {"signer": "hybrid", "files": []}
    with tempfile.TemporaryDirectory() as tmp:
        kf = Path(tmp) / "keyfile"
        kf.write_bytes(keyfile)
        for name, options, content, kind, unlock, signed in cases:
            if options.pop("keyfile", False):
                options["keyfile"] = str(kf)
            opts = EncryptOptions(**options, signer=hybrid if signed else None)
            blob = engine.encrypt_bytes(content, opts, name=f"{name}.txt", kind=kind)
            (HERE / f"{name}.locked").write_bytes(blob)
            vectors["files"].append(_record(name, f"{name}.locked", blob, unlock, password, keyfile, classical,
                                            hybrid, signer_public))

        # A signed folder, armored, through encrypt_paths: the tar content and the armor wrapper.
        folder = Path(tmp) / "Project"
        (folder / "docs").mkdir(parents=True)
        (folder / "readme.txt").write_bytes(TEXT)
        (folder / "docs" / "data.bin").write_bytes(DATA)
        out = engine.encrypt_paths([folder], HERE, EncryptOptions(
            password=password, kdf="argon2id", preset="fast", suite="cascade-3", armor=True, compression="zstd",
            strip_metadata=True, signer=hybrid))
        target = HERE / "v2-signed-cascade3-folder-armored.locked.txt"
        out.replace(target)
        blob = spec_reader.dearmor(target.read_text(encoding="utf-8"))
        vectors["files"].append(_record("v2-signed-cascade3-folder-armored", target.name, blob,
                                        {"password": password}, password, keyfile, classical, hybrid, signer_public))
    (HERE / "v2-vectors.json").write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _record(name, file, blob, unlock, password, keyfile, classical, hybrid, signer_public) -> dict:
    ident = {"classical": classical, "hybrid": hybrid}.get(unlock.get("identity"))
    r = spec_reader.read(blob, unlock.get("password"), keyfile if unlock.get("keyfile") else None, ident,
                         verifiers=(signer_public,))
    meta = {k: v for k, v in r["meta"].items() if k != "created"}
    sig = r["signature"]
    assert sig is None or sig["status"] == "valid"
    return {"name": name, "file": file, "unlock": unlock, "suite": r["header"]["suite"],
            "slots": len(r["slots"]), "dek": r["dek"].hex(), "meta": meta,
            "content_sha256": hashlib.sha256(r["content"]).hexdigest(), "content_size": len(r["content"]),
            "signed_at": sig["created"] if sig else None}


if __name__ == "__main__":
    main()
