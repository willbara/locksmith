"""Regenerate the test vectors in this folder (run from the repository root):

    .venv/bin/python tests/vectors/make_vectors.py

Only do this deliberately: the committed files are the evidence that every later
version still reads files made by this one. Encryption is randomised, so each run
produces different files; vectors.json records the inputs and expected results,
including each file's data key (DEK), which the second reader recovers.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent.parent), str(HERE.parent)]

import spec_reader  # noqa: E402

from locksmith.core import engine, keys  # noqa: E402
from locksmith.core.engine import EncryptOptions  # noqa: E402

PASSWORD = "correct horse battery staple ✓"
TEXT = b"Hello from the Locksmith test vectors.\n" * 3
DATA = bytes(range(256)) * 12   # 3072 bytes: several 1 KiB chunks


def main():
    keyfile = os.urandom(64)
    classical, hybrid = os.urandom(32), os.urandom(96)
    pub = keys.public_from_private
    cases = [
        ("password-aes256gcm-zstd", dict(password=PASSWORD, kdf="argon2id", preset="fast", compression="zstd"),
         TEXT, "text", {"password": PASSWORD}),
        ("password-keyfile-chacha20-padme", dict(password=PASSWORD, keyfile=True, kdf="scrypt", preset="fast",
                                                 suite="chacha20-poly1305", compression="none", padding="padme",
                                                 chunk_size=1024),
         DATA, "file", {"password": PASSWORD, "keyfile": True}),
        ("keyfile-only-aessiv-bz2", dict(keyfile=True, kdf="pbkdf2-sha512", preset="fast", suite="aes-256-siv",
                                         compression="bz2"),
         DATA, "file", {"keyfile": True}),
        ("x25519-aesgcmsiv-zlib", dict(recipients=[pub(classical)], suite="aes-256-gcm-siv", compression="zlib",
                                       chunk_size=1024),
         DATA, "file", {"identity": "classical"}),
        ("hybrid-ocb3-lzma-hidden-recipients", dict(recipients=[pub(hybrid)], suite="aes-256-ocb3",
                                                    compression="lzma", hide_recipients=True),
         TEXT, "text", {"identity": "hybrid"}),
        ("cascade2-password-and-recipient-64k", dict(password=PASSWORD, recipients=[pub(classical)],
                                                     kdf="pbkdf2-sha512", preset="fast", suite="cascade-2",
                                                     compression="none", padding="64k"),
         TEXT, "text", {"identity": "classical"}),
    ]
    vectors = {"password": PASSWORD, "keyfile": keyfile.hex(), "identities": {
        "classical": classical.hex(), "hybrid": hybrid.hex()}, "files": []}
    with tempfile.TemporaryDirectory() as tmp:
        kf = Path(tmp) / "keyfile"
        kf.write_bytes(keyfile)
        for name, options, content, kind, unlock in cases:
            if options.pop("keyfile", False):
                options["keyfile"] = str(kf)
            blob = engine.encrypt_bytes(content, EncryptOptions(**options), name=f"{name}.txt", kind=kind)
            (HERE / f"{name}.locked").write_bytes(blob)
            vectors["files"].append(_record(name, f"{name}.locked", blob, unlock, keyfile, classical, hybrid))

        # A folder, armored, through encrypt_paths: the tar content and the armor wrapper.
        folder = Path(tmp) / "Project"
        (folder / "docs").mkdir(parents=True)
        (folder / "readme.txt").write_bytes(TEXT)
        (folder / "docs" / "data.bin").write_bytes(DATA)
        out = engine.encrypt_paths([folder], HERE, EncryptOptions(
            password=PASSWORD, kdf="argon2id", preset="fast", suite="cascade-3", armor=True, compression="zstd",
            strip_metadata=True))  # no user name, ids or file times in the committed archive
        target = HERE / "cascade3-folder-armored.locked.txt"
        out.replace(target)
        blob = spec_reader.dearmor(target.read_text(encoding="utf-8"))
        vectors["files"].append(_record("cascade3-folder-armored", target.name, blob, {"password": PASSWORD},
                                        keyfile, classical, hybrid))
    (HERE / "vectors.json").write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _record(name, file, blob, unlock, keyfile, classical, hybrid) -> dict:
    ident = {"classical": classical, "hybrid": hybrid}.get(unlock.get("identity"))
    r = spec_reader.read(blob, unlock.get("password"), keyfile if unlock.get("keyfile") else None, ident)
    meta = {k: v for k, v in r["meta"].items() if k != "created"}
    return {"name": name, "file": file, "unlock": unlock, "suite": r["header"]["suite"],
            "slots": len(r["header"]["slots"]), "dek": r["dek"].hex(), "meta": meta,
            "content_sha256": hashlib.sha256(r["content"]).hexdigest(), "content_size": len(r["content"])}


if __name__ == "__main__":
    main()
