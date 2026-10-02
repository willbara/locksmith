"""An independent reader for the Locksmith file format, written from docs/FORMAT.md.

It uses only the standard library and `cryptography`, never the engine, so the test
vectors check the specification and the engine against each other.
"""

from __future__ import annotations

import base64
import bz2
import hashlib
import json
import lzma
import struct
import unicodedata
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, AESOCB3, AESSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    from compression import zstd
except ImportError:
    from backports import zstd

MAGIC = b"LOCKED\x00\x01"
LABEL = b"locksmith/v1/"
HYBRID_LABEL = b"locksmith/v1/x25519-mlkem768"
SUITES = {
    "aes-256-gcm": ["aes-gcm"], "chacha20-poly1305": ["chacha20"], "aes-256-gcm-siv": ["aes-gcm-siv"],
    "aes-256-ocb3": ["aes-ocb3"], "aes-256-siv": ["aes-siv"], "cascade-2": ["aes-gcm", "chacha20"],
    "cascade-3": ["aes-gcm", "chacha20", "aes-ocb3"],
}
AEADS = {"aes-gcm": AESGCM, "chacha20": ChaCha20Poly1305, "aes-gcm-siv": AESGCMSIV, "aes-ocb3": AESOCB3}
DECOMPRESS = {"zstd": zstd.decompress, "zlib": zlib.decompress, "bz2": bz2.decompress,
              "lzma": lambda b: lzma.decompress(b, format=lzma.FORMAT_XZ)}


def hkdf(ikm: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA512(), length, salt, info).derive(ikm)


def b64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def dearmor(text: str) -> bytes:
    start = text.index("-----BEGIN LOCKSMITH MESSAGE-----") + len("-----BEGIN LOCKSMITH MESSAGE-----")
    return b64("".join(text[start:text.index("-----END LOCKSMITH MESSAGE-----")].split()))


def kdf(name: str, p: dict, secret: bytes, salt: bytes) -> bytes:
    if name == "argon2id":
        return Argon2id(salt=salt, length=32, iterations=p["t"], lanes=p["p"], memory_cost=p["m"]).derive(secret)
    if name == "scrypt":
        return Scrypt(salt=salt, length=32, n=p["n"], r=p["r"], p=p["p"]).derive(secret)
    return PBKDF2HMAC(hashes.SHA512(), 32, salt, p["i"]).derive(secret)


def _slot_keys(slot: dict, password, keyfile, identity):
    """Yield (KEK, slot kind) candidates this slot could be opened with."""
    if slot["t"] == "pw" and (password is not None or keyfile is not None) and slot["kf"] == (keyfile is not None):
        secret = unicodedata.normalize("NFC", password or "").encode()
        base = kdf(slot["kdf"], slot["p"], secret, b64(slot["salt"]))
        extra = hashlib.sha512(keyfile).digest() if keyfile is not None else b""
        yield hkdf(base + extra, 32, b64(slot["salt"]), LABEL + b"pw" + (b"+keyfile" if extra else b"")), b"pw"
    elif slot["t"] in ("x25519", "x25519-mlkem768") and identity is not None:
        sk = X25519PrivateKey.from_private_bytes(identity[:32])
        x_pub = sk.public_key().public_bytes_raw()
        epk = b64(slot["epk"])
        ss_x = sk.exchange(X25519PublicKey.from_public_bytes(epk))
        if slot["t"] == "x25519":
            yield hkdf(ss_x, 32, epk + x_pub, LABEL + b"x25519"), b"x25519"
        elif len(identity) == 96:
            mlkem = MLKEM768PrivateKey.from_seed_bytes(identity[32:])
            kct = b64(slot["kct"])
            full_pub = x_pub + mlkem.public_key().public_bytes_raw()
            transcript = hashlib.sha256(epk + kct + full_pub).digest()
            yield hkdf(mlkem.decapsulate(kct) + ss_x, 32, transcript, HYBRID_LABEL), b"x25519-mlkem768"


def read(blob: bytes, password: str | None = None, keyfile: bytes | None = None,
         identity: bytes | None = None) -> dict:
    """Decrypt a file. Returns the DEK, metadata, content and the parsed header."""
    assert blob[:8] == MAGIC
    (hlen,) = struct.unpack(">I", blob[8:12])
    raw = blob[12:12 + hlen]
    h = json.loads(raw)
    salt = b64(h["salt"])
    dek = None
    for slot in h["slots"]:
        for kek, kind in _slot_keys(slot, password, keyfile, identity):
            try:
                candidate = AESGCM(kek).decrypt(b64(slot["n"]), b64(slot["w"]), LABEL + b"slot/" + kind)
            except InvalidTag:
                continue
            if hkdf(candidate, 32, salt, LABEL + b"commit") == b64(h["kc"]):
                dek = candidate
        if dek:
            break
    assert dek is not None, "no slot opened"

    meta = json.loads(AESGCM(hkdf(dek, 32, salt, LABEL + b"meta")).decrypt(
        b64(h["meta"]["n"]), b64(h["meta"]["c"]), LABEL + b"meta"))
    layers = []
    for i, name in enumerate(SUITES[h["suite"]]):
        key = hkdf(dek, 64 if name == "aes-siv" else 32, salt, LABEL + f"layer/{i}/{name}".encode())
        layers.append((name, AESSIV(key) if name == "aes-siv" else AEADS[name](key)))

    prefix, aad = b64(h["np"]), hashlib.sha256(raw).digest()
    pos, cts = 12 + hlen, []
    while pos < len(blob):
        (n,) = struct.unpack(">I", blob[pos:pos + 4])
        cts.append(blob[pos + 4:pos + 4 + n])
        pos += 4 + n
    content = b""
    for i, ct in enumerate(cts):
        nonce = prefix + struct.pack(">I", i) + (b"\x01" if i == len(cts) - 1 else b"\x00")
        for name, aead in reversed(layers):
            ct = aead.decrypt(ct, [aad, nonce]) if name == "aes-siv" else aead.decrypt(nonce, ct, aad)
        kind, n = struct.unpack(">BI", ct[:5])
        block = ct[5:5 + n]
        assert ct[5 + n:] == bytes(len(ct) - 5 - n), "padding must be zero"
        if kind == 1:
            content += DECOMPRESS[meta["comp"]](block)
        elif kind == 0:
            content += block
    return {"dek": dek, "meta": meta, "content": content, "header": h}
