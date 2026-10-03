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
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
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

MAGICS = {b"LOCKED\x00\x01": 1, b"LOCKED\x00\x02": 2}
LABELS = {1: b"locksmith/v1/", 2: b"locksmith/v2/"}
LABEL = LABELS[1]   # signing keys and detached signatures (sections 13, 14) keep the v1 labels
FIXED_FIELDS = {"v", "suite", "chunk", "np", "salt", "meta"}
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


def _slot_keys(slot: dict, label: bytes, password, keyfile, identity):
    """Yield (KEK, slot kind) candidates this slot could be opened with."""
    if slot["t"] == "pw" and (password is not None or keyfile is not None) and slot["kf"] == (keyfile is not None):
        secret = unicodedata.normalize("NFC", password or "").encode()
        base = kdf(slot["kdf"], slot["p"], secret, b64(slot["salt"]))
        extra = hashlib.sha512(keyfile).digest() if keyfile is not None else b""
        yield hkdf(base + extra, 32, b64(slot["salt"]), label + b"pw" + (b"+keyfile" if extra else b"")), b"pw"
    elif slot["t"] in ("x25519", "x25519-mlkem768") and identity is not None:
        sk = X25519PrivateKey.from_private_bytes(identity[:32])
        x_pub = sk.public_key().public_bytes_raw()
        epk = b64(slot["epk"])
        ss_x = sk.exchange(X25519PublicKey.from_public_bytes(epk))
        if slot["t"] == "x25519":
            yield hkdf(ss_x, 32, epk + x_pub, label + b"x25519"), b"x25519"
        elif len(identity) == 96:
            mlkem = MLKEM768PrivateKey.from_seed_bytes(identity[32:])
            kct = b64(slot["kct"])
            full_pub = x_pub + mlkem.public_key().public_bytes_raw()
            transcript = hashlib.sha256(epk + kct + full_pub).digest()
            yield hkdf(mlkem.decapsulate(kct) + ss_x, 32, transcript, label + b"x25519-mlkem768"), b"x25519-mlkem768"


def _u32(blob: bytes, pos: int) -> int:
    return struct.unpack(">I", blob[pos:pos + 4])[0]


def read(blob: bytes, password: str | None = None, keyfile: bytes | None = None,
         identity: bytes | None = None, verifiers: tuple[bytes, ...] = ()) -> dict:
    """Decrypt a version 1 or 2 file. Returns the DEK, metadata, content, the parsed fixed header,
    the slots and, for a signed file, its signature ("valid" with the key, or "unknown")."""
    version = MAGICS[blob[:8]]
    label = LABELS[version]
    if version == 1:
        hlen = _u32(blob, 8)
        raw = blob[12:12 + hlen]
        h = json.loads(raw)
        assert h["v"] == 1
        slots, kc, pos = h["slots"], b64(h["kc"]), 12 + hlen
        commit_info = label + b"commit"
    else:
        kc = blob[8:40]
        flen = _u32(blob, 40)
        raw = blob[44:44 + flen]
        h = json.loads(raw)
        assert set(h) == FIXED_FIELDS and h["v"] == 2, "bad fixed header"
        slen = _u32(blob, 44 + flen)
        slots = json.loads(blob[48 + flen:48 + flen + slen])
        pos = 48 + flen + slen
        commit_info = label + b"commit" + hashlib.sha256(raw).digest()
    salt = b64(h["salt"])
    dek = None
    for slot in slots:
        for kek, kind in _slot_keys(slot, label, password, keyfile, identity):
            try:
                candidate = AESGCM(kek).decrypt(b64(slot["n"]), b64(slot["w"]), label + b"slot/" + kind)
            except InvalidTag:
                continue
            if hkdf(candidate, 32, salt, commit_info) == kc:
                dek = candidate
        if dek:
            break
    assert dek is not None, "no slot opened"

    meta = json.loads(AESGCM(hkdf(dek, 32, salt, label + b"meta")).decrypt(
        b64(h["meta"]["n"]), b64(h["meta"]["c"]), label + b"meta"))
    layers = []
    for i, name in enumerate(SUITES[h["suite"]]):
        key = hkdf(dek, 64 if name == "aes-siv" else 32, salt, label + f"layer/{i}/{name}".encode())
        layers.append((name, AESSIV(key) if name == "aes-siv" else AEADS[name](key)))

    prefix, aad = b64(h["np"]), hashlib.sha256(raw).digest()
    cts = []
    while pos < len(blob):
        n = _u32(blob, pos)
        cts.append(blob[pos + 4:pos + 4 + n])
        pos += 4 + n
    content, signature, stage = b"", b"", 0   # stage: 0 content, 1 padding, 2 signature
    for i, ct in enumerate(cts):
        nonce = prefix + struct.pack(">I", i) + (b"\x01" if i == len(cts) - 1 else b"\x00")
        for name, aead in reversed(layers):
            ct = aead.decrypt(ct, [aad, nonce]) if name == "aes-siv" else aead.decrypt(nonce, ct, aad)
        kind, n = struct.unpack(">BI", ct[:5])
        block = ct[5:5 + n]
        assert ct[5 + n:] == bytes(len(ct) - 5 - n), "padding must be zero"
        assert kind <= (3 if version == 2 else 2), "unknown frame kind"
        frame_stage = {0: 0, 1: 0, 2: 1, 3: 2}[kind]
        assert frame_stage >= stage and (i or frame_stage == 0), "frames out of order"
        stage = frame_stage
        if kind == 1:
            content += DECOMPRESS[meta["comp"]](block)
        elif kind == 0:
            content += block
        elif kind == 3:
            signature += block
    return {"dek": dek, "meta": meta, "content": content, "header": h, "slots": slots,
            "signature": _check_locked_signature(signature, raw, content, verifiers) if signature else None}


def _check_locked_signature(blob: bytes, fixed: bytes, content: bytes, verifiers) -> dict:
    """Section 15: verify a signed file's signature with whichever trusted key made it."""
    assert len(blob) == 3424 and blob[:8] == SIG_MAGIC and blob[8] == 1, "bad signature"
    created, key_id, clen = struct.unpack(">Q32sH", blob[9:51])
    assert clen == 0, "a signed file's signature has no comment"
    key = next((k for k in verifiers if len(k) == 3200 and hashlib.sha256(k).digest() == key_id), None)
    if key is None:
        return {"status": "unknown", "key_id": key_id, "created": created}
    label = LABELS[2]
    m = label + b"sig/locked" + b"\x00" + blob[:51] + hashlib.sha256(fixed).digest() + hashlib.sha512(content).digest()
    try:
        Ed25519PublicKey.from_public_bytes(key[1216:1248]).verify(blob[51:115], m)
        MLDSA65PublicKey.from_public_bytes(key[1248:]).verify(blob[115:], m, label + b"sig")
    except InvalidSignature:
        raise AssertionError("the file's signature does not verify") from None
    return {"status": "valid", "key": key, "key_id": key_id, "created": created}


# ── public keys, signing keys and detached signatures (sections 9, 13, 14) ──

PREFIXES = {32: "locksmith1", 1216: "locksmith2", 3200: "locksmith3"}
SIG_MAGIC = b"LOCKSIG\x01"
SIG_BEGIN, SIG_END = "-----BEGIN LOCKSMITH SIGNATURE-----", "-----END LOCKSMITH SIGNATURE-----"


def encode_public(raw: bytes) -> str:
    return PREFIXES[len(raw)] + base64.urlsafe_b64encode(raw + hashlib.sha256(raw).digest()[:4]).decode().rstrip("=")


def decode_public(text: str) -> bytes:
    for size, prefix in PREFIXES.items():
        if text.startswith(prefix):
            body = text[len(prefix):]
            blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            raw = blob[:-4]
            assert len(raw) == size and hashlib.sha256(raw).digest()[:4] == blob[-4:], "bad public key"
            return raw
    raise AssertionError("unknown prefix")


def fingerprint(raw: bytes) -> str:
    h = hashlib.sha256(raw).hexdigest()[:20].upper()
    return " ".join(h[i:i + 4] for i in range(0, 20, 4))


def qr_payload(raw: bytes) -> str:
    return "LOCKSMITH3:FP:" + hashlib.sha256(raw).hexdigest().upper()


def signing_seeds(raw: bytes) -> tuple[bytes, bytes]:
    """(Ed25519 seed, ML-DSA-65 seed) of a 96-byte hybrid private key."""
    assert len(raw) == 96, "only hybrid identities sign"
    return hkdf(raw, 32, b"", LABEL + b"sig/ed25519"), hkdf(raw, 32, b"", LABEL + b"sig/ml-dsa-65")


def public3(raw: bytes) -> bytes:
    """The locksmith3 raw public key of a 96-byte hybrid private key."""
    ed_seed, ml_seed = signing_seeds(raw)
    x = X25519PrivateKey.from_private_bytes(raw[:32]).public_key().public_bytes_raw()
    m = MLKEM768PrivateKey.from_seed_bytes(raw[32:]).public_key().public_bytes_raw()
    return (x + m + Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes_raw()
            + MLDSA65PrivateKey.from_seed_bytes(ml_seed).public_key().public_bytes_raw())


def signed_message(head: bytes, data: bytes) -> bytes:
    return LABEL + b"sig/file" + b"\x00" + head + hashlib.sha512(data).digest()


@dataclass
class Signature:
    created: int
    key_id: bytes
    comment: str
    head: bytes
    sig_ed: bytes
    sig_ml: bytes


def read_signature(text: str) -> Signature:
    assert len(text.encode()) <= 16 << 10
    start = text.index(SIG_BEGIN) + len(SIG_BEGIN)
    blob = b64("".join(text[start:text.index(SIG_END)].split()))
    assert blob[:8] == SIG_MAGIC and blob[8] == 1, "not an Ed25519 + ML-DSA-65 signature"
    created, key_id, clen = struct.unpack(">Q32sH", blob[9:51])
    assert clen <= 1024 and len(blob) == 3424 + clen, "wrong length"
    comment = blob[51:51 + clen].decode("utf-8")
    assert not any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in comment), "bad comment"
    head = blob[:51 + clen]
    return Signature(created, key_id, comment, head, blob[51 + clen:115 + clen], blob[115 + clen:])


def verify_signature(text: str, data: bytes, keys: list[bytes]) -> tuple[bytes, Signature]:
    """The locksmith3 raw key that made a valid signature over ``data``. Raises otherwise."""
    sig = read_signature(text)
    key = next(k for k in keys if hashlib.sha256(k).digest() == sig.key_id)
    assert len(key) == 3200, "only locksmith3 keys verify signatures"
    m = signed_message(sig.head, data)
    try:
        Ed25519PublicKey.from_public_bytes(key[1216:1248]).verify(sig.sig_ed, m)
        MLDSA65PublicKey.from_public_bytes(key[1248:]).verify(sig.sig_ml, m, LABEL + b"sig")
    except InvalidSignature:
        raise AssertionError("signature does not verify") from None
    return key, sig
