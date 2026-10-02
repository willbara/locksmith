"""Streaming, chunked, authenticated encryption for files, folders and text.

Container layout (all integers big-endian)::

    magic      8 bytes   b"LOCKED\\x00\\x01"
    hdr_len    u32
    header     hdr_len bytes of UTF-8 JSON
    frames     repeated [u32 ct_len][ct]

A random 256-bit data key (DEK) encrypts the file. It is wrapped once per
"slot": a password slot (KDF + optional keyfile) and/or one slot per
recipient. Recipient slots are classical (X25519) or hybrid post-quantum
(X25519 + ML-KEM-768); a hybrid slot's key needs both shared secrets. Per-layer keys, the metadata key and a key-commitment value are
derived from the DEK with HKDF-SHA512.

Each frame's plaintext is ``[u8 kind][u32 len][block][zero padding]`` where
kind is 0 = raw, 1 = compressed, 2 = padding only. Frame ``i`` uses nonce
``prefix(7) || i(u32) || final(u8)`` and the SHA-256 of the header as
associated data, so frames cannot be reordered, dropped, truncated or moved
between files without detection.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import shutil
import struct
import tarfile
import threading
import time
import unicodedata
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import compress as comp
from . import kdf as kdfmod
from . import metadata, scratch
from .ciphers import NONCE_SIZE, SUITES, SuiteCipher, layer_key_sizes
from .errors import CancelledError, CorruptedError, LocksmithError, WrongKeyError
from .osutil import IS_WINDOWS, copy_zone_identifier, fsync_dir, fsync_tree, open_new, portable_name, windows_unsafe


@dataclass(frozen=True)
class Format:
    """A file format profile: its signature and the labels that domain-separate
    every derived key. A future format version adds a profile here."""
    name: str
    magic: bytes            # 8 bytes at the start of the file
    version: int            # must match the header's "v"
    label: bytes            # prefix for every HKDF / AEAD label
    hybrid_label: bytes
    allows_hybrid: bool


LOCKED = Format("Locksmith", b"LOCKED\x00\x01", 1, b"locksmith/v1/", b"locksmith/v1/x25519-mlkem768", True)
FORMATS = {f.magic: f for f in (LOCKED,)}
WRITE_FORMAT = LOCKED
MAGIC = LOCKED.magic


def looks_encrypted(head: bytes) -> bool:
    """True if the first bytes are a Locksmith signature."""
    return head[:6] == b"LOCKED"
HYBRID = "x25519-mlkem768"
X25519_LEN, MLKEM_PUBLIC_LEN, MLKEM_SEED_LEN, MLKEM_CT_LEN = 32, 1184, 64, 1088
EXTENSION = ".locked"
ARMOR_BEGIN = "-----BEGIN LOCKSMITH MESSAGE-----"
ARMOR_END = "-----END LOCKSMITH MESSAGE-----"


def is_encrypted_name(name: str) -> bool:
    return name.endswith(EXTENSION) or name.endswith(EXTENSION + ".txt")

MAX_HEADER = 1 << 20
MIN_CHUNK = 1 << 10
MAX_CHUNK = 64 << 20
MAX_SLOTS = 64
MAX_PASSWORD_ATTEMPTS = 4   # KDF runs per file; each may cost seconds and GiBs
MIN_KEYFILE_ONLY = 32       # bytes a keyfile needs when it is the only secret
MAX_FRAMES = 1 << 32        # the frame counter is 32 bits
# ASCII armor is built and parsed in memory (peak about 4x the size), so it is
# meant for messages and small files only.
MAX_ARMOR_INPUT = 64 << 20        # plaintext size accepted for armored output and in-memory messages
MAX_ARMOR_TEXT = 128 << 20        # armored text accepted when decrypting
NONCE_PREFIX = 7
FRAME_HDR = struct.Struct(">BI")
U32 = struct.Struct(">I")

KIND_RAW, KIND_COMPRESSED, KIND_PAD = 0, 1, 2

CHUNK_SIZES = {
    256 << 10: "256 KiB",
    1 << 20: "1 MiB",
    4 << 20: "4 MiB",
    16 << 20: "16 MiB",
}

PADDING = {
    "none": "None",
    "padme": "Padmé (≤12% overhead)",
    "64k": "Round up to 64 KiB",
    "1m": "Round up to 1 MiB",
    "pow2": "Next power of two",
}

Progress = Callable[[float | None, str], None]


# ── options & results ────────────────────────────────────────────────────────

@dataclass
class EncryptOptions:
    suite: str = "aes-256-gcm"
    kdf: str = "argon2id"
    preset: str = "balanced"
    compression: str = comp.DEFAULT_CODEC   # codec id, "none" or "auto"
    level: str = "balanced"
    chunk_size: int = 1 << 20
    padding: str = "none"
    threads: int = 0                        # 0 = automatic
    password: str | None = None
    keyfile: str | None = None
    recipients: list[bytes] = field(default_factory=list)  # raw X25519 keys
    hide_name: bool = False
    note: str = ""
    armor: bool = False
    strip_metadata: bool = False   # JPEG/PNG/WebP metadata, file times and archive owner names
    hide_recipients: bool = False  # pad recipient slots with dummies so their number is hidden


@dataclass
class DecryptKeys:
    password: str | None = None
    keyfile: str | None = None
    identities: list[bytes] = field(default_factory=list)  # raw X25519 private


@dataclass
class FileInfo:
    suite: str
    chunk_size: int
    password_slots: list[dict]
    recipient_slots: int
    needs_keyfile: bool
    header_size: int
    format_name: str = "Locksmith"
    post_quantum_slots: int = 0

    @property
    def suite_label(self) -> str:
        s = SUITES.get(self.suite)
        return s.label if s else self.suite


@dataclass
class DecryptResult:
    path: Path | None
    meta: dict
    data: bytes | None = None
    skipped: list[str] = field(default_factory=list)  # unsafe archive members left out
    # True only when everything was restored as stored and confirmed on disk, so the
    # source can be deleted. Anything skipped, renamed or not flushed makes it False.
    complete: bool = False


@dataclass
class Extraction:
    skipped: list[str] = field(default_factory=list)  # members left out
    renamed: list[str] = field(default_factory=list)  # members written under another name
    flushed: bool = False                             # every file and folder fsynced


# ── small helpers ────────────────────────────────────────────────────────────

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception as e:
        raise CorruptedError("The file header is damaged.") from e


def _hkdf(ikm: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA512(), length, salt, info).derive(ikm)


def _password_bytes(password: str | None) -> bytes:
    return unicodedata.normalize("NFC", password or "").encode()


def hash_keyfile(path: str) -> bytes:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            h.update(block)
    return h.digest()


def auto_threads(threads: int) -> int:
    return threads if threads > 0 else max(1, min(8, os.cpu_count() or 1))


def pad_target(size: int, mode: str) -> int:
    if mode == "padme":
        if size < 2:
            return size
        e = size.bit_length() - 1
        s = e.bit_length()
        mask = (1 << (e - s)) - 1
        return (size + mask) & ~mask
    if mode == "64k":
        return -(-size // (64 << 10)) * (64 << 10)
    if mode == "1m":
        return -(-size // (1 << 20)) * (1 << 20)
    if mode == "pow2":
        return 1 << max(0, (size - 1).bit_length())
    return size


def unique_path(path: Path) -> Path:
    # lexists: a dangling symlink counts as taken, so it is never replaced.
    if not os.path.lexists(path):
        return path
    stem, suffix = path.name, ""
    if path.is_file() or "." in path.name[1:]:
        stem, suffix = path.stem, path.suffix
    n = 1
    while True:
        candidate = path.with_name(f"{stem} ({n}){suffix}")
        if not os.path.lexists(candidate):
            return candidate
        n += 1


def _read_full(f: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = f.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def create_private(path: Path) -> BinaryIO:
    """Create a new file readable only by the owner. Never follows or reuses an
    existing path, so a planted symlink cannot redirect the write."""
    return os.fdopen(open_new(path), "wb")


def write_private(path: Path, data: bytes):
    with create_private(path) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def validate_options(opts: EncryptOptions):
    """Reject settings that would produce a file this version cannot read back."""
    if opts.suite not in SUITES:
        raise LocksmithError(f"Unknown cipher suite: {opts.suite}")
    if opts.kdf not in kdfmod.KDFS or opts.preset not in kdfmod.PRESETS:
        raise LocksmithError("Unknown key derivation setting.")
    if opts.compression not in ("auto", "none", *comp.CODECS):
        raise LocksmithError(f"Unknown compression method: {opts.compression}")
    if opts.level not in comp.LEVELS:
        raise LocksmithError(f"Unknown compression level: {opts.level}")
    if not (isinstance(opts.chunk_size, int) and MIN_CHUNK <= opts.chunk_size <= MAX_CHUNK):
        raise LocksmithError("Chunk size is out of range.")
    if opts.padding not in PADDING:
        raise LocksmithError(f"Unknown padding mode: {opts.padding}")
    if not (isinstance(opts.threads, int) and 0 <= opts.threads <= 256):
        raise LocksmithError("Thread count is out of range.")
    if not (opts.password or opts.keyfile or opts.recipients):
        raise LocksmithError("Add a password, a keyfile or at least one recipient.")
    if opts.keyfile:
        try:
            size = os.path.getsize(opts.keyfile)
        except OSError as e:
            raise LocksmithError(f"Cannot read the keyfile: {e.strerror}") from e
        if size == 0:
            raise LocksmithError("The keyfile is empty, so it adds no secret.")
        if not opts.password and size < MIN_KEYFILE_ONLY:
            raise LocksmithError(f"A keyfile used without a password must be at least "
                               f"{MIN_KEYFILE_ONLY} bytes of random data.")
    for rpk in opts.recipients:
        if not isinstance(rpk, bytes) or len(rpk) not in (X25519_LEN, X25519_LEN + MLKEM_PUBLIC_LEN):
            raise LocksmithError("A recipient's public key is invalid.")
    # The reader accepts at most MAX_SLOTS slots: never write a file it would refuse.
    opts.recipients = list(dict.fromkeys(opts.recipients))  # a repeated key adds nothing
    slots = len(opts.recipients) + bool(opts.password or opts.keyfile)
    if slots > MAX_SLOTS:
        raise LocksmithError(f"A file can have at most {MAX_SLOTS} ways to open it, counting the password "
                             f"as one. Choose fewer recipients (this needs {slots}).")


class _Checker:
    def __init__(self, cancel: threading.Event | None, progress: Progress | None):
        self.cancel = cancel
        self.progress = progress

    def check(self):
        if self.cancel is not None and self.cancel.is_set():
            raise CancelledError()

    def report(self, fraction: float | None, stage: str):
        if self.progress:
            self.progress(fraction, stage)


# ── key schedule ─────────────────────────────────────────────────────────────

class _Keys:
    def __init__(self, dek: bytes, salt: bytes, suite_id: str, fmt: Format):
        self.fmt = fmt
        suite = SUITES.get(suite_id)
        if suite is None:
            raise CorruptedError(f"Unsupported cipher suite: {suite_id}")
        layer_keys = [
            _hkdf(dek, size, salt, fmt.label + f"layer/{i}/{name}".encode())
            for i, (name, size) in enumerate(zip(suite.layers, layer_key_sizes(suite), strict=True))
        ]
        self.cipher = SuiteCipher(suite, layer_keys)
        self.meta_key = _hkdf(dek, 32, salt, fmt.label + b"meta")
        self.commitment = _hkdf(dek, 32, salt, fmt.label + b"commit")


def _password_kek(password: str | None, keyfile_hash: bytes | None, salt: bytes,
                  kdf: str, params: dict, fmt: Format) -> bytes:
    base = kdfmod.derive(_password_bytes(password), salt, kdf, params)
    info = fmt.label + b"pw" + (b"+keyfile" if keyfile_hash else b"")
    return _hkdf(base + (keyfile_hash or b""), 32, salt, info)


def _recipient_kek(shared: bytes, epk: bytes, rpk: bytes, fmt: Format) -> bytes:
    return _hkdf(shared, 32, epk + rpk, fmt.label + b"x25519")


def _hybrid_kek(ss_x: bytes, ss_m: bytes, epk: bytes, kem_ct: bytes, rpk: bytes, fmt: Format) -> bytes:
    """Combine both shared secrets: the result stays secret unless X25519 *and*
    ML-KEM are broken. The transcript (ephemeral key, KEM ciphertext, recipient's
    full public key) is bound in as well."""
    transcript = hashlib.sha256(epk + kem_ct + rpk).digest()
    return _hkdf(ss_m + ss_x, 32, transcript, fmt.hybrid_label)


def _x25519_exchange(sk: X25519PrivateKey, pk_raw: bytes) -> bytes:
    try:
        return sk.exchange(X25519PublicKey.from_public_bytes(pk_raw))
    except ValueError:
        raise LocksmithError("A recipient's public key is invalid (low-order point).") from None


def _wrap(kek: bytes, dek: bytes, kind: bytes, fmt: Format) -> tuple[bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(kek).encrypt(nonce, dek, fmt.label + b"slot/" + kind)


def _unwrap(kek: bytes, nonce: bytes, wrapped: bytes, kind: bytes, fmt: Format) -> bytes | None:
    try:
        return AESGCM(kek).decrypt(nonce, wrapped, fmt.label + b"slot/" + kind)
    except InvalidTag:
        return None


# ── header ───────────────────────────────────────────────────────────────────

def _build_header(opts: EncryptOptions, meta: dict, chk: _Checker,
                  fmt: Format = WRITE_FORMAT) -> tuple[bytes, _Keys]:
    validate_options(opts)
    dek = secrets.token_bytes(32)
    salt = os.urandom(32)
    keys = _Keys(dek, salt, opts.suite, fmt)
    slots = []

    if opts.password or opts.keyfile:
        chk.report(None, "Deriving key")
        kf_hash = hash_keyfile(opts.keyfile) if opts.keyfile else None
        psalt = kdfmod.new_salt()
        params = kdfmod.params_for(opts.kdf, opts.preset)
        kek = _password_kek(opts.password, kf_hash, psalt, opts.kdf, params, fmt)
        nonce, wrapped = _wrap(kek, dek, b"pw", fmt)
        slots.append({"t": "pw", "kdf": opts.kdf, "p": params, "salt": _b64(psalt),
                      "kf": bool(kf_hash), "n": _b64(nonce), "w": _b64(wrapped)})

    for rpk in opts.recipients:
        slots.append(_recipient_slot(rpk, dek, fmt))
    for rpk in _dummy_recipients(opts):
        # A genuine slot for a key that is thrown away at once, wrapping a random value:
        # it looks exactly like a real one, and nothing can ever open it.
        slots.append(_recipient_slot(rpk, secrets.token_bytes(32), fmt))

    # Shuffle so slot order leaks nothing about who was added first.
    secrets.SystemRandom().shuffle(slots)

    mnonce = os.urandom(NONCE_SIZE)
    mct = AESGCM(keys.meta_key).encrypt(
        mnonce, json.dumps(meta, separators=(",", ":")).encode(), fmt.label + b"meta")

    header = {
        "v": fmt.version,
        "suite": opts.suite,
        "chunk": opts.chunk_size,
        "np": _b64(os.urandom(NONCE_PREFIX)),
        "salt": _b64(salt),
        "kc": _b64(keys.commitment),
        "slots": slots,
        "meta": {"n": _b64(mnonce), "c": _b64(mct)},
    }
    raw = json.dumps(header, separators=(",", ":")).encode()
    # Hold the new header to the reader's rules, so a mismatch between writer and
    # reader fails here, before anything is written, not when the file is opened.
    if len(raw) > MAX_HEADER:
        raise LocksmithError("The note is too long to store in the file. Shorten it and try again.")
    try:
        _check_header(json.loads(raw), fmt)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise LocksmithError("These settings would make a file that can't be opened. "
                             "Nothing was written.") from e
    return raw, keys


def _recipient_slot(rpk: bytes, dek: bytes, fmt: Format) -> dict:
    eph = X25519PrivateKey.generate()
    epk = eph.public_key().public_bytes_raw()
    ss_x = _x25519_exchange(eph, rpk[:X25519_LEN])
    if len(rpk) == X25519_LEN:
        nonce, wrapped = _wrap(_recipient_kek(ss_x, epk, rpk, fmt), dek, b"x25519", fmt)
        return {"t": "x25519", "epk": _b64(epk), "n": _b64(nonce), "w": _b64(wrapped)}
    try:
        ss_m, kem_ct = MLKEM768PublicKey.from_public_bytes(rpk[X25519_LEN:]).encapsulate()
    except ValueError:
        raise LocksmithError("A recipient's post-quantum key is invalid.") from None
    kek = _hybrid_kek(ss_x, ss_m, epk, kem_ct, rpk, fmt)
    nonce, wrapped = _wrap(kek, dek, HYBRID.encode(), fmt)
    return {"t": HYBRID, "epk": _b64(epk), "kct": _b64(kem_ct), "n": _b64(nonce), "w": _b64(wrapped)}


def recipient_slot_target(real: int, password: bool) -> int:
    """How many recipient slots a file with ``real`` recipients gets when their number is
    hidden: the next of 8, 16, 32 or 64, keeping the whole file within MAX_SLOTS."""
    target = 8
    while target < real:
        target *= 2
    return max(real, min(target, MAX_SLOTS - password))


def _dummy_recipients(opts: EncryptOptions) -> list[bytes]:
    if not (opts.hide_recipients and opts.recipients):
        return []
    n = recipient_slot_target(len(opts.recipients), bool(opts.password or opts.keyfile)) - len(opts.recipients)
    # Same kind as the real recipients (post-quantum if any is), so the slot types reveal nothing more.
    hybrid = any(len(r) > X25519_LEN for r in opts.recipients)
    keys = []
    for _ in range(n):
        raw = X25519PrivateKey.generate().public_key().public_bytes_raw()
        if hybrid:
            raw += MLKEM768PrivateKey.generate().public_key().public_bytes_raw()
        keys.append(raw)
    return keys


def _read_header(f: BinaryIO) -> tuple[dict, bytes, Format]:
    magic = f.read(8)
    fmt = FORMATS.get(magic)
    if fmt is None:
        if magic[:6] == b"LOCKED":
            raise CorruptedError("This file was made by a newer version of Locksmith.")
        raise CorruptedError("This is not a Locksmith file.")
    raw_len = f.read(4)
    if len(raw_len) != 4:
        raise CorruptedError("The file is truncated.")
    (hlen,) = U32.unpack(raw_len)
    if hlen > MAX_HEADER:
        raise CorruptedError("The file header is damaged.")
    raw = f.read(hlen)
    if len(raw) != hlen:
        raise CorruptedError("The file is truncated.")
    try:
        header = json.loads(raw)
        _check_header(header, fmt)
    except CorruptedError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
        # RecursionError: deeply nested JSON, such as a header of 200,000 "[".
        raise CorruptedError("The file header is damaged.") from e
    return header, raw, fmt


def _b64len(value, n: int | None = None, max_len: int = 1 << 16) -> bytes:
    if not isinstance(value, str):
        raise ValueError
    raw = base64.b64decode(value, validate=True)
    if (n is not None and len(raw) != n) or len(raw) > max_len:
        raise ValueError
    return raw


def _check_header(h: dict, fmt: Format):
    """Validate every field's type and size up front, so later code never hits
    a malformed value from a crafted file."""
    if not isinstance(h, dict) or h.get("v") != fmt.version:
        raise ValueError
    chunk = h["chunk"]
    if isinstance(chunk, bool) or not (isinstance(chunk, int) and MIN_CHUNK <= chunk <= MAX_CHUNK):
        raise ValueError
    if h["suite"] not in SUITES:
        raise ValueError
    _b64len(h["np"], NONCE_PREFIX)
    _b64len(h["salt"], 32)
    _b64len(h["kc"], 32)
    _b64len(h["meta"]["n"], NONCE_SIZE)
    _b64len(h["meta"]["c"], max_len=MAX_HEADER)
    slots = h["slots"]
    if not isinstance(slots, list) or not 1 <= len(slots) <= MAX_SLOTS:
        raise ValueError
    for slot in slots:
        kind = slot["t"]
        _b64len(slot["n"], NONCE_SIZE)
        _b64len(slot["w"], 32 + 16)
        if kind == "pw":
            if not isinstance(slot["p"], dict) or not isinstance(slot.get("kf", False), bool):
                raise ValueError
            _b64len(slot["salt"], kdfmod.SALT_LEN)
            kdfmod.validate(slot["kdf"], slot["p"])
        elif kind == "x25519":
            _b64len(slot["epk"], X25519_LEN)
        elif kind == HYBRID and fmt.allows_hybrid:
            _b64len(slot["epk"], X25519_LEN)
            _b64len(slot["kct"], MLKEM_CT_LEN)
        else:
            raise ValueError


def _info_from_header(header: dict, raw: bytes, fmt: Format) -> FileInfo:
    pw = [s for s in header["slots"] if s.get("t") == "pw"]
    return FileInfo(
        suite=header["suite"],
        chunk_size=header["chunk"],
        password_slots=[{"kdf": s["kdf"], "params": s["p"], "keyfile": s.get("kf", False)}
                        for s in pw],
        recipient_slots=sum(1 for s in header["slots"] if s.get("t") in ("x25519", HYBRID)),
        post_quantum_slots=sum(1 for s in header["slots"] if s.get("t") == HYBRID),
        needs_keyfile=any(s.get("kf") for s in pw),
        header_size=len(raw),
        format_name=fmt.name,
    )


def inspect(path: str | Path) -> FileInfo:
    with _open_source(Path(path)) as f:
        header, raw, fmt = _read_header(f)
    return _info_from_header(header, raw, fmt)


def inspect_bytes(blob: bytes) -> FileInfo:
    header, raw, fmt = _read_header(io.BytesIO(blob))
    return _info_from_header(header, raw, fmt)


class _Identity:
    """A raw private key (classical or hybrid) prepared for unwrapping slots."""

    def __init__(self, raw: bytes):
        if len(raw) not in (X25519_LEN, X25519_LEN + MLKEM_SEED_LEN):
            raise LocksmithError("An identity's private key is damaged.")
        self.x25519 = X25519PrivateKey.from_private_bytes(raw[:X25519_LEN])
        self.x25519_public = self.x25519.public_key().public_bytes_raw()
        self.mlkem = MLKEM768PrivateKey.from_seed_bytes(raw[X25519_LEN:]) if len(raw) > X25519_LEN else None
        self.public = self.x25519_public + (self.mlkem.public_key().public_bytes_raw() if self.mlkem else b"")


def _unlock(header: dict, keys: DecryptKeys, chk: _Checker, fmt: Format) -> _Keys:
    salt = _unb64(header["salt"])
    commitment = _unb64(header["kc"])
    dek = None

    def committed(candidate: bytes | None) -> bytes | None:
        # A slot whose key fails the commitment is treated like a slot that didn't open:
        # the search goes on, and a tampered header reads as a wrong key, not a separate
        # error that tells a prober their slot unwrapped.
        if candidate is None:
            return None
        ok = hmac.compare_digest(_hkdf(candidate, 32, salt, fmt.label + b"commit"), commitment)
        return candidate if ok else None

    idents = [_Identity(raw) for raw in keys.identities]
    for slot in header["slots"]:
        if slot["t"] not in ("x25519", HYBRID) or not idents:
            continue
        epk = _unb64(slot["epk"])
        for ident in idents:
            try:
                ss_x = ident.x25519.exchange(X25519PublicKey.from_public_bytes(epk))
            except ValueError:
                continue
            if slot["t"] == "x25519":
                kek, kind = _recipient_kek(ss_x, epk, ident.x25519_public, fmt), b"x25519"
            elif ident.mlkem is not None:
                kem_ct = _unb64(slot["kct"])
                # ML-KEM never fails here: a wrong key yields a random secret
                # ("implicit rejection"), which the authenticated unwrap then rejects.
                ss_m = ident.mlkem.decapsulate(kem_ct)
                kek, kind = _hybrid_kek(ss_x, ss_m, epk, kem_ct, ident.public, fmt), HYBRID.encode()
            else:
                continue
            dek = committed(_unwrap(kek, _unb64(slot["n"]), _unb64(slot["w"]), kind, fmt))
            if dek:
                break
        if dek:
            break

    if dek is None and (keys.password or keys.keyfile):
        kf_hash = hash_keyfile(keys.keyfile) if keys.keyfile else None
        candidates = [s for s in header["slots"]
                      if s["t"] == "pw" and bool(s.get("kf")) == bool(kf_hash)]
        for slot in candidates[:MAX_PASSWORD_ATTEMPTS]:
            chk.check()
            chk.report(None, "Deriving key")
            kek = _password_kek(keys.password, kf_hash, _unb64(slot["salt"]),
                                slot["kdf"], slot["p"], fmt)
            dek = committed(_unwrap(kek, _unb64(slot["n"]), _unb64(slot["w"]), b"pw", fmt))
            if dek:
                break

    if dek is None:
        needs_kf = any(s.get("t") == "pw" and s.get("kf") for s in header["slots"])
        has_pw = any(s.get("t") == "pw" for s in header["slots"])
        if needs_kf and not keys.keyfile:
            raise WrongKeyError("This file also needs its keyfile.")
        if not has_pw:
            raise WrongKeyError("None of your identities can open this file.")
        raise WrongKeyError("Wrong password, keyfile or identity.")

    return _Keys(dek, salt, header["suite"], fmt)


# Expected type of each metadata field. The sender chooses the metadata, so a
# field of the wrong type (e.g. a list as "comp") is dropped rather than trusted.
_META_TYPES = {"name": str, "kind": str, "comp": str, "note": str, "size": int, "mtime": int,
               "created": int, "items": int}


def _read_meta(header: dict, keys: _Keys) -> dict:
    try:
        m = header["meta"]
        plain = AESGCM(keys.meta_key).decrypt(_unb64(m["n"]), _unb64(m["c"]),
                                              keys.fmt.label + b"meta")
        meta = json.loads(plain)
        if not isinstance(meta, dict):
            raise ValueError
    except (InvalidTag, KeyError, ValueError, RecursionError) as e:
        raise CorruptedError("The encrypted metadata is damaged.") from e
    return {k: v for k, v in meta.items()
            if k not in _META_TYPES or (isinstance(v, _META_TYPES[k]) and not isinstance(v, bool))}


# ── frame streams ────────────────────────────────────────────────────────────

def _nonce(prefix: bytes, index: int, final: bool) -> bytes:
    return prefix + U32.pack(index) + (b"\x01" if final else b"\x00")


def _encrypt_stream(src: BinaryIO, total: int, out: BinaryIO, header: bytes,
                    keys: _Keys, opts: EncryptOptions, codec_id: str, chk: _Checker,
                    max_input: int | None = None):
    hdr = json.loads(header)
    prefix = _unb64(hdr["np"])
    aad = hashlib.sha256(header).digest()
    chunk = opts.chunk_size
    codec = comp.CODECS.get(codec_id)
    level = codec.levels[opts.level] if codec else 0
    threads = auto_threads(opts.threads)
    batch = max(1, min(threads * 2, (256 << 20) // chunk))
    compressing = codec is not None

    def make_frame(block: bytes) -> bytes:
        if compressing and block:
            packed = codec.compress(block, level)
            if len(packed) < len(block):
                return FRAME_HDR.pack(KIND_COMPRESSED, len(packed)) + packed
        return FRAME_HDR.pack(KIND_RAW, len(block)) + block

    def seal(item: tuple[int, bytes, bool]) -> bytes:
        idx, frame, final = item
        if idx >= MAX_FRAMES:
            raise LocksmithError("File too large for this chunk size. Choose a larger chunk size.")
        return keys.cipher.seal(_nonce(prefix, idx, final), frame, aad)

    def write(ct: bytes):
        out.write(U32.pack(len(ct)))
        out.write(ct)

    out.write(keys.fmt.magic)
    out.write(U32.pack(len(header)))
    out.write(header)

    index = 0
    payload = 0
    done = 0
    pending: bytes | None = None
    started = time.monotonic()

    with ThreadPoolExecutor(threads) as pool:
        while True:
            chk.check()
            blocks = []
            for _ in range(batch):
                b = _read_full(src, chunk)
                if not b:
                    break
                blocks.append(b)
            if not blocks:
                break
            done += sum(map(len, blocks))
            # Checked on what is actually read: a folder's archive is larger than its
            # files, and a file can grow while it is read.
            if max_input is not None and done > max_input:
                raise LocksmithError(f"Text (ASCII armor) output is limited to {max_input >> 20} MiB. "
                                     "Turn off ASCII armor for larger files.")

            frames = list(pool.map(make_frame, blocks))
            # Adaptive compression: give up early on incompressible data.
            if compressing and index == 0 and pending is None:
                raw = sum(map(len, blocks))
                packed = sum(len(fr) - FRAME_HDR.size for fr in frames)
                if packed > raw * 0.97:
                    compressing = False

            if pending is not None:
                frames.insert(0, pending)
            pending = frames.pop()
            if frames:
                items = [(index + i, fr, False) for i, fr in enumerate(frames)]
                for ct in pool.map(seal, items):
                    write(ct)
                index += len(frames)
                payload += sum(map(len, frames))

            rate = done / max(time.monotonic() - started, 1e-6)
            chk.report(min(done / total, 1.0) if total else None,
                       f"Encrypting · {_rate(rate)}")

    # Final frames: the last data frame plus any size-hiding padding.
    if pending is None:
        pending = make_frame(b"")
    total_len = payload + len(pending)
    pad = pad_target(total_len, opts.padding) - total_len
    frame_cap = chunk + FRAME_HDR.size
    tail = [pending + bytes(min(pad, max(0, frame_cap - len(pending))))]
    pad -= len(tail[0]) - len(pending)
    while pad > 0:
        take = min(pad, frame_cap - FRAME_HDR.size)
        tail.append(FRAME_HDR.pack(KIND_PAD, 0) + bytes(take))
        pad -= take
    for i, fr in enumerate(tail):
        chk.check()
        write(seal((index + i, fr, i == len(tail) - 1)))


def _frames(f: BinaryIO, limit: int):
    """Yield (ciphertext, is_last) pairs, looking one frame ahead for EOF."""
    def read_one():
        raw = f.read(4)
        if not raw:
            return None
        if len(raw) != 4:
            raise CorruptedError("The file is truncated.")
        (n,) = U32.unpack(raw)
        if n > limit:
            raise CorruptedError("The file is damaged (frame too large).")
        ct = _read_full(f, n)
        if len(ct) != n:
            raise CorruptedError("The file is truncated.")
        return ct

    cur = read_one()
    if cur is None:
        raise CorruptedError("The file is truncated (no data).")
    while cur is not None:
        nxt = read_one()
        yield cur, nxt is None
        cur = nxt


def _decrypt_stream(f: BinaryIO, total: int, header: dict, raw_header: bytes,
                    keys: _Keys, meta: dict, out: BinaryIO, threads: int, chk: _Checker,
                    max_output: int | None = None):
    """Decrypt the frames after the header into ``out``. ``max_output`` caps the total
    plaintext: chunks are capped one by one, but many small chunks can still expand
    without limit, which matters when ``out`` is in memory."""
    prefix = _unb64(header["np"])
    aad = hashlib.sha256(raw_header).digest()
    chunk = header["chunk"]
    codec = comp.CODECS.get(meta.get("comp", "none"))
    limit = chunk + FRAME_HDR.size + keys.cipher.suite.overhead
    threads = auto_threads(threads)
    batch = max(1, min(threads * 2, (256 << 20) // chunk))

    def open_frame(item) -> tuple[int, bytes]:
        idx, ct, final = item
        if idx >= MAX_FRAMES:
            raise CorruptedError("The file has too many chunks.")
        try:
            frame = keys.cipher.open(_nonce(prefix, idx, final), ct, aad)
        except InvalidTag:
            raise CorruptedError(
                f"Authentication failed at chunk {idx + 1}: "
                "the file was modified, reordered or truncated.") from None
        if len(frame) < FRAME_HDR.size:
            raise CorruptedError("A chunk is malformed.")
        kind, n = FRAME_HDR.unpack_from(frame)
        end = FRAME_HDR.size + n
        block = frame[FRAME_HDR.size:end]
        # Everything after the block is padding and must be zero; a padding frame
        # carries no block. The writer never does otherwise, so reject any other layout.
        if len(block) != n or frame.count(0, end) != len(frame) - end or (kind == KIND_PAD and n):
            raise CorruptedError("A chunk is malformed.")
        if kind == KIND_COMPRESSED:
            if codec is None:
                raise CorruptedError("Unknown compression method.")
            return kind, codec.decompress(block, chunk)
        if kind in (KIND_RAW, KIND_PAD):
            return kind, block
        raise CorruptedError("A chunk is malformed.")

    index = 0
    written = 0
    padding = False     # padding frames come only after the last data frame
    started = time.monotonic()
    it = _frames(f, limit)
    with ThreadPoolExecutor(threads) as pool:
        while True:
            chk.check()
            items = []
            for ct, last in it:
                items.append((index + len(items), ct, last))
                if len(items) >= batch:
                    break
            if not items:
                break
            for kind, plain in pool.map(open_frame, items):
                if kind == KIND_PAD:
                    padding = True
                elif padding:
                    raise CorruptedError("A chunk is malformed.")
                else:
                    written += len(plain)
                    if max_output is not None and written > max_output:
                        raise CorruptedError(f"The content is larger than {max_output >> 20} MiB, "
                                             "the limit for messages opened in memory.")
                    out.write(plain)
            index += len(items)
            pos = f.tell() if f.seekable() else 0
            rate = pos / max(time.monotonic() - started, 1e-6)
            chk.report(min(pos / total, 1.0) if total else None, f"Decrypting · {_rate(rate)}")


def _rate(bps: float) -> str:
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1000:
            return f"{bps:.0f} {unit}"
        bps /= 1000
    return f"{bps:.1f} TB/s"


# ── sources: files, folders, bundles ─────────────────────────────────────────

class _TarStream(io.RawIOBase):
    """Streams a tar archive of the given paths without a temp file."""

    def __init__(self, items: list[tuple[Path, str]], strip: bool = False, stats: dict | None = None):
        super().__init__()
        self._strip = strip
        self._stats = stats if stats is not None else {}
        rfd, wfd = os.pipe()
        self._r = os.fdopen(rfd, "rb")
        self._w = os.fdopen(wfd, "wb")
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, args=(items,), daemon=True)
        self._thread.start()

    def _run(self, items):
        try:
            with tarfile.open(fileobj=self._w, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                for path, arcname in items:
                    if self._strip:
                        self._add_stripped(tar, Path(path), arcname)
                    else:
                        tar.add(str(path), arcname=arcname)
        except BrokenPipeError:
            pass
        except BaseException as e:  # surfaced to the reader
            self._error = e
        finally:
            try:
                self._w.close()
            except OSError:
                pass

    def _add_stripped(self, tar: tarfile.TarFile, path: Path, arcname: str):
        """Like tar.add, but strips image metadata and anonymises every entry
        (no user or group names or ids, no original timestamps)."""
        info = tar.gettarinfo(str(path), arcname)
        if info is None:  # sockets and similar cannot be archived
            return
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = int(time.time())
        if info.isreg():
            plan = metadata.plan_for(path)
            if plan is None:
                self._stats["unchanged"] = self._stats.get("unchanged", 0) + 1
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)
            else:
                self._stats["stripped"] = self._stats.get("stripped", 0) + 1
                info.size = plan.size
                with metadata.PlanReader(path, plan.plan) as fh:
                    tar.addfile(info, fh)
        elif info.isdir():
            tar.addfile(info)
            for child in sorted(os.listdir(path)):
                self._add_stripped(tar, path / child, f"{arcname}/{child}")
        else:
            tar.addfile(info)

    def readable(self):
        return True

    def read(self, n=-1):
        data = self._r.read(n)
        if not data:
            self._thread.join()
            if self._error:
                raise LocksmithError(f"Could not read folder: {self._error}")
        return data

    def close(self):
        self._r.close()
        self._thread.join(timeout=5)
        super().close()


def _tree_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size + 1024
    total = 0
    for root, dirs, files in os.walk(path):
        total += 512 * (len(dirs) + 1)
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name)) + 1024
            except OSError:
                pass
    return total


def _codec_for(opts: EncryptOptions, paths: list[Path]) -> str:
    if opts.compression == "auto":
        if len(paths) == 1 and paths[0].is_file() and \
                paths[0].suffix.lower() in comp.PRECOMPRESSED:
            return "none"
        return comp.DEFAULT_CODEC
    return opts.compression if opts.compression in comp.CODECS else "none"


def _output_name(opts: EncryptOptions, base: str) -> str:
    stem = secrets.token_hex(8) if opts.hide_name else base
    return stem + EXTENSION + (".txt" if opts.armor else "")


def encrypt_paths(paths: list[Path], out_dir: Path | None, opts: EncryptOptions,
                  bundle_name: str | None = None, progress: Progress | None = None,
                  cancel: threading.Event | None = None, verify: bool = False,
                  stats: dict | None = None) -> Path:
    """Encrypt one file, one folder, or several items bundled as one archive.

    With ``verify``, the written file is read back and every chunk is
    authenticated and decoded before it is moved into place. Callers that will
    delete the originals afterwards must pass ``verify=True``.

    With ``opts.strip_metadata``, ``stats`` (if given) receives counts of images
    "stripped" and files left "unchanged" because their format is not supported.
    """
    stats = stats if stats is not None else {}
    chk = _Checker(cancel, progress)
    validate_options(opts)
    paths = [Path(p) for p in paths]
    if not paths:
        raise LocksmithError("Nothing to encrypt.")
    for p in paths:
        if not p.exists():
            raise LocksmithError(f"{p.name} no longer exists.")
    out_dir = Path(out_dir) if out_dir else paths[0].parent
    resolved_out = out_dir.resolve()
    for p in paths:
        if p.is_dir() and resolved_out.is_relative_to(p.resolve()):
            raise LocksmithError(f"The output folder is inside “{p.name}”, the folder being encrypted. "
                               "Choose an output folder outside it.")

    now = int(time.time())
    strip = opts.strip_metadata
    if len(paths) == 1 and paths[0].is_file():
        src_path = paths[0]
        kind, name = "file", src_path.name
        total = src_path.stat().st_size
        meta_extra = {"size": total, "mtime": int(src_path.stat().st_mtime)}
        opener = lambda: open(src_path, "rb")  # noqa: E731
        if strip:
            meta_extra.pop("mtime")
            plan = metadata.plan_for(src_path)
            if plan is None:
                stats["unchanged"] = stats.get("unchanged", 0) + 1
            else:
                stats["stripped"] = stats.get("stripped", 0) + 1
                total = meta_extra["size"] = plan.size
                opener = lambda: metadata.PlanReader(src_path, plan.plan)  # noqa: E731
    elif len(paths) == 1:
        kind, name = "dir", paths[0].name
        total = _tree_size(paths[0])
        meta_extra = {}
        opener = lambda: _TarStream([(paths[0], paths[0].name)], strip, stats)  # noqa: E731
    else:
        kind = "bundle"
        name = bundle_name or time.strftime("Locksmith bundle %Y-%m-%d %H.%M")
        total = sum(_tree_size(p) for p in paths)
        meta_extra = {"items": len(paths)}
        opener = lambda: _TarStream([(p, p.name) for p in paths], strip, stats)  # noqa: E731

    if opts.armor and total > MAX_ARMOR_INPUT:
        raise LocksmithError(f"Text (ASCII armor) output is limited to {MAX_ARMOR_INPUT >> 20} MiB. "
                           "Turn off ASCII armor for larger files.")
    codec_id = _codec_for(opts, paths)
    meta = {"name": name, "kind": kind, "comp": codec_id, "created": now, **meta_extra}
    if opts.note:
        meta["note"] = opts.note

    out_dir.mkdir(parents=True, exist_ok=True)
    target = unique_path(out_dir / _output_name(opts, name))
    tmp = out_dir / f".{target.name}.{secrets.token_hex(4)}.part"

    header, keys = _build_header(opts, meta, chk)
    try:
        with opener() as src:
            if opts.armor:
                buf = io.BytesIO()
                _encrypt_stream(src, total, buf, header, keys, opts, codec_id, chk,
                                max_input=MAX_ARMOR_INPUT)
                write_private(tmp, armor(buf.getvalue()).encode())
            else:
                with create_private(tmp) as out:
                    _encrypt_stream(src, total, out, header, keys, opts, codec_id, chk)
                    out.flush()
                    os.fsync(out.fileno())
        if verify:
            _verify_written(tmp, header, keys, meta, opts.threads, chk)
        chk.report(1.0, "Done")
        os.replace(tmp, target)
        fsync_dir(out_dir)  # callers may shred the originals as soon as this returns
        os.chmod(target, 0o644)  # ciphertext is safe to share
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target


def _verify_written(path: Path, header: bytes, keys: _Keys, meta: dict, threads: int, chk: _Checker):
    """Read a freshly written file back and authenticate every chunk with the
    in-memory keys, proving the bytes on disk decrypt."""
    with _open_source(path) as f:
        total = f.seek(0, os.SEEK_END)
        f.seek(0)
        parsed, raw, _fmt = _read_header(f)
        if raw != header:
            raise LocksmithError("Verification failed: the header on disk does not match.")
        sub = _Checker(chk.cancel, lambda frac, _stage: chk.report(frac, "Verifying"))
        _decrypt_stream(f, total, parsed, raw, keys, meta, _NullWriter(), threads, sub)


class _NullWriter(io.RawIOBase):
    def writable(self):
        return True

    def write(self, b):
        return len(b)


def encrypt_bytes(data: bytes, opts: EncryptOptions, name: str = "message.txt",
                  kind: str = "text") -> bytes:
    # decrypt_bytes refuses more than this, so every message written here can be read.
    if len(data) > MAX_ARMOR_INPUT:
        raise LocksmithError(f"Messages are limited to {MAX_ARMOR_INPUT >> 20} MiB. "
                             "Encrypt larger content as a file.")
    chk = _Checker(None, None)
    codec_id = _codec_for(opts, [])
    meta = {"name": name, "kind": kind, "comp": codec_id, "created": int(time.time()),
            "size": len(data)}
    if opts.note:
        meta["note"] = opts.note
    header, keys = _build_header(opts, meta, chk)
    out = io.BytesIO()
    _encrypt_stream(io.BytesIO(data), len(data), out, header, keys, opts, codec_id, chk)
    return out.getvalue()


# ── armor ────────────────────────────────────────────────────────────────────

def armor(blob: bytes) -> str:
    body = base64.b64encode(blob).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "\n".join([ARMOR_BEGIN, *lines, ARMOR_END]) + "\n"


def dearmor(text: str) -> bytes:
    if len(text) > MAX_ARMOR_TEXT:
        raise LocksmithError(f"Armored text over {MAX_ARMOR_TEXT >> 20} MiB is not supported.")
    text = text.strip()
    start, end = text.find(ARMOR_BEGIN), text.find(ARMOR_END)
    if start < 0 or end < start:
        raise CorruptedError("No Locksmith message found in the text.")
    body = "".join(text[start + len(ARMOR_BEGIN):end].split())
    try:
        return base64.b64decode(body, validate=True)
    except ValueError as e:
        raise CorruptedError("The armored text is damaged.") from e


def is_armored(path: Path) -> bool:
    with open(path, "rb") as f:
        head = f.read(64).lstrip()
    return head.startswith(ARMOR_BEGIN.encode())


def _open_source(path: Path) -> BinaryIO:
    if is_armored(path):
        if path.stat().st_size > MAX_ARMOR_TEXT:
            raise LocksmithError(f"Armored text files over {MAX_ARMOR_TEXT >> 20} MiB are not supported.")
        return io.BytesIO(dearmor(path.read_text(encoding="utf-8", errors="replace")))
    return open(path, "rb")


# ── decryption ───────────────────────────────────────────────────────────────

def decrypt_path(path: Path, out_dir: Path | None, keys: DecryptKeys, threads: int = 0,
                 progress: Progress | None = None,
                 cancel: threading.Event | None = None) -> DecryptResult:
    chk = _Checker(cancel, progress)
    path = Path(path)
    out_dir = Path(out_dir) if out_dir else path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    with _open_source(path) as f:
        total = f.seek(0, os.SEEK_END)
        f.seek(0)
        header, raw, fmt = _read_header(f)
        k = _unlock(header, keys, chk, fmt)
        meta = _read_meta(header, k)
        name = safe_name(meta.get("name") or path.stem)
        tmp = out_dir / f".locksmith-{secrets.token_hex(6)}.part"
        skipped: list[str] = []
        complete = True
        with scratch.tracked(tmp):  # removed on the next start if this run is killed
            try:
                with create_private(tmp) as out:
                    _decrypt_stream(f, total, header, raw, k, meta, out, threads, chk)
                    out.flush()
                    os.fsync(out.fileno())
                kind = meta.get("kind", "file")
                if kind in ("dir", "bundle"):
                    chk.report(None, "Extracting")
                    target = unique_path(out_dir / name)
                    if kind == "dir":
                        staging = out_dir / f".locksmith-{secrets.token_hex(6)}"
                        with scratch.tracked(staging):
                            ext = extract_archive(tmp, staging)
                            # Unwrap the archive's top-level folder (stored under its original
                            # name, which may differ from the safe one). Only a real folder: a
                            # symlink moved out of staging would resolve against the output folder.
                            inner = next((e for e in staging.iterdir() if safe_name(e.name) == name
                                          and e.is_dir() and not e.is_symlink()), staging)
                            os.replace(inner, target)
                            # Anything stored beside the top-level folder is discarded: report it.
                            if staging.exists():
                                ext.skipped += sorted(e.name for e in staging.iterdir())
                            shutil.rmtree(staging, ignore_errors=True)
                    else:
                        ext = extract_archive(tmp, target)
                    skipped = ext.skipped
                    complete = ext.flushed and not ext.skipped and not ext.renamed
                    tmp.unlink(missing_ok=True)
                else:
                    target = unique_path(out_dir / name)
                    os.replace(tmp, target)
                    mtime = meta.get("mtime")
                    if isinstance(mtime, int) and not isinstance(mtime, bool):
                        try:
                            os.utime(target, (time.time(), mtime))
                        except (OverflowError, OSError, ValueError):
                            pass
                # Callers may delete the source as soon as this returns.
                complete = fsync_dir(out_dir) and complete
            except BaseException:
                tmp.unlink(missing_ok=True)
                raise
    copy_zone_identifier(path, target)
    chk.report(1.0, "Done")
    return DecryptResult(target, meta, skipped=skipped, complete=complete)


def decrypt_bytes(blob: bytes, keys: DecryptKeys) -> DecryptResult:
    chk = _Checker(None, None)
    f = io.BytesIO(blob)
    header, raw, fmt = _read_header(f)
    k = _unlock(header, keys, chk, fmt)
    meta = _read_meta(header, k)
    out = io.BytesIO()
    _decrypt_stream(f, len(blob), header, raw, k, meta, out, 1, chk, max_output=MAX_ARMOR_INPUT)
    return DecryptResult(None, meta, out.getvalue())


def safe_name(name) -> str:
    """Make a received file name safe to create. Besides staying inside the output
    folder, it drops control and invisible formatting characters (a right-to-left
    override, U+202E, can make "photo\u202egpj.exe" display as "photoexe.jpg") and
    leading dots, so a sender cannot plant hidden files such as .bash_profile or .ssh."""
    if not isinstance(name, str):
        return "decrypted"
    name = "".join(ch for ch in name if unicodedata.category(ch) not in ("Cc", "Cf"))
    name = os.path.basename(name.replace("\\", "/")).strip().lstrip(".").strip()
    # 240 bytes leaves room for a " (n)" suffix within the usual 255-byte limit.
    name = name.encode()[:240].decode(errors="ignore")
    name = portable_name(name) if name not in ("", ".", "..") else "decrypted"
    return name if name not in ("", ".", "..") else "decrypted"


def _extracted_key(dest: str, name: str) -> str:
    """Identify the file an archive member would be written to. The folder part is
    resolved as it stands on disk, so a path through an extracted folder link matches
    the real path; Windows compares names without case."""
    parent, leaf = os.path.split(os.path.normpath(name))
    key = os.path.join(os.path.realpath(os.path.join(dest, parent)), leaf)
    return key.casefold() if IS_WINDOWS else key


# Long names, link targets and PAX records are a few KB at most. tarfile reads such a
# header into memory whole, whatever size it declares, so a compressed archive could
# otherwise expand one into gigabytes of memory.
MAX_ARCHIVE_HEADER = 1 << 20
_HEADER_TYPES = (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE, tarfile.XGLTYPE,
                 tarfile.SOLARIS_XHDTYPE)
_SPARSE = "The archive inside the file holds a sparse file, which Locksmith never writes."


class _BoundedTarInfo(tarfile.TarInfo):
    """Refuses oversized metadata headers and sparse members before tarfile reads them.
    Locksmith never writes sparse members (tarfile cannot), and their maps are read
    without limit, so only a crafted archive has them."""

    def _proc_member(self, tar):
        if self.type in _HEADER_TYPES and self.size > MAX_ARCHIVE_HEADER:
            raise CorruptedError("The archive inside the file is damaged (an oversized header).")
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise CorruptedError(_SPARSE)
        member = super()._proc_member(tar)
        if member.sparse is not None:  # sparse formats 0.0 and 0.1, declared in a PAX header
            raise CorruptedError(_SPARSE)
        return member

    def _proc_gnusparse_10(self, next, pax_headers, tar):  # noqa: A002 (tarfile's signature)
        # Format 1.0 reads its map from the member's data, as many numbers as it declares.
        raise CorruptedError(_SPARSE)


def extract_archive(archive: Path, dest: Path) -> Extraction:
    """Extract with the tarfile "data" filter. Members the filter rejects (such as
    links pointing outside the folder, or device files) are skipped and reported
    instead of aborting, so one odd entry cannot make a whole folder unrecoverable.
    Everything extracted is then fsynced."""
    result = Extraction()
    skipped = result.skipped
    extracted: dict[str, bool] = {}  # _extracted_key -> is a folder

    def keep_safe(member, path):
        name = member.name
        # On Windows, a name such as "a:b" would write into an NTFS alternate data
        # stream and "CON" is a device: skip anything Windows cannot create safely.
        if IS_WINDOWS and any(windows_unsafe(part) for part in name.split("/") if part):
            skipped.append(name)
            return None
        # No file system accepts a NUL in a name; the filter's path checks would raise.
        if "\x00" in name or "\x00" in (member.linkname or ""):
            skipped.append(name.replace("\x00", "\\0"))
            return None
        try:
            member = tarfile.data_filter(member, path)
        except tarfile.FilterError:
            skipped.append(name)
            return None
        # A later member must never replace an earlier one: an exact duplicate, a name
        # differing only in case on Windows (Notes.txt, notes.txt), or a path through a
        # folder link. The first is kept and the collision reported. A folder listed
        # twice just merges, overwriting nothing.
        key = _extracted_key(path, member.name)
        if key in extracted and not (extracted[key] and member.isdir()):
            skipped.append(name)
            return None
        extracted[key] = member.isdir()
        if member.name != name:  # e.g. a leading "/" stripped
            result.renamed.append(name)
        # Owner only, like a decrypted file: the archived modes (often 0755/0644) would let
        # other users read the plaintext wherever the output folder is reachable.
        if member.isdir():
            member = member.replace(mode=0o700, deep=False)
        elif (member.isreg() or member.islnk()) and member.mode is not None:
            member = member.replace(mode=member.mode & 0o700, deep=False)
        return member

    dest.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        with tarfile.open(archive, "r:", tarinfo=_BoundedTarInfo) as tar:
            tar.extractall(dest, filter=keep_safe)
    except CorruptedError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except (tarfile.TarError, OSError, ValueError) as e:
        # ValueError: values tarfile itself cannot handle in a crafted header.
        shutil.rmtree(dest, ignore_errors=True)
        raise LocksmithError(f"Could not unpack the archive: {e}") from e
    result.flushed = fsync_tree(dest)
    return result


def verify_path(path: Path, keys: DecryptKeys, threads: int = 0,
                progress: Progress | None = None,
                cancel: threading.Event | None = None) -> dict:
    """Authenticate every chunk without writing any plaintext to disk."""
    chk = _Checker(cancel, progress)
    with _open_source(Path(path)) as f:
        total = f.seek(0, os.SEEK_END)
        f.seek(0)
        header, raw, fmt = _read_header(f)
        k = _unlock(header, keys, chk, fmt)
        meta = _read_meta(header, k)
        _decrypt_stream(f, total, header, raw, k, meta, _NullWriter(), threads, chk)
    chk.report(1.0, "Verified")
    return meta
