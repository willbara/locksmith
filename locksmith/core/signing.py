"""Detached Locksmith signatures (docs/FORMAT.md §14): Ed25519 and ML-DSA-65 together.

A signature file holds::

    "LOCKSIG" 0x01 || alg (u8 = 1) || created (u64) || key_id (32) || clen (u16) || comment
                   || Ed25519 signature (64) || ML-DSA-65 signature (3309)

Both parts sign ``LABEL || "sig/file" || 0x00 || head || SHA-512(file)``, where ``head`` is
everything before the signatures. ``key_id`` is the SHA-256 of the signer's locksmith3
key, so each part is bound to the whole key, and both must verify. Only a locksmith3 key
verifies a signature: the key, never the signature, decides the algorithm.

A valid signature shows the file was signed with that key, nothing more: whose key it is
is what the contact's fingerprint check settles.

Signed .locked files (§15) carry the same structure, without a comment, inside the
encryption; ``sign_locked`` and ``check_locked`` make and check it for the engine.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey

from . import keys
from .errors import CorruptedError, LocksmithError
from .tools import hash_file, read_text

MAGIC = b"LOCKSIG\x01"
ALG_ED25519_MLDSA65 = 1
LABEL = b"locksmith/v1/"
CONTEXT = LABEL + b"sig"              # ML-DSA context string
PURPOSE = LABEL + b"sig/file\x00"
ED_LEN, ML_LEN = 64, 3309
HEAD = struct.Struct(">8sBQ32sH")     # magic, alg, created, key_id, clen
MAX_COMMENT = 1024
MAX_TEXT = 16 << 10
EXTENSION = ".lsig"
LOCKED_LEN = HEAD.size + ED_LEN + ML_LEN   # a signed file's signature: no comment
LOCKED_LABEL = b"locksmith/v2/"
LOCKED_PURPOSE = LOCKED_LABEL + b"sig/locked\x00"
LOCKED_CONTEXT = LOCKED_LABEL + b"sig"
ARMOR_BEGIN = "-----BEGIN LOCKSMITH SIGNATURE-----"
ARMOR_END = "-----END LOCKSMITH SIGNATURE-----"
_BAD = "That is not a valid Locksmith signature."


class UnknownSignerError(LocksmithError):
    """None of the keys given made the signature, so it could not be checked."""


class SignatureError(CorruptedError):
    """A signed file whose signature doesn't verify: nothing of it may be shown or kept."""


@dataclass
class LockedSignature:
    """A signed file's signer, as far as the reader's saved keys can tell."""
    key: bytes | None   # the signer's locksmith3 key, or None when it isn't one of the saved keys
    fingerprint: str
    created: int        # the signer's claim

    @property
    def verified(self) -> bool:
        return self.key is not None


@dataclass
class Signature:
    created: int
    key_id: bytes
    comment: str
    head: bytes
    sig_ed: bytes
    sig_ml: bytes

    @property
    def fingerprint(self) -> str:
        """The signer's fingerprint, which is the start of key_id."""
        return keys.group_hex(self.key_id.hex())


@dataclass
class Verified:
    key: bytes          # the signer's raw locksmith3 key
    fingerprint: str
    comment: str
    created: int        # the signer's claim


def key_id(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def check_comment(comment: str) -> bytes:
    """The comment as signed: one line of at most 1024 UTF-8 bytes, nothing invisible."""
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs") for c in comment):
        raise LocksmithError("The comment must be one line, without control or formatting characters.")
    data = comment.encode("utf-8")
    if len(data) > MAX_COMMENT:
        raise LocksmithError(f"The comment is too long ({len(data)} bytes; at most {MAX_COMMENT}).")
    return data


def _message(head: bytes, digest: bytes) -> bytes:
    return PURPOSE + head + digest


def _verify_parts(raw: bytes, sig_ed: bytes, sig_ml: bytes, message: bytes, context: bytes = CONTEXT):
    """Raises InvalidSignature unless both parts verify with the locksmith3 key ``raw``."""
    if not keys.can_verify(raw):
        raise InvalidSignature
    ed = raw[keys.HYBRID_PUBLIC_LEN:keys.HYBRID_PUBLIC_LEN + keys.ED25519_LEN]
    Ed25519PublicKey.from_public_bytes(ed).verify(sig_ed, message)
    MLDSA65PublicKey.from_public_bytes(raw[keys.HYBRID_PUBLIC_LEN + keys.ED25519_LEN:]).verify(
        sig_ml, message, context)


def check_signer(private: bytes):
    """Refuse a private key that can't sign (a classical identity's), before anything is written."""
    keys.signing_keys(private)


def public_key(private: bytes) -> bytes:
    """The locksmith3 raw public key of a hybrid private key."""
    return keys.public_from_private(private) + keys.verify_key(private)


def armor(blob: bytes) -> str:
    body = base64.b64encode(blob).decode()
    return "\n".join([ARMOR_BEGIN, *(body[i:i + 64] for i in range(0, len(body), 64)), ARMOR_END]) + "\n"


def sign_file(path: Path, private: bytes, comment: str = "", created: int | None = None,
              progress: Callable[[float], None] | None = None,
              cancel: threading.Event | None = None) -> str:
    """A detached signature of ``path`` by the hybrid identity with raw private key ``private``."""
    ed, ml = keys.signing_keys(private)
    public = public_key(private)
    c = check_comment(comment)
    created = int(time.time()) if created is None else created
    head = HEAD.pack(MAGIC, ALG_ED25519_MLDSA65, created, key_id(public), len(c)) + c
    message = _message(head, bytes.fromhex(hash_file(path, "sha512", progress, cancel)))
    sig_ed, sig_ml = ed.sign(message), ml.sign(message, CONTEXT)
    try:
        _verify_parts(public, sig_ed, sig_ml, message)   # never hand out a signature that doesn't verify
    except InvalidSignature:
        raise LocksmithError("Signing failed: the new signature did not verify. Nothing was saved.") from None
    return armor(head + sig_ed + sig_ml)


def parse(text: str) -> Signature:
    """The fields of a signature, checked for structure but not verified."""
    if len(text) > MAX_TEXT:
        raise LocksmithError("That signature is too large.")
    text = text.strip()
    if not text.startswith(ARMOR_BEGIN) or not text.endswith(ARMOR_END):
        raise LocksmithError(f"That is not a Locksmith signature (it should start with “{ARMOR_BEGIN}”).")
    try:
        blob = base64.b64decode("".join(text[len(ARMOR_BEGIN):-len(ARMOR_END)].split()), validate=True)
    except (ValueError, binascii.Error):
        raise LocksmithError(_BAD) from None
    return parse_blob(blob)


def parse_blob(blob: bytes) -> Signature:
    if len(blob) < HEAD.size or blob[:8] != MAGIC:
        if blob[:7] == MAGIC[:7]:
            raise LocksmithError("This signature was made by a newer version of Locksmith.")
        raise LocksmithError(_BAD)
    _, alg, created, kid, clen = HEAD.unpack_from(blob)
    if alg != ALG_ED25519_MLDSA65:
        raise LocksmithError("This signature uses an algorithm Locksmith doesn't know.")
    end = HEAD.size + clen
    if clen > MAX_COMMENT or len(blob) != end + ED_LEN + ML_LEN:
        raise LocksmithError(_BAD)
    try:
        comment = blob[HEAD.size:end].decode("utf-8")
        check_comment(comment)
    except (UnicodeDecodeError, LocksmithError):
        raise LocksmithError(_BAD) from None
    return Signature(created, kid, comment, blob[:end], blob[end:end + ED_LEN], blob[end + ED_LEN:])


def read_small(path: Path) -> str:
    """Read a signature file, refusing anything unexpectedly large."""
    return read_text(path, MAX_TEXT, "a Locksmith signature")


def verify_file(path: Path, signature: str, candidates: Iterable[bytes],
                progress: Callable[[float], None] | None = None,
                cancel: threading.Event | None = None) -> Verified:
    """Check ``path`` against a signature, using whichever of the raw public keys in
    ``candidates`` made it. Raises LocksmithError with the reason unless it is valid."""
    sig = parse(signature)
    signer = next((k for k in candidates if keys.can_verify(k) and key_id(k) == sig.key_id), None)
    if signer is None:
        # key_id is whatever the signature claims: nothing about it has been checked yet.
        raise UnknownSignerError(f"None of the keys checked made this signature, so nothing has been verified. It "
                                 f"claims to be made with the key whose fingerprint is {sig.fingerprint}.")
    message = _message(sig.head, bytes.fromhex(hash_file(path, "sha512", progress, cancel)))
    try:
        _verify_parts(signer, sig.sig_ed, sig.sig_ml, message)
    except InvalidSignature:
        raise LocksmithError("The signature does not match this file: it was changed, or this is not the file "
                             "that was signed.") from None
    return Verified(signer, keys.fingerprint(signer), sig.comment, sig.created)


# ── signed .locked files (FORMAT.md §15) ─────────────────────────────────────

def _locked_message(head: bytes, fixed: bytes, content_digest: bytes) -> bytes:
    return LOCKED_PURPOSE + head + hashlib.sha256(fixed).digest() + content_digest


def sign_locked(private: bytes, fixed: bytes, content_digest: bytes, created: int | None = None) -> bytes:
    """The signature a signed file carries: over its fixed header and the SHA-512 of its content."""
    ed, ml = keys.signing_keys(private)
    public = public_key(private)
    created = int(time.time()) if created is None else created
    head = HEAD.pack(MAGIC, ALG_ED25519_MLDSA65, created, key_id(public), 0)
    message = _locked_message(head, fixed, content_digest)
    sig_ed, sig_ml = ed.sign(message), ml.sign(message, LOCKED_CONTEXT)
    try:
        _verify_parts(public, sig_ed, sig_ml, message, LOCKED_CONTEXT)
    except InvalidSignature:
        raise LocksmithError("Signing failed: the new signature did not verify. Nothing was saved.") from None
    return head + sig_ed + sig_ml


def check_locked(blob: bytes, fixed: bytes, content_digest: bytes, candidates: Iterable[bytes]) -> LockedSignature:
    """The signer of a signed file. An unsaved signer is reported as such (``key`` None); a
    damaged signature, or one that doesn't verify with the signer's key, raises SignatureError."""
    invalid = SignatureError("This file's signature is invalid: the file was changed after it was signed, by "
                             "someone who could open it, or the signature is damaged. Nothing was saved or "
                             "shown.")
    if len(blob) != LOCKED_LEN:
        raise invalid
    try:
        sig = parse_blob(blob)
    except LocksmithError:
        raise invalid from None
    if sig.comment:
        raise invalid
    signer = next((k for k in candidates if keys.can_verify(k) and key_id(k) == sig.key_id), None)
    if signer is None:
        return LockedSignature(None, sig.fingerprint, sig.created)
    try:
        _verify_parts(signer, sig.sig_ed, sig.sig_ml, _locked_message(sig.head, fixed, content_digest),
                      LOCKED_CONTEXT)
    except InvalidSignature:
        raise invalid from None
    return LockedSignature(signer, keys.fingerprint(signer), sig.created)
