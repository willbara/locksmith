"""Verify minisign signatures (https://jedisct1.github.io/minisign/).

A public key is base64 of ``"Ed" || key ID (8) || Ed25519 key (32)``, usually on the
second line of a ``.pub`` file. A ``.minisig`` file has four lines::

    untrusted comment: <anything>
    base64("ED" or "Ed" || key ID (8) || signature (64))
    trusted comment: <text>
    base64(global signature (64))

"ED" signs the BLAKE2b-512 hash of the file; "Ed" (legacy) signs the file itself. The
global signature covers the signature followed by the trusted comment, so the
trusted comment is authenticated and the untrusted one is not: only the trusted
comment is ever shown. A valid signature proves the file was signed with the key you
gave, nothing more: whose key it is has to be checked separately.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import CancelledError, LocksmithError
from .tools import open_regular, read_text

MAX_SIGNATURE_FILE = 64 << 10   # real ones are under 1 KB
MAX_LEGACY_FILE = 64 << 20      # legacy signatures need the whole file in memory
_UNTRUSTED, _TRUSTED = "untrusted comment:", "trusted comment: "


@dataclass
class Verified:
    key_id: str            # as minisign prints it
    trusted_comment: str
    prehashed: bool


def _b64(text: str, size: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (ValueError, binascii.Error):
        raise LocksmithError(f"The {what} is not valid base64.") from None
    if len(raw) != size:
        raise LocksmithError(f"The {what} has the wrong length.")
    return raw


def _key_id_text(key_id: bytes) -> str:
    return key_id[::-1].hex().upper()   # minisign prints the little-endian number


def parse_public_key(text: str) -> tuple[bytes, bytes]:
    """(key ID, Ed25519 key) from a key line or a whole ``.pub`` file."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if lines and lines[0].startswith(_UNTRUSTED):
        lines = lines[1:]
    if len(lines) != 1:
        raise LocksmithError("Paste the minisign public key (the line starting with “RW”).")
    raw = _b64(lines[0], 42, "public key")
    if raw[:2] != b"Ed":
        raise LocksmithError("That is not a minisign public key.")
    return raw[2:10], raw[10:]


def parse_signature(text: str) -> tuple[bool, bytes, bytes, str, bytes]:
    """(prehashed, key ID, signature, trusted comment, global signature) from a ``.minisig``."""
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and lines[-1] == "":
        lines.pop()
    if (len(lines) != 4 or not lines[0].startswith(_UNTRUSTED)
            or not lines[2].startswith(_TRUSTED)):
        raise LocksmithError("That is not a minisign signature file.")
    raw = _b64(lines[1], 74, "signature")
    if raw[:2] not in (b"ED", b"Ed"):
        raise LocksmithError("This signature uses an algorithm minisign doesn't define.")
    return raw[:2] == b"ED", raw[2:10], raw[10:], lines[2][len(_TRUSTED):], _b64(lines[3], 64, "global signature")


def read_small(path: Path) -> str:
    """Read a signature or key file, refusing anything unexpectedly large."""
    return read_text(path, MAX_SIGNATURE_FILE, "a minisign file")


def verify_file(path: Path, signature: str, public_key: str,
                progress: Callable[[float], None] | None = None,
                cancel: threading.Event | None = None) -> Verified:
    """Check ``path`` against a ``.minisig`` text and a public key. Raises LocksmithError
    with the reason unless the signature and its trusted comment are both valid."""
    key_id, pk = parse_public_key(public_key)
    prehashed, sig_key_id, sig, comment, global_sig = parse_signature(signature)
    if sig_key_id != key_id:
        raise LocksmithError(f"This file was signed with a different key (key ID {_key_id_text(sig_key_id)}), "
                             f"not the one given ({_key_id_text(key_id)}).")
    with open_regular(path) as f:
        size = f.seek(0, 2)
        f.seek(0)
        if not prehashed and size > MAX_LEGACY_FILE:
            raise LocksmithError("This file has an old-style minisign signature, which Locksmith only "
                                 f"checks for files up to {MAX_LEGACY_FILE >> 20} MiB.")
        h = hashlib.blake2b(digest_size=64) if prehashed else None
        chunks, done = [], 0
        while block := f.read(4 << 20):
            if cancel and cancel.is_set():
                raise CancelledError()
            done += len(block)
            if h:
                h.update(block)
            elif done > MAX_LEGACY_FILE:  # it grew while being read
                raise LocksmithError(f"Files over {MAX_LEGACY_FILE >> 20} MiB need a current minisign signature.")
            else:
                chunks.append(block)
            if progress:
                progress(done / max(size, 1))
    message = h.digest() if h else b"".join(chunks)
    key = Ed25519PublicKey.from_public_bytes(pk)
    try:
        key.verify(sig, message)
    except InvalidSignature:
        raise LocksmithError("The signature does not match this file: it was changed, or this is not "
                             "the file that was signed.") from None
    try:
        key.verify(global_sig, sig + comment.encode("utf-8", "surrogateescape"))  # the bytes as signed
    except InvalidSignature:
        raise LocksmithError("The file's signature is valid, but its trusted comment was altered.") from None
    return Verified(_key_id_text(key_id), comment, prehashed)
