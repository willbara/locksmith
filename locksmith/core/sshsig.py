"""Verify SSH signatures made by ``ssh-keygen -Y sign`` (OpenSSH's PROTOCOL.sshsig).

A signature file is armored base64 between ``-----BEGIN SSH SIGNATURE-----`` and
``-----END SSH SIGNATURE-----``. The blob inside is, in SSH wire encoding::

    "SSHSIG" || u32 version (1) || string public key || string namespace
             || string reserved || string hash algorithm || string signature

and the signature covers::

    "SSHSIG" || string namespace || string reserved || string hash algorithm
             || string H(file)

The namespace (``file``, ``git``, …) says what the signature is for, so a signature
made for one purpose is never accepted for another. Ed25519, RSA (rsa-sha2-256/512)
and ECDSA keys are supported; security-key (``sk-``) signatures and certificates are
refused. A valid signature proves the file was signed with the key you gave, nothing
more: whose key it is has to be checked separately.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from .errors import LocksmithError
from .tools import hash_file, read_text

MAX_SIGNATURE_FILE = 64 << 10   # real ones are under 2 KB, even for 16384-bit RSA
MIN_RSA_BITS = 2048
ARMOR_BEGIN = "-----BEGIN SSH SIGNATURE-----"
ARMOR_END = "-----END SSH SIGNATURE-----"
MAGIC = b"SSHSIG"
HASHES = {"sha256": hashes.SHA256, "sha512": hashes.SHA512}
# Key type → (label, cryptography key class, hash for ECDSA signatures)
KEY_TYPES = {
    "ssh-ed25519": ("ED25519", ed25519.Ed25519PublicKey, None),
    "ssh-rsa": ("RSA", rsa.RSAPublicKey, None),
    "ecdsa-sha2-nistp256": ("ECDSA P-256", ec.EllipticCurvePublicKey, hashes.SHA256),
    "ecdsa-sha2-nistp384": ("ECDSA P-384", ec.EllipticCurvePublicKey, hashes.SHA384),
    "ecdsa-sha2-nistp521": ("ECDSA P-521", ec.EllipticCurvePublicKey, hashes.SHA512),
}
RSA_SIGNATURES = {"rsa-sha2-256": hashes.SHA256, "rsa-sha2-512": hashes.SHA512}

_BAD_SIGNATURE = "That is not a valid SSH signature."


@dataclass
class PublicKey:
    key_type: str
    blob: bytes             # SSH wire encoding, as in the signature
    key: object             # the cryptography public key

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.blob)

    @property
    def label(self) -> str:
        name = KEY_TYPES[self.key_type][0]
        return f"{name} {self.key.key_size}" if self.key_type == "ssh-rsa" else name


@dataclass
class Signature:
    key_blob: bytes
    namespace: bytes
    reserved: bytes
    hash_algorithm: str
    sig_type: str
    sig: bytes


@dataclass
class Verified:
    fingerprint: str        # as ssh-keygen -l prints it
    key_label: str          # "ED25519", "RSA 4096", "ECDSA P-256"
    namespace: str
    hash_algorithm: str


class _Reader:
    """SSH wire-format reader. Every read is bounds-checked; a short read means a bad file."""

    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n > len(self.data) - self.pos:
            raise ValueError("truncated")
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.u32())

    def mpint(self) -> int:
        b = self.string()
        # Positive and minimally encoded, as OpenSSH writes them.
        if not b or b[0] & 0x80 or (b[0] == 0 and (len(b) == 1 or not b[1] & 0x80)):
            raise ValueError("bad mpint")
        return int.from_bytes(b, "big")

    def end(self):
        if self.pos != len(self.data):
            raise ValueError("trailing data")


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def fingerprint(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _shown(raw: bytes) -> str:
    """Text from a signature, made safe to display: no control characters, bounded length."""
    text = "".join(c if c.isprintable() else "�" for c in raw.decode("utf-8", "replace"))
    return text if len(text) <= 64 else text[:64] + "…"


def _refusal(key_type: str) -> str | None:
    if key_type.startswith(("sk-", "webauthn-sk-")):
        return "Security-key (FIDO) SSH signatures aren't supported."
    if "-cert-v01@openssh.com" in key_type:
        return "SSH certificates aren't supported. Use the signer's plain public key."
    return None


def parse_public_key(text: str) -> PublicKey:
    """A public key from a ``.pub`` file or one ``ssh-ed25519 AAAA… comment`` line."""
    lines = [line.strip() for line in text.strip().splitlines()
             if line.strip() and not line.strip().startswith("#")]
    if len(lines) != 1:
        raise LocksmithError("Paste one SSH public key (the line starting with “ssh-ed25519”, “ssh-rsa” "
                             "or “ecdsa-sha2-…”).")
    parts = lines[0].split()
    key_type = parts[0]
    if refusal := _refusal(key_type):
        raise LocksmithError(refusal)
    if key_type not in KEY_TYPES:
        if any(p in KEY_TYPES or _refusal(p) for p in parts[1:]):
            # allowed_signers and authorized_keys lines put names or options first. Their
            # restrictions (namespaces=, valid-after=) would be ignored here, so refuse them.
            raise LocksmithError("Paste just the public key, without the names or options in front of it.")
        raise LocksmithError("That is not a supported SSH public key. It should start with “ssh-ed25519”, "
                             "“ssh-rsa” or “ecdsa-sha2-…”.")
    if len(parts) < 2 or len(parts[1]) > 4 * MAX_SIGNATURE_FILE:
        raise LocksmithError("That SSH public key is incomplete.")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        if _Reader(blob).string() != key_type.encode():
            raise ValueError("key type differs")
        key = load_ssh_public_key(f"{key_type} {parts[1]}".encode())
    except (ValueError, binascii.Error, UnsupportedAlgorithm, NotImplementedError):  # compressed EC points
        raise LocksmithError("That SSH public key is damaged.") from None
    if not isinstance(key, KEY_TYPES[key_type][1]):
        raise LocksmithError("That SSH public key is damaged.")
    if key_type == "ssh-rsa" and key.key_size < MIN_RSA_BITS:
        raise LocksmithError(f"This RSA key has only {key.key_size} bits. Locksmith accepts RSA keys of "
                             f"{MIN_RSA_BITS} bits or more.")
    return PublicKey(key_type, blob, key)


def parse_signature(text: str) -> Signature:
    """The fields of an armored SSH signature, checked for structure but not verified."""
    text = text.strip()
    if not text.startswith(ARMOR_BEGIN) or not text.endswith(ARMOR_END):
        raise LocksmithError("That is not an SSH signature file (it should start with “" + ARMOR_BEGIN + "”).")
    body = "".join(text[len(ARMOR_BEGIN):-len(ARMOR_END)].split())
    try:
        r = _Reader(base64.b64decode(body, validate=True))
        if r.take(len(MAGIC)) != MAGIC:
            raise ValueError("magic")
        version = r.u32()
        if version != 1:
            raise LocksmithError(f"This SSH signature uses version {version}, which Locksmith doesn't know.")
        key_blob, namespace, reserved, hash_alg, sig_blob = (r.string() for _ in range(5))
        r.end()
        key_type = _Reader(key_blob).string().decode("ascii")
        s = _Reader(sig_blob)
        sig_type = s.string().decode("ascii")
        if refusal := _refusal(key_type) or _refusal(sig_type):
            raise LocksmithError(refusal)
        sig = s.string()
        s.end()
    except (ValueError, binascii.Error):   # includes UnicodeDecodeError
        raise LocksmithError(_BAD_SIGNATURE) from None
    if not namespace:
        raise LocksmithError(_BAD_SIGNATURE)
    if hash_alg.decode("ascii", "replace") not in HASHES:
        raise LocksmithError(f"This SSH signature uses a hash Locksmith doesn't accept ({_shown(hash_alg)}).")
    return Signature(key_blob, namespace, reserved, hash_alg.decode("ascii"), sig_type, sig)


def read_small(path: Path) -> str:
    """Read a signature or key file, refusing anything unexpectedly large."""
    return read_text(path, MAX_SIGNATURE_FILE, "an SSH signature or key")


def _check(key: PublicKey, sig: Signature, signed: bytes):
    """Verify ``sig`` over ``signed`` with ``key``. The key's type decides the algorithm."""
    mismatch = LocksmithError(f"The signature's algorithm ({_shown(sig.sig_type.encode())}) doesn't match "
                              f"the key ({key.key_type}).")
    try:
        if key.key_type == "ssh-ed25519":
            if sig.sig_type != key.key_type:
                raise mismatch
            key.key.verify(sig.sig, signed)
        elif key.key_type == "ssh-rsa":
            if sig.sig_type == "ssh-rsa":
                raise LocksmithError("This signature uses RSA with SHA-1, which SSH signatures don't allow.")
            if sig.sig_type not in RSA_SIGNATURES:
                raise mismatch
            size = (key.key.key_size + 7) // 8
            if len(sig.sig) > size:
                raise InvalidSignature
            # OpenSSH accepts signatures with their leading zero bytes left out.
            key.key.verify(sig.sig.rjust(size, b"\0"), signed, padding.PKCS1v15(), RSA_SIGNATURES[sig.sig_type]())
        else:
            if sig.sig_type != key.key_type:
                raise mismatch
            r = _Reader(sig.sig)
            der = encode_dss_signature(r.mpint(), r.mpint())
            r.end()
            key.key.verify(der, signed, ec.ECDSA(KEY_TYPES[key.key_type][2]()))
    except ValueError:
        raise LocksmithError(_BAD_SIGNATURE) from None


def verify_file(path: Path, signature: str, public_key: str, namespace: str = "file",
                progress: Callable[[float], None] | None = None,
                cancel: threading.Event | None = None) -> Verified:
    """Check ``path`` against an armored SSH signature, a public key and the namespace the
    signature must have been made for. Raises LocksmithError with the reason unless valid."""
    namespace = namespace.strip()
    if not namespace:
        raise LocksmithError("Enter the namespace the file was signed for, usually “file”.")
    key = parse_public_key(public_key)
    sig = parse_signature(signature)
    if sig.key_blob != key.blob:
        raise LocksmithError(f"This file was signed with a different key ({fingerprint(sig.key_blob)}), "
                             f"not the one given ({key.fingerprint}).")
    if sig.namespace != namespace.encode():
        raise LocksmithError(f"This signature was made for “{_shown(sig.namespace)}”, not "
                             f"“{_shown(namespace.encode())}”. A signature only counts for the namespace "
                             "it was made for.")
    digest = bytes.fromhex(hash_file(path, sig.hash_algorithm, progress, cancel))
    signed = MAGIC + b"".join(map(_string, (sig.namespace, sig.reserved, sig.hash_algorithm.encode(), digest)))
    try:
        _check(key, sig, signed)
    except InvalidSignature:
        raise LocksmithError("The signature does not match this file: it was changed, or this is not "
                             "the file that was signed.") from None
    return Verified(key.fingerprint, key.label, namespace, sig.hash_algorithm)
