"""SSH keys as recipients (docs/FORMAT.md §3).

* ``ssh-ed25519``: the Ed25519 public key is converted to the X25519 key of the same
  secret (the birational map from the Edwards curve to its Montgomery form) and files
  use an ordinary ``x25519`` slot, so nothing about the file says SSH. The SSH private
  key opens it through the matching X25519 private key, ``SHA-512(seed)[0..32]``.
* ``ssh-rsa``: RSA keys can't be converted, so they get their own slot type, which
  Locksmith 3.0 and earlier don't know: they can't open such a file at all.

Both are classical: a quantum computer could open files encrypted to them. The SSH key
stays a login and signing key too, so anyone who gets the private key can also open these
files; opening a file reveals nothing about the key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
    load_ssh_private_key,
)

from . import sshsig
from .errors import LocksmithError, WrongKeyError
from .tools import read_text

ED25519, RSA = "ssh-ed25519", "ssh-rsa"
RSA_PREFIX = b"\x00\x00\x00\x07ssh-rsa"   # the start of every ssh-rsa key blob
MIN_RSA_BITS, MAX_RSA_BITS = 2048, 16384
MAX_KEY_FILE = 64 << 10
_P = 2 ** 255 - 19
_D = -121665 * pow(121666, -1, _P) % _P


@dataclass
class SshRecipient:
    key_type: str       # "ssh-ed25519" or "ssh-rsa"
    blob: bytes         # SSH wire encoding
    raw: bytes          # what files are encrypted to: the X25519 key, or the RSA key blob

    @property
    def text(self) -> str:
        """The key as one line, without its comment (nothing vouches for a comment)."""
        return f"{self.key_type} {base64.b64encode(self.blob).decode()}"

    @property
    def fingerprint(self) -> str:
        return sshsig.fingerprint(self.blob)

    @property
    def label(self) -> str:
        if self.key_type == ED25519:
            return "SSH Ed25519"
        return f"SSH RSA {rsa_public(self.blob).key_size}"


def is_ssh_text(text: str) -> bool:
    return text.strip().startswith(("ssh-", "sk-", "ecdsa-"))


def is_rsa_raw(raw: bytes) -> bool:
    """Whether a recipient's raw key is an RSA key blob. X25519 and hybrid keys are 32 and 1216
    bytes, and RSA keys of those exact sizes are refused, so the length alone tells them apart."""
    return len(raw) not in (32, 1216) and raw.startswith(RSA_PREFIX)


def ed25519_to_x25519(public: bytes) -> bytes:
    """The X25519 public key of an Ed25519 public key: u = (1 + y) / (1 - y) mod p."""
    if len(public) != 32:
        raise LocksmithError("That SSH Ed25519 key is damaged.")
    y = int.from_bytes(public, "little") & ((1 << 255) - 1)
    sign = public[31] >> 7
    if y >= _P or y == 1:
        raise LocksmithError("That SSH Ed25519 key is not usable.")
    # A valid point must have an x: x² = (y² - 1) / (d·y² + 1) has to be a square.
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    if (x2 == 0 and sign) or (x2 and pow(x2, (_P - 1) // 2, _P) != 1):
        raise LocksmithError("That SSH Ed25519 key is not a valid point.")
    u = (1 + y) * pow(1 - y, -1, _P) % _P
    raw = u.to_bytes(32, "little")
    try:
        X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(raw))
    except ValueError:
        raise LocksmithError("That SSH Ed25519 key is not usable (low-order point).") from None
    return raw


def ed25519_seed_to_x25519(seed: bytes) -> bytes:
    """The raw X25519 private key of an Ed25519 private key (its 32-byte seed): the first half
    of SHA-512(seed), which X25519 clamps exactly as Ed25519 does."""
    return hashlib.sha512(seed).digest()[:32]


def rsa_public(blob: bytes) -> rsa.RSAPublicKey:
    return sshsig.parse_public_key(f"{RSA} {base64.b64encode(blob).decode()}").key


def parse_recipient(text: str) -> SshRecipient:
    """An SSH public key (one ``.pub`` line) that files can be encrypted to."""
    key = sshsig.parse_public_key(text)
    if key.key_type == ED25519:
        pk = key.key.public_bytes_raw()
        return SshRecipient(ED25519, key.blob, ed25519_to_x25519(pk))
    if key.key_type == RSA:
        _check_rsa(key.key)
        if len(key.blob) in (32, 1216):
            raise LocksmithError("RSA keys of this exact size can't be used. Use an Ed25519 or another RSA key.")
        return SshRecipient(RSA, key.blob, key.blob)
    raise LocksmithError("Only SSH Ed25519 and RSA keys can be recipients. ECDSA keys can only verify signatures.")


def recipient_from_raw(raw: bytes) -> SshRecipient:
    """An RSA recipient from the raw key a slot is made for (its key blob)."""
    return parse_recipient(f"{RSA} {base64.b64encode(raw).decode()}")


def _check_rsa(key):
    if not MIN_RSA_BITS <= key.key_size <= MAX_RSA_BITS:
        raise LocksmithError(f"Locksmith encrypts to RSA keys of {MIN_RSA_BITS} to {MAX_RSA_BITS} bits; this one "
                             f"has {key.key_size}.")


# ── private keys, for opening files ──────────────────────────────────────────

@dataclass
class SshIdentity:
    """An SSH private key, ready to open files: Ed25519 as its X25519 identity, RSA as the key."""
    key_type: str
    fingerprint: str
    x25519: bytes | None = None                      # raw X25519 private key (Ed25519)
    rsa_key: rsa.RSAPrivateKey | None = None
    public_raw: bytes = b""                          # what files are encrypted to
    blob: bytes = b""                                # the SSH public key's wire encoding


def read_private(path: Path) -> bytes:
    return read_text(Path(path), MAX_KEY_FILE, "an SSH private key").encode("utf-8", "surrogateescape")


def needs_passphrase(data: bytes) -> bool:
    """Whether an SSH private key is protected by a passphrase (checked without one)."""
    try:
        _load(data, None)
    except WrongKeyError:
        return True
    except LocksmithError:
        return False
    return False


def _load(data: bytes, passphrase: str | None):
    if b"-----BEGIN OPENSSH PRIVATE KEY-----" in data:
        load = load_ssh_private_key
    elif data.lstrip().startswith(b"-----BEGIN"):
        load = load_pem_private_key
    else:
        load = load_der_private_key
    unreadable = LocksmithError("That is not an SSH private key Locksmith can read.")
    try:
        try:
            return load(data, passphrase.encode() if passphrase else None)
        except TypeError:
            # cryptography says which: a protected key without a passphrase, or a passphrase given
            # for a key that has none (then it isn't needed).
            if not passphrase:
                raise WrongKeyError("This SSH key is protected by a passphrase.") from None
            return load(data, None)
        except ValueError:
            if passphrase:
                raise WrongKeyError("Wrong passphrase for the SSH key.") from None
            raise unreadable from None
    except (ValueError, TypeError):
        raise unreadable from None
    except UnsupportedAlgorithm:
        raise LocksmithError("That SSH key uses an algorithm Locksmith can't read.") from None


def load_identity(data: bytes, passphrase: str | None = None) -> SshIdentity:
    """Load an SSH private key (OpenSSH, PEM or DER) for opening files. Only Ed25519 and RSA keys
    can open files; a passphrase-protected OpenSSH key needs the bcrypt module."""
    key = _load(data, passphrase)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        blob = _ssh_blob(key.public_key())
        x = ed25519_seed_to_x25519(key.private_bytes_raw())
        public = X25519PrivateKey.from_private_bytes(x).public_key().public_bytes_raw()
        if public != ed25519_to_x25519(key.public_key().public_bytes_raw()):
            raise LocksmithError("This SSH key is damaged.")
        return SshIdentity(ED25519, sshsig.fingerprint(blob), x25519=x, public_raw=public, blob=blob)
    if isinstance(key, rsa.RSAPrivateKey):
        _check_rsa(key)
        blob = _ssh_blob(key.public_key())
        return SshIdentity(RSA, sshsig.fingerprint(blob), rsa_key=key, public_raw=blob, blob=blob)
    raise LocksmithError("Only SSH Ed25519 and RSA keys can open files.")


def public_blob(public) -> bytes:
    """The SSH wire encoding of a cryptography public key."""
    return _ssh_blob(public)


def _ssh_blob(public) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    line = public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).split()
    try:
        return base64.b64decode(line[1], validate=True)
    except (IndexError, ValueError, binascii.Error):
        raise LocksmithError("This SSH key is damaged.") from None


# ── the ssh-rsa slot (FORMAT.md §3) ──────────────────────────────────────────

def _oaep(label: bytes) -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def rsa_encrypt(blob: bytes, secret: bytes, label: bytes) -> bytes:
    key = rsa_public(blob)
    _check_rsa(key)
    return key.encrypt(secret, _oaep(label))


def rsa_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes, label: bytes) -> bytes | None:
    if len(ciphertext) != (key.key_size + 7) // 8:
        return None
    try:
        return key.decrypt(ciphertext, _oaep(label))
    except ValueError:
        return None
