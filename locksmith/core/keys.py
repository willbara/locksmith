"""Identities (your key pairs) and contacts (other people's public keys).

Two kinds of key exist:

* classical: X25519 only. Public keys look like ``locksmith1…``.
* hybrid post-quantum: X25519 plus ML-KEM-768. Public keys look like ``locksmith2…``.
  Files encrypted to them stay safe unless *both* algorithms are broken, which
  protects against "harvest now, decrypt later" by a future quantum computer.

Raw forms passed to the engine: public keys are 32 bytes (classical) or
32 + 1184 bytes (hybrid); private keys are 32 bytes or 32 + 64 bytes (the X25519
key followed by the ML-KEM seed).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
import unicodedata
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import kdf
from .errors import LocksmithError, WrongKeyError
from .osutil import config_base, fsync_dir, open_new
from .sysenv import clean_env

PUBKEY_PREFIX = "locksmith1"         # classical X25519
HYBRID_PREFIX = "locksmith2"         # X25519 + ML-KEM-768
X25519_LEN = 32
MLKEM_PUBLIC_LEN = 1184
MLKEM_SEED_LEN = 64
HYBRID_PUBLIC_LEN = X25519_LEN + MLKEM_PUBLIC_LEN
HYBRID_PRIVATE_LEN = X25519_LEN + MLKEM_SEED_LEN


TPM_CREDENTIAL_NAME = "locksmith-identity"
IDENTITY_LABEL = b"locksmith/v1/identity"


def tpm_available() -> bool:
    """True if identities can be sealed to this machine's TPM 2.0 (via systemd-creds)."""
    if not shutil.which("systemd-creds"):
        return False
    try:
        return subprocess.run(["systemd-creds", "has-tpm2", "--quiet"], env=clean_env(),
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _creds(args: list[str], data: bytes) -> bytes:
    try:
        r = subprocess.run(["systemd-creds", *args, f"--name={TPM_CREDENTIAL_NAME}", "-", "-"], input=data,
                           env=clean_env(), capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise LocksmithError(f"The TPM could not be used: {e}") from e
    if r.returncode != 0:
        raise LocksmithError("The TPM refused the request. The key may belong to another machine or "
                           "user, or the TPM was reset. Restore the identity from a backup.")
    return r.stdout


def tpm_seal(data: bytes) -> bytes:
    # host+tpm2: needs this machine's TPM *and* its root-only host key. The credential is
    # bound to the current user and TPM_CREDENTIAL_NAME. --tpm2-pcrs= (none) so firmware
    # or Secure Boot updates do not lock the key away.
    return _creds(["encrypt", "--user", "--with-key=host+tpm2", "--tpm2-pcrs="], data)


def tpm_unseal(blob: bytes) -> bytes:
    return _creds(["decrypt", "--user"], blob)


def is_hybrid(raw: bytes) -> bool:
    return len(raw) in (HYBRID_PUBLIC_LEN, HYBRID_PRIVATE_LEN)


def public_from_private(raw: bytes) -> bytes:
    """Derive the raw public key (classical or hybrid) from a raw private key."""
    if len(raw) not in (X25519_LEN, HYBRID_PRIVATE_LEN):
        raise ValueError("wrong private key length")
    pub = X25519PrivateKey.from_private_bytes(raw[:X25519_LEN]).public_key().public_bytes_raw()
    if len(raw) == HYBRID_PRIVATE_LEN:
        pub += MLKEM768PrivateKey.from_seed_bytes(raw[X25519_LEN:]).public_key().public_bytes_raw()
    return pub


def config_dir() -> Path:
    path = config_base() / "locksmith"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def write_secret_file(path: Path, data: str | bytes):
    """Atomically write a file that is never readable by other users, even briefly.
    An existing file (or symlink) at ``path`` is replaced, never written through."""
    path = Path(path)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = open_new(tmp)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(path.parent)


def _norm(passphrase: str) -> bytes:
    return unicodedata.normalize("NFC", passphrase).encode()


def check_public(raw: bytes):
    """Reject keys that are the wrong size, low-order X25519 points, or malformed
    ML-KEM keys, which would make encryption to them fail or be insecure."""
    if not isinstance(raw, bytes) or len(raw) not in (X25519_LEN, HYBRID_PUBLIC_LEN):
        raise LocksmithError("That public key is not valid.")
    try:
        X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(raw[:X25519_LEN]))
    except ValueError:
        raise LocksmithError("That public key is not usable (low-order point).") from None
    if len(raw) == HYBRID_PUBLIC_LEN:
        try:
            MLKEM768PublicKey.from_public_bytes(raw[X25519_LEN:]).encapsulate()
        except ValueError:
            raise LocksmithError("That public key's post-quantum part is not valid.") from None


def encode_public(raw: bytes) -> str:
    prefix = HYBRID_PREFIX if len(raw) == HYBRID_PUBLIC_LEN else PUBKEY_PREFIX
    check = hashlib.sha256(raw).digest()[:4]
    return prefix + base64.urlsafe_b64encode(raw + check).decode().rstrip("=")


def decode_public(text: str) -> bytes:
    text = "".join(text.split())
    if text.startswith(PUBKEY_PREFIX):
        prefix, size = PUBKEY_PREFIX, X25519_LEN
    elif text.startswith(HYBRID_PREFIX):
        prefix, size = HYBRID_PREFIX, HYBRID_PUBLIC_LEN
    else:
        raise LocksmithError("Public keys start with “locksmith1” or “locksmith2”.")
    body = text[len(prefix):]
    if len(body) > 4 * (size + 4):
        raise LocksmithError("That public key is not valid.")
    try:
        blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (ValueError, binascii.Error):
        raise LocksmithError("That public key is not valid.") from None
    raw, check = blob[:size], blob[size:]
    if len(raw) != size or len(check) != 4 or hashlib.sha256(raw).digest()[:4] != check:
        raise LocksmithError("That public key has a typo (checksum mismatch).")
    check_public(raw)
    return raw


def fingerprint(raw: bytes) -> str:
    h = hashlib.sha256(raw).hexdigest()[:20].upper()
    return " ".join(h[i:i + 4] for i in range(0, 20, 4))


@dataclass
class Identity:
    name: str
    public: str               # encoded public key
    created: int
    private: str | None = None  # base64 raw key when not protected
    locked: dict | None = None  # passphrase-protected private key
    sealed: str | None = None   # TPM-sealed {"private": ...} or {"locked": ...}, base64
    sealed_locked: bool = False # whether the sealed content is passphrase protected

    @property
    def public_raw(self) -> bytes:
        return decode_public(self.public)

    @property
    def is_locked(self) -> bool:
        return self.locked is not None or (self.sealed is not None and self.sealed_locked)

    @property
    def is_sealed(self) -> bool:
        return self.sealed is not None

    def unsealed(self) -> dict:
        """The storage form inside the TPM seal: {"private": ...} or {"locked": {...}}."""
        if not self.sealed:
            return {"private": self.private} if self.private else {"locked": self.locked}
        try:
            inner = json.loads(tpm_unseal(base64.b64decode(self.sealed, validate=True)))
        except (ValueError, binascii.Error):
            raise LocksmithError(f"The sealed key of “{self.name}” is damaged.") from None
        if not isinstance(inner, dict) or len(inner) != 1 or not ({"private", "locked"} & inner.keys()):
            raise LocksmithError(f"The sealed key of “{self.name}” is damaged.")
        return inner

    @property
    def is_post_quantum(self) -> bool:
        return is_hybrid(self.public_raw)

    def private_raw(self, passphrase: str | None = None) -> bytes:
        """Return the private key, checking it really belongs to this public key."""
        if self.is_locked and not passphrase:
            raise WrongKeyError(f"“{self.name}” is protected by a passphrase.")
        store = self.unsealed() if self.sealed else {"private": self.private, "locked": self.locked}
        if store.get("private"):
            try:
                raw = base64.b64decode(store["private"], validate=True)
            except (ValueError, binascii.Error, TypeError):
                raise LocksmithError(f"The private key of “{self.name}” is damaged.") from None
        elif store.get("locked"):
            raw = self._unlock(passphrase, store["locked"])
        else:
            raise LocksmithError(f"“{self.name}” has no private key.")
        self._check_pair(raw)
        return raw

    def _unlock(self, passphrase: str, lk: dict) -> bytes:
        try:
            salt, nonce, ct = (base64.b64decode(lk[k], validate=True) for k in ("salt", "n", "c"))
            kdf_name, params = lk["kdf"], lk["p"]
        except (KeyError, TypeError, ValueError, binascii.Error):
            raise LocksmithError(f"The protected key of “{self.name}” is damaged.") from None
        # NFC first; fall back to the raw bytes in case a key was protected before
        # normalisation was added.
        attempts = [_norm(passphrase)]
        if passphrase.encode() != attempts[0]:
            attempts.append(passphrase.encode())
        for secret in attempts:
            key = kdf.derive(secret, salt, kdf_name, params)
            try:
                return AESGCM(key).decrypt(nonce, ct, IDENTITY_LABEL)
            except InvalidTag:
                continue
        raise WrongKeyError(f"Wrong passphrase for “{self.name}”.")

    def _check_pair(self, raw: bytes):
        try:
            derived = public_from_private(raw)
        except ValueError:
            raise LocksmithError(f"The private key of “{self.name}” is damaged.") from None
        if derived != self.public_raw:
            raise LocksmithError(f"The private key of “{self.name}” does not match its public key.")


@dataclass
class Contact:
    name: str
    public: str
    added: int

    @property
    def public_raw(self) -> bytes:
        return decode_public(self.public)


def _protect(raw: bytes, passphrase: str) -> dict:
    salt = kdf.new_salt()
    params = kdf.params_for("argon2id", "balanced")
    key = kdf.derive(_norm(passphrase), salt, "argon2id", params)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, raw, IDENTITY_LABEL)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return {"kdf": "argon2id", "p": params, "salt": b64(salt), "n": b64(nonce), "c": b64(ct)}


def _from_dict(cls, data):
    """Build a dataclass from stored JSON, ignoring unknown fields (from newer
    versions) and rejecting entries with missing or mistyped required fields."""
    if not isinstance(data, dict):
        raise TypeError
    known = {f.name for f in fields(cls)}
    obj = cls(**{k: v for k, v in data.items() if k in known})
    if not isinstance(obj.name, str) or not isinstance(obj.public, str):
        raise TypeError
    if cls is Identity and sum(x is not None for x in (obj.private, obj.locked, obj.sealed)) != 1:
        raise TypeError
    decode_public(obj.public)
    return obj


class KeyStore:
    def __init__(self, directory: Path | None = None):
        self.dir = directory or config_dir()
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.dir / "keys.json"
        self.identities: list[Identity] = []
        self.contacts: list[Contact] = []
        self.problem: str | None = None   # shown to the user when loading had trouble
        self._unreadable: dict[str, list] = {"identities": [], "contacts": []}
        self.load()

    def load(self):
        """Load keys without ever discarding data. Entries that cannot be parsed are
        kept verbatim and written back on save; an unreadable file is backed up."""
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError
        except (OSError, ValueError, UnicodeDecodeError):
            backup = self.path.with_name(f"keys.json.unreadable-{time.strftime('%Y%m%d-%H%M%S')}")
            shutil.copy2(self.path, backup)
            os.chmod(backup, 0o600)
            self.problem = (f"Your key file could not be read. A copy was kept at {backup}. "
                            "New keys will be saved to a fresh file.")
            return
        for key, cls, target in (("identities", Identity, self.identities),
                                 ("contacts", Contact, self.contacts)):
            entries = data.get(key, [])
            if not isinstance(entries, list):
                self._unreadable[key].append(entries)  # preserved verbatim on save
                continue
            for entry in entries:
                try:
                    target.append(_from_dict(cls, entry))
                except (TypeError, ValueError, LocksmithError):
                    self._unreadable[key].append(entry)
        bad = sum(map(len, self._unreadable.values()))
        if bad:
            self.problem = (f"{bad} saved key{'s' if bad != 1 else ''} could not be read and "
                            f"{'were' if bad != 1 else 'was'} left untouched in keys.json.")

    def save(self):
        data = {"identities": [asdict(i) for i in self.identities] + self._unreadable["identities"],
                "contacts": [asdict(c) for c in self.contacts] + self._unreadable["contacts"]}
        write_secret_file(self.path, json.dumps(data, indent=2))

    def generate(self, name: str, passphrase: str | None = None, post_quantum: bool = True) -> Identity:
        raw = X25519PrivateKey.generate().private_bytes_raw()
        if post_quantum:
            raw += MLKEM768PrivateKey.generate().private_bytes_raw()  # the 64-byte seed
        ident = Identity(name=name.strip() or "My key", public=encode_public(public_from_private(raw)),
                         created=int(time.time()))
        self._store_private(ident, raw, passphrase)
        self.identities.append(ident)
        self.save()
        return ident

    def upgrade(self, ident: Identity, passphrase: str | None = None) -> Identity:
        """Add an ML-KEM key to a classical identity. The X25519 part is kept, so
        files already encrypted to it still open; the public key changes and should
        be shared again."""
        if ident.is_post_quantum:
            return ident
        was_locked, was_sealed = ident.is_locked, ident.is_sealed
        raw = ident.private_raw(passphrase) + MLKEM768PrivateKey.generate().private_bytes_raw()
        ident.public = encode_public(public_from_private(raw))
        ident.private = ident.locked = ident.sealed = None
        ident.sealed_locked = False
        self._store_private(ident, raw, passphrase if was_locked else None)
        if was_sealed:
            self._seal(ident)
        self.save()
        return ident

    def seal(self, ident: Identity) -> Identity:
        """Seal an identity's stored key to this machine's TPM."""
        if not ident.is_sealed:
            self._seal(ident)
            self.save()
        return ident

    def unseal(self, ident: Identity) -> Identity:
        """Remove TPM sealing, keeping the key (and any passphrase) portable again."""
        if ident.is_sealed:
            inner = ident.unsealed()
            ident.private, ident.locked = inner.get("private"), inner.get("locked")
            ident.sealed, ident.sealed_locked = None, False
            self.save()
        return ident

    @staticmethod
    def _seal(ident: Identity):
        inner = {"private": ident.private} if ident.private else {"locked": ident.locked}
        data = json.dumps(inner).encode()
        blob = tpm_seal(data)
        # Only drop the unsealed copy once the TPM has proven it can give it back.
        if not secrets.compare_digest(tpm_unseal(blob), data):
            raise LocksmithError("The TPM returned different data. Nothing was changed.")
        ident.sealed = base64.b64encode(blob).decode()
        ident.sealed_locked = ident.locked is not None
        ident.private = ident.locked = None

    @staticmethod
    def _store_private(ident: Identity, raw: bytes, passphrase: str | None):
        if passphrase:
            ident.locked = _protect(raw, passphrase)
        else:
            ident.private = base64.b64encode(raw).decode()

    def add_contact(self, name: str, public_text: str) -> Contact:
        raw = decode_public(public_text)
        encoded = encode_public(raw)
        if any(c.public == encoded for c in self.contacts):
            raise LocksmithError("That contact is already saved.")
        contact = Contact(name=name.strip() or "Contact", public=encoded, added=int(time.time()))
        self.contacts.append(contact)
        self.save()
        return contact

    def remove_identity(self, ident: Identity):
        self.identities.remove(ident)
        self.save()

    def remove_contact(self, contact: Contact):
        self.contacts.remove(contact)
        self.save()

    def export_identity(self, ident: Identity, path: Path):
        """Write a portable backup. TPM-sealed keys are unsealed first, since a sealed
        key cannot be opened on any other machine."""
        data = asdict(ident)
        if ident.is_sealed:
            inner = ident.unsealed()
            data.update(private=inner.get("private"), locked=inner.get("locked"), sealed=None,
                        sealed_locked=False)
        write_secret_file(Path(path), json.dumps({"locksmith-identity": 1, **data}, indent=2))

    def import_identity(self, path: Path) -> Identity:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if data.pop("locksmith-identity") != 1:
                raise ValueError
            ident = _from_dict(Identity, data)
            if ident.sealed is not None or bool(ident.private) == bool(ident.locked):
                raise ValueError
            if ident.locked is not None and not isinstance(ident.locked, dict):
                raise ValueError
        except (KeyError, ValueError, TypeError, AttributeError, LocksmithError, UnicodeDecodeError,
                RecursionError) as e:
            raise LocksmithError("That is not a valid Locksmith identity backup.") from e
        if ident.private:
            ident.private_raw()  # raises if the pair does not match
        # Protected keys are checked against their public key when first unlocked.
        if any(i.public == ident.public for i in self.identities):
            raise LocksmithError("That identity is already imported.")
        self.identities.append(ident)
        self.save()
        return ident

    def unlocked_private_keys(self) -> list[bytes]:
        keys = []
        for ident in self.identities:
            if ident.is_locked:
                continue
            try:
                keys.append(ident.private_raw())
            except LocksmithError:
                continue  # a damaged identity must not block the others
        return keys
