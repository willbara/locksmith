"""Identities (your key pairs) and contacts (other people's public keys).

Two kinds of key exist:

* classical: X25519 only. Public keys look like ``locksmith1…``.
* hybrid post-quantum: X25519 plus ML-KEM-768. Public keys look like ``locksmith2…``.
  Files encrypted to them stay safe unless *both* algorithms are broken, which
  protects against "harvest now, decrypt later" by a future quantum computer.

Hybrid identities also sign, with Ed25519 and ML-DSA-65 keys derived from their
private key (docs/FORMAT.md §13). Their full public key adds the two verify keys and
looks like ``locksmith3…``; files are still encrypted to its first 1216 bytes.

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
from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import age, kdf, sshkeys
from .errors import LocksmithError, WrongKeyError
from .osutil import config_base, fsync_dir, open_new
from .sysenv import clean_env

PUBKEY_PREFIX = "locksmith1"         # classical X25519
HYBRID_PREFIX = "locksmith2"         # X25519 + ML-KEM-768
SIGNING_PREFIX = "locksmith3"        # X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65
X25519_LEN = 32
MLKEM_PUBLIC_LEN = 1184
MLKEM_SEED_LEN = 64
ED25519_LEN = 32
MLDSA_PUBLIC_LEN = 1952
HYBRID_PUBLIC_LEN = X25519_LEN + MLKEM_PUBLIC_LEN
HYBRID_PRIVATE_LEN = X25519_LEN + MLKEM_SEED_LEN
VERIFY_LEN = ED25519_LEN + MLDSA_PUBLIC_LEN
SIGNING_PUBLIC_LEN = HYBRID_PUBLIC_LEN + VERIFY_LEN
PREFIXES = {X25519_LEN: PUBKEY_PREFIX, HYBRID_PUBLIC_LEN: HYBRID_PREFIX, SIGNING_PUBLIC_LEN: SIGNING_PREFIX}
QR_FINGERPRINT = "LOCKSMITH3:FP:"    # a locksmith3 key's QR code holds only its hash


TPM_CREDENTIAL_NAME = "locksmith-identity"
IDENTITY_LABEL = b"locksmith/v1/identity"
SIGNING_LABEL = b"locksmith/v1/sig/"


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
    return len(raw) in (HYBRID_PUBLIC_LEN, HYBRID_PRIVATE_LEN, SIGNING_PUBLIC_LEN)


def signing_keys(raw: bytes) -> tuple[Ed25519PrivateKey, MLDSA65PrivateKey]:
    """The Ed25519 and ML-DSA-65 keys derived from a hybrid private key (FORMAT.md §13).
    A classical key has none: a quantum computer could recover it from its public key,
    and with it any key derived from it."""
    if len(raw) != HYBRID_PRIVATE_LEN:
        raise LocksmithError("Only post-quantum identities can sign. Upgrade this identity on the Keys page "
                             "first.")

    def seed(name: bytes) -> bytes:
        return HKDF(hashes.SHA512(), 32, b"", SIGNING_LABEL + name).derive(raw)

    return Ed25519PrivateKey.from_private_bytes(seed(b"ed25519")), MLDSA65PrivateKey.from_seed_bytes(seed(b"ml-dsa-65"))


def verify_key(raw: bytes) -> bytes:
    """The raw Ed25519 + ML-DSA-65 public keys of a hybrid private key."""
    ed, ml = signing_keys(raw)
    return ed.public_key().public_bytes_raw() + ml.public_key().public_bytes_raw()


def encryption_part(raw: bytes) -> bytes:
    """The part of a raw public key that files are encrypted to."""
    return raw[:HYBRID_PUBLIC_LEN] if len(raw) == SIGNING_PUBLIC_LEN else raw


def can_verify(raw: bytes) -> bool:
    return len(raw) == SIGNING_PUBLIC_LEN


def qr_text(raw: bytes) -> str:
    """What a public key's QR code holds: the key, or only the hash of a locksmith3 key,
    which is too large for a QR code."""
    if can_verify(raw):
        return QR_FINGERPRINT + hashlib.sha256(raw).hexdigest().upper()
    return encode_public(raw)


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
    ML-KEM or ML-DSA keys, which would make encryption to them fail or be insecure."""
    if not isinstance(raw, bytes) or len(raw) not in PREFIXES:
        raise LocksmithError("That public key is not valid.")
    try:
        X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(raw[:X25519_LEN]))
    except ValueError:
        raise LocksmithError("That public key is not usable (low-order point).") from None
    if len(raw) >= HYBRID_PUBLIC_LEN:
        try:
            MLKEM768PublicKey.from_public_bytes(raw[X25519_LEN:HYBRID_PUBLIC_LEN]).encapsulate()
        except ValueError:
            raise LocksmithError("That public key's post-quantum part is not valid.") from None
    if len(raw) == SIGNING_PUBLIC_LEN:
        try:
            Ed25519PublicKey.from_public_bytes(raw[HYBRID_PUBLIC_LEN:HYBRID_PUBLIC_LEN + ED25519_LEN])
            MLDSA65PublicKey.from_public_bytes(raw[HYBRID_PUBLIC_LEN + ED25519_LEN:])
        except ValueError:
            raise LocksmithError("That public key's signing part is not valid.") from None


def decode_recipient(text: str) -> bytes:
    """The key files are encrypted to, from a key someone shared: a Locksmith public key, an age
    recipient (age1… or age1pq1…), or an SSH Ed25519 or RSA public key (docs/FORMAT.md §3)."""
    if sshkeys.is_ssh_text(text):
        return sshkeys.parse_recipient(text).raw
    if age.is_recipient_text(text):
        return age.parse_recipient_key(text)   # the same keys as locksmith1 / locksmith2, written for age
    return decode_public(text)


def encode_public(raw: bytes) -> str:
    check = hashlib.sha256(raw).digest()[:4]
    return PREFIXES[len(raw)] + base64.urlsafe_b64encode(raw + check).decode().rstrip("=")


def decode_public(text: str) -> bytes:
    text = "".join(text.split())
    found = [(size, prefix) for size, prefix in PREFIXES.items() if text.startswith(prefix)]
    if not found:
        raise LocksmithError("Public keys start with “locksmith1”, “locksmith2” or “locksmith3”.")
    size, prefix = found[0]
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


# ── backups of a raw private key: words and Shamir shares ────────────────────
#
# Backup words are proquints: each 16 bits of the key become one pronounceable
# five-letter word (consonant, vowel, consonant, vowel, consonant). Two more words
# carry a checksum, so a typo is caught instead of restoring the wrong key. A
# classical key is 16 + 2 words, a post-quantum key 48 + 2. The words are the
# private key itself, without any passphrase.

_PQ_CONS, _PQ_VOW = "bdfghjklmnprstvz", "aiou"
_WORDS_LABEL = b"locksmith/v1/backup-words"
_SHARE_MAGIC = b"LSI1"   # identity shares split this prefix plus the raw private key


def _proquint(n: int) -> str:
    return (_PQ_CONS[n >> 12 & 15] + _PQ_VOW[n >> 10 & 3] + _PQ_CONS[n >> 6 & 15]
            + _PQ_VOW[n >> 4 & 3] + _PQ_CONS[n & 15])


def _unproquint(word: str) -> int | None:
    if len(word) != 5:
        return None
    n = 0
    for ch, alphabet, bits in zip(word, (_PQ_CONS, _PQ_VOW) * 2 + (_PQ_CONS,), (4, 2, 4, 2, 4), strict=True):
        i = alphabet.find(ch)
        if i < 0:
            return None
        n = n << bits | i
    return n


def _words_check(raw: bytes) -> bytes:
    return hashlib.sha256(_WORDS_LABEL + raw).digest()[:4]


def backup_words(raw: bytes) -> list[str]:
    if len(raw) not in (X25519_LEN, HYBRID_PRIVATE_LEN):
        raise LocksmithError("That private key can't be written as backup words.")
    data = raw + _words_check(raw)
    return [_proquint(int.from_bytes(data[i:i + 2], "big")) for i in range(0, len(data), 2)]


def private_from_words(text: str) -> bytes:
    """The raw private key written as backup words, checked against its checksum."""
    words = text.lower().replace("-", " ").split()
    if len(words) not in ((X25519_LEN + 4) // 2, (HYBRID_PRIVATE_LEN + 4) // 2):
        raise LocksmithError(f"Backup words come in sets of {(X25519_LEN + 4) // 2} or "
                             f"{(HYBRID_PRIVATE_LEN + 4) // 2}; this has {len(words)}.")
    data = bytearray()
    for i, word in enumerate(words, 1):
        n = _unproquint(word)
        if n is None:
            raise LocksmithError(f"Word {i} (“{word[:12]}”) is not a backup word.")
        data += n.to_bytes(2, "big")
    raw, check = bytes(data[:-4]), bytes(data[-4:])
    if not secrets.compare_digest(_words_check(raw), check):
        raise LocksmithError("The words have a typo: their checksum doesn't match.")
    return raw


PAPER_PREFIX = "LOCKSMITH-ID1:"   # a paper backup's QR code (FORMAT.md §10)


def paper_qr_text(raw: bytes) -> str:
    """What a paper backup's QR code holds: the backup words' bytes (the raw private key and its
    checksum) in base32, which QR codes store compactly as alphanumeric text."""
    if len(raw) not in (X25519_LEN, HYBRID_PRIVATE_LEN):
        raise LocksmithError("That private key can't be written on a paper backup.")
    return PAPER_PREFIX + base64.b32encode(raw + _words_check(raw)).decode().rstrip("=")


def is_paper_text(text: str) -> bool:
    return text.strip().upper().startswith(PAPER_PREFIX)


def private_from_paper(text: str) -> bytes:
    """The raw private key in a paper backup's QR code, checked against its checksum."""
    body = "".join(text.split())[len(PAPER_PREFIX):].upper()
    if len(body) not in (-(-(X25519_LEN + 4) * 8 // 5), -(-(HYBRID_PRIVATE_LEN + 4) * 8 // 5)):
        raise LocksmithError("That QR code is not a complete Locksmith paper backup.")
    try:
        data = base64.b32decode(body + "=" * (-len(body) % 8))
    except (ValueError, binascii.Error):
        raise LocksmithError("That QR code is not a Locksmith paper backup.") from None
    raw, check = data[:-4], data[-4:]
    if not secrets.compare_digest(_words_check(raw), check):
        raise LocksmithError("The paper backup's checksum doesn't match: the code was misread or damaged.")
    return raw


def identity_shares(raw: bytes, threshold: int, shares: int) -> list[str]:
    """Split a raw private key into Shamir shares that only restore as an identity."""
    from .tools import shamir_split
    if len(raw) not in (X25519_LEN, HYBRID_PRIVATE_LEN):
        raise LocksmithError("That private key can't be split.")
    return shamir_split(_SHARE_MAGIC + raw, threshold, shares)


def is_identity_secret(secret: bytes) -> bool:
    """True for a secret recovered from identity shares (see ``identity_shares``)."""
    return secret.startswith(_SHARE_MAGIC) and len(secret) - len(_SHARE_MAGIC) in (X25519_LEN, HYBRID_PRIVATE_LEN)


def private_from_shares(texts: list[str]) -> bytes:
    from .tools import shamir_combine
    secret = shamir_combine(texts)
    if not is_identity_secret(secret):
        raise LocksmithError("These shares hold a password or other secret, not an identity. "
                             "Combine them on the Share page.")
    return secret[len(_SHARE_MAGIC):]


def fingerprint(raw: bytes) -> str:
    h = hashlib.sha256(raw).hexdigest()[:20].upper()
    return " ".join(h[i:i + 4] for i in range(0, 20, 4))


@dataclass
class Identity:
    name: str
    public: str               # encoded encryption key (locksmith1/2), which older versions read
    created: int
    private: str | None = None  # base64 raw key when not protected
    locked: dict | None = None  # passphrase-protected private key
    sealed: str | None = None   # TPM-sealed {"private": ...} or {"locked": ...}, base64
    sealed_locked: bool = False # whether the sealed content is passphrase protected
    # base64 Ed25519 + ML-DSA-65 public keys, so a locked or sealed identity can show its full
    # public key. Only a cache: derived again whenever the private key is unlocked, and
    # older versions drop it on save.
    verify: str | None = None

    @property
    def public_raw(self) -> bytes:
        """The key files are encrypted to."""
        return decode_public(self.public)

    @property
    def verify_raw(self) -> bytes | None:
        if not self.verify or not self.is_post_quantum:
            return None
        try:
            raw = base64.b64decode(self.verify, validate=True)
        except (ValueError, binascii.Error):
            return None
        return raw if len(raw) == VERIFY_LEN else None

    @property
    def key_raw(self) -> bytes:
        """The full public key to share: with the verify keys once they are known."""
        return self.public_raw + (self.verify_raw or b"")

    @property
    def key_text(self) -> str:
        return encode_public(self.key_raw)

    @property
    def can_sign(self) -> bool:
        return self.is_post_quantum

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
        if len(raw) == HYBRID_PRIVATE_LEN:
            self.verify = base64.b64encode(verify_key(raw)).decode()   # refresh the cache
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
    public: str               # encoded public key, including any verify keys (locksmith3), or an SSH key line
    added: int

    @property
    def ssh(self) -> sshkeys.SshRecipient | None:
        return sshkeys.parse_recipient(self.public) if sshkeys.is_ssh_text(self.public) else None

    @property
    def key_raw(self) -> bytes:
        ssh = self.ssh
        return ssh.raw if ssh else decode_public(self.public)

    @property
    def fingerprint(self) -> str:
        """The fingerprint its owner sees: SSH keys use SSH's own (as ``ssh-keygen -l`` prints it)."""
        ssh = self.ssh
        return ssh.fingerprint if ssh else fingerprint(self.key_raw)

    @property
    def kind(self) -> str:
        ssh = self.ssh
        if ssh:
            return f"{ssh.label}, classical"
        if self.can_verify:
            return "Post-quantum, verifies signatures"
        return "Post-quantum" if len(self.public_raw) > X25519_LEN else "Classical"

    @property
    def public_raw(self) -> bytes:
        """The key files are encrypted to."""
        return encryption_part(self.key_raw)

    @property
    def can_verify(self) -> bool:
        return can_verify(self.key_raw)


def _protect(raw: bytes, passphrase: str) -> dict:
    salt = kdf.new_salt()
    params = kdf.params_for("argon2id", "balanced")
    key = kdf.derive(_norm(passphrase), salt, "argon2id", params)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, raw, IDENTITY_LABEL)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return {"kdf": "argon2id", "p": params, "salt": b64(salt), "n": b64(nonce), "c": b64(ct)}


def _assign(target, source):
    """Copy every dataclass field of ``source`` onto ``target`` in place."""
    for f in fields(target):
        setattr(target, f.name, getattr(source, f.name))


def _from_dict(cls, data):
    """Build a dataclass from stored JSON, ignoring unknown fields (from newer
    versions) and rejecting entries with missing or mistyped required fields."""
    if not isinstance(data, dict):
        raise TypeError
    known = {f.name for f in fields(cls)}
    obj = cls(**{k: v for k, v in data.items() if k in known})
    if not isinstance(obj.name, str) or not isinstance(obj.public, str):
        raise TypeError
    if cls is Identity:
        if sum(x is not None for x in (obj.private, obj.locked, obj.sealed)) != 1:
            raise TypeError
        # A mistyped field would fail later, outside LocksmithError, and block every decrypt.
        if not (isinstance(obj.private, str | None) and isinstance(obj.sealed, str | None)
                and isinstance(obj.locked, dict | None) and isinstance(obj.sealed_locked, bool)):
            raise TypeError
        if not isinstance(obj.verify, str) or obj.verify_raw is None:
            obj.verify = None   # only a cache: a bad one is dropped, not a reason to reject the identity
        if len(decode_public(obj.public)) == SIGNING_PUBLIC_LEN:
            raise TypeError     # an identity's stored public key is its encryption key
    when = obj.created if cls is Identity else obj.added
    if isinstance(when, bool) or not isinstance(when, int):
        raise TypeError
    decode_public(obj.public) if cls is Identity else decode_recipient(obj.public)
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
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
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
        for ident in self.identities:
            # Identities without a passphrase or TPM seal can always show their verify keys.
            if ident.private and ident.is_post_quantum:
                try:
                    ident.private_raw()
                except LocksmithError:
                    pass   # reported when the identity is used
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
        self._remember_verify(ident, raw)
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
        # Build the upgrade on a copy and apply it only once every step has succeeded:
        # if the TPM refuses the new seal, the identity must not be left holding the
        # key unsealed, where the next save of anything would write it to disk.
        new = replace(ident, public=encode_public(public_from_private(raw)),
                      private=None, locked=None, sealed=None, sealed_locked=False)
        self._store_private(new, raw, passphrase if was_locked else None)
        self._remember_verify(new, raw)
        if was_sealed:
            self._seal(new)
        old = replace(ident)
        _assign(ident, new)
        try:
            self.save()
        except BaseException:
            _assign(ident, old)  # the save is atomic, so the file still holds the old identity
            raise
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

    def remember_verify(self, ident: Identity, passphrase: str | None = None) -> Identity:
        """Unlock a hybrid identity once so its full public key (with verify keys) is known."""
        ident.private_raw(passphrase)
        self.save()
        return ident

    @staticmethod
    def _remember_verify(ident: Identity, raw: bytes):
        if len(raw) == HYBRID_PRIVATE_LEN:
            ident.verify = base64.b64encode(verify_key(raw)).decode()

    @staticmethod
    def _store_private(ident: Identity, raw: bytes, passphrase: str | None):
        if passphrase:
            ident.locked = _protect(raw, passphrase)
        else:
            ident.private = base64.b64encode(raw).decode()

    def contact_with_encryption_key(self, raw: bytes) -> Contact | None:
        """The saved contact whose key encrypts to the same key as ``raw``, if any."""
        part = encryption_part(raw)
        return next((c for c in self.contacts if c.public_raw == part), None)

    def add_contact(self, name: str, public_text: str) -> Contact:
        raw = decode_recipient(public_text)
        encoded = sshkeys.parse_recipient(public_text).text if sshkeys.is_ssh_text(public_text) else encode_public(raw)
        same = self.contact_with_encryption_key(raw)
        if same is not None:
            if same.public == encoded or (same.can_verify and not can_verify(raw)):
                raise LocksmithError(f"That key is already saved as “{same.name}”.")
            if same.can_verify:
                raise LocksmithError(self._FORGED.format(same.name))
            raise LocksmithError(f"“{same.name}” already has this key without its signing keys. Update that "
                                 "contact instead.")
        contact = Contact(name=name.strip() or "Contact", public=encoded, added=int(time.time()))
        self.contacts.append(contact)
        self.save()
        return contact

    _FORGED = ("This key encrypts to the same key as “{}” but has different signing keys, so it was not made "
               "by the same identity. It was not saved.")

    def update_contact_key(self, contact: Contact, public_text: str) -> Contact:
        """Give a contact saved without signing keys its full locksmith3 key. Only the same
        encryption key is accepted; the fingerprint changes and should be checked again."""
        raw = decode_public(public_text)
        if not can_verify(raw):
            raise LocksmithError("That key has no signing keys.")
        if encryption_part(raw) != contact.public_raw:
            raise LocksmithError(f"That is not a key of “{contact.name}”: it encrypts to a different key.")
        if contact.can_verify and contact.key_raw != raw:
            raise LocksmithError(self._FORGED.format(contact.name))
        contact.public = encode_public(raw)
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
        data.pop("verify")   # derived from the private key; not part of the backup format
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
        ident.verify = None   # never taken from the file: derived when the key is first unlocked
        if ident.private:
            ident.private_raw()  # raises if the pair does not match
        # Protected keys are checked against their public key when first unlocked.
        if any(i.public == ident.public for i in self.identities):
            raise LocksmithError("That identity is already imported.")
        self.identities.append(ident)
        self.save()
        return ident

    def restore(self, name: str, raw: bytes, passphrase: str | None = None) -> Identity:
        """Add an identity rebuilt from a raw private key (backup words or shares)."""
        try:
            public = encode_public(public_from_private(raw))
        except ValueError:
            raise LocksmithError("That is not a valid private key.") from None
        if any(i.public == public for i in self.identities):
            raise LocksmithError("That identity is already on this device.")
        ident = Identity(name=name.strip() or "Restored key", public=public, created=int(time.time()))
        self._store_private(ident, raw, passphrase)
        self._remember_verify(ident, raw)
        self.identities.append(ident)
        try:
            self.save()
        except BaseException:
            self.identities.remove(ident)
            raise
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
