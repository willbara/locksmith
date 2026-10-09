"""The age file format (age-encryption.org/v1, specified at c2sp.org/age): read and write
``.age`` files, so files can be exchanged with age, rage and other age tools.

Recipient types: ``X25519`` (``age1…``), the post-quantum ``mlkem768x25519`` (X-Wing in HPKE,
``age1pq1…``), ``scrypt`` (a passphrase), and ``ssh-ed25519`` / ``ssh-rsa`` (SSH keys).
Stanzas of any other type (plugins, hardware tags, "grease") are ignored, as the format
requires.

Locksmith keys map onto age keys exactly: a classical identity is an age X25519 identity, and
a post-quantum identity (X25519 key and ML-KEM-768 seed) holds the same two keys an age
``AGE-SECRET-KEY-PQ-1…`` identity expands to, so it opens ``mlkem768x25519`` stanzas and its
public key is an ``age1pq1…`` recipient with the two halves swapped.

age files carry no metadata (no name, signature, padding or note): a folder is stored as a
tar archive and comes back as one.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import sshkeys
from .errors import CorruptedError, LocksmithError, WrongKeyError

INTRO = b"age-encryption.org/"
VERSION_LINE = b"age-encryption.org/v1\n"
EXTENSION = ".age"
CHUNK = 64 << 10
TAG = 16
MAX_HEADER = 1 << 20
MAX_LINE = 64 << 10
MAX_STANZAS = 1024           # real files have a few; each may cost a key operation
DEFAULT_WORK_FACTOR = 18     # age's own default: 256 MiB
MAX_WORK_FACTOR = 21         # 2 GiB, as for Locksmith's own scrypt slots
ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"
ARMOR_END = "-----END AGE ENCRYPTED FILE-----"
MAX_ARMOR = 128 << 20
X25519_LABEL = b"age-encryption.org/v1/X25519"
SCRYPT_LABEL = b"age-encryption.org/v1/scrypt"
SSH_ED25519_LABEL = b"age-encryption.org/v1/ssh-ed25519"
SSH_RSA_LABEL = b"age-encryption.org/v1/ssh-rsa"
HYBRID_INFO = b"age-encryption.org/mlkem768x25519"
X25519_LEN, MLKEM_PUBLIC_LEN, MLKEM_CT_LEN = 32, 1184, 1088
HYBRID_ENC_LEN = MLKEM_CT_LEN + X25519_LEN    # 1120
_B64 = re.compile(rb"[A-Za-z0-9+/]*")


class AgeHeaderError(CorruptedError):
    """The header is malformed (or a stanza addressed to one of our keys is)."""


class AgeMacError(CorruptedError):
    """The header was changed: its MAC doesn't match."""


class AgePayloadError(CorruptedError):
    """The encrypted content is damaged, truncated or extended."""


class AgeArmorError(CorruptedError):
    """The ASCII armor isn't the strict form age writes."""


# ── encodings ────────────────────────────────────────────────────────────────

def b64encode(data: bytes) -> bytes:
    """Unpadded standard base64, as age's header uses."""
    return base64.b64encode(data).rstrip(b"=")


def b64decode(text: bytes, size: int | None = None) -> bytes:
    """Canonical unpadded base64 only: no padding, no stray bits, nothing outside the alphabet."""
    if not isinstance(text, bytes) or not _B64.fullmatch(text) or len(text) % 4 == 1:
        raise AgeHeaderError("The age file's header is damaged (bad base64).")
    data = base64.b64decode(text + b"=" * (-len(text) % 4))
    if b64encode(data) != text or (size is not None and len(data) != size):
        raise AgeHeaderError("The age file's header is damaged (bad base64).")
    return data


_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if top >> i & 1:
                chk ^= _GEN[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert(data, frm: int, to: int, pad: bool) -> list[int] | None:
    acc = bits = 0
    out = []
    for v in data:
        acc = acc << frm | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append(acc >> bits & ((1 << to) - 1))
    if pad and bits:
        out.append(acc << (to - bits) & ((1 << to) - 1))
    elif not pad and (bits >= frm or acc & ((1 << bits) - 1)):
        return None
    return out


def bech32_encode(hrp: str, data: bytes, upper: bool = False) -> str:
    """BIP 173 Bech32, without its length limit (as age uses it)."""
    words = _convert(data, 8, 5, True)
    check = _polymod(_hrp_expand(hrp.lower()) + words + [0] * 6) ^ 1
    words += [check >> 5 * (5 - i) & 31 for i in range(6)]
    text = hrp.lower() + "1" + "".join(_CHARSET[w] for w in words)
    return text.upper() if upper else text


def bech32_decode(text: str) -> tuple[str, bytes]:
    bad = LocksmithError("That age key is not valid (or has a typo).")
    text = text.strip()
    if len(text) > 8192 or (text != text.lower() and text != text.upper()) or not text.isascii():
        raise bad
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or len(text) - pos < 7:
        raise bad
    hrp, words = text[:pos], []
    if any(not 33 <= ord(c) <= 126 for c in hrp):
        raise bad
    for c in text[pos + 1:]:
        i = _CHARSET.find(c)
        if i < 0:
            raise bad
        words.append(i)
    if _polymod(_hrp_expand(hrp) + words) != 1:
        raise bad
    data = _convert(words[:-6], 5, 8, False)
    if data is None:
        raise bad
    return hrp, bytes(data)


# ── keys ─────────────────────────────────────────────────────────────────────

def _xwing_expand(seed: bytes) -> bytes:
    """An age post-quantum identity (32-byte seed) as a Locksmith hybrid private key: the X25519
    key followed by the 64-byte ML-KEM-768 seed (X-Wing: SHAKE256(seed, 96) = d || z || sk_X)."""
    expanded = hashlib.shake_256(seed).digest(96)
    return expanded[64:] + expanded[:64]


def parse_identity(text: str) -> bytes:
    """A Locksmith raw private key from an age identity: ``AGE-SECRET-KEY-1…`` (X25519, 32 bytes)
    or ``AGE-SECRET-KEY-PQ-1…`` (post-quantum, 96 bytes)."""
    hrp, data = bech32_decode(text)
    if len(data) != 32 or hrp not in ("age-secret-key-", "age-secret-key-pq-"):
        raise LocksmithError("That is not an age identity (AGE-SECRET-KEY-1… or AGE-SECRET-KEY-PQ-1…).")
    return data if hrp == "age-secret-key-" else _xwing_expand(data)


def is_identity_text(text: str) -> bool:
    return text.strip().upper().startswith("AGE-SECRET-KEY-")


def is_recipient_text(text: str) -> bool:
    return text.strip().lower().startswith("age1")


def parse_recipient_key(text: str) -> bytes:
    """A Locksmith raw public key from an age recipient: ``age1…`` (X25519, 32 bytes) or
    ``age1pq1…`` (1216 bytes, in Locksmith's order: X25519 key, then ML-KEM-768 key)."""
    hrp, data = bech32_decode(text)
    if hrp == "age" and len(data) == X25519_LEN:
        return data
    if hrp == "age1pq" and len(data) == MLKEM_PUBLIC_LEN + X25519_LEN:
        return data[MLKEM_PUBLIC_LEN:] + data[:MLKEM_PUBLIC_LEN]
    raise LocksmithError("That is not an age recipient Locksmith can use (age1… or age1pq1…).")


def recipient_text(public: bytes) -> str:
    """The age recipient of a Locksmith public key (classical or post-quantum)."""
    if len(public) == X25519_LEN:
        return bech32_encode("age", public)
    if len(public) == X25519_LEN + MLKEM_PUBLIC_LEN:
        return bech32_encode("age1pq", public[X25519_LEN:] + public[:X25519_LEN])
    raise LocksmithError("Only Locksmith keys can be written as age recipients.")


@dataclass
class Recipient:
    """Whom an age file is encrypted to. ``key``: an X25519 key (32 bytes), a hybrid key in
    Locksmith's order (1216), or an SSH key blob."""
    kind: str      # "X25519", "mlkem768x25519", "ssh-ed25519" or "ssh-rsa"
    key: bytes

    @property
    def post_quantum(self) -> bool:
        return self.kind == "mlkem768x25519"


def recipient_for(raw: bytes, ssh_blob: bytes | None = None) -> Recipient:
    """The age recipient for a key Locksmith encrypts to (see EncryptOptions.recipients). An SSH
    Ed25519 contact gives its key blob, so age tools see an ordinary ssh-ed25519 stanza."""
    if ssh_blob is not None and ssh_blob.startswith(b"\x00\x00\x00\x0bssh-ed25519"):
        return Recipient("ssh-ed25519", ssh_blob)
    if sshkeys.is_rsa_raw(raw):
        sshkeys.recipient_from_raw(raw)
        return Recipient("ssh-rsa", raw)
    if len(raw) == X25519_LEN:
        return Recipient("X25519", raw)
    if len(raw) == X25519_LEN + MLKEM_PUBLIC_LEN:
        return Recipient("mlkem768x25519", raw)
    raise LocksmithError("A recipient's public key is invalid.")


@dataclass
class Keys:
    """What can open an age file."""
    identities: list[bytes] = field(default_factory=list)   # Locksmith raw private keys (32 or 96 bytes)
    ssh: list[sshkeys.SshIdentity] = field(default_factory=list)
    passphrase: str | None = None


# ── X-Wing and HPKE (for mlkem768x25519) ─────────────────────────────────────

_XWING_LABEL = b"\\.//^\\"
_SUITE = b"HPKE" + (0x647A).to_bytes(2, "big") + (1).to_bytes(2, "big") + (3).to_bytes(2, "big")


def _xwing_combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _XWING_LABEL).digest()


def _x25519(private: X25519PrivateKey, public: bytes) -> bytes:
    """Raises AgeHeaderError for an all-zero result (a low-order or identity point)."""
    try:
        return private.exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError:
        raise AgeHeaderError("The age file's header holds an unusable key share.") from None


def _labeled_extract(salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, b"HPKE-v1" + _SUITE + label + ikm, hashlib.sha256).digest()


def _labeled_expand(prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled = length.to_bytes(2, "big") + b"HPKE-v1" + _SUITE + label + info
    return HKDFExpand(hashes.SHA256(), length, labeled).derive(prk)


def _hpke_key(shared: bytes, info: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 KeySchedule in base mode: the AEAD key and base nonce."""
    ctx = b"\x00" + _labeled_extract(b"", b"psk_id_hash", b"") + _labeled_extract(b"", b"info_hash", info)
    secret = _labeled_extract(shared, b"secret", b"")
    return _labeled_expand(secret, b"key", ctx, 32), _labeled_expand(secret, b"base_nonce", ctx, 12)


def _hybrid_seal(public: bytes, file_key: bytes) -> tuple[bytes, bytes]:
    pk_x, pk_m = public[:X25519_LEN], public[X25519_LEN:]
    ss_m, ct_m = MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    eph = X25519PrivateKey.generate()
    ct_x = eph.public_key().public_bytes_raw()
    shared = _xwing_combine(ss_m, _x25519(eph, pk_x), ct_x, pk_x)
    key, nonce = _hpke_key(shared, HYBRID_INFO)
    return ct_m + ct_x, ChaCha20Poly1305(key).encrypt(nonce, file_key, b"")


def _hybrid_open(private: bytes, enc: bytes, body: bytes) -> bytes | None:
    sk_x = X25519PrivateKey.from_private_bytes(private[:X25519_LEN])
    ss_m = MLKEM768PrivateKey.from_seed_bytes(private[X25519_LEN:]).decapsulate(enc[:MLKEM_CT_LEN])
    ct_x = enc[MLKEM_CT_LEN:]
    shared = _xwing_combine(ss_m, _x25519(sk_x, ct_x), ct_x, sk_x.public_key().public_bytes_raw())
    key, nonce = _hpke_key(shared, HYBRID_INFO)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, body, b"")
    except InvalidTag:
        return None


# ── stanzas ──────────────────────────────────────────────────────────────────

@dataclass
class Stanza:
    args: list[bytes]
    body: bytes

    @property
    def type(self) -> bytes:
        return self.args[0]

    def encode(self) -> bytes:
        text = b64encode(self.body)
        lines = [text[i:i + 64] for i in range(0, len(text), 64)]
        if not lines or len(lines[-1]) == 64:
            lines.append(b"")
        return b"-> " + b" ".join(self.args) + b"\n" + b"".join(line + b"\n" for line in lines)


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt, info).derive(ikm)


def _aead_wrap(key: bytes, file_key: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(bytes(12), file_key, None)


def _aead_unwrap(key: bytes, body: bytes) -> bytes | None:
    try:
        return ChaCha20Poly1305(key).decrypt(bytes(12), body, None)
    except InvalidTag:
        return None


def _ssh_tag(blob: bytes) -> bytes:
    return b64encode(hashlib.sha256(blob).digest()[:4])


def _ssh_tweak(blob: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(_hkdf(b"", blob, SSH_ED25519_LABEL))


def _ssh_ed25519_public(blob: bytes) -> bytes:
    return sshkeys.parse_recipient(f"ssh-ed25519 {base64.b64encode(blob).decode()}").raw


def wrap(recipient: Recipient, file_key: bytes) -> Stanza:
    if recipient.kind == "X25519":
        eph = X25519PrivateKey.generate()
        share = eph.public_key().public_bytes_raw()
        key = _hkdf(_x25519(eph, recipient.key), share + recipient.key, X25519_LABEL)
        return Stanza([b"X25519", b64encode(share)], _aead_wrap(key, file_key))
    if recipient.kind == "mlkem768x25519":
        enc, body = _hybrid_seal(recipient.key, file_key)
        return Stanza([b"mlkem768x25519", b64encode(enc)], body)
    if recipient.kind == "ssh-ed25519":
        pk = _ssh_ed25519_public(recipient.key)
        eph = X25519PrivateKey.generate()
        share = eph.public_key().public_bytes_raw()
        shared = _x25519(_ssh_tweak(recipient.key), _x25519(eph, pk))
        key = _hkdf(shared, share + pk, SSH_ED25519_LABEL)
        return Stanza([b"ssh-ed25519", _ssh_tag(recipient.key), b64encode(share)], _aead_wrap(key, file_key))
    if recipient.kind == "ssh-rsa":
        return Stanza([b"ssh-rsa", _ssh_tag(recipient.key)], sshkeys.rsa_encrypt(recipient.key, file_key, SSH_RSA_LABEL))
    raise LocksmithError(f"Unknown age recipient type {recipient.kind}.")


def _scrypt_key(passphrase: str, salt: bytes, work_factor: int) -> bytes:
    return Scrypt(SCRYPT_LABEL + salt, 32, 1 << work_factor, 8, 1).derive(passphrase.encode())


def scrypt_stanza(passphrase: str, file_key: bytes, work_factor: int = DEFAULT_WORK_FACTOR) -> Stanza:
    salt = os.urandom(16)
    body = _aead_wrap(_scrypt_key(passphrase, salt, work_factor), file_key)
    return Stanza([b"scrypt", b64encode(salt), str(work_factor).encode()], body)


def _need(cond: bool, what: str):
    if not cond:
        raise AgeHeaderError(f"The age file's header is damaged ({what}).")


def _body32(st: Stanza):
    # The body is checked to be exactly a 16-byte file key and its tag before decrypting it,
    # so a different length can't be used to learn anything ("partitioning oracles").
    _need(len(st.body) == 32, "a stanza's body has the wrong length")


def unwrap(stanzas: list[Stanza], keys: Keys) -> bytes:
    """The file key, from the first stanza one of ``keys`` opens. Raises AgeHeaderError for a
    malformed stanza of a type we hold a key for, and WrongKeyError when none opens."""
    if any(st.type == b"scrypt" for st in stanzas) and len(stanzas) != 1:
        raise AgeHeaderError("The age file's header is damaged (a passphrase stanza must be alone).")
    x25519 = [X25519PrivateKey.from_private_bytes(r[:X25519_LEN]) for r in keys.identities]
    x25519 += [X25519PrivateKey.from_private_bytes(s.x25519) for s in keys.ssh if s.x25519 is not None]
    hybrid = [r for r in keys.identities if len(r) == X25519_LEN + 64]
    ssh_ed = [s for s in keys.ssh if s.x25519 is not None]
    ssh_rsa = [s for s in keys.ssh if s.rsa_key is not None]
    for st in stanzas:
        args = st.args[1:]
        if st.type == b"X25519" and x25519:
            _need(len(args) == 1, "an X25519 stanza has the wrong arguments")
            share = b64decode(args[0], X25519_LEN)
            _body32(st)
            for sk in x25519:
                pk = sk.public_key().public_bytes_raw()
                fk = _aead_unwrap(_hkdf(_x25519(sk, share), share + pk, X25519_LABEL), st.body)
                if fk is not None:
                    return fk
        elif st.type == b"mlkem768x25519" and hybrid:
            _need(len(args) == 1, "a post-quantum stanza has the wrong arguments")
            enc = b64decode(args[0], HYBRID_ENC_LEN)
            _body32(st)
            for raw in hybrid:
                fk = _hybrid_open(raw, enc, st.body)
                if fk is not None:
                    return fk
        elif st.type == b"scrypt" and keys.passphrase is not None:
            _need(len(args) == 2, "a passphrase stanza has the wrong arguments")
            salt = b64decode(args[0], 16)
            _need(re.fullmatch(rb"[1-9][0-9]{0,1}", args[1]) is not None, "a bad work factor")
            work = int(args[1])
            if work > MAX_WORK_FACTOR:
                raise AgeHeaderError(f"This age file's passphrase takes 2^{work} scrypt work, more than the "
                                     f"2^{MAX_WORK_FACTOR} Locksmith allows.")
            _body32(st)
            fk = _aead_unwrap(_scrypt_key(keys.passphrase, salt, work), st.body)
            if fk is not None:
                return fk
        elif st.type == b"ssh-ed25519" and ssh_ed:
            _need(len(args) == 2, "an ssh-ed25519 stanza has the wrong arguments")
            for ident in ssh_ed:
                if args[0] != _ssh_tag(ident.blob):
                    continue
                share = b64decode(args[1], X25519_LEN)
                _body32(st)
                shared = _x25519(_ssh_tweak(ident.blob), _x25519(X25519PrivateKey.from_private_bytes(ident.x25519),
                                                                 share))
                fk = _aead_unwrap(_hkdf(shared, share + ident.public_raw, SSH_ED25519_LABEL), st.body)
                if fk is not None:
                    return fk
        elif st.type == b"ssh-rsa" and ssh_rsa:
            _need(len(args) == 1, "an ssh-rsa stanza has the wrong arguments")
            for ident in ssh_rsa:
                if args[0] != _ssh_tag(ident.blob):
                    continue
                fk = sshkeys.rsa_decrypt(ident.rsa_key, st.body, SSH_RSA_LABEL)
                if fk is not None:
                    _need(len(fk) == 16, "a file key has the wrong length")
                    return fk
    raise WrongKeyError("None of your keys, passwords or SSH keys can open this age file.")


# ── header ───────────────────────────────────────────────────────────────────

@dataclass
class Header:
    stanzas: list[Stanza]
    mac: bytes
    signed: bytes      # what the MAC covers: everything up to and including "---"


def _readline(f: BinaryIO, budget: list[int]) -> bytes:
    line = f.readline(min(MAX_LINE, budget[0]) + 1)
    budget[0] -= len(line)
    if not line.endswith(b"\n") or budget[0] < 0:
        raise AgeHeaderError("The age file's header is damaged or too long.")
    return line


def _check_arg(arg: bytes):
    _need(arg != b"" and all(0x21 <= c <= 0x7E for c in arg), "a stanza argument is malformed")


def read_header(f: BinaryIO) -> Header:
    budget = [MAX_HEADER]
    first = f.readline(len(VERSION_LINE) + 64)
    if not first.startswith(INTRO):
        raise AgeHeaderError("This is not an age file.")
    if first != VERSION_LINE:
        raise AgeHeaderError("This age file uses a version Locksmith doesn't know.")
    signed = bytearray(first)
    stanzas = []
    while True:
        line = _readline(f, budget)
        if line.startswith(b"--- "):
            mac = line[4:-1]
            _need(len(mac) == 43, "its MAC is malformed")
            signed += b"---"
            _need(bool(stanzas), "it has no stanzas")
            return Header(stanzas, b64decode(mac, 32), bytes(signed))
        _need(line.startswith(b"-> "), "a line doesn't start a stanza")
        _need(len(stanzas) < MAX_STANZAS, "it has too many stanzas")
        args = line[3:-1].split(b" ")
        for arg in args:
            _check_arg(arg)
        signed += line
        text = bytearray()
        while True:
            body = _readline(f, budget)
            signed += body
            chunk = body[:-1]
            _need(len(chunk) <= 64 and _B64.fullmatch(chunk) is not None, "a stanza body line is malformed")
            text += chunk
            if len(chunk) < 64:
                break
        stanzas.append(Stanza(args, b64decode(bytes(text))))


def header_bytes(stanzas: list[Stanza], file_key: bytes) -> bytes:
    signed = VERSION_LINE + b"".join(st.encode() for st in stanzas) + b"---"
    return signed + b" " + b64encode(_mac(file_key, signed)) + b"\n"


def _mac(file_key: bytes, signed: bytes) -> bytes:
    return hmac.new(_hkdf(file_key, b"", b"header"), signed, hashlib.sha256).digest()


# ── payload ──────────────────────────────────────────────────────────────────

def _chunk_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _read_full(f: BinaryIO, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        part = f.read(n - len(buf))
        if not part:
            break
        buf += part
    return bytes(buf)


def encrypt_stream(src: BinaryIO, out: BinaryIO, recipients: list[Recipient], passphrase: str | None = None,
                   work_factor: int = DEFAULT_WORK_FACTOR, cancel: threading.Event | None = None,
                   progress=None, total: int = 0) -> bytes:
    """Write an age file of everything ``src`` holds. Returns the file key, for checking the
    written file. age doesn't allow a passphrase beside other recipients, nor (by default)
    post-quantum recipients beside classical ones, which would undo their protection."""
    if passphrase and recipients:
        raise LocksmithError("An age file is opened either with a passphrase or by recipients, not both.")
    if not passphrase and not recipients:
        raise LocksmithError("Add a passphrase or at least one recipient.")
    if recipients and len({r.post_quantum for r in recipients}) > 1:
        raise LocksmithError("age doesn't mix post-quantum and classical recipients in one file: it would leave "
                             "the file only as strong as the classical ones. Choose one kind.")
    file_key = secrets.token_bytes(16)
    unique = {(r.kind, r.key): r for r in recipients}.values()
    stanzas = [scrypt_stanza(passphrase, file_key, work_factor)] if passphrase else [wrap(r, file_key) for r in unique]
    secrets.SystemRandom().shuffle(stanzas)
    out.write(header_bytes(stanzas, file_key))
    nonce = os.urandom(16)
    out.write(nonce)
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    counter, done = 0, 0
    cur = _read_full(src, CHUNK)
    while True:
        if cancel is not None and cancel.is_set():
            from .errors import CancelledError
            raise CancelledError()
        nxt = _read_full(src, CHUNK) if len(cur) == CHUNK else b""
        last = not nxt
        out.write(aead.encrypt(_chunk_nonce(counter, last), cur, None))
        done += len(cur)
        if progress and total:
            progress(min(done / total, 1.0), "Encrypting")
        if last:
            return file_key
        cur, counter = nxt, counter + 1


def decrypt_stream(f: BinaryIO, out: BinaryIO, keys: Keys, cancel: threading.Event | None = None,
                   progress=None, total: int = 0, max_output: int | None = None, space=None) -> Header:
    """Decrypt an age file (binary, already de-armored) from ``f`` into ``out``. Everything is
    authenticated as it goes; a failure raises after writing only the chunks that came before
    it, so callers keep the output out of sight until this returns."""
    header = read_header(f)
    file_key = unwrap(header.stanzas, keys)
    if not hmac.compare_digest(_mac(file_key, header.signed), header.mac):
        raise AgeMacError("This age file's header was changed: its MAC doesn't match.")
    decrypt_payload(f, out, file_key, cancel, progress, total, max_output, space)
    return header


def decrypt_payload(f: BinaryIO, out: BinaryIO, file_key: bytes, cancel=None, progress=None, total: int = 0,
                    max_output: int | None = None, space=None):
    nonce = _read_full(f, 16)
    if len(nonce) != 16:
        raise AgeHeaderError("The age file is truncated after its header.")
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    damaged = AgePayloadError("The age file is damaged: it was changed, truncated or extended.")
    counter, written = 0, 0
    cur = _read_full(f, CHUNK + TAG)
    while True:
        if cancel is not None and cancel.is_set():
            from .errors import CancelledError
            raise CancelledError()
        if len(cur) < TAG:
            raise damaged
        # A full chunk may be the final one: tried as a middle chunk first, as age does.
        plain, last = None, len(cur) < CHUNK + TAG
        for final in ((False, True) if not last else (True,)):
            try:
                plain, last = aead.decrypt(_chunk_nonce(counter, final), cur, None), final
                break
            except InvalidTag:
                continue
        if plain is None:
            raise damaged
        if last and not plain and counter:
            raise AgePayloadError("The age file is damaged (an empty final chunk).")
        written += len(plain)
        if max_output is not None and written > max_output:
            raise AgePayloadError(f"The content is larger than {max_output >> 20} MiB, the limit for messages "
                                  "opened in memory.")
        if space is not None:
            space.need(len(plain))
        out.write(plain)
        if progress and total:
            progress(min(f.tell() / total, 1.0) if f.seekable() else None, "Decrypting")
        if last:
            if f.read(1):
                raise AgePayloadError("The age file has data after its end.")
            return
        cur, counter = _read_full(f, CHUNK + TAG), counter + 1
        if not cur:
            raise AgePayloadError("The age file is truncated: its last chunk is missing.")


# ── armor ────────────────────────────────────────────────────────────────────

def armor(blob: bytes) -> str:
    body = base64.b64encode(blob).decode()
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "\n".join([ARMOR_BEGIN, *lines, ARMOR_END]) + "\n"


def is_armored(head: bytes) -> bool:
    return head.lstrip(b" \t\r\n").startswith(ARMOR_BEGIN.encode())


def dearmor(data: bytes) -> bytes:
    """Strict PEM (RFC 7468 §3, figure 3) as age writes it: only whitespace around the block,
    LF or CRLF line ends, 64-column lines and canonical padded base64."""
    bad = AgeArmorError("The age armor is damaged or not in the strict form age writes.")
    if len(data) > MAX_ARMOR:
        raise LocksmithError(f"Armored age files over {MAX_ARMOR >> 20} MiB are not supported.")
    text = data.strip(b" \t\r\n")
    lines = text.split(b"\n")
    lines = [line[:-1] if line.endswith(b"\r") else line for line in lines]
    if len(lines) < 2 or lines[0] != ARMOR_BEGIN.encode() or lines[-1] != ARMOR_END.encode():
        raise bad
    body = lines[1:-1]
    if any(len(line) != 64 for line in body[:-1]) or (body and not 0 < len(body[-1]) <= 64):
        raise bad
    joined = b"".join(body)
    if not re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", joined) or len(joined) % 4:
        raise bad
    blob = base64.b64decode(joined)
    if base64.b64encode(blob) != joined:
        raise bad
    return blob


def is_age(head: bytes) -> bool:
    """Whether the first bytes of a file are an age file (binary or armored)."""
    return head.startswith(INTRO) or is_armored(head)


def open_source(path: Path) -> BinaryIO:
    with open(path, "rb") as f:
        head = f.read(64)
    if is_armored(head):
        if Path(path).stat().st_size > MAX_ARMOR:
            raise LocksmithError(f"Armored age files over {MAX_ARMOR >> 20} MiB are not supported.")
        return io.BytesIO(dearmor(Path(path).read_bytes()))
    return open(path, "rb")


@dataclass
class AgeInfo:
    stanza_types: list[str]
    work_factor: int | None = None   # a passphrase stanza's scrypt cost (log2 N), as the file states it

    @property
    def password_slots(self) -> list[dict]:
        """The passphrase stanza in the shape of engine.FileInfo.password_slots, for cost checks."""
        if self.work_factor is None:
            return []
        return [{"kdf": "scrypt", "params": {"n": 1 << self.work_factor, "r": 8, "p": 1}, "keyfile": False}]

    @property
    def summary(self) -> str:
        names = {"X25519": "age key", "mlkem768x25519": "post-quantum age key", "scrypt": "passphrase",
                 "ssh-ed25519": "SSH Ed25519 key", "ssh-rsa": "SSH RSA key"}
        counts: dict[str, int] = {}
        for t in self.stanza_types:
            label = names.get(t, "other")
            counts[label] = counts.get(label, 0) + 1
        return ", ".join(f"{n} × {label}" if n > 1 else label for label, n in counts.items())


def inspect(path: Path) -> AgeInfo:
    with open_source(Path(path)) as f:
        return _info(read_header(f))


def inspect_bytes(blob: bytes) -> AgeInfo:
    return _info(read_header(io.BytesIO(blob)))


def _info(header: Header) -> AgeInfo:
    work = None
    for st in header.stanzas:
        if st.type == b"scrypt" and len(st.args) == 3 and re.fullmatch(rb"[1-9][0-9]?", st.args[2]):
            work = int(st.args[2])
    return AgeInfo([st.type.decode("ascii", "replace") for st in header.stanzas], work)


# ── files ────────────────────────────────────────────────────────────────────

class _Null(io.RawIOBase):
    def writable(self):
        return True

    def write(self, b):
        return len(b)


def encrypt_paths(paths: list[Path], out_dir: Path | None, recipients: list[Recipient], passphrase: str | None = None,
                  armored: bool = False, bundle_name: str | None = None, progress=None,
                  cancel: threading.Event | None = None, verify: bool = False,
                  work_factor: int = DEFAULT_WORK_FACTOR, strip: bool = False, hide_name: bool = False,
                  stats: dict | None = None) -> Path:
    """Write one ``.age`` file: a file as it is, a folder or several items as a tar archive
    (``name.tar.age``). With ``verify``, the written file is read back and decrypted with its
    file key before it is moved into place, as callers that shred the originals need.
    ``strip`` removes image metadata as for Locksmith files (counts go to ``stats``);
    ``hide_name`` gives the output a random name (age stores no name inside)."""
    from . import engine, metadata
    stats = stats if stats is not None else {}
    paths = [Path(p) for p in paths]
    if not paths:
        raise LocksmithError("Nothing to encrypt.")
    for p in paths:
        if engine.is_link(p):
            raise LocksmithError(f"{p.name} is a link. Add the file or folder it points to instead.")
        if not p.exists():
            raise LocksmithError(f"{p.name} no longer exists.")
    out_dir = Path(out_dir) if out_dir else paths[0].parent
    for p in paths:
        if p.is_dir() and out_dir.resolve().is_relative_to(p.resolve()):
            raise LocksmithError(f"The output folder is inside “{p.name}”, the folder being encrypted. "
                                 "Choose an output folder outside it.")
    if len(paths) == 1 and paths[0].is_file():
        name, total = paths[0].name, paths[0].stat().st_size
        opener = lambda: open(paths[0], "rb")  # noqa: E731
        plan = metadata.plan_for(paths[0]) if strip else None
        if strip:
            stats["stripped" if plan else "unchanged"] = stats.get("stripped" if plan else "unchanged", 0) + 1
        if plan is not None:
            total = plan.size
            opener = lambda: metadata.PlanReader(paths[0], plan.plan)  # noqa: E731
    else:
        import time
        name = (paths[0].name if len(paths) == 1 else
                bundle_name or time.strftime("Locksmith bundle %Y-%m-%d %H.%M")) + ".tar"
        total = sum(engine._tree_size(p) for p in paths)
        opener = lambda: engine._TarStream([(p, p.name) for p in paths], strip, stats)  # noqa: E731
    if armored and total > engine.MAX_ARMOR_INPUT:
        raise LocksmithError(f"Text (ASCII armor) output is limited to {engine.MAX_ARMOR_INPUT >> 20} MiB. "
                             "Turn off ASCII armor for larger files.")
    out_dir.mkdir(parents=True, exist_ok=True)
    if hide_name:
        name = secrets.token_hex(8)
    target = engine.unique_path(out_dir / (name + EXTENSION))   # armored files are .age too, as age names them
    tmp = out_dir / f".{target.name}.{secrets.token_hex(4)}.part"

    def report(frac, stage):
        if progress:
            progress(frac, stage)
    try:
        with opener() as src:
            if armored:
                buf = io.BytesIO()
                file_key = encrypt_stream(src, buf, recipients, passphrase, work_factor, cancel, report, total)
                if buf.tell() > engine.MAX_ARMOR_INPUT + (1 << 20):
                    raise LocksmithError(f"Text (ASCII armor) output is limited to {engine.MAX_ARMOR_INPUT >> 20} "
                                         "MiB. Turn off ASCII armor for larger files.")
                engine.write_private(tmp, armor(buf.getvalue()).encode())
            else:
                with engine.create_private(tmp) as out:
                    file_key = encrypt_stream(src, out, recipients, passphrase, work_factor, cancel, report, total)
                    out.flush()
                    os.fsync(out.fileno())
        if verify:
            report(None, "Verifying")
            with open_source(tmp) as f:
                header = read_header(f)
                if not hmac.compare_digest(_mac(file_key, header.signed), header.mac):
                    raise LocksmithError("Verification failed: the header on disk does not match.")
                decrypt_payload(f, _Null(), file_key, cancel)
        os.replace(tmp, target)
        engine.fsync_dir(out_dir)
        os.chmod(target, 0o644)   # ciphertext is safe to share
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target


def output_name(source_name: str) -> str:
    """What a decrypted age file is called: its name without ``.age`` (or ``.age.txt``)."""
    for suffix in (EXTENSION + ".txt", EXTENSION, ".txt"):
        if source_name.lower().endswith(suffix) and len(source_name) > len(suffix):
            return source_name[:-len(suffix)]
    return source_name + ".decrypted"


def decrypt_path(path: Path, out_dir: Path | None, keys: Keys, progress=None,
                 cancel: threading.Event | None = None, name: str | None = None, mark_untrusted: bool = False):
    """Decrypt an age file next to it (or into ``out_dir``). Nothing is in place until every
    chunk authenticated; the output is owner-only, and on Windows it inherits the source's Mark
    of the Web (or is marked as from the internet, for pasted text). Returns an engine.DecryptResult."""
    from . import engine, osutil, scratch
    path = Path(path)
    out_dir = Path(out_dir) if out_dir else path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    target_name = engine.safe_name(name or output_name(path.name))
    tmp = out_dir / f".locksmith-{secrets.token_hex(6)}.part"
    space = engine._DiskGuard(out_dir)

    def report(frac, stage):
        if progress:
            progress(frac, stage)
    with scratch.tracked(tmp):
        try:
            with open_source(path) as f:
                total = f.seek(0, os.SEEK_END)
                f.seek(0)
                with engine.create_private(tmp) as out:
                    decrypt_stream(f, out, keys, cancel, report, total, space=space)
                    out.flush()
                    os.fsync(out.fileno())
            target = engine.unique_path(out_dir / target_name)
            os.replace(tmp, target)
        except BaseException:
            scratch.discard(tmp)   # partly decrypted plaintext: shredded
            raise
    complete = osutil.fsync_dir(out_dir)
    if mark_untrusted:
        osutil.mark_untrusted(target)
    else:
        osutil.copy_zone_identifier(path, target)
    report(1.0, "Done")
    return engine.DecryptResult(target, {"name": target.name, "kind": "file", "format": "age"}, complete=complete)


def verify_path(path: Path, keys: Keys, progress=None, cancel: threading.Event | None = None):
    from . import engine
    with open_source(Path(path)) as f:
        total = f.seek(0, os.SEEK_END)
        f.seek(0)
        decrypt_stream(f, _Null(), keys, cancel, progress, total)
    return engine.DecryptResult(None, {"name": Path(path).name, "format": "age"})


def decrypt_bytes(blob: bytes, keys: Keys, max_output: int) -> bytes:
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, keys, max_output=max_output)
    return out.getvalue()


def is_age_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return is_age(f.read(64))
    except OSError:
        return False


def decrypt_pasted(blob: bytes, out_dir: Path, keys: Keys, max_output: int):
    """Open a pasted age message (already de-armored). It has no name or kind, so content that
    reads as text stays in memory, in ``data``; anything else is written to ``out_dir`` as
    "decrypted" and marked as coming from the internet on Windows."""
    from . import engine, osutil, scratch
    data = decrypt_bytes(blob, keys, max_output)
    try:
        text = data.decode("utf-8")
        is_text = all(c.isprintable() or c in "\n\r\t" for c in text)
    except UnicodeDecodeError:
        is_text = False
    if is_text:
        return engine.DecryptResult(None, {"name": "message.txt", "kind": "text", "format": "age"}, data)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp = out_dir / f".locksmith-{secrets.token_hex(6)}.part"
    try:
        engine.write_private(tmp, data)
        target = engine.unique_path(out_dir / "decrypted")
        os.replace(tmp, target)
    except BaseException:
        scratch.discard(tmp)
        raise
    complete = osutil.fsync_dir(out_dir)
    osutil.mark_untrusted(target)
    return engine.DecryptResult(target, {"name": target.name, "kind": "file", "format": "age"}, complete=complete)
