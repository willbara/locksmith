"""Verify detached OpenPGP signatures (RFC 9580, version 4 keys and signatures, as GnuPG makes
them) against one public key the user gives: no keyring, no web of trust.

Accepted: RSA (2048 bits or more), ECDSA on P-256/384/521, and Ed25519 (EdDSALegacy and the
RFC 9580 Ed25519 algorithm), with SHA-2 or SHA-3 hashes; binary (0x00) and text (0x01)
signatures. A signature may come from the primary key or from a signing subkey bound to it
(with its back-signature). The key must carry a valid self-signature; a revoked key or subkey
is refused, and a signature made after the key expired is refused. MD5 and SHA-1 signatures,
DSA and ElGamal keys, version 3, 5 and 6 packets are refused.

A valid signature proves the file was signed with that key. The user IDs on a key are only its
owner's claims: whose key it is has to be checked separately.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

from .errors import CancelledError, LocksmithError
from .tools import open_regular

MAX_KEY_FILE = 1 << 20
MAX_SIGNATURE_FILE = 64 << 10
MIN_RSA_BITS = 2048
HASHES = {8: ("sha256", hashes.SHA256), 9: ("sha384", hashes.SHA384), 10: ("sha512", hashes.SHA512),
          11: ("sha224", hashes.SHA224), 12: ("sha3_256", hashes.SHA3_256), 14: ("sha3_512", hashes.SHA3_512)}
WEAK_HASHES = {1: "MD5", 2: "SHA-1", 3: "RIPEMD-160"}
RSA_ALGS, ECDSA, EDDSA_LEGACY, ED25519 = (1, 3), 19, 22, 27
CURVES = {bytes.fromhex("2a8648ce3d030107"): ("P-256", ec.SECP256R1),
          bytes.fromhex("2b81040022"): ("P-384", ec.SECP384R1),
          bytes.fromhex("2b81040023"): ("P-521", ec.SECP521R1)}
ED25519_OID = bytes.fromhex("2b06010401da470f01")
TAG_SIG, TAG_PUBKEY, TAG_USERID, TAG_PUBSUB, TAG_UATTR = 2, 6, 13, 14, 17
SIG_BINARY, SIG_TEXT = 0x00, 0x01
CERTIFICATIONS = (0x10, 0x11, 0x12, 0x13)
SUBKEY_BINDING, PRIMARY_BINDING, DIRECT_KEY, KEY_REVOCATION, SUBKEY_REVOCATION, CERT_REVOCATION = \
    0x18, 0x19, 0x1F, 0x20, 0x28, 0x30
# Subpackets
SP_CREATED, SP_SIG_EXPIRES, SP_KEY_EXPIRES, SP_ISSUER, SP_KEY_FLAGS, SP_EMBEDDED, SP_ISSUER_FPR = \
    2, 3, 9, 16, 27, 32, 33
_KNOWN_CRITICAL = {SP_CREATED, SP_SIG_EXPIRES, SP_KEY_EXPIRES, SP_KEY_FLAGS, SP_ISSUER_FPR, SP_ISSUER, 11, 21, 22,
                   25, 30, 23, 4, 5, 7, 34}
FLAG_SIGN = 0x02
_BAD_KEY = "That is not an OpenPGP public key Locksmith can read."
_BAD_SIG = "That is not a valid OpenPGP signature."


class _Bad(Exception):
    pass


def _need(cond: bool):
    if not cond:
        raise _Bad


# ── packets ──────────────────────────────────────────────────────────────────

@dataclass
class Packet:
    tag: int
    body: bytes


def packets(data: bytes) -> list[Packet]:
    """Split OpenPGP packets (both header formats). Partial and indeterminate lengths are only
    for data packets, which never appear in keys or signatures, so they are refused."""
    out, pos = [], 0
    while pos < len(data):
        ctb = data[pos]
        _need(ctb & 0x80)
        if ctb & 0x40:   # new format
            tag = ctb & 0x3F
            _need(pos + 1 < len(data))
            first = data[pos + 1]
            if first < 192:
                length, pos = first, pos + 2
            elif first < 224:
                _need(pos + 2 < len(data))
                length, pos = ((first - 192) << 8) + data[pos + 2] + 192, pos + 3
            elif first == 255:
                _need(pos + 6 <= len(data))
                length, pos = struct.unpack(">I", data[pos + 2:pos + 6])[0], pos + 6
            else:
                raise _Bad
        else:            # old format
            tag, ltype = (ctb >> 2) & 0x0F, ctb & 3
            _need(ltype != 3)
            n = 1 << ltype
            _need(pos + 1 + n <= len(data))
            length, pos = int.from_bytes(data[pos + 1:pos + 1 + n], "big"), pos + 1 + n
        _need(pos + length <= len(data))
        out.append(Packet(tag, data[pos:pos + length]))
        pos += length
    return out


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        _need(0 <= n <= len(self.data) - self.pos)
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def mpi(self) -> bytes:
        bits = self.u16()
        value = self.take((bits + 7) // 8)
        # Bit counts must be exact, as RFC 9580 requires, except for the 0x40-prefixed EdDSA points.
        _need(not value or value[0].bit_length() + 8 * (len(value) - 1) == bits)
        return value

    def rest(self) -> bytes:
        return self.take(len(self.data) - self.pos)

    def end(self):
        _need(self.pos == len(self.data))


def _armored(text: bytes, kind: str) -> bytes:
    """The data inside "-----BEGIN PGP <kind>-----" armor (headers and the CRC-24 checksum, which
    RFC 9580 says to ignore, are skipped), or the input itself when it is binary."""
    begin, end = f"-----BEGIN PGP {kind}-----".encode(), f"-----END PGP {kind}-----".encode()
    stripped = text.strip()
    if not stripped.startswith(b"-----BEGIN PGP"):
        return text
    if not stripped.startswith(begin):
        raise LocksmithError(f"This is not an OpenPGP {kind.lower()}.")
    _need(stripped.endswith(end))
    try:
        lines = stripped[len(begin):-len(end)].decode("ascii").replace("\r", "").split("\n")
    except UnicodeDecodeError:
        raise _Bad from None
    while lines and lines[0].strip() == "":
        lines.pop(0)
    if any(":" in line for line in lines):   # armor headers, then a blank line
        while lines and lines[0].strip():
            lines.pop(0)
    body = [line.strip() for line in lines if line.strip() and not line.strip().startswith("=")]
    try:
        return base64.b64decode("".join(body), validate=True)
    except ValueError:
        raise _Bad from None


# ── keys ─────────────────────────────────────────────────────────────────────

@dataclass
class Key:
    body: bytes          # the public key packet's body
    created: int
    alg: int
    public: object       # cryptography key
    label: str           # "Ed25519", "RSA 3072", "ECDSA P-256"
    fingerprint: bytes   # SHA-1 of the v4 packet (RFC 9580 §5.5.4.2)
    flags: int | None = None
    expires: int | None = None   # Unix time, from the newest valid self-signature
    revoked: bool = False
    bound_at: int | None = None  # a subkey's newest valid binding signature, which decides its flags and expiry

    @property
    def key_id(self) -> bytes:
        return self.fingerprint[-8:]

    @property
    def hashed_form(self) -> bytes:
        return b"\x99" + struct.pack(">H", len(self.body)) + self.body


@dataclass
class Certificate:
    primary: Key
    subkeys: list[Key] = field(default_factory=list)
    user_ids: list[str] = field(default_factory=list)


def _parse_key(body: bytes) -> Key:
    r = _Reader(body)
    version = r.u8()
    if version != 4:
        raise LocksmithError(f"This is a version {version} OpenPGP key. Locksmith reads version 4 keys, which GnuPG "
                             "makes.")
    created, alg = r.u32(), r.u8()
    try:
        if alg in RSA_ALGS:
            n, e = int.from_bytes(r.mpi(), "big"), int.from_bytes(r.mpi(), "big")
            public = rsa.RSAPublicNumbers(e, n).public_key()
            if public.key_size < MIN_RSA_BITS:
                raise LocksmithError(f"This RSA key has only {public.key_size} bits. Locksmith accepts RSA keys of "
                                     f"{MIN_RSA_BITS} bits or more.")
            label = f"RSA {public.key_size}"
        elif alg == ECDSA:
            oid = r.take(r.u8())
            if oid not in CURVES:
                raise LocksmithError("This OpenPGP key uses an elliptic curve Locksmith doesn't accept.")
            name, curve = CURVES[oid]
            public = ec.EllipticCurvePublicKey.from_encoded_point(curve(), r.mpi())
            label = f"ECDSA {name}"
        elif alg == EDDSA_LEGACY:
            oid = r.take(r.u8())
            if oid != ED25519_OID:
                raise LocksmithError("This OpenPGP key uses an EdDSA curve Locksmith doesn't accept (only Ed25519).")
            point = r.mpi()
            _need(len(point) == 33 and point[0] == 0x40)
            public, label = ed25519.Ed25519PublicKey.from_public_bytes(point[1:]), "Ed25519"
        elif alg == ED25519:
            public, label = ed25519.Ed25519PublicKey.from_public_bytes(r.take(32)), "Ed25519"
        elif alg in (17, 16, 20):
            raise LocksmithError("DSA and ElGamal keys aren't accepted.")
        else:
            raise LocksmithError(f"This OpenPGP key uses an algorithm Locksmith doesn't know ({alg}).")
    except (ValueError, UnsupportedAlgorithm):
        raise _Bad from None
    r.end()
    fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body, usedforsecurity=False).digest()
    return Key(body, created, alg, public, label, fpr)


# ── signatures ───────────────────────────────────────────────────────────────

@dataclass
class Signature:
    sig_type: int
    alg: int
    hash_alg: int
    hashed: bytes        # the hashed subpacket area
    subpackets: dict     # type -> list of values (hashed area), plus issuer info from the unhashed one
    left16: bytes
    values: list[bytes]  # the signature's MPIs (or the raw Ed25519 signature)
    created: int
    issuer_fpr: bytes | None
    issuer_id: bytes | None

    def trailer(self) -> bytes:
        head = bytes((4, self.sig_type, self.alg, self.hash_alg)) + struct.pack(">H", len(self.hashed)) + self.hashed
        return head + b"\x04\xff" + struct.pack(">I", len(head))


def _subpackets(area: bytes, hashed: bool) -> list[tuple[int, bytes, bool]]:
    out, pos = [], 0
    while pos < len(area):
        first = area[pos]
        if first < 192:
            length, pos = first, pos + 1
        elif first < 255:
            _need(pos + 1 < len(area))
            length, pos = ((first - 192) << 8) + area[pos + 1] + 192, pos + 2
        else:
            _need(pos + 5 <= len(area))
            length, pos = struct.unpack(">I", area[pos + 1:pos + 5])[0], pos + 5
        _need(length >= 1 and pos + length <= len(area))
        sp_type, critical = area[pos] & 0x7F, bool(area[pos] & 0x80)
        out.append((sp_type, area[pos + 1:pos + length], critical and hashed))
        pos += length
    return out


def _parse_signature(body: bytes) -> Signature:
    r = _Reader(body)
    version = r.u8()
    if version != 4:
        raise LocksmithError(f"This is a version {version} OpenPGP signature. Locksmith reads version 4 signatures, "
                             "which GnuPG makes.")
    sig_type, alg, hash_alg = r.u8(), r.u8(), r.u8()
    hashed = r.take(r.u16())
    unhashed = r.take(r.u16())
    left16 = r.take(2)
    if alg in RSA_ALGS:
        values = [r.mpi()]
    elif alg in (ECDSA, EDDSA_LEGACY):
        values = [r.mpi(), r.mpi()]
    elif alg == ED25519:
        values = [r.take(64)]
    else:
        values = [r.rest()]
    r.end()
    subs: dict[int, list[bytes]] = {}
    for sp_type, value, critical in _subpackets(hashed, True):
        if critical and sp_type not in _KNOWN_CRITICAL:
            raise LocksmithError("This OpenPGP signature has a critical part Locksmith doesn't understand, so it "
                                 "can't be accepted.")
        subs.setdefault(sp_type, []).append(value)
    issuer_fpr = issuer_id = None
    embedded: list[bytes] = []
    for sp_type, value, _ in _subpackets(hashed, True) + _subpackets(unhashed, False):
        if sp_type == SP_ISSUER_FPR and len(value) == 21 and value[0] == 4 and issuer_fpr is None:
            issuer_fpr = value[1:]
        elif sp_type == SP_ISSUER and len(value) == 8 and issuer_id is None:
            issuer_id = value
        elif sp_type == SP_EMBEDDED:
            # A back-signature is the subkey's own signature, so it counts in either area.
            embedded.append(value)
    subs[SP_EMBEDDED] = embedded
    created = subs.get(SP_CREATED, [b""])[0]
    _need(len(created) == 4)
    return Signature(sig_type, alg, hash_alg, hashed, subs, left16, values, struct.unpack(">I", created)[0],
                     issuer_fpr, issuer_id)


def _hasher(sig: Signature):
    if sig.hash_alg in WEAK_HASHES:
        raise LocksmithError(f"This signature uses {WEAK_HASHES[sig.hash_alg]}, which is broken. Locksmith accepts "
                             "SHA-2 and SHA-3 signatures only.")
    if sig.hash_alg not in HASHES:
        raise LocksmithError("This signature uses a hash Locksmith doesn't know.")
    return hashlib.new(HASHES[sig.hash_alg][0])


def _check(key: Key, sig: Signature, h) -> bool:
    """Whether ``sig`` verifies with ``key`` over the hash state ``h`` (which has everything but the
    signature's own trailer)."""
    if sig.alg != key.alg and not (sig.alg in RSA_ALGS and key.alg in RSA_ALGS):
        return False
    h.update(sig.trailer())
    digest = h.digest()
    if digest[:2] != sig.left16:
        return False
    algorithm = HASHES[sig.hash_alg][1]()
    try:
        if key.alg in RSA_ALGS:
            size = (key.public.key_size + 7) // 8
            _need(len(sig.values[0]) <= size)
            key.public.verify(sig.values[0].rjust(size, b"\0"), digest, padding.PKCS1v15(), Prehashed(algorithm))
        elif key.alg == ECDSA:
            r, s = (int.from_bytes(v, "big") for v in sig.values)
            key.public.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(algorithm)))
        else:
            raw = sig.values[0] if key.alg == ED25519 else b"".join(v.rjust(32, b"\0") for v in sig.values)
            _need(len(raw) == 64)
            key.public.verify(raw, digest)
    except (InvalidSignature, ValueError, _Bad):
        return False
    return True


def _new(sig: Signature):
    return _hasher(sig)


def _subkey_hash(primary: Key, subkey: Key, sig: Signature):
    h = _new(sig)
    h.update(primary.hashed_form + subkey.hashed_form)
    return h


def _key_expiry(key: Key, sig: Signature) -> int | None:
    value = sig.subpackets.get(SP_KEY_EXPIRES)
    if value and len(value[0]) == 4:
        seconds = struct.unpack(">I", value[0])[0]
        return key.created + seconds if seconds else None
    return None


def _flags(sig: Signature) -> int | None:
    value = sig.subpackets.get(SP_KEY_FLAGS)
    return value[0][0] if value and value[0] else None


def parse_key(data: bytes) -> Certificate:
    """A transferable public key (binary or armored), with only the self-signatures that verify."""
    try:
        pkts = packets(_armored(data, "PUBLIC KEY BLOCK"))
        _need(pkts and pkts[0].tag == TAG_PUBKEY)
        primary = _parse_key(pkts[0].body)
        cert = Certificate(primary)
        newest_self = None
        component: object = primary   # what the following signatures are about
        for pkt in pkts[1:]:
            if pkt.tag == TAG_USERID:
                component = pkt.body
            elif pkt.tag == TAG_UATTR:
                component = None
            elif pkt.tag == TAG_PUBSUB:
                try:
                    component = _parse_key(pkt.body)
                except LocksmithError:
                    component = None   # a subkey of a kind we don't take: only its signatures are skipped
            elif pkt.tag == TAG_SIG:
                try:
                    sig = _parse_signature(pkt.body)
                except (LocksmithError, _Bad):
                    continue
                try:
                    h = _new(sig)
                except LocksmithError:
                    continue
                if component is primary and sig.sig_type in (DIRECT_KEY, KEY_REVOCATION):
                    h.update(primary.hashed_form)
                    if _check(primary, sig, h):
                        if sig.sig_type == KEY_REVOCATION:
                            primary.revoked = True
                        elif newest_self is None or sig.created >= newest_self.created:
                            newest_self = sig
                elif isinstance(component, bytes) and sig.sig_type in CERTIFICATIONS:
                    h.update(primary.hashed_form + b"\xb4" + struct.pack(">I", len(component)) + component)
                    if _check(primary, sig, h):
                        name = component.decode("utf-8", "replace")
                        if name not in cert.user_ids:
                            cert.user_ids.append(name)
                        if newest_self is None or sig.created >= newest_self.created:
                            newest_self = sig
                elif isinstance(component, Key) and component is not primary:
                    _subkey_signature(cert, component, sig)
            # Trust, marker and other packets are skipped.
    except _Bad:
        raise LocksmithError(_BAD_KEY) from None
    if newest_self is None:
        raise LocksmithError("This OpenPGP key has no valid self-signature, so nothing shows it is complete and "
                             "unaltered.")
    primary.flags, primary.expires = _flags(newest_self), _key_expiry(primary, newest_self)
    return cert


def _subkey_signature(cert: Certificate, subkey: Key, sig: Signature):
    primary = cert.primary
    if sig.sig_type == SUBKEY_REVOCATION:
        if _check(primary, sig, _subkey_hash(primary, subkey, sig)):
            subkey.revoked = True
        return
    if sig.sig_type != SUBKEY_BINDING or not _check(primary, sig, _subkey_hash(primary, subkey, sig)):
        return
    if subkey.bound_at is not None and sig.created < subkey.bound_at:
        # An older binding never overrides a newer one, wherever it sits: otherwise reordering the
        # packets would bring back a signing flag or lift an expiry the owner has since set.
        return
    flags = _flags(sig)
    if flags is not None and flags & FLAG_SIGN:
        # A signing subkey must sign its primary back, or anyone could claim someone else's
        # signing key as their subkey (RFC 9580 §5.2.3.34).
        back = None
        for value in sig.subpackets.get(SP_EMBEDDED, []):
            try:
                emb = _parse_signature(value)
            except (LocksmithError, _Bad):
                continue
            if emb.sig_type == PRIMARY_BINDING and _check(subkey, emb, _subkey_hash(primary, subkey, emb)):
                back = emb
        if back is None:
            return
    if subkey not in cert.subkeys:
        cert.subkeys.append(subkey)
    subkey.flags, subkey.expires, subkey.bound_at = flags, _key_expiry(subkey, sig), sig.created


def read_key_file(path: Path) -> bytes:
    with open_regular(Path(path)) as f:
        data = f.read(MAX_KEY_FILE + 1)
    if len(data) > MAX_KEY_FILE:
        raise LocksmithError(f"{Path(path).name} is too large to be an OpenPGP public key.")
    return data


def read_signature_file(path: Path) -> bytes:
    with open_regular(Path(path)) as f:
        data = f.read(MAX_SIGNATURE_FILE + 1)
    if len(data) > MAX_SIGNATURE_FILE:
        raise LocksmithError(f"{Path(path).name} is too large to be an OpenPGP signature.")
    return data


def parse_signature(data: bytes) -> Signature:
    try:
        pkts = packets(_armored(data, "SIGNATURE"))
        _need(len(pkts) == 1 and pkts[0].tag == TAG_SIG)
        sig = _parse_signature(pkts[0].body)
    except _Bad:
        raise LocksmithError(_BAD_SIG) from None
    if sig.sig_type not in (SIG_BINARY, SIG_TEXT):
        raise LocksmithError("This is not a signature of a file (it certifies a key, or signs something else).")
    return sig


# ── verifying a file ─────────────────────────────────────────────────────────

@dataclass
class Verified:
    fingerprint: str          # the primary key's, as GnuPG prints it
    signing_key: str          # the (sub)key that made the signature
    key_label: str
    user_ids: list[str]       # the key owner's claims, not checked by anyone
    created: int              # the signer's claim
    text_mode: bool
    hash_name: str
    expired: bool             # the key has expired since (the signature was made before that)


def fingerprint_text(fpr: bytes) -> str:
    h = fpr.hex().upper()
    return " ".join(h[i:i + 4] for i in range(0, len(h), 4))


class _TextHasher:
    """Feeds text-mode data with line ends converted to CR LF, as RFC 9580 §5.2.1.2 asks."""

    def __init__(self, h):
        self.h, self.cr = h, False

    def update(self, block: bytes):
        if self.cr and block.startswith(b"\n"):
            self.h.update(b"\n")
            block = block[1:]
        self.cr = block.endswith(b"\r")
        self.h.update(re.sub(rb"(?<!\r)\n", b"\r\n", block))


def verify_file(path: Path, signature: bytes, key: bytes, now: int | None = None,
                progress: Callable[[float], None] | None = None,
                cancel: threading.Event | None = None) -> Verified:
    """Check ``path`` against a detached OpenPGP signature made by ``key`` (one transferable public
    key, binary or armored). Raises LocksmithError with the reason unless it is valid."""
    cert = parse_key(key)
    sig = parse_signature(signature)
    primary = cert.primary
    candidates = [primary, *cert.subkeys]
    if sig.issuer_fpr is not None:
        signer = next((k for k in candidates if k.fingerprint == sig.issuer_fpr), None)
    else:
        signer = next((k for k in candidates if sig.issuer_id is not None and k.key_id == sig.issuer_id), None)
    if signer is None:
        made_by = sig.issuer_fpr or sig.issuer_id
        raise LocksmithError("This file was signed with a different key" +
                             (f" ({fingerprint_text(made_by)})" if made_by else "") + ", not the one given.")
    if primary.revoked or signer.revoked:
        raise LocksmithError("The key that made this signature has been revoked by its owner, so its signatures "
                             "can't be trusted.")
    if signer.flags is not None and not signer.flags & FLAG_SIGN:
        raise LocksmithError("The key that made this signature isn't allowed to sign files.")
    if sig.created < signer.created:
        raise LocksmithError("This signature claims to be older than the key that made it.")
    for k in (primary, signer):
        if k.expires is not None and sig.created > k.expires:
            raise LocksmithError("This signature was made after the key expired.")
    expires = sig.subpackets.get(SP_SIG_EXPIRES)
    now = int(time.time()) if now is None else now
    if expires and len(expires[0]) == 4 and struct.unpack(">I", expires[0])[0] and \
            now > sig.created + struct.unpack(">I", expires[0])[0]:
        raise LocksmithError("This signature has expired.")
    h = _new(sig)
    feed = _TextHasher(h) if sig.sig_type == SIG_TEXT else h
    with open_regular(Path(path)) as f:
        size = max(f.seek(0, 2), 1)
        f.seek(0)
        done = 0
        while block := f.read(4 << 20):
            if cancel is not None and cancel.is_set():
                raise CancelledError()
            feed.update(block)
            done += len(block)
            if progress:
                progress(done / size)
    if not _check(signer, sig, h):
        raise LocksmithError("The signature does not match this file: it was changed, or this is not the file that "
                             "was signed.")
    expired = any(k.expires is not None and now > k.expires for k in (primary, signer))
    return Verified(fingerprint_text(primary.fingerprint), fingerprint_text(signer.fingerprint), signer.label,
                    cert.user_ids, sig.created, sig.sig_type == SIG_TEXT, HASHES[sig.hash_alg][0].upper(), expired)

