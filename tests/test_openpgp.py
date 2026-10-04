"""OpenPGP detached signatures (locksmith/core/openpgp.py): vectors made by GnuPG
(tests/interop/openpgp), and certificates built here to craft what GnuPG wouldn't make."""

import hashlib
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from locksmith.core import openpgp
from locksmith.core.errors import LocksmithError

HERE = Path(__file__).parent / "interop" / "openpgp"


def _v(sig, key, msg="message.bin", **kw):
    return openpgp.verify_file(HERE / msg, (HERE / sig).read_bytes(), (HERE / key).read_bytes(), **kw)


@pytest.mark.parametrize("sig,key,msg,label", [
    ("ed25519.sig", "ed25519.asc", "message.bin", "Ed25519"),
    ("ed25519.sig.asc", "ed25519.gpg", "message.bin", "Ed25519"),
    ("ed25519-sha512.sig", "ed25519.asc", "message.bin", "Ed25519"),
    ("ed25519-text.sig", "ed25519.asc", "message.txt", "Ed25519"),
    ("rsa-subkey.sig", "rsa.asc", "message.bin", "RSA 3072"),
    ("p256.sig", "p256.gpg", "message.bin", "ECDSA P-256"),
])
def test_gnupg_signatures_verify(sig, key, msg, label):
    v = _v(sig, key, msg)
    assert v.key_label == label and not v.expired
    assert v.user_ids == [f"Locksmith interop {key.split('.')[0]} <{key.split('.')[0]}@example.invalid>"]
    assert v.text_mode == sig.endswith("-text.sig")


def test_fingerprints_match_gnupg():
    v = _v("rsa-subkey.sig", "rsa.asc")
    assert v.signing_key != v.fingerprint   # made by the signing subkey
    v = _v("ed25519.sig", "ed25519.asc")
    assert v.signing_key == v.fingerprint and len(v.fingerprint.replace(" ", "")) == 40


def test_a_changed_file_or_another_file_fails(tmp_path):
    with pytest.raises(LocksmithError, match="does not match"):
        _v("ed25519.sig", "ed25519.asc", "message.txt")
    changed = tmp_path / "m.bin"
    changed.write_bytes((HERE / "message.bin").read_bytes() + b" ")
    with pytest.raises(LocksmithError, match="does not match"):
        openpgp.verify_file(changed, (HERE / "p256.sig").read_bytes(), (HERE / "p256.asc").read_bytes())


def test_the_wrong_key_is_named():
    with pytest.raises(LocksmithError, match="different key"):
        _v("ed25519.sig", "rsa.asc")


def test_expired_and_revoked_keys():
    assert _v("expired.sig", "expired.asc").expired   # made while the key was valid: still good
    with pytest.raises(LocksmithError, match="revoked"):
        _v("revoked.sig", "revoked.asc")


def test_signatures_are_not_keys_and_keys_are_not_signatures():
    with pytest.raises(LocksmithError):
        _v("ed25519.asc", "ed25519.asc")
    with pytest.raises(LocksmithError):
        _v("ed25519.sig", "ed25519.sig")


# ── certificates made here ───────────────────────────────────────────────────

def _packet(tag: int, body: bytes) -> bytes:
    return bytes((0xC0 | tag, 255)) + struct.pack(">I", len(body)) + body


def _sp(sp_type: int, value: bytes, critical=False) -> bytes:
    return bytes((len(value) + 1, sp_type | (0x80 if critical else 0))) + value


def _mpi(b: bytes) -> bytes:
    b = b.lstrip(b"\0")
    return struct.pack(">H", len(b) * 8 - (8 - b[0].bit_length()) if b else 0) + b


class Cert:
    def __init__(self, created=1_700_000_000):
        self.sk = Ed25519PrivateKey.generate()
        self.created = created
        self.body = self._key_body(self.sk, created)

    @staticmethod
    def _key_body(sk, created):
        point = b"\x40" + sk.public_key().public_bytes_raw()
        return b"\x04" + struct.pack(">I", created) + bytes((22, len(openpgp.ED25519_OID))) + openpgp.ED25519_OID + \
            _mpi(point)

    @staticmethod
    def fpr(body):
        return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()

    def sign(self, sk, sig_type, prefix: bytes, data: bytes = b"", hashed=b"", unhashed=b"", hash_alg=10,
             created=1_700_000_100, issuer_body=None):
        hashed = _sp(2, struct.pack(">I", created)) + hashed
        issuer = self.fpr(issuer_body or self.body)
        unhashed = _sp(16, issuer[-8:]) + unhashed
        head = bytes((4, sig_type, 22, hash_alg)) + struct.pack(">H", len(hashed)) + hashed
        h = hashlib.new({10: "sha512", 2: "sha1", 8: "sha256"}[hash_alg])
        h.update(prefix + data + head + b"\x04\xff" + struct.pack(">I", len(head)))
        digest = h.digest()
        raw = sk.sign(digest)
        return _packet(2, head + struct.pack(">H", len(unhashed)) + unhashed + digest[:2] + _mpi(raw[:32]) +
                       _mpi(raw[32:]))

    def hashed_form(self, body=None):
        body = body or self.body
        return b"\x99" + struct.pack(">H", len(body)) + body

    def uid(self, name=b"Test <t@example.invalid>", hashed=b""):
        prefix = self.hashed_form() + b"\xb4" + struct.pack(">I", len(name)) + name
        return _packet(13, name) + self.sign(self.sk, 0x13, prefix, hashed=_sp(27, b"\x03") + hashed)

    def key(self, *extra: bytes, uid=True) -> bytes:
        return _packet(6, self.body) + (self.uid() if uid else b"") + b"".join(extra)

    def subkey(self, backsig=True, flags=b"\x02"):
        sub = Ed25519PrivateKey.generate()
        body = self._key_body(sub, self.created)
        prefix = self.hashed_form() + self.hashed_form(body)
        emb = b""
        if backsig:
            back = self.sign(sub, 0x19, prefix, issuer_body=body)
            emb = _sp(32, back[6:])
        return sub, body, _packet(14, body) + self.sign(self.sk, 0x18, prefix, hashed=_sp(27, flags) + emb)

    def file_sig(self, data: bytes, sk=None, body=None, **kw) -> bytes:
        return self.sign(sk or self.sk, 0x00, b"", data, issuer_body=body, **kw)


def _verify(tmp_path, data: bytes, sig: bytes, key: bytes, **kw):
    f = tmp_path / "f.bin"
    f.write_bytes(data)
    return openpgp.verify_file(f, sig, key, **kw)


def test_built_certificate_verifies(tmp_path):
    c = Cert()
    assert _verify(tmp_path, b"data", c.file_sig(b"data"), c.key()).user_ids == ["Test <t@example.invalid>"]


def test_a_key_without_a_valid_self_signature_is_refused(tmp_path):
    c = Cert()
    with pytest.raises(LocksmithError, match="self-signature"):
        _verify(tmp_path, b"data", c.file_sig(b"data"), c.key(uid=False))
    bad_uid = _packet(13, b"Other") + Cert().uid()[len(_packet(13, b"Test <t@example.invalid>")):]
    with pytest.raises(LocksmithError, match="self-signature"):
        _verify(tmp_path, b"data", c.file_sig(b"data"), _packet(6, c.body) + bad_uid)


def test_signing_subkey_needs_its_back_signature(tmp_path):
    c = Cert()
    sub, body, packets = c.subkey(backsig=True)
    assert _verify(tmp_path, b"d", c.file_sig(b"d", sub, body), c.key(packets)).signing_key != ""
    sub, body, packets = c.subkey(backsig=False)   # anyone could bind someone else's key this way
    with pytest.raises(LocksmithError, match="different key"):
        _verify(tmp_path, b"d", c.file_sig(b"d", sub, body), c.key(packets))
    sub, body, packets = c.subkey(flags=b"\x0c")   # an encryption subkey can't sign
    with pytest.raises(LocksmithError, match="allowed to sign"):
        _verify(tmp_path, b"d", c.file_sig(b"d", sub, body), c.key(packets))


def test_weak_hashes_and_unknown_critical_parts_are_refused(tmp_path):
    c = Cert()
    with pytest.raises(LocksmithError, match="SHA-1"):
        _verify(tmp_path, b"d", c.file_sig(b"d", hash_alg=2), c.key())
    with pytest.raises(LocksmithError, match="critical"):
        _verify(tmp_path, b"d", c.file_sig(b"d", hashed=_sp(100, b"x", critical=True)), c.key())
    assert _verify(tmp_path, b"d", c.file_sig(b"d", hashed=_sp(100, b"x")), c.key())   # not critical: ignored


def test_signatures_after_expiry_are_refused(tmp_path):
    c = Cert()
    key = _packet(6, c.body) + c.uid(hashed=_sp(9, struct.pack(">I", 1000)))   # expires 1000 s after creation
    assert _verify(tmp_path, b"d", c.file_sig(b"d", created=c.created + 10), key).expired
    with pytest.raises(LocksmithError, match="after the key expired"):
        _verify(tmp_path, b"d", c.file_sig(b"d", created=c.created + 2000), key)
    with pytest.raises(LocksmithError, match="older than the key"):
        _verify(tmp_path, b"d", c.file_sig(b"d", created=c.created - 10), key)


def test_signature_expiry(tmp_path):
    c = Cert()
    sig = c.file_sig(b"d", hashed=_sp(3, struct.pack(">I", 60)))
    assert _verify(tmp_path, b"d", sig, c.key(), now=1_700_000_120)
    with pytest.raises(LocksmithError, match="expired"):
        _verify(tmp_path, b"d", sig, c.key(), now=1_700_001_000)


@pytest.mark.parametrize("data", [b"", b"\n", b"\r\n", b"a\r\nb\nc\r", b"x" * (4 << 20) + b"\r" + b"\n" + b"y"],
                         ids=["empty", "lf", "crlf", "mixed", "crlf-across-reads"])
def test_text_mode_line_ends(tmp_path, data):
    """Text signatures hash LF line ends as CR LF, also across the 4 MiB read boundary."""
    c = Cert()
    canonical = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    sig = c.sign(c.sk, 0x01, b"", canonical)
    assert _verify(tmp_path, data, sig, c.key()).text_mode


def test_version_6_is_refused():
    with pytest.raises(LocksmithError, match="version 6"):
        openpgp.parse_signature(_packet(2, b"\x06" + bytes(40)))
    with pytest.raises(LocksmithError, match="version 6"):
        openpgp.parse_key(_packet(6, b"\x06" + bytes(40)))


@pytest.mark.parametrize("blob", [b"", b"\x00", b"\xc2\xff\xff\xff\xff\xff", b"\x88\x05abc", b"\xc2\x05" + bytes(5),
                                  b"-----BEGIN PGP SIGNATURE-----\n\n!!!\n-----END PGP SIGNATURE-----\n"])
def test_malformed_signatures(blob):
    with pytest.raises(LocksmithError):
        openpgp.parse_signature(blob)
