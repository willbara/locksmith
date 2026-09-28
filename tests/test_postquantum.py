"""Hybrid X25519 + ML-KEM-768 recipients."""

import base64
import hashlib
import json
import struct

import pytest

from locksmith.core import engine, keys
from locksmith.core.engine import DecryptKeys, EncryptOptions
from locksmith.core.errors import CorruptedError, LocksmithError, WrongKeyError


@pytest.fixture
def store(tmp_path):
    return keys.KeyStore(tmp_path / "keys")


def _file(tmp_path, data=b"quantum-safe payload"):
    src = tmp_path / "doc.txt"
    src.write_bytes(data)
    return src


def _header(path):
    blob = path.read_bytes()
    (n,) = struct.unpack(">I", blob[8:12])
    return blob[:8], json.loads(blob[12:12 + n])


def test_new_identities_are_hybrid(store):
    ident = store.generate("me")
    assert ident.is_post_quantum and ident.public.startswith("locksmith2")
    assert len(ident.public_raw) == keys.HYBRID_PUBLIC_LEN
    assert len(ident.private_raw()) == keys.HYBRID_PRIVATE_LEN
    classic = store.generate("old", post_quantum=False)
    assert classic.public.startswith("locksmith1") and not classic.is_post_quantum


def test_hybrid_roundtrip(tmp_path, store):
    ident = store.generate("me")
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(recipients=[ident.public_raw]))
    magic, header = _header(enc)
    assert magic == engine.LOCKED.magic and header["v"] == 1
    assert [s["t"] for s in header["slots"]] == [engine.HYBRID]
    assert engine.inspect(enc).post_quantum_slots == 1
    out = engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(identities=[ident.private_raw()]))
    assert out.path.read_bytes() == b"quantum-safe payload"


def test_classical_files_use_the_same_format(tmp_path, store):
    ident = store.generate("old", post_quantum=False)
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(recipients=[ident.public_raw]))
    magic, header = _header(enc)
    assert magic == engine.LOCKED.magic and header["v"] == 1


def test_mixed_recipients_and_password(tmp_path, store):
    pq, classic = store.generate("pq", passphrase="pass"), store.generate("classic", post_quantum=False)
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(
        password="pw", kdf="pbkdf2-sha512", preset="fast", recipients=[pq.public_raw, classic.public_raw]))
    for i, k in enumerate([DecryptKeys(identities=[pq.private_raw("pass")]),
                           DecryptKeys(identities=[classic.private_raw()]), DecryptKeys(password="pw")]):
        assert engine.decrypt_path(enc, tmp_path / f"d{i}", k).path.read_bytes() == b"quantum-safe payload"


def test_wrong_hybrid_identity_rejected(tmp_path, store):
    me, eve = store.generate("me"), store.generate("eve")
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(recipients=[me.public_raw]))
    with pytest.raises(WrongKeyError):
        engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(identities=[eve.private_raw()]))


def test_classical_half_alone_cannot_open_hybrid_slot(tmp_path, store):
    """Knowing only the X25519 private key (e.g. after a quantum attack on it) is not enough."""
    me = store.generate("me")
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(recipients=[me.public_raw]))
    x_only = me.private_raw()[:keys.X25519_LEN]
    with pytest.raises(WrongKeyError):
        engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(identities=[x_only]))


@pytest.mark.parametrize("field", ["kct", "epk", "w"])
def test_tampered_hybrid_slot_rejected(tmp_path, store, field):
    me = store.generate("me")
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(recipients=[me.public_raw]))
    magic, header = _header(enc)
    raw = bytearray(base64.b64decode(header["slots"][0][field]))
    raw[5] ^= 1
    header["slots"][0][field] = base64.b64encode(bytes(raw)).decode()
    blob = json.dumps(header).encode()
    body = enc.read_bytes()[12 + struct.unpack(">I", enc.read_bytes()[8:12])[0]:]
    enc.write_bytes(magic + struct.pack(">I", len(blob)) + blob + body)
    with pytest.raises((WrongKeyError, CorruptedError)):
        engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(identities=[me.private_raw()]))


def test_version_and_slot_type_must_agree(tmp_path, store):
    me = store.generate("me")
    enc = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e", EncryptOptions(recipients=[me.public_raw]))
    blob = enc.read_bytes()
    # A header version that contradicts the signature, or an unknown signature, is rejected.
    for evil in (blob.replace(b'"v":1', b'"v":2', 1), b"LOCKED\x00\x02" + blob[8:]):
        enc.write_bytes(evil)
        with pytest.raises(CorruptedError):
            engine.inspect(enc)


def test_upgrade_keeps_old_files_readable(tmp_path, store):
    ident = store.generate("me", passphrase="pass", post_quantum=False)
    old_public = ident.public_raw
    old = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e1", EncryptOptions(recipients=[old_public]))
    store.upgrade(ident, "pass")
    assert ident.is_post_quantum and ident.is_locked and ident.public_raw[:32] == old_public
    new = engine.encrypt_paths([_file(tmp_path)], tmp_path / "e2", EncryptOptions(recipients=[ident.public_raw]))
    raw = keys.KeyStore(store.dir).identities[0].private_raw("pass")  # reloaded from disk
    for i, enc in enumerate((old, new)):
        assert engine.decrypt_path(enc, tmp_path / f"d{i}", DecryptKeys(identities=[raw])).path.exists()


def test_upgrade_keeps_unprotected_identity_unprotected(store):
    ident = store.generate("me", post_quantum=False)
    store.upgrade(ident, "ignored")
    assert not ident.is_locked and len(ident.private_raw()) == keys.HYBRID_PRIVATE_LEN


def test_public_key_encoding_and_validation(store):
    raw = store.generate("me").public_raw
    text = keys.encode_public(raw)
    assert keys.decode_public(text) == raw and len(text) < 1700
    bad_kem = raw[:32] + b"\xff" * keys.MLKEM_PUBLIC_LEN
    bad_text = keys.HYBRID_PREFIX + base64.urlsafe_b64encode(
        bad_kem + hashlib.sha256(bad_kem).digest()[:4]).decode().rstrip("=")
    with pytest.raises(LocksmithError):
        keys.decode_public(bad_text)
    with pytest.raises(LocksmithError):  # right prefix, wrong length
        keys.decode_public(keys.HYBRID_PREFIX + text[len(keys.HYBRID_PREFIX):-40])


def test_locked_hybrid_pair_is_verified(store):
    a, b = store.generate("a", passphrase="p"), store.generate("b")
    a.public = b.public
    with pytest.raises(LocksmithError, match="does not match"):
        a.private_raw("p")


def test_public_key_fits_in_a_qr_code(store):
    import segno
    segno.make(store.generate("me").public, error="m")
