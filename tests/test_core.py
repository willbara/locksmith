import os
import threading
from pathlib import Path

import pytest

from locksmith.core import compress, engine, tools
from locksmith.core.ciphers import SUITES
from locksmith.core.engine import DecryptKeys, EncryptOptions
from locksmith.core.errors import CancelledError, CorruptedError, LocksmithError, WrongKeyError
from locksmith.core.keys import KeyStore, decode_public, encode_public

FAST = dict(kdf="pbkdf2-sha512", preset="fast")


def _roundtrip(tmp_path, data: bytes, **kw) -> tuple[Path, bytes]:
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    opts = EncryptOptions(password="correct horse", **{**FAST, **kw})
    enc = engine.encrypt_paths([src], tmp_path / "enc", opts)
    res = engine.decrypt_path(enc, tmp_path / "dec", DecryptKeys(password="correct horse"))
    return enc, res.path.read_bytes()


@pytest.mark.parametrize("suite", list(SUITES))
def test_every_suite(tmp_path, suite):
    data = os.urandom(300_000)
    _, out = _roundtrip(tmp_path, data, suite=suite, chunk_size=256 << 10)
    assert out == data


@pytest.mark.parametrize("codec", [*compress.CODECS, "none", "auto"])
def test_every_codec(tmp_path, codec):
    data = b"hello locksmith " * 200_000
    enc, out = _roundtrip(tmp_path, data, compression=codec)
    assert out == data
    if codec != "none":
        assert enc.stat().st_size < len(data) / 10


@pytest.mark.parametrize("pad", list(engine.PADDING))
@pytest.mark.parametrize("size", [0, 1, 1000, 1 << 20, (1 << 20) + 7, 3_000_000])
def test_padding_and_sizes(tmp_path, pad, size):
    data = os.urandom(size)
    enc, out = _roundtrip(tmp_path, data, padding=pad, compression="none")
    assert out == data


def test_pow2_padding_hides_size(tmp_path):
    enc, _ = _roundtrip(tmp_path, os.urandom(600_000), padding="pow2", compression="none")
    assert enc.stat().st_size > 1 << 20


def test_wrong_password(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("secret")
    enc = engine.encrypt_paths([src], None, EncryptOptions(password="one", **FAST))
    with pytest.raises(WrongKeyError):
        engine.decrypt_path(enc, tmp_path / "out", DecryptKeys(password="two"))
    assert not list((tmp_path / "out").glob("*"))


@pytest.mark.parametrize("where", ["body", "header", "truncate", "append", "drop_last"])
def test_tamper_detected(tmp_path, where):
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(700_000))
    enc = engine.encrypt_paths([src], None, EncryptOptions(
        password="pw", chunk_size=256 << 10, compression="none", **FAST))
    blob = bytearray(enc.read_bytes())
    if where == "body":
        blob[-100] ^= 1
    elif where == "header":
        i = blob.index(b'"chunk"')
        blob[i + 9] = ord("5") if blob[i + 9] != ord("5") else ord("4")
    elif where == "truncate":
        del blob[-50:]
    elif where == "append":
        blob += blob[-300:]
    elif where == "drop_last":
        # remove the final frame entirely
        import struct
        pos = 12 + struct.unpack(">I", blob[8:12])[0]
        frames = []
        while pos < len(blob):
            n = struct.unpack(">I", blob[pos:pos + 4])[0]
            frames.append(pos)
            pos += 4 + n
        del blob[frames[-1]:]
    enc.write_bytes(bytes(blob))
    with pytest.raises((CorruptedError, WrongKeyError)):
        engine.decrypt_path(enc, tmp_path / "out", DecryptKeys(password="pw"))
    assert not [p for p in (tmp_path / "out").glob("*")]


def test_keyfile_and_recipients(tmp_path):
    store = KeyStore(tmp_path / "cfg")
    alice = store.generate("alice")
    bob = store.generate("bob", passphrase="bobpass")
    kf = tmp_path / "key.bin"
    kf.write_bytes(os.urandom(64))
    src = tmp_path / "doc.txt"
    src.write_text("for alice and bob")
    enc = engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(
        password="pw", keyfile=str(kf), recipients=[alice.public_raw, bob.public_raw], **FAST))

    info = engine.inspect(enc)
    assert info.recipient_slots == 2 and info.needs_keyfile

    with pytest.raises(WrongKeyError):
        engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password="pw"))
    r = engine.decrypt_path(enc, tmp_path / "d1", DecryptKeys(password="pw", keyfile=str(kf)))
    assert r.path.read_text() == "for alice and bob"
    r = engine.decrypt_path(enc, tmp_path / "d2", DecryptKeys(identities=[alice.private_raw()]))
    assert r.path.read_text() == "for alice and bob"
    r = engine.decrypt_path(enc, tmp_path / "d3",
                            DecryptKeys(identities=[bob.private_raw("bobpass")]))
    assert r.path.read_text() == "for alice and bob"
    with pytest.raises(WrongKeyError):
        bob.private_raw("nope")
    stranger = KeyStore(tmp_path / "cfg2").generate("eve")
    with pytest.raises(WrongKeyError):
        engine.decrypt_path(enc, tmp_path / "d4", DecryptKeys(identities=[stranger.private_raw()]))


def test_folder_bundle_hidden_name_armor(tmp_path):
    d = tmp_path / "Photos"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("A")
    (d / "sub" / "b.bin").write_bytes(os.urandom(5000))
    extra = tmp_path / "notes.md"
    extra.write_text("# notes")

    enc = engine.encrypt_paths([d], tmp_path / "e", EncryptOptions(password="x", hide_name=True, **FAST))
    assert "Photos" not in enc.name
    r = engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password="x"))
    assert r.path.name == "Photos" and (r.path / "sub" / "b.bin").read_bytes() == \
        (d / "sub" / "b.bin").read_bytes()

    enc = engine.encrypt_paths([d, extra], tmp_path / "e", EncryptOptions(password="x", armor=True, **FAST),
                               bundle_name="stuff")
    assert engine.is_armored(enc)
    r = engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password="x"))
    assert (r.path / "notes.md").read_text() == "# notes" and (r.path / "Photos" / "a.txt").exists()


def test_bytes_and_note():
    blob = engine.encrypt_bytes(b"hi there", EncryptOptions(password="p", note="n1", **FAST))
    text = engine.armor(blob)
    res = engine.decrypt_bytes(engine.dearmor(text), DecryptKeys(password="p"))
    assert res.data == b"hi there" and res.meta["note"] == "n1"


def test_cancel(tmp_path):
    src = tmp_path / "big"
    src.write_bytes(os.urandom(4 << 20))
    ev = threading.Event()
    ev.set()
    with pytest.raises(CancelledError):
        engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(password="p", **FAST), cancel=ev)
    assert not list((tmp_path / "e").iterdir())


def test_verify(tmp_path):
    src = tmp_path / "v"
    src.write_bytes(b"x" * 10)
    enc = engine.encrypt_paths([src], None, EncryptOptions(password="p", **FAST))
    assert engine.verify_path(enc, DecryptKeys(password="p"))["name"] == "v"


def test_argon_and_scrypt(tmp_path):
    for k in ("argon2id", "scrypt"):
        _, out = _roundtrip(tmp_path, b"abc", kdf=k, preset="fast")
        assert out == b"abc"


def test_pubkey_encoding():
    raw = os.urandom(32)
    enc = encode_public(raw)
    assert decode_public(enc) == raw
    bad = enc[:-3] + ("A" if enc[-3] != "A" else "B") + enc[-2:]
    with pytest.raises(LocksmithError):
        decode_public(bad)


def test_shamir():
    secret = b"my very secret password"
    shares = tools.shamir_split(secret, 3, 5)
    assert tools.shamir_combine(shares[1:4]) == secret
    assert tools.shamir_combine([shares[0], shares[4], shares[2]]) == secret
    with pytest.raises(LocksmithError):
        tools.shamir_combine(shares[:2])


def test_split_join_shred(tmp_path):
    f = tmp_path / "x.locked"
    data = os.urandom(2500)
    f.write_bytes(data)
    parts = tools.split_file(f, 1000)
    assert len(parts) == 3
    (tmp_path / "joined").mkdir()
    out = tools.join_parts(parts[::-1], tmp_path / "joined")
    assert out.read_bytes() == data
    tools.shred(f)
    assert not f.exists()


def test_passwords():
    pw = tools.generate_password(32)
    assert len(pw) == 32
    assert tools.strength_label(tools.estimate_entropy(pw))[0] >= 3
    assert tools.strength_label(tools.estimate_entropy("password1"))[0] <= 1
    assert tools.generate_passphrase(5).count("-") == 4


def test_new_files_use_the_locksmith_format(tmp_path):
    src = tmp_path / "a.txt"
    src.write_text("new")
    enc = engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(password="p", **FAST))
    assert enc.name == "a.txt.locked" and enc.read_bytes().startswith(b"LOCKED\x00\x01")
    assert engine.inspect(enc).format_name == "Locksmith"
    foreign = tmp_path / "old.cryptor"
    foreign.write_bytes(b"CRYPTOR\x01" + enc.read_bytes()[8:])
    with pytest.raises(CorruptedError, match="not a Locksmith file"):
        engine.inspect(foreign)
