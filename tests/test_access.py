"""Changing who can open a file without re-encrypting it (engine.change_access, FORMAT.md §3)."""

import os
import stat
import sys
from pathlib import Path

import fileformat
import pytest

from locksmith.core import engine, keys, signing
from locksmith.core.engine import AccessChange, DecryptKeys, EncryptOptions, LockoutError
from locksmith.core.errors import LocksmithError, WrongKeyError

FAST = dict(kdf="pbkdf2-sha512", preset="fast")
DATA = os.urandom(5000) + b"text " * 3000


def _identity(hybrid=True) -> tuple[bytes, bytes]:
    raw = os.urandom(96 if hybrid else 32)
    return raw, keys.public_from_private(raw)


def _encrypt(tmp_path, **kw) -> Path:
    src = tmp_path / "doc.bin"
    src.write_bytes(DATA)
    return engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(chunk_size=4096, **FAST, **kw))


def _opens(path, **kw) -> bool:
    try:
        res = engine.decrypt_bytes(_blob(path), DecryptKeys(**kw))
    except WrongKeyError:
        return False
    assert res.data == DATA
    return True


def _blob(path) -> bytes:
    data = Path(path).read_bytes()
    return engine.dearmor(data.decode()) if data.startswith(b"-----BEGIN") else data


def _unchanged_except_slots(before: bytes, after: bytes):
    h1, body1 = fileformat.split(before)
    h2, body2 = fileformat.split(after)
    assert body1 == body2, "the frames must not change"
    assert h1["kc"] == h2["kc"] and fileformat.fixed_bytes(before) == fileformat.fixed_bytes(after)


def test_change_the_password(tmp_path):
    path = _encrypt(tmp_path, password="old")
    before = path.read_bytes()
    res = engine.change_access(path, DecryptKeys(password="old"),
                               AccessChange(set_password=True, password="new", **FAST))
    assert res.you_can_open and res.password_slots == 1 and res.recipient_slots == 0
    assert _opens(path, password="new") and not _opens(path, password="old")
    _unchanged_except_slots(before, path.read_bytes())


def test_switch_to_a_keyfile_and_back(tmp_path):
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(os.urandom(64))
    path = _encrypt(tmp_path, password="pw")
    engine.change_access(path, DecryptKeys(password="pw"), AccessChange(set_password=True, keyfile=str(keyfile), **FAST))
    assert _opens(path, keyfile=str(keyfile)) and not _opens(path, password="pw")
    engine.change_access(path, DecryptKeys(keyfile=str(keyfile)),
                         AccessChange(set_password=True, password="pw", keyfile=str(keyfile), **FAST))
    assert _opens(path, password="pw", keyfile=str(keyfile))
    short = tmp_path / "short.bin"
    short.write_bytes(b"x" * 8)
    with pytest.raises(LocksmithError, match="at least"):
        engine.change_access(path, DecryptKeys(password="pw", keyfile=str(keyfile)),
                             AccessChange(set_password=True, keyfile=str(short), **FAST))


def test_add_a_recipient(tmp_path):
    bob, bob_pub = _identity()
    carol, carol_pub = _identity(hybrid=False)
    path = _encrypt(tmp_path, password="pw")
    before = path.read_bytes()
    res = engine.change_access(path, DecryptKeys(password="pw"), AccessChange(add_recipients=[bob_pub, carol_pub]))
    assert res.password_slots == 1 and res.recipient_slots == 2
    assert _opens(path, identities=[bob]) and _opens(path, identities=[carol]) and _opens(path, password="pw")
    _unchanged_except_slots(before, path.read_bytes())


def test_replace_the_recipients(tmp_path):
    """Recipients aren't named in the file, so removing one means listing everyone who keeps access."""
    alice, alice_pub = _identity()
    bob, bob_pub = _identity()
    carol, carol_pub = _identity()
    path = _encrypt(tmp_path, recipients=[alice_pub, bob_pub])
    res = engine.change_access(path, DecryptKeys(identities=[alice]),
                               AccessChange(replace_recipients=True, add_recipients=[alice_pub, carol_pub]))
    assert res.you_can_open and res.recipient_slots == 2
    assert _opens(path, identities=[alice]) and _opens(path, identities=[carol]) and not _opens(path, identities=[bob])


def test_remove_the_password_keeps_the_recipients(tmp_path):
    alice, alice_pub = _identity()
    path = _encrypt(tmp_path, password="pw", recipients=[alice_pub])
    res = engine.change_access(path, DecryptKeys(identities=[alice]), AccessChange(set_password=True))
    assert res.password_slots == 0 and res.you_can_open
    assert _opens(path, identities=[alice]) and not _opens(path, password="pw")


def test_lockout_needs_confirmation(tmp_path):
    """Removing the password you opened it with, leaving only someone else, is refused
    unless allowed: you could never open the file again."""
    bob, bob_pub = _identity()
    path = _encrypt(tmp_path, password="pw", recipients=[bob_pub])
    before = path.read_bytes()
    with pytest.raises(LockoutError):
        engine.change_access(path, DecryptKeys(password="pw"), AccessChange(set_password=True))
    assert path.read_bytes() == before
    res = engine.change_access(path, DecryptKeys(password="pw"), AccessChange(set_password=True), allow_lockout=True)
    assert not res.you_can_open and _opens(path, identities=[bob]) and not _opens(path, password="pw")


def test_nothing_left_to_open_it_is_refused(tmp_path):
    path = _encrypt(tmp_path, password="pw")
    before = path.read_bytes()
    with pytest.raises(LocksmithError, match="at least one way"):
        engine.change_access(path, DecryptKeys(password="pw"), AccessChange(set_password=True), allow_lockout=True)
    assert path.read_bytes() == before


def test_wrong_key_changes_nothing(tmp_path):
    path = _encrypt(tmp_path, password="pw")
    before = path.read_bytes()
    with pytest.raises(WrongKeyError):
        engine.change_access(path, DecryptKeys(password="nope"), AccessChange(set_password=True, password="x", **FAST))
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name]


def test_a_signed_file_stays_signed(tmp_path):
    alice = os.urandom(96)
    bob, bob_pub = _identity()
    path = _encrypt(tmp_path, password="pw", signer=alice)
    engine.change_access(path, DecryptKeys(password="pw"), AccessChange(add_recipients=[bob_pub]))
    res = engine.decrypt_bytes(path.read_bytes(), DecryptKeys(identities=[bob], verifiers=[signing.public_key(alice)]))
    assert res.data == DATA and res.signature.verified


def test_armored_files_stay_armored(tmp_path):
    path = _encrypt(tmp_path, password="pw", armor=True)
    engine.change_access(path, DecryptKeys(password="pw"), AccessChange(set_password=True, password="new", **FAST))
    assert path.read_text(encoding="utf-8").startswith(engine.ARMOR_BEGIN)
    assert _opens(path, password="new")


def test_hiding_the_number_of_recipients(tmp_path):
    alice, alice_pub = _identity()
    bob, bob_pub = _identity()
    path = _encrypt(tmp_path, password="pw", recipients=[alice_pub], hide_recipients=True)
    assert engine.inspect(path).recipient_slots == 8
    # Kept slots can't be told from decoys, so adding one rounds up again rather than shrinking.
    res = engine.change_access(path, DecryptKeys(password="pw"), AccessChange(add_recipients=[bob_pub],
                                                                             hide_recipients=True))
    assert res.recipient_slots == 16
    info = engine.inspect(path)
    assert info.recipient_slots == info.post_quantum_slots == 16
    res = engine.change_access(path, DecryptKeys(identities=[bob]), AccessChange(
        replace_recipients=True, add_recipients=[bob_pub], hide_recipients=True))
    assert res.recipient_slots == 8 and _opens(path, identities=[bob]) and not _opens(path, identities=[alice])


def test_slot_limit(tmp_path):
    many = [_identity(hybrid=False)[1] for _ in range(63)]
    path = _encrypt(tmp_path, password="pw", recipients=many)
    before = path.read_bytes()
    with pytest.raises(LocksmithError, match="at most 64"):
        engine.change_access(path, DecryptKeys(password="pw"), AccessChange(add_recipients=[_identity()[1]] * 2 +
                                                                            [_identity()[1]]))
    assert path.read_bytes() == before


def test_version_1_files_are_refused(tmp_path):
    v1 = Path(__file__).parent / "vectors" / "password-aes256gcm-zstd.locked"
    path = tmp_path / "v1.locked"
    path.write_bytes(v1.read_bytes())
    with pytest.raises(LocksmithError, match="version 1"):
        engine.change_access(path, DecryptKeys(password="x"), AccessChange(set_password=True, password="y"))


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_file_mode_is_kept(tmp_path):
    path = _encrypt(tmp_path, password="pw")
    os.chmod(path, 0o640)
    engine.change_access(path, DecryptKeys(password="pw"), AccessChange(set_password=True, password="new", **FAST))
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_removing_the_password_used_is_fine_when_your_identity_stays(tmp_path):
    """Opened with the password, but the user's own identity is also a recipient: no lockout."""
    me, me_pub = _identity()
    path = _encrypt(tmp_path, password="pw", recipients=[me_pub])
    res = engine.change_access(path, DecryptKeys(password="pw", identities=[me]), AccessChange(set_password=True))
    assert res.you_can_open and _opens(path, identities=[me])
