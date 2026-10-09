"""SSH Ed25519 and RSA public keys as recipients (FORMAT.md §3), with keys made by the real
ssh-keygen (tests/interop/sshkeys) and the committed vector tests/vectors/v2-ssh-recipients.locked."""

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import fileformat
import pytest
import spec_reader
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

from locksmith.core import engine, keys, signing, sshkeys
from locksmith.core.engine import AccessChange, DecryptKeys, EncryptOptions
from locksmith.core.errors import CorruptedError, LocksmithError, WrongKeyError

TESTS = Path(__file__).parent
KEYS = TESTS / "interop" / "sshkeys"
VECTOR = json.loads((TESTS / "vectors" / "ssh-vectors.json").read_text(encoding="utf-8"))
PASS = (KEYS / "passphrase.txt").read_text(encoding="utf-8").strip()
FAST = dict(kdf="pbkdf2-sha512", preset="fast")


def _pub(name: str) -> sshkeys.SshRecipient:
    return sshkeys.parse_recipient((KEYS / f"{name}.pub").read_text(encoding="utf-8"))


def _ident(name: str, passphrase=None) -> sshkeys.SshIdentity:
    return sshkeys.load_identity(sshkeys.read_private(KEYS / name), passphrase)


# ── the committed vector ─────────────────────────────────────────────────────

@pytest.mark.parametrize("key,passphrase", [("id_ed25519", None), ("id_ed25519_protected", PASS),
                                            ("id_rsa3072", None), ("id_rsa3072_protected", PASS),
                                            ("id_rsa3072_protected.pem", PASS)])
def test_vector_opens_with_each_ssh_key(key, passphrase):
    blob = (TESTS / "vectors" / VECTOR["file"]).read_bytes()
    res = engine.decrypt_bytes(blob, DecryptKeys(ssh=[_ident(key, passphrase)]))
    assert hashlib.sha256(res.data).hexdigest() == VECTOR["content_sha256"]


def test_vector_matches_the_specification():
    blob = (TESTS / "vectors" / VECTOR["file"]).read_bytes()
    assert sorted(s["t"] for s in fileformat.split(blob)[0]["slots"]) == VECTOR["slot_types"]
    ed = load_ssh_private_key((KEYS / "id_ed25519").read_bytes(), None)
    rsa = load_ssh_private_key((KEYS / "id_rsa3072").read_bytes(), None)
    for r in (spec_reader.read(blob, identity=spec_reader.ssh_ed25519_identity(ed.private_bytes_raw())),
              spec_reader.read(blob, rsa_key=rsa)):
        assert r["dek"].hex() == VECTOR["dek"]
    # The conversions as the specification states them, against Locksmith's.
    assert _pub("id_ed25519").raw.hex() == VECTOR["ed25519_x25519_public"]
    assert _pub("id_rsa3072").raw == base64.b64decode(VECTOR["rsa_blob"])
    assert _ident("id_ed25519").public_raw.hex() == VECTOR["ed25519_x25519_public"]


def test_fingerprints_match_ssh_keygen():
    for name in ("id_ed25519", "id_rsa3072"):
        try:
            out = subprocess.run(["ssh-keygen", "-lf", str(KEYS / f"{name}.pub")], capture_output=True, text=True,
                                 timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            pytest.skip("ssh-keygen is not installed")
        assert _pub(name).fingerprint == out.split()[1]
        assert _ident(name).fingerprint == out.split()[1]


# ── encrypting to SSH keys ───────────────────────────────────────────────────

def test_round_trip_and_wrong_keys():
    blob = engine.encrypt_bytes(b"to ssh", EncryptOptions(recipients=[_pub("id_ed25519").raw]))
    assert engine.decrypt_bytes(blob, DecryptKeys(ssh=[_ident("id_ed25519")])).data == b"to ssh"
    with pytest.raises(WrongKeyError):
        engine.decrypt_bytes(blob, DecryptKeys(ssh=[_ident("id_rsa3072")]))
    rsa_blob = engine.encrypt_bytes(b"to rsa", EncryptOptions(recipients=[_pub("id_rsa3072").raw]))
    assert engine.inspect_bytes(rsa_blob).recipient_slots == 1
    assert engine.decrypt_bytes(rsa_blob, DecryptKeys(ssh=[_ident("id_rsa3072")])).data == b"to rsa"
    with pytest.raises(WrongKeyError):
        engine.decrypt_bytes(rsa_blob, DecryptKeys(ssh=[_ident("id_ed25519")], identities=[os.urandom(96)]))


def test_passphrases():
    assert sshkeys.needs_passphrase(sshkeys.read_private(KEYS / "id_ed25519_protected"))
    assert sshkeys.needs_passphrase(sshkeys.read_private(KEYS / "id_rsa3072_protected.pem"))
    assert not sshkeys.needs_passphrase(sshkeys.read_private(KEYS / "id_ed25519"))
    for name in ("id_ed25519_protected", "id_rsa3072_protected", "id_rsa3072_protected.pem"):
        with pytest.raises(WrongKeyError):
            _ident(name, "not the passphrase")
        with pytest.raises(WrongKeyError):
            _ident(name)
    assert _ident("id_ed25519", "unneeded").key_type == "ssh-ed25519"   # a passphrase it doesn't need is ignored


def test_unsupported_keys_are_refused():
    with pytest.raises(LocksmithError, match="ECDSA"):
        _pub("id_ecdsa")
    with pytest.raises(LocksmithError, match="Ed25519 and RSA"):
        _ident("id_ecdsa")
    with pytest.raises(LocksmithError, match="2048"):
        sshkeys.parse_recipient((TESTS / "interop" / "sshsig" / "rsa1024.pub").read_text(encoding="utf-8"))
    with pytest.raises(LocksmithError):
        sshkeys.load_identity(b"-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----\n")
    with pytest.raises(LocksmithError):
        sshkeys.load_identity(os.urandom(300))


@pytest.mark.parametrize("y", [0, 1, 2 ** 255 - 19, 2 ** 255 - 1])
def test_invalid_ed25519_points_are_refused(y):
    raw = y.to_bytes(32, "little")
    blob = b"".join(len(p).to_bytes(4, "big") + p for p in (b"ssh-ed25519", raw))
    with pytest.raises(LocksmithError):
        sshkeys.parse_recipient(f"ssh-ed25519 {base64.b64encode(blob).decode()}")


def test_conversion_matches_libsodium_style_key_pairs():
    """Any Ed25519 key pair: the converted public key is the X25519 public key of the converted seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    for _ in range(20):
        k = Ed25519PrivateKey.generate()
        x = X25519PrivateKey.from_private_bytes(sshkeys.ed25519_seed_to_x25519(k.private_bytes_raw()))
        assert sshkeys.ed25519_to_x25519(k.public_key().public_bytes_raw()) == x.public_key().public_bytes_raw()


def test_rsa_slot_header_rules():
    blob = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", recipients=[_pub("id_rsa3072").raw], **FAST))
    header, body = fileformat.split(blob)
    slot = next(s for s in header["slots"] if s["t"] == "ssh-rsa")
    assert len(base64.b64decode(slot["c"])) == 384 and set(slot) == {"t", "c", "n", "w"}
    for c in (os.urandom(255), os.urandom(2049), "not base64", None):
        slot["c"] = base64.b64encode(c).decode() if isinstance(c, bytes) else c
        with pytest.raises(CorruptedError):
            engine.decrypt_bytes(fileformat.join(header, body), DecryptKeys(password="pw"))


def test_rsa_slots_only_in_version_2():
    with pytest.raises(LocksmithError, match="version 2"):
        engine._build_header(EncryptOptions(recipients=[_pub("id_rsa3072").raw]), {}, engine._Checker(None, None),
                             engine.LOCKED_V1)


def test_decoys_beside_ssh_recipients_are_classical():
    """Each kind is rounded up on its own (audit A9): 8 x25519 slots and 8 RSA-3072 ones."""
    blob = engine.encrypt_bytes(b"x", EncryptOptions(recipients=[_pub("id_rsa3072").raw, _pub("id_ed25519").raw],
                                                     hide_recipients=True))
    info = engine.inspect_bytes(blob)
    assert info.recipient_slots == 16 and info.post_quantum_slots == 0
    assert engine.decrypt_bytes(blob, DecryptKeys(ssh=[_ident("id_rsa3072")])).data == b"x"


def test_adding_an_ssh_recipient_later(tmp_path):
    path = tmp_path / "f.locked"
    path.write_bytes(engine.encrypt_bytes(b"later", EncryptOptions(password="pw", **FAST)))
    engine.change_access(path, DecryptKeys(password="pw"), AccessChange(add_recipients=[_pub("id_rsa3072").raw]))
    assert engine.decrypt_bytes(path.read_bytes(), DecryptKeys(ssh=[_ident("id_rsa3072")])).data == b"later"


def test_ssh_recipients_in_a_recipient_list():
    alice = os.urandom(96)
    blob = engine.encrypt_bytes(b"x", EncryptOptions(recipients=[_pub("id_rsa3072").raw], signer=alice,
                                                     address_to=True))
    res = engine.decrypt_bytes(blob, DecryptKeys(ssh=[_ident("id_rsa3072")], verifiers=[signing.public_key(alice)]))
    assert res.intent == "listed"


# ── contacts ─────────────────────────────────────────────────────────────────

def test_ssh_contacts(tmp_path):
    store = keys.KeyStore(tmp_path)
    line = (KEYS / "id_ed25519.pub").read_text(encoding="utf-8")
    c = store.add_contact("Server", line)
    assert c.public == _pub("id_ed25519").text and "locksmith-interop" not in c.public   # the comment is dropped
    assert c.public_raw == _pub("id_ed25519").raw and not c.can_verify
    assert c.fingerprint == _pub("id_ed25519").fingerprint and c.kind == "SSH Ed25519, classical"
    rsa = store.add_contact("Laptop", (KEYS / "id_rsa3072.pub").read_text(encoding="utf-8"))
    assert rsa.kind == "SSH RSA 3072, classical" and sshkeys.is_rsa_raw(rsa.public_raw)
    with pytest.raises(LocksmithError, match="already saved"):
        store.add_contact("Again", line)
    reloaded = keys.KeyStore(tmp_path)
    assert [x.public for x in reloaded.contacts] == [c.public, rsa.public] and reloaded.problem is None
    blob = engine.encrypt_bytes(b"hi", EncryptOptions(recipients=[x.public_raw for x in reloaded.contacts]))
    assert engine.decrypt_bytes(blob, DecryptKeys(ssh=[_ident("id_rsa3072")])).data == b"hi"


def test_a_damaged_ssh_contact_is_kept_but_not_used(tmp_path):
    (tmp_path / "keys.json").write_text(json.dumps({"identities": [], "contacts": [
        {"name": "Bad", "public": "ssh-ed25519 AAAAgarbage", "added": 1}]}), encoding="utf-8")
    store = keys.KeyStore(tmp_path)
    assert store.contacts == [] and store.problem
    store.save()
    assert "AAAAgarbage" in (tmp_path / "keys.json").read_text(encoding="utf-8")
