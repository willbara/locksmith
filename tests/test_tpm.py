"""Sealing identity keys to the TPM (runs only where systemd-creds can use a TPM 2.0)."""

import base64
import json

import pytest

from locksmith.core import engine, keys
from locksmith.core.engine import DecryptKeys, EncryptOptions
from locksmith.core.errors import LocksmithError, WrongKeyError

pytestmark = pytest.mark.skipif(not keys.tpm_available(), reason="no usable TPM 2.0 on this machine")


def _roundtrip(tmp_path, ident, passphrase=None, tag="x"):
    src = tmp_path / f"{tag}.txt"
    src.write_text("sealed identity works")
    enc = engine.encrypt_paths([src], tmp_path / f"e-{tag}", EncryptOptions(recipients=[ident.public_raw]))
    res = engine.decrypt_path(enc, tmp_path / f"d-{tag}", DecryptKeys(identities=[ident.private_raw(passphrase)]))
    return res.path.read_text()


def test_seal_unprotected_identity(tmp_path):
    store = keys.KeyStore(tmp_path / "k")
    ident = store.seal(store.generate("me"))
    on_disk = json.loads(store.path.read_text())["identities"][0]
    assert on_disk["private"] is None and on_disk["locked"] is None and on_disk["sealed"]
    assert not ident.is_locked
    reloaded = keys.KeyStore(tmp_path / "k").identities[0]
    assert _roundtrip(tmp_path, reloaded) == "sealed identity works"
    assert keys.KeyStore(tmp_path / "k").unlocked_private_keys()


def test_seal_keeps_passphrase_requirement(tmp_path):
    store = keys.KeyStore(tmp_path / "k")
    ident = store.seal(store.generate("me", passphrase="pass"))
    assert ident.is_locked and ident.is_sealed
    with pytest.raises(WrongKeyError):
        ident.private_raw()
    with pytest.raises(WrongKeyError):
        ident.private_raw("wrong")
    assert _roundtrip(tmp_path, ident, "pass") == "sealed identity works"


def test_tampered_seal_rejected(tmp_path):
    store = keys.KeyStore(tmp_path / "k")
    ident = store.seal(store.generate("me"))
    blob = bytearray(base64.b64decode(ident.sealed))
    blob[len(blob) // 2] ^= 1
    ident.sealed = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(LocksmithError):
        ident.private_raw()


def test_export_is_portable_and_unseal_restores(tmp_path):
    store = keys.KeyStore(tmp_path / "k")
    ident = store.seal(store.generate("me", passphrase="pass"))
    backup = tmp_path / "backup.json"
    store.export_identity(ident, backup)
    data = json.loads(backup.read_text())
    assert data["sealed"] is None and data["locked"], "backups must work on other machines"
    other = keys.KeyStore(tmp_path / "elsewhere").import_identity(backup)
    assert _roundtrip(tmp_path, other, "pass", "imported") == "sealed identity works"
    store.unseal(ident)
    assert not ident.is_sealed and ident.locked and _roundtrip(tmp_path, ident, "pass", "u") == "sealed identity works"


def test_upgrade_keeps_seal(tmp_path):
    store = keys.KeyStore(tmp_path / "k")
    ident = store.seal(store.generate("me", post_quantum=False))
    store.upgrade(ident)
    assert ident.is_sealed and ident.is_post_quantum
    assert _roundtrip(tmp_path, ident) == "sealed identity works"


def test_sealed_backup_cannot_be_imported(tmp_path):
    store = keys.KeyStore(tmp_path / "k")
    ident = store.seal(store.generate("me"))
    raw = tmp_path / "raw.json"
    raw.write_text(json.dumps({"locksmith-identity": 1, **json.loads(store.path.read_text())["identities"][0]}))
    with pytest.raises(LocksmithError):
        keys.KeyStore(tmp_path / "other").import_identity(raw)
    assert ident.is_sealed
