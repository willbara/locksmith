"""Hybrid signing keys, locksmith3 public keys and detached signatures: every way a
signature must be refused, and how signing keys live in the key store."""

import base64
import json
import struct

import pytest

from locksmith.core import engine, keys, signing
from locksmith.core.engine import DecryptKeys, EncryptOptions
from locksmith.core.errors import LocksmithError


@pytest.fixture
def store(tmp_path):
    return keys.KeyStore(tmp_path / "keys")


@pytest.fixture
def signer(store):
    ident = store.generate("Alice")
    return ident, ident.private_raw()


@pytest.fixture
def signed(tmp_path):
    f = tmp_path / "release.tar"
    f.write_bytes(b"release contents\n" * 100)
    return f


def _blob(text: str) -> bytes:
    return base64.b64decode("".join(text.strip().splitlines()[1:-1]))


def _text(blob: bytes) -> str:
    return signing.armor(blob)


# ── signing and verifying ────────────────────────────────────────────────────

def test_sign_and_verify(signer, signed):
    ident, raw = signer
    text = signing.sign_file(signed, raw, "Release 1.0 ✓", created=1_700_000_000)
    v = signing.verify_file(signed, text, [ident.key_raw])
    assert (v.key, v.comment, v.created) == (ident.key_raw, "Release 1.0 ✓", 1_700_000_000)
    assert v.fingerprint == keys.fingerprint(ident.key_raw)
    assert signing.parse(text).fingerprint == v.fingerprint   # the key ID starts with the fingerprint


def test_the_right_key_is_found_among_many(store, signer, signed):
    ident, raw = signer
    others = [store.generate(f"other {i}").key_raw for i in range(3)]
    v = signing.verify_file(signed, signing.sign_file(signed, raw), others + [ident.key_raw])
    assert v.key == ident.key_raw


def test_classical_identities_cannot_sign(store, signed):
    classical = store.generate("old", post_quantum=False)
    assert not classical.can_sign and classical.key_raw == classical.public_raw
    with pytest.raises(LocksmithError, match="Upgrade"):
        signing.sign_file(signed, classical.private_raw())


def test_comment_rules(signer, signed):
    _, raw = signer
    for bad in ("two\nlines", "tab\there", "bidi ‮ override", "x" * 1025, "zero​width"):
        with pytest.raises(LocksmithError):
            signing.sign_file(signed, raw, bad)
    signing.sign_file(signed, raw, "é" * 512)   # 1024 bytes exactly


@pytest.mark.parametrize("case,match", [
    ("ml-dsa stripped", "not a valid"),
    ("ml-dsa zeroed", "does not match"),
    ("ed25519 zeroed", "does not match"),
    ("ed25519 from another file", "does not match"),
    ("ml-dsa from another file", "does not match"),
    ("comment altered", "does not match"),
    ("created altered", "does not match"),
    ("unknown algorithm", "algorithm Locksmith doesn't know"),
    ("newer version", "newer version"),
    ("trailing data", "not a valid"),
    ("truncated", "not a valid"),
    ("comment with a line break", "not a valid"),
    ("comment length too large", "not a valid"),
    ("key id of another key", "None of the keys"),
    ("not armored", "not a Locksmith signature"),
    ("bad base64", "not a valid"),
])
def test_tampered_signatures_are_refused(store, signer, signed, tmp_path, case, match):
    ident, raw = signer
    good = _blob(signing.sign_file(signed, raw, "comment"))
    other_file = tmp_path / "other"
    other_file.write_bytes(b"something else")
    other = _blob(signing.sign_file(other_file, raw, "comment"))
    head, ed, ml = good[:-3373], good[-3373:-3309], good[-3309:]
    blob = {
        "ml-dsa stripped": head + ed,
        "ml-dsa zeroed": head + ed + bytes(3309),
        "ed25519 zeroed": head + bytes(64) + ml,
        "ed25519 from another file": head + other[-3373:-3309] + ml,
        "ml-dsa from another file": head + ed + other[-3309:],
        "comment altered": head.replace(b"comment", b"cOmment") + ed + ml,
        "created altered": head[:9] + struct.pack(">Q", 1) + head[17:] + ed + ml,
        "unknown algorithm": head[:8] + b"\x02" + head[9:] + ed + ml,
        "newer version": b"LOCKSIG\x02" + good[8:],
        "trailing data": good + b"\0",
        "truncated": good[:-1],
        "comment with a line break": head.replace(b"comment", b"comm\nnt") + ed + ml,
        "comment length too large": head[:49] + struct.pack(">H", 2000) + head[51:] + ed + ml,
        "key id of another key": head[:17] + signing.key_id(store.generate("Bob").key_raw) + head[49:] + ed + ml,
    }.get(case)
    text = _text(blob) if blob is not None else {
        "not armored": base64.b64encode(good).decode(),
        "bad base64": signing.ARMOR_BEGIN + "\n!!!!\n" + signing.ARMOR_END,
    }[case]
    with pytest.raises(LocksmithError, match=match):
        signing.verify_file(signed, text, [ident.key_raw, store.generate("Bob").key_raw])


def test_signature_is_bound_to_the_file(signer, signed):
    ident, raw = signer
    text = signing.sign_file(signed, raw)
    data = bytearray(signed.read_bytes())
    data[500] ^= 0x10
    signed.write_bytes(bytes(data))
    with pytest.raises(LocksmithError, match="does not match"):
        signing.verify_file(signed, text, [ident.key_raw])


def test_only_locksmith3_keys_verify(signer, signed):
    """The key decides the algorithm: the same identity's encryption-only key never verifies."""
    ident, raw = signer
    text = signing.sign_file(signed, raw)
    with pytest.raises(LocksmithError, match="None of the keys"):
        signing.verify_file(signed, text, [ident.public_raw])


def test_halves_of_two_keys_cannot_be_combined(store, signer, signed):
    """A key made of Alice's Ed25519 key and someone else's ML-DSA key gets nothing from her
    signatures: the key ID binds both halves, and rewriting it breaks the Ed25519 part."""
    ident, raw = signer
    mallory = store.generate("Mallory").key_raw
    spliced = ident.key_raw[:1248] + mallory[1248:]
    blob = _blob(signing.sign_file(signed, raw))
    forged = blob[:17] + signing.key_id(spliced) + blob[49:]
    with pytest.raises(LocksmithError, match="does not match"):
        signing.verify_file(signed, _text(forged), [spliced])


def test_signature_text_tolerates_line_ending_changes(signer, signed):
    ident, raw = signer
    text = signing.sign_file(signed, raw).replace("\n", "\r\n")
    assert signing.verify_file(signed, text, [ident.key_raw])


def test_signature_files_are_read_small(tmp_path):
    (tmp_path / "big.lsig").write_bytes(b"a" * (signing.MAX_TEXT + 1))
    with pytest.raises(LocksmithError, match="too large"):
        signing.read_small(tmp_path / "big.lsig")


# ── locksmith3 public keys ───────────────────────────────────────────────────

def test_locksmith3_keys_round_trip_and_encrypt_to_their_first_part(store, signer, tmp_path):
    ident, raw = signer
    text = ident.key_text
    assert text.startswith("locksmith3") and keys.decode_public(text) == ident.key_raw
    assert len(ident.key_raw) == keys.SIGNING_PUBLIC_LEN and ident.public.startswith("locksmith2")
    contact = store.add_contact("Alice", text)
    assert contact.can_verify and contact.public_raw == ident.public_raw
    blob = engine.encrypt_bytes(b"for alice", EncryptOptions(recipients=[contact.public_raw]))
    assert engine.decrypt_bytes(blob, DecryptKeys(identities=[raw])).data == b"for alice"
    with pytest.raises(LocksmithError, match="invalid"):   # the engine never takes a full locksmith3 key
        engine.encrypt_bytes(b"x", EncryptOptions(recipients=[contact.key_raw]))


def test_locksmith3_qr_code_holds_the_hash(signer):
    ident, _ = signer
    qr = keys.qr_text(ident.key_raw)
    assert qr.startswith("LOCKSMITH3:FP:") and len(qr) == 14 + 64
    assert qr[14:34] == keys.fingerprint(ident.key_raw).replace(" ", "")
    assert keys.qr_text(ident.public_raw) == ident.public   # locksmith2 keys still fit whole


def test_locksmith3_key_typos_are_caught(signer):
    ident, _ = signer
    text = ident.key_text
    with pytest.raises(LocksmithError, match="typo"):
        keys.decode_public(text[:2000] + ("A" if text[2000] != "A" else "B") + text[2001:])
    with pytest.raises(LocksmithError):
        keys.decode_public(text[:-10])


def test_contact_gains_signing_keys_only_from_the_same_identity(store, signer):
    ident, _ = signer
    old = store.add_contact("Alice", ident.public)   # shared before signing existed
    assert not old.can_verify
    with pytest.raises(LocksmithError, match="Update that contact"):
        store.add_contact("Alice again", ident.key_text)
    assert store.contact_with_encryption_key(ident.key_raw) is old
    store.update_contact_key(old, ident.key_text)
    assert old.can_verify and old.public == ident.key_text
    with pytest.raises(LocksmithError, match="already saved"):
        store.add_contact("Alice", ident.public)
    # Alice's encryption key with Mallory's signing keys: not Alice's identity.
    forged = keys.encode_public(ident.public_raw + store.generate("Mallory").verify_raw)
    with pytest.raises(LocksmithError, match="not made by the same identity"):
        store.add_contact("Alice?", forged)
    with pytest.raises(LocksmithError, match="not made by the same identity"):
        store.update_contact_key(old, forged)
    bob = store.add_contact("Bob", store.generate("Bob").public)
    with pytest.raises(LocksmithError, match="different key"):
        store.update_contact_key(bob, ident.key_text)


# ── signing keys in the key store ────────────────────────────────────────────

def test_identities_store_only_their_encryption_key(store, signer):
    ident, _ = signer
    data = json.loads(store.path.read_text(encoding="utf-8"))
    assert data["identities"][0]["public"].startswith("locksmith2")   # what older versions read
    assert base64.b64decode(data["identities"][0]["verify"]) == ident.verify_raw


def test_locked_identity_shows_its_full_key_from_the_cache(tmp_path):
    store = keys.KeyStore(tmp_path)
    ident = store.generate("Locked", passphrase="pass phrase")
    full = ident.key_text
    assert full.startswith("locksmith3")
    assert keys.KeyStore(tmp_path).identities[0].key_text == full


def test_cache_dropped_by_an_older_version_comes_back_on_unlock(tmp_path):
    store = keys.KeyStore(tmp_path)
    store.generate("Locked", passphrase="pass phrase")
    full = store.identities[0].key_text
    data = json.loads(store.path.read_text(encoding="utf-8"))
    del data["identities"][0]["verify"]   # an older version saved the file
    store.path.write_text(json.dumps(data), encoding="utf-8")
    again = keys.KeyStore(tmp_path)
    ident = again.identities[0]
    assert ident.key_text == ident.public and not again.problem
    again.remember_verify(ident, "pass phrase")
    assert ident.key_text == full and keys.KeyStore(tmp_path).identities[0].key_text == full


def test_unprotected_identity_rederives_a_missing_or_wrong_cache(tmp_path):
    store = keys.KeyStore(tmp_path)
    full = store.generate("Plain").key_text
    data = json.loads(store.path.read_text(encoding="utf-8"))
    for bad in (None, "not base64!", base64.b64encode(b"short").decode(),
                base64.b64encode(bytes(keys.VERIFY_LEN)).decode()):
        data["identities"][0]["verify"] = bad
        store.path.write_text(json.dumps(data), encoding="utf-8")
        loaded = keys.KeyStore(tmp_path)
        assert loaded.identities[0].key_text == full and not loaded.problem


def test_an_identity_stored_with_a_locksmith3_key_is_left_untouched(tmp_path, signer):
    ident, _ = signer
    store = keys.KeyStore(tmp_path)
    store.generate("ok")
    data = json.loads(store.path.read_text(encoding="utf-8"))
    data["identities"].append({**data["identities"][0], "public": ident.key_text})
    store.path.write_text(json.dumps(data), encoding="utf-8")
    loaded = keys.KeyStore(tmp_path)
    assert len(loaded.identities) == 1 and "could not be read" in loaded.problem
    loaded.save()
    assert len(json.loads(store.path.read_text(encoding="utf-8"))["identities"]) == 2


def test_backups_restore_the_signing_keys(store, signer, tmp_path):
    ident, raw = signer
    words = keys.backup_words(raw)
    other = keys.KeyStore(tmp_path / "other")
    assert other.restore("Alice", keys.private_from_words(" ".join(words))).key_text == ident.key_text
    path = tmp_path / "backup.json"
    store.export_identity(ident, path)
    assert "verify" not in json.loads(path.read_text(encoding="utf-8"))
    third = keys.KeyStore(tmp_path / "third")
    assert third.import_identity(path).key_text == ident.key_text


def test_imported_backup_cannot_supply_its_own_verify_keys(store, tmp_path):
    ident = store.generate("Locked", passphrase="pass phrase")
    path = tmp_path / "backup.json"
    store.export_identity(ident, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["verify"] = base64.b64encode(store.generate("Mallory").verify_raw).decode()
    path.write_text(json.dumps(data), encoding="utf-8")
    imported = keys.KeyStore(tmp_path / "other").import_identity(path)
    assert imported.key_text == imported.public   # unknown until unlocked, never taken from the file


def test_upgrade_adds_signing_keys(store, signed):
    ident = store.generate("old", post_quantum=False)
    store.upgrade(ident)
    assert ident.can_sign and ident.key_text.startswith("locksmith3")
    text = signing.sign_file(signed, ident.private_raw())
    assert signing.verify_file(signed, text, [ident.key_raw]).key == ident.key_raw
