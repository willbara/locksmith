"""A signed file's intended recipients (the "to" list, FORMAT.md §7): what Decrypt says about
the reader, and that the list can't be changed without breaking the signature."""

import base64
import hashlib
import json
import os

import fileformat
import pytest

from locksmith.core import engine, keys, signing
from locksmith.core.engine import KIND_RAW, KIND_SIG, AccessChange, DecryptKeys, EncryptOptions
from locksmith.core.errors import CorruptedError, LocksmithError

FAST = dict(kdf="pbkdf2-sha512", preset="fast")


@pytest.fixture(scope="module")
def people():
    """Alice signs; Bob and Carol are recipients; Dave isn't addressed."""
    out = {}
    for name in ("alice", "bob", "carol", "dave"):
        raw = os.urandom(96)
        out[name] = (raw, keys.public_from_private(raw))
    return out


def _addressed(people, to=("bob", "carol"), password="pw", **kw) -> bytes:
    return engine.encrypt_bytes(b"for you", EncryptOptions(
        password=password, recipients=[people[n][1] for n in to], signer=people["alice"][0], address_to=True,
        **FAST, **kw))


def _read(people, blob, who=None, password=None, own=()):
    verifiers = [signing.public_key(people["alice"][0])]
    identities = [people[who][0]] if who else []
    return engine.decrypt_bytes(blob, DecryptKeys(password=password, identities=identities, verifiers=verifiers,
                                                  own_keys=[people[n][1] for n in own]))


def test_the_list_holds_a_hash_of_each_recipients_encryption_key(people):
    blob = _addressed(people)
    meta = _read(people, blob, "bob").meta
    tags = {base64.b64decode(t) for t in meta["to"]}
    assert tags == {hashlib.sha256(b"locksmith/v2/recipient\x00" + people[n][1]).digest() for n in ("bob", "carol")}


def test_a_reader_on_the_list_gets_no_warning(people):
    res = _read(people, _addressed(people), "bob")
    assert res.signature.verified and res.intent == "listed"


def test_a_reader_left_off_the_list_is_told(people):
    """Someone who could open the file gave Dave a slot (the signature excludes slots): the
    file still verifies as signed by Alice, and Dave learns he wasn't on her list."""
    blob = _addressed(people)
    header, body = fileformat.split(blob)
    k = engine._unlock(header, fileformat.fixed_bytes(blob), DecryptKeys(identities=[people["bob"][0]]),
                       engine._Checker(None, None), engine.LOCKED_V2)
    header["slots"].append(engine._recipient_slot(people["dave"][1], k.dek, engine.LOCKED_V2))
    res = _read(people, fileformat.join(header, body), "dave")
    assert res.data == b"for you" and res.signature.verified and res.intent == "not_listed"


def test_a_reader_who_used_the_password_is_not_told_they_were_left_off(people):
    res = _read(people, _addressed(people), password="pw")
    assert res.intent == "password"
    # Whoever has a listed identity is on the list, however they opened the file.
    assert _read(people, _addressed(people), password="pw", own=("carol",)).intent == "listed"


def test_every_saved_identity_is_checked_not_only_the_one_that_opened_it(people):
    blob = _addressed(people, to=("bob",))
    forwarded_to = os.urandom(96)   # an identity the file was forwarded to, beside the reader's listed one
    header, body = fileformat.split(blob)
    k = engine._unlock(header, fileformat.fixed_bytes(blob), DecryptKeys(password="pw"), engine._Checker(None, None),
                       engine.LOCKED_V2)
    header["slots"].append(engine._recipient_slot(keys.public_from_private(forwarded_to), k.dek, engine.LOCKED_V2))
    forwarded = fileformat.join(header, body)
    res = engine.decrypt_bytes(forwarded, DecryptKeys(identities=[forwarded_to], own_keys=[people["bob"][1]],
                                                      verifiers=[signing.public_key(people["alice"][0])]))
    assert res.intent == "listed"


def test_without_a_list_nothing_is_said_about_intent(people):
    blob = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", recipients=[people["bob"][1]],
                                                     signer=people["alice"][0], **FAST))
    res = _read(people, blob, "dave", password="pw")
    assert res.signature.verified and res.intent is None and "to" not in res.meta


def test_an_unknown_signer_vouches_for_nothing(people):
    res = engine.decrypt_bytes(_addressed(people), DecryptKeys(password="pw"))   # Alice not saved
    assert not res.signature.verified and res.intent is None


def test_an_unsigned_file_with_a_list_is_ignored(people):
    """Anyone who can open a file can rewrite its metadata, so only a signature makes the list count."""
    opts = EncryptOptions(password="pw", chunk_size=4096, **FAST)
    meta = {"name": "x", "kind": "text", "comp": "none",
            "to": [base64.b64encode(engine.recipient_tag(people["bob"][1])).decode()]}
    blob = fileformat.forge(opts, meta, [engine.FRAME_HDR.pack(KIND_RAW, 1) + b"x"])
    assert _read(people, blob, password="pw", own=("bob",)).intent is None


def _head(meta):
    opts = EncryptOptions(password="pw", chunk_size=4096, **FAST)
    return engine._build_header(opts, meta, engine._Checker(None, None))


def _seal(head, frames) -> bytes:
    out = bytearray(head.preamble)
    prefix = base64.b64decode(json.loads(head.fixed)["np"])
    aad = hashlib.sha256(head.fixed).digest()
    for i, fr in enumerate(frames):
        ct = head.keys.cipher.seal(engine._nonce(prefix, i, i == len(frames) - 1), fr, aad)
        out += engine.U32.pack(len(ct)) + ct
    return bytes(out)


def _resigned_elsewhere(people, original_to: list, new_to: list | None) -> bytes:
    """A key holder writes a new file around Alice's signature: the same content and signature,
    the metadata's list changed (or removed when ``new_to`` is None)."""
    tag = lambda n: base64.b64encode(engine.recipient_tag(people[n][1])).decode()  # noqa: E731
    meta = {"name": "x", "kind": "text", "comp": "none", "to": [tag(n) for n in original_to]}
    original = _head(meta)
    sig = signing.sign_locked(people["alice"][0], original.fixed, hashlib.sha512(b"for you").digest())
    frames = [engine.FRAME_HDR.pack(KIND_RAW, 7) + b"for you", engine.FRAME_HDR.pack(KIND_SIG, len(sig)) + sig]
    assert _read(people, _seal(original, frames), password="pw").signature.verified
    altered = dict(meta)
    if new_to is None:
        del altered["to"]
    else:
        altered["to"] = new_to
    return _seal(_head(altered), frames)


def test_stripping_the_list_breaks_the_signature(people):
    with pytest.raises(CorruptedError, match="signature is invalid"):
        _read(people, _resigned_elsewhere(people, ["bob"], None), password="pw")


def test_altering_one_entry_breaks_the_signature(people):
    dave = base64.b64encode(engine.recipient_tag(people["dave"][1])).decode()
    with pytest.raises(CorruptedError, match="signature is invalid"):
        _read(people, _resigned_elsewhere(people, ["bob", "carol"], [dave, "x"]), password="pw")
    bob = base64.b64encode(engine.recipient_tag(people["bob"][1])).decode()
    with pytest.raises(CorruptedError, match="signature is invalid"):
        _read(people, _resigned_elsewhere(people, ["bob", "carol"], [bob, dave]), password="pw")


@pytest.mark.parametrize("to", [[], ["not base64!"], [base64.b64encode(b"short").decode()], "a string", [1],
                                [base64.b64encode(bytes(32)).decode()] * 65])
def test_a_malformed_list_says_nothing(people, to):
    """A signed but malformed list (the signer's software is broken) makes no claim either way."""
    meta = {"name": "x", "kind": "text", "comp": "none", "to": to}
    head = _head(meta)
    sig = signing.sign_locked(people["alice"][0], head.fixed, hashlib.sha512(b"x").digest())
    blob = _seal(head, [engine.FRAME_HDR.pack(KIND_RAW, 1) + b"x", engine.FRAME_HDR.pack(KIND_SIG, len(sig)) + sig])
    res = _read(people, blob, password="pw")
    assert res.signature.verified and res.intent is None


def test_writer_rules(people):
    with pytest.raises(LocksmithError, match="no key to list"):
        engine.encrypt_bytes(b"x", EncryptOptions(password="pw", signer=people["alice"][0], address_to=True, **FAST))
    with pytest.raises(LocksmithError, match="signed"):
        engine.encrypt_bytes(b"x", EncryptOptions(recipients=[people["bob"][1]], address_to=True, **FAST))


def test_the_list_survives_slot_changes_and_decoys_are_left_out(people, tmp_path):
    path = tmp_path / "f.locked"
    path.write_bytes(_addressed(people, to=("bob",), hide_recipients=True))
    meta = _read(people, path.read_bytes(), "bob").meta
    assert len(meta["to"]) == 1 and engine.inspect(path).recipient_slots == 8
    engine.change_access(path, DecryptKeys(identities=[people["bob"][0]]),
                         AccessChange(add_recipients=[people["dave"][1]]))
    assert _read(people, path.read_bytes(), "dave").intent == "not_listed"
    assert _read(people, path.read_bytes(), "bob").intent == "listed"


def test_files_and_folders_on_disk_report_intent(people, tmp_path):
    src = tmp_path / "doc.txt"
    src.write_text("hi", encoding="utf-8")
    opts = EncryptOptions(recipients=[people["bob"][1]], signer=people["alice"][0], address_to=True, **FAST)
    enc = engine.encrypt_paths([src], tmp_path / "enc", opts)
    keys_ = DecryptKeys(identities=[people["bob"][0]], verifiers=[signing.public_key(people["alice"][0])])
    assert engine.decrypt_path(enc, tmp_path / "dec", keys_).intent == "listed"
    assert engine.verify_path(enc, keys_).intent == "listed"
