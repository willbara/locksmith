"""Format version 2: the commitment over the fixed header, slots that change without
re-encrypting, and signed files (FORMAT.md §1–4, §15)."""

import base64
import hashlib
import json
import os
import struct

import fileformat
import pytest

from locksmith.core import engine, keys, signing
from locksmith.core.engine import KIND_PAD, KIND_RAW, KIND_SIG, DecryptKeys, EncryptOptions
from locksmith.core.errors import CorruptedError, LocksmithError, WrongKeyError

FAST = dict(kdf="pbkdf2-sha512", preset="fast")
PW = DecryptKeys(password="pw")


@pytest.fixture(scope="module")
def alice():
    raw = os.urandom(96)
    return raw, signing.public_key(raw)


def _frame(kind, block):
    return engine.FRAME_HDR.pack(kind, len(block)) + block


def _sig_frames(sig: bytes, chunk: int):
    return [_frame(KIND_SIG, sig[i:i + chunk]) for i in range(0, len(sig), chunk)]


def _head(meta=None, chunk=4096):
    opts = EncryptOptions(password="pw", chunk_size=chunk, **FAST)
    return engine._build_header(opts, meta or {"name": "x", "kind": "file", "comp": "none"},
                                engine._Checker(None, None))


def _seal(head, frames) -> bytes:
    """The file a holder of its key would write: ``head`` followed by ``frames``, sealed."""
    out = bytearray(head.preamble)
    prefix, aad = base64.b64decode(json.loads(head.fixed)["np"]), hashlib.sha256(head.fixed).digest()
    for i, fr in enumerate(frames):
        ct = head.keys.cipher.seal(engine._nonce(prefix, i, i == len(frames) - 1), fr, aad)
        out += struct.pack(">I", len(ct)) + ct
    return bytes(out)


def _password_dek(header: dict) -> bytes:
    """Unwrap a file's DEK as the holder of its password "pw" would."""
    slot = next(s for s in header["slots"] if s["t"] == "pw")
    kek = engine._password_kek("pw", None, base64.b64decode(slot["salt"]), slot["kdf"], slot["p"], engine.LOCKED_V2)
    return engine._unwrap(kek, base64.b64decode(slot["n"]), base64.b64decode(slot["w"]), b"pw", engine.LOCKED_V2)


# ── the fixed header and the slots ───────────────────────────────────────────

def test_new_files_are_version_2():
    blob = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", **FAST))
    assert blob[:8] == b"LOCKED\x00\x02" and fileformat.split(blob)[0]["v"] == 2


@pytest.mark.parametrize("field", ["np", "salt", "chunk", "suite", "meta"])
def test_changing_the_fixed_header_fails_at_unlock(field):
    """The commitment covers the fixed header, so tampering reads as a wrong key before any
    frame is read, instead of failing at the first chunk."""
    blob = engine.encrypt_bytes(b"x" * 5000, EncryptOptions(password="pw", **FAST))
    header, body = fileformat.split(blob)
    header[field] = {
        "np": base64.b64encode(os.urandom(7)).decode(),
        "salt": base64.b64encode(os.urandom(32)).decode(),
        "chunk": header["chunk"] // 2,
        "suite": "chacha20-poly1305" if header["suite"] != "chacha20-poly1305" else "aes-256-gcm",
        "meta": {**header["meta"], "n": base64.b64encode(os.urandom(12)).decode()},
    }[field]
    with pytest.raises(WrongKeyError):
        engine.decrypt_bytes(fileformat.join(header, body), PW)


def test_slots_change_without_re_encrypting(alice):
    """A key holder can give someone else access by adding a slot: the commitment and every
    frame stay as they are. (This is also what lets a signed file be forwarded.)"""
    bob = os.urandom(96)
    blob = engine.encrypt_bytes(b"for bob too", EncryptOptions(password="pw", signer=alice[0], **FAST))
    header, body = fileformat.split(blob)
    dek = _password_dek(header)
    header["slots"].append(engine._recipient_slot(keys.public_from_private(bob), dek, engine.LOCKED_V2))
    forwarded = fileformat.join(header, body)
    assert forwarded.endswith(body)
    r = engine.decrypt_bytes(forwarded, DecryptKeys(identities=[bob], verifiers=[alice[1]]))
    assert r.data == b"for bob too" and r.signature.key == alice[1]   # still signed by Alice
    header["slots"] = header["slots"][1:]   # and the password slot can go
    assert engine.decrypt_bytes(fileformat.join(header, body), DecryptKeys(identities=[bob])).data == b"for bob too"


def test_version_1_files_still_open(tmp_path):
    v1 = fileformat.forge(EncryptOptions(password="pw", chunk_size=1024, **FAST),
                          {"name": "old.txt", "kind": "file", "comp": "none"}, [_frame(KIND_RAW, b"old file")],
                          fmt=engine.LOCKED_V1)
    assert v1[:8] == b"LOCKED\x00\x01"
    res = engine.decrypt_bytes(v1, PW)
    assert res.data == b"old file" and res.signature is None


def test_version_1_files_cannot_carry_a_signature(alice):
    sig = signing.sign_locked(alice[0], b"{}", bytes(64))
    v1 = fileformat.forge(EncryptOptions(password="pw", chunk_size=4096, **FAST),
                          {"name": "x", "kind": "file", "comp": "none"},
                          [_frame(KIND_RAW, b"data"), *_sig_frames(sig, 4096)], fmt=engine.LOCKED_V1)
    with pytest.raises(CorruptedError, match="malformed"):
        engine.decrypt_bytes(v1, PW)


# ── signed files ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("chunk,padding", [(1024, "none"), (1024, "64k"), (1 << 20, "padme")])
def test_signed_file_round_trip(alice, chunk, padding):
    data = os.urandom(3000) + b"text" * 2000
    blob = engine.encrypt_bytes(data, EncryptOptions(password="pw", signer=alice[0], chunk_size=chunk,
                                                     padding=padding, compression="zlib", **FAST))
    res = engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=[os.urandom(3200), alice[1]]))
    assert res.data == data and res.signature.verified and res.signature.key == alice[1]
    assert res.signature.fingerprint == keys.fingerprint(alice[1])


def test_unknown_signer_still_opens(alice):
    blob = engine.encrypt_bytes(b"hi", EncryptOptions(password="pw", signer=alice[0], **FAST))
    res = engine.decrypt_bytes(blob, PW)   # Alice isn't a saved key
    assert res.data == b"hi" and not res.signature.verified
    assert res.signature.fingerprint == keys.fingerprint(alice[1])


def test_unsigned_files_report_no_signature(alice):
    blob = engine.encrypt_bytes(b"hi", EncryptOptions(password="pw", **FAST))
    assert engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=[alice[1]])).signature is None


def test_signed_files_and_folders_on_disk(tmp_path, alice):
    folder = tmp_path / "proj"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "a.txt").write_text("a", encoding="utf-8")
    keys_ = DecryptKeys(password="pw", verifiers=[alice[1]])
    for armor in (False, True):
        enc = engine.encrypt_paths([folder], tmp_path / f"enc{armor}", EncryptOptions(
            password="pw", signer=alice[0], armor=armor, **FAST), verify=True)
        res = engine.decrypt_path(enc, tmp_path / f"dec{armor}", keys_)
        assert (res.path / "sub" / "a.txt").read_text(encoding="utf-8") == "a" and res.signature.verified
        assert engine.verify_path(enc, keys_).signature.verified
    blob = engine.dearmor(enc.read_text(encoding="utf-8"))
    res = engine.decrypt_pasted(blob, tmp_path / "pasted", keys_)
    assert res.signature.verified


def test_classical_identities_cannot_sign():
    with pytest.raises(LocksmithError, match="Upgrade"):
        engine.encrypt_bytes(b"x", EncryptOptions(password="pw", signer=os.urandom(32), **FAST))


def _forged(alice, content: bytes, signed_content: bytes | None = None, *, sig: bytes | None = None,
            chunk=4096, meta=None, tamper=None):
    """A file made by someone holding its key: content we choose, plus a signature by Alice
    over ``signed_content`` (default: the same content) computed for this file's header,
    then passed through ``tamper``."""
    head = _head(meta, chunk)
    if sig is None:
        sig = signing.sign_locked(alice[0], head.fixed, hashlib.sha512(
            content if signed_content is None else signed_content).digest())
    if tamper:
        sig = tamper(sig, head)
    return _seal(head, [_frame(KIND_RAW, content), *_sig_frames(sig, chunk)])


def test_forged_signed_file_verifies(alice):
    blob = _forged(alice, b"genuine")
    assert engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=[alice[1]])).signature.verified


@pytest.mark.parametrize("case", ["content changed", "ml-dsa stripped", "ml-dsa zeroed", "ed25519 zeroed",
                                  "ml-dsa from another signature", "ed25519 from another signature",
                                  "comment added", "signed for another header", "too long"])
def test_invalid_signatures_fail_and_write_nothing(tmp_path, alice, case):
    good = signing.sign_locked(alice[0], b"other header", hashlib.sha512(b"genuine").digest())
    blob = {
        "content changed": lambda: _forged(alice, b"altered", b"genuine"),
        "ml-dsa stripped": lambda: _forged(alice, b"genuine", sig=good[:-3309]),
        # A valid signature for this very file, with one half spoiled: the other half alone must not do.
        "ml-dsa zeroed": lambda: _forged(alice, b"genuine", tamper=lambda sig, h: sig[:-3309] + bytes(3309)),
        "ed25519 zeroed": lambda: _forged(alice, b"genuine", tamper=lambda sig, h: sig[:51] + bytes(64) + sig[115:]),
        "ml-dsa from another signature": lambda: _forged(
            alice, b"genuine", tamper=lambda sig, h: sig[:-3309] + good[-3309:]),
        "ed25519 from another signature": lambda: _forged(
            alice, b"genuine", tamper=lambda sig, h: sig[:51] + good[51:115] + sig[115:]),
        "comment added": lambda: _forged(alice, b"genuine", sig=good[:49] + b"\x00\x01x" + good[51:]),
        "signed for another header": lambda: _forged(alice, b"genuine", sig=good),
        "too long": lambda: _forged(alice, b"genuine", sig=good + b"\x00"),
    }[case]()
    with pytest.raises(CorruptedError):
        engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=[alice[1]]))
    f = tmp_path / "evil.locked"
    f.write_bytes(blob)
    with pytest.raises(CorruptedError):
        engine.decrypt_path(f, tmp_path / "out", DecryptKeys(password="pw", verifiers=[alice[1]]))
    assert not list((tmp_path / "out").iterdir()), "nothing may be written"


def test_an_invalid_signature_fails_even_when_the_signer_is_unknown(alice):
    """A damaged signature is invalid whoever made it; only a well-formed one from an unsaved
    key is reported as 'unknown'."""
    good = signing.sign_locked(alice[0], b"h", hashlib.sha512(b"genuine").digest())
    with pytest.raises(CorruptedError):
        engine.decrypt_bytes(_forged(alice, b"genuine", sig=good[:-1]), PW)
    unknown = engine.decrypt_bytes(_forged(alice, b"genuine", sig=good), PW)   # not checkable: unknown key
    assert not unknown.signature.verified


def test_signature_frames_must_come_last(alice):
    head = _head()
    sig = signing.sign_locked(alice[0], head.fixed, hashlib.sha512(b"genuine").digest())
    assert engine.decrypt_bytes(_seal(head, [_frame(KIND_RAW, b"genuine"), _frame(KIND_PAD, b""),
                                             _frame(KIND_SIG, sig)]), PW).signature   # content, padding, signature
    for frames in ([_frame(KIND_SIG, sig), _frame(KIND_RAW, b"genuine")],
                   [_frame(KIND_RAW, b"genuine"), _frame(KIND_SIG, sig), _frame(KIND_PAD, b"")]):
        with pytest.raises(CorruptedError, match="malformed"):
            engine.decrypt_bytes(_seal(head, frames), PW)


def test_a_rewritten_note_breaks_the_signature(alice):
    """The note and name are signed. A key holder can write a whole new file around Alice's
    signature (new header, re-sealed frames, the same content), but not keep it valid."""
    meta = {"name": "invoice.txt", "kind": "file", "comp": "none", "note": "from Alice"}
    original = _head(meta)
    sig = signing.sign_locked(alice[0], original.fixed, hashlib.sha512(b"pay 10").digest())
    keys_ = DecryptKeys(password="pw", verifiers=[alice[1]])
    assert engine.decrypt_bytes(_seal(original, [_frame(KIND_RAW, b"pay 10"), _frame(KIND_SIG, sig)]),
                                keys_).signature.verified
    rewritten = _head({**meta, "note": "from Mallory"})
    with pytest.raises(CorruptedError, match="signature is invalid"):
        engine.decrypt_bytes(_seal(rewritten, [_frame(KIND_RAW, b"pay 10"), _frame(KIND_SIG, sig)]), keys_)
