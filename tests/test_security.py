"""Adversarial tests: crafted files, malicious senders, bad options and damaged config.

The invariant throughout: hostile input may only ever produce a LocksmithError,
never a crash, a write outside the chosen folder, or partial plaintext on disk.
"""

import base64
import dataclasses
import errno
import hashlib
import io
import json
import os
import random
import shutil
import stat
import struct
import sys
import tarfile
import time
from pathlib import Path

import fileformat
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from locksmith.core import compress, engine, kdf, keys, osutil, tools
from locksmith.core.engine import DecryptKeys, EncryptOptions
from locksmith.core.errors import CorruptedError, LocksmithError, WrongKeyError

FAST = dict(kdf="pbkdf2-sha512", preset="fast")
PW = DecryptKeys(password="pw")


def _encrypt(tmp_path, data=b"secret data " * 1000, **kw) -> Path:
    src = tmp_path / "plain.txt"
    src.write_bytes(data)
    opts = EncryptOptions(password="pw", **{**FAST, **kw})
    return engine.encrypt_paths([src], tmp_path / "enc", opts)


_split, _join = fileformat.split, fileformat.join


def _assert_rejected(tmp_path, blob: bytes, keys=PW):
    f = tmp_path / "evil.locked"
    f.write_bytes(blob)
    out = tmp_path / "out"
    with pytest.raises(LocksmithError):
        engine.decrypt_path(f, out, keys)
    assert not out.exists() or not any(out.iterdir()), "nothing may be written on failure"


# ── crafted & fuzzed files ───────────────────────────────────────────────────

MUTATIONS = [
    lambda h: h.update(v=1),   # contradicts the version in the signature
    lambda h: h.update(v=3),
    lambda h: h.update(extra=1),   # a version 2 fixed header has exactly its fields
    lambda h: h.update(chunk=True),
    lambda h: h.update(chunk=-1),
    lambda h: h.update(chunk=10**12),
    lambda h: h.update(chunk="1048576"),
    lambda h: h.update(suite="rot13"),
    lambda h: h.update(suite=["aes-256-gcm"]),
    lambda h: h.update(np=base64.b64encode(b"123").decode()),
    lambda h: h.update(np=123),
    lambda h: h.update(salt="!!notbase64!!"),
    lambda h: h.update(kc=base64.b64encode(bytes(31)).decode()),
    lambda h: h.update(slots=[]),
    lambda h: h.update(slots={}),
    lambda h: h.update(slots=[h["slots"][0]] * 65),
    lambda h: h.update(meta=None),
    lambda h: h.update(meta={"n": h["meta"]["n"]}),
    lambda h: h["slots"][0].update(t="rsa"),
    lambda h: h["slots"][0].update(kdf="md5"),
    lambda h: h["slots"][0].update(kdf=["argon2id"]),
    lambda h: h["slots"][0].update(p={"i": 10**9}),
    lambda h: h["slots"][0].update(p={"i": 0}),
    lambda h: h["slots"][0].update(p={"i": True}),
    lambda h: h["slots"][0].update(p={"i": 1000, "extra": 1}),
    lambda h: h["slots"][0].update(p=[1]),
    lambda h: h["slots"][0].update(kdf="argon2id", p={"m": 8 << 20, "t": 3, "p": 4}),
    lambda h: h["slots"][0].update(kdf="argon2id", p={"m": 8, "t": 1, "p": 4}),
    lambda h: h["slots"][0].update(kdf="scrypt", p={"n": 2**21, "r": 16, "p": 1}),
    lambda h: h["slots"][0].update(kdf="scrypt", p={"n": 1000, "r": 8, "p": 1}),
    lambda h: h["slots"][0].update(n=base64.b64encode(bytes(8)).decode()),
    lambda h: h["slots"][0].update(w=base64.b64encode(bytes(10)).decode()),
    lambda h: h["slots"][0].update(salt=None),
    lambda h: h["slots"][0].update(kf="yes"),
    lambda h: h["slots"].__setitem__(0, "slot"),
    lambda h: h["slots"].__setitem__(0, {"t": "x25519", "n": h["slots"][0]["n"], "w": h["slots"][0]["w"],
                                         "epk": base64.b64encode(bytes(32)).decode()}),
]


@pytest.mark.parametrize("mutate", range(len(MUTATIONS)))
def test_crafted_headers_rejected_cleanly(tmp_path, mutate):
    header, body = _split(_encrypt(tmp_path).read_bytes())
    MUTATIONS[mutate](header)
    _assert_rejected(tmp_path, _join(header, body))
    try:  # inspecting may succeed on structurally valid headers, but must never crash
        engine.inspect_bytes(_join(header, body))
    except LocksmithError:
        pass


@pytest.mark.parametrize("raw", [b"", b"LOCKED", b"LOCKED\x00\x01", b"LOCKED\x00\x01\xff\xff\xff\xff",
                                 b"LOCKED\x00\x01\x00\x00\x00\x02[]", b"LOCKED\x00\x01\x00\x00\x00\x04null",
                                 b"LOCKED\x00\x01\x00\x00\x00\x03\xff\xfe\x00", b"LOCKED\x00\x09" + bytes(8),
                                 b"PK\x03\x04" + bytes(100)])
def test_garbage_files(tmp_path, raw):
    _assert_rejected(tmp_path, raw)


def test_random_bitflips_never_crash(tmp_path):
    """Flip bytes all over a valid file: every result must be a clean rejection."""
    blob = _encrypt(tmp_path, os.urandom(50_000), chunk_size=4096, compression="zlib").read_bytes()
    rng = random.Random(1234)
    for i in range(300):
        evil = bytearray(blob)
        for _ in range(rng.randint(1, 4)):
            evil[rng.randrange(len(evil))] ^= 1 << rng.randrange(8)
        d = tmp_path / f"case{i}"
        d.mkdir()
        _assert_rejected(d, bytes(evil))


def test_random_truncations_never_crash(tmp_path):
    blob = _encrypt(tmp_path, os.urandom(20_000), chunk_size=4096).read_bytes()
    for i, cut in enumerate(sorted(random.Random(7).sample(range(1, len(blob)), 60))):
        d = tmp_path / f"cut{i}"
        d.mkdir()
        _assert_rejected(d, blob[:cut])


def test_slot_flood_caps_kdf_work(tmp_path, monkeypatch):
    header, body = _split(_encrypt(tmp_path).read_bytes())
    pw_slot = header["slots"][0]
    header["slots"] = [dict(pw_slot) for _ in range(64)]
    calls = []
    real = kdf.derive
    monkeypatch.setattr(engine.kdfmod, "derive", lambda *a: (calls.append(1), real(*a))[1])
    _assert_rejected(tmp_path, _join(header, body), DecryptKeys(password="wrong"))
    assert len(calls) == engine.MAX_PASSWORD_ATTEMPTS


def test_armored_garbage(tmp_path):
    for text in ("", "hello", engine.ARMOR_BEGIN, f"{engine.ARMOR_BEGIN}\n@@@\n{engine.ARMOR_END}",
                 f"{engine.ARMOR_BEGIN}\nQUJD\n{engine.ARMOR_END}"):
        with pytest.raises(LocksmithError):
            engine.decrypt_bytes(engine.dearmor(text), PW)


# ── malicious sender (holds a valid key, crafts the plaintext) ───────────────

def _forge(tmp_path, frames: list[bytes], meta: dict, chunk=4096, meta_raw: bytes | None = None) -> Path:
    """Build a correctly encrypted file whose frames and metadata we choose.
    ``meta_raw`` replaces the encrypted metadata with arbitrary bytes."""
    opts = EncryptOptions(password="pw", chunk_size=chunk, **FAST)
    path = tmp_path / "forged.locked"
    path.write_bytes(fileformat.forge(opts, meta, frames, meta_raw))
    return path


def _frame(kind, block):
    return engine.FRAME_HDR.pack(kind, len(block)) + block


@pytest.mark.parametrize("codec", list(compress.CODECS))
def test_decompression_bomb_rejected(tmp_path, codec):
    bomb = compress.CODECS[codec].compress(bytes(64 << 20), 1)
    evil = _forge(tmp_path, [_frame(engine.KIND_COMPRESSED, bomb)],
                  {"name": "x", "kind": "file", "comp": codec}, chunk=max(4096, len(bomb) + 64))
    with pytest.raises(CorruptedError, match="expands"):
        engine.decrypt_path(evil, tmp_path / "out", PW)


@pytest.mark.parametrize("frame", [b"", b"\x01", _frame(9, b"abc"),
                                   engine.FRAME_HDR.pack(0, 999) + b"short",
                                   _frame(engine.KIND_COMPRESSED, b"not compressed data")])
def test_malformed_frames(tmp_path, frame):
    evil = _forge(tmp_path, [frame], {"name": "x", "kind": "file", "comp": "zlib"})
    _assert_rejected(tmp_path, evil.read_bytes())


PAD0 = engine.FRAME_HDR.pack(engine.KIND_PAD, 0)


@pytest.mark.parametrize("frames", [
    [_frame(engine.KIND_RAW, b"data"), _frame(engine.KIND_PAD, b"hidden")],     # pad frame carrying data
    [_frame(engine.KIND_PAD, b"hidden")],
    [_frame(engine.KIND_RAW, b"data") + b"\x00\x00\x01"],                         # non-zero padding bytes
    [_frame(engine.KIND_RAW, b"data"), PAD0 + bytes(8) + b"\xff"],
    [_frame(engine.KIND_RAW, b"a"), PAD0 + bytes(16), _frame(engine.KIND_RAW, b"b")],  # data after padding
    [_frame(engine.KIND_RAW, b"a"), PAD0, PAD0, _frame(engine.KIND_RAW, b"")],
], ids=["pad-with-data", "only-pad-with-data", "nonzero-tail", "nonzero-pad", "data-after-pad",
        "empty-data-after-pad"])
def test_padding_is_validated(tmp_path, frames):
    evil = _forge(tmp_path, frames, {"name": "x", "kind": "file", "comp": "none"})
    _assert_rejected(tmp_path, evil.read_bytes())


def test_valid_padding_is_accepted(tmp_path):
    ok = _forge(tmp_path, [_frame(engine.KIND_RAW, b"da"), _frame(engine.KIND_RAW, b"ta") + bytes(100),
                           PAD0 + bytes(4000), PAD0],
                {"name": "x", "kind": "file", "comp": "none"})
    assert engine.decrypt_path(ok, tmp_path / "out", PW).path.read_bytes() == b"data"


@pytest.mark.parametrize("pad", list(engine.PADDING))
def test_every_padding_mode_decrypts_with_many_pad_frames(tmp_path, pad):
    data = os.urandom(5000)
    enc = _encrypt(tmp_path, data, chunk_size=engine.MIN_CHUNK, padding=pad)
    assert engine.decrypt_path(enc, tmp_path / "out", PW).path.read_bytes() == data


def test_deeply_nested_header_is_reported_as_damage():
    raw = b"[" * 200_000
    with pytest.raises(CorruptedError):
        engine.inspect_bytes(engine.MAGIC + bytes(32) + struct.pack(">I", len(raw)) + raw)


def test_deeply_nested_metadata_is_reported_as_damage(tmp_path):
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, b"x")], {}, meta_raw=b"[" * 200_000)
    with pytest.raises(CorruptedError):
        engine.decrypt_path(evil, tmp_path / "out", PW)
    with pytest.raises(CorruptedError):
        engine.decrypt_bytes(evil.read_bytes(), PW)


@pytest.mark.parametrize("name", ["../../escape.txt", "/etc/passwd", "..", ".", "", "a/../../b",
                                  "..\\..\\win.txt", "nul\x00byte", 12345, None, ["x"], "x" * 1000])
def test_hostile_names_stay_in_output_folder(tmp_path, name):
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, b"payload")],
                  {"name": name, "kind": "file", "comp": "none", "mtime": "yesterday"})
    out = tmp_path / "out"
    res = engine.decrypt_path(evil, out, PW)
    assert res.path.parent == out and res.path.read_bytes() == b"payload"
    assert len(res.path.name) <= 255
    assert {p.name for p in tmp_path.iterdir()} == {"forged.locked", "out"}


@pytest.mark.parametrize("meta", ["string", [1, 2], 42, None])
def test_metadata_must_be_object(tmp_path, meta):
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, b"x")], meta)
    _assert_rejected(tmp_path, evil.read_bytes())


def test_hostile_archive_contents(tmp_path):
    """Traversal, absolute paths, links out and device nodes are dropped; the rest extracts."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(name, data=b"", **kw):
            info = tarfile.TarInfo(name)
            for k, v in kw.items():
                setattr(info, k, v)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        add("folder/good.txt", b"fine")
        add("folder/../../escape.txt", b"bad")
        add("/tmp/absolute.txt", b"bad")
        add("folder/link-out", type=tarfile.SYMTYPE, linkname="/etc/passwd")
        add("folder/link-up", type=tarfile.SYMTYPE, linkname="../../../../etc")
        add("folder/hard-out", type=tarfile.LNKTYPE, linkname="/etc/passwd")
        add("folder/dev", type=tarfile.CHRTYPE, devmajor=1, devminor=3)
        add("folder/suid.sh", b"#!/bin/sh", mode=0o4755)
    data = buf.getvalue()
    frames = [_frame(engine.KIND_RAW, data[i:i + 4096]) for i in range(0, len(data), 4096)]
    evil = _forge(tmp_path, frames, {"name": "folder", "kind": "dir", "comp": "none"})
    out = tmp_path / "out"
    res = engine.decrypt_path(evil, out, PW)
    assert (res.path / "good.txt").read_text() == "fine"
    assert not (res.path / "suid.sh").stat().st_mode & stat.S_ISUID
    for bad in ("link-out", "link-up", "hard-out", "dev"):
        assert not (res.path / bad).exists() and not (res.path / bad).is_symlink()
    assert len(res.skipped) >= 5
    assert not (tmp_path / "escape.txt").exists() and not Path("/tmp/absolute.txt").exists()


def test_folder_with_absolute_symlink_still_recoverable(tmp_path, needs_symlinks):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "data.txt").write_text("keep me")
    (src / "abs-link").symlink_to("/usr/bin")
    (src / "rel-link").symlink_to("data.txt")
    enc = engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(password="pw", **FAST))
    res = engine.decrypt_path(enc, tmp_path / "d", PW)
    assert (res.path / "data.txt").read_text() == "keep me"
    assert (res.path / "rel-link").read_text() == "keep me"
    assert res.skipped == ["proj/abs-link"]
    assert not res.complete  # the source is the only copy of the skipped link


@pytest.mark.parametrize("kind", ["file", "dir", "bundle"])
def test_decrypt_complete_only_when_restored_and_flushed(tmp_path, monkeypatch, kind):
    src = tmp_path / "src"
    (src / "folder" / "sub").mkdir(parents=True)
    (src / "folder" / "sub" / "a.txt").write_text("a", encoding="utf-8")
    (src / "b.txt").write_text("b", encoding="utf-8")
    paths = {"file": [src / "b.txt"], "dir": [src / "folder"], "bundle": [src / "folder", src / "b.txt"]}[kind]
    enc = engine.encrypt_paths(paths, tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    assert engine.decrypt_path(enc, tmp_path / "ok", PW).complete
    monkeypatch.setattr(engine, "fsync_dir", lambda p: False)
    assert not engine.decrypt_path(enc, tmp_path / "no-dir-sync", PW).complete
    if kind != "file":
        monkeypatch.setattr(engine, "fsync_dir", lambda p: True)
        monkeypatch.setattr(engine, "fsync_tree", lambda p: False)
        assert not engine.decrypt_path(enc, tmp_path / "no-tree-sync", PW).complete


def test_extracted_files_and_folders_are_flushed(tmp_path, monkeypatch):
    synced = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(os.fstat(fd).st_ino), real_fsync(fd))[1])
    archive = _tar(tmp_path, [("d", None), ("d/x.txt", b"x"), ("d/e", None), ("d/e/y.txt", b"y")])
    out = tmp_path / "out"
    ext = engine.extract_archive(archive, out)
    assert ext.flushed and not ext.skipped and not ext.renamed
    expected = [out, out / "d", out / "d" / "x.txt", out / "d" / "e", out / "d" / "e" / "y.txt"]
    if osutil.IS_WINDOWS:  # folders can't be fsynced there
        expected = [p for p in expected if p.is_file()]
    assert {p.stat().st_ino for p in expected} <= set(synced)


def test_members_outside_the_top_folder_block_complete(tmp_path):
    """A crafted "dir" file with entries beside its top folder: those are discarded, so reported."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in ("folder/a.txt", "stray.txt", "/abs.txt"):
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    data = buf.getvalue()
    frames = [_frame(engine.KIND_RAW, data[i:i + 4096]) for i in range(0, len(data), 4096)]
    evil = _forge(tmp_path, frames, {"name": "folder", "kind": "dir", "comp": "none"})
    res = engine.decrypt_path(evil, tmp_path / "out", PW)
    assert (res.path / "a.txt").read_bytes() == b"x"
    assert "stray.txt" in res.skipped and not res.complete


# ── option validation: nothing unreadable may ever be written ────────────────

@pytest.mark.parametrize("bad", [
    dict(suite="des"), dict(kdf="md5"), dict(preset="none"), dict(compression="rar"),
    dict(level="ultra"), dict(chunk_size=0), dict(chunk_size=1023), dict(chunk_size=(64 << 20) + 1),
    dict(chunk_size=True), dict(chunk_size=1.5), dict(padding="random"), dict(threads=-1),
    dict(threads=10_000), dict(recipients=[b"short"]), dict(recipients=[bytes(32)]),
    dict(password=None), dict(password=""),
])
def test_invalid_options_rejected_before_writing(tmp_path, bad):
    src = tmp_path / "f.txt"
    src.write_text("data")
    opts = EncryptOptions(password="pw", **FAST)
    for k, v in bad.items():
        setattr(opts, k, v)
    with pytest.raises(LocksmithError):
        engine.encrypt_paths([src], tmp_path / "out", opts)
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").iterdir())
    assert src.read_text() == "data"


def _recipients(n: int) -> tuple[list[bytes], list[bytes]]:
    """n classical key pairs as (private, public) raw bytes."""
    privs = [X25519PrivateKey.generate() for _ in range(n)]
    return [p.private_bytes_raw() for p in privs], [p.public_key().public_bytes_raw() for p in privs]


def _no_output(folder: Path) -> bool:
    return not folder.exists() or not any(folder.iterdir())


def test_too_many_slots_refused_before_writing(tmp_path):
    """The reader accepts at most MAX_SLOTS slots, so the writer must never make more."""
    src = tmp_path / "f.txt"
    src.write_text("data", encoding="utf-8")
    privs, pubs = _recipients(engine.MAX_SLOTS)
    with pytest.raises(LocksmithError, match="64"):
        engine.encrypt_paths([src], tmp_path / "out", EncryptOptions(password="pw", recipients=pubs, **FAST))
    assert _no_output(tmp_path / "out")
    with pytest.raises(LocksmithError):
        engine.encrypt_bytes(b"x", EncryptOptions(password="pw", recipients=pubs, **FAST))

    # Right at the limit: 63 recipients plus a password, or 64 recipients alone.
    for i, opts in enumerate((EncryptOptions(password="pw", recipients=pubs[:-1], **FAST),
                              EncryptOptions(recipients=pubs, **FAST))):
        enc = engine.encrypt_paths([src], tmp_path / f"ok{i}", opts)
        assert engine.inspect(enc).recipient_slots == len(opts.recipients)
        res = engine.decrypt_path(enc, tmp_path / f"dec{i}", DecryptKeys(identities=[privs[-2]]))
        assert res.path.read_text(encoding="utf-8") == "data"


def test_duplicate_recipients_share_one_slot(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("data", encoding="utf-8")
    privs, pubs = _recipients(2)
    # Duplicates don't count towards the limit either.
    opts = EncryptOptions(password="pw", recipients=[pubs[0]] * engine.MAX_SLOTS + [pubs[1]], **FAST)
    enc = engine.encrypt_paths([src], tmp_path / "out", opts)
    assert engine.inspect(enc).recipient_slots == 2
    for priv in privs:
        assert engine.decrypt_bytes(enc.read_bytes(), DecryptKeys(identities=[priv])).data == b"data"


def test_oversized_header_refused_before_writing(tmp_path):
    """A note that pushes the header past MAX_HEADER would make an unreadable file."""
    src = tmp_path / "f.txt"
    src.write_text("data", encoding="utf-8")
    opts = EncryptOptions(password="pw", note="n" * engine.MAX_HEADER, **FAST)
    with pytest.raises(LocksmithError, match="note"):
        engine.encrypt_paths([src], tmp_path / "out", opts)
    assert _no_output(tmp_path / "out")
    with pytest.raises(LocksmithError, match="note"):
        engine.encrypt_bytes(b"x", opts)
    # A long note that still fits is fine.
    opts.note = "n" * (engine.MAX_HEADER // 2)
    enc = engine.encrypt_paths([src], tmp_path / "out", opts)
    assert engine.decrypt_path(enc, tmp_path / "dec", PW).meta["note"] == opts.note


def test_writer_runs_reader_checks_on_its_header(monkeypatch):
    """Any future mismatch between writer and reader fails before anything is written."""
    monkeypatch.setattr(engine, "_check_header", lambda h, fmt: (_ for _ in ()).throw(ValueError()))
    with pytest.raises(LocksmithError):
        engine.encrypt_bytes(b"x", EncryptOptions(password="pw", **FAST))


def test_keyfile_rules(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("data")
    empty, tiny, good = tmp_path / "empty", tmp_path / "tiny", tmp_path / "good"
    empty.write_bytes(b"")
    tiny.write_bytes(b"123")
    good.write_bytes(os.urandom(64))
    for kf, pw in ((empty, "pw"), (empty, None), (tiny, None), (tmp_path / "missing", "pw")):
        with pytest.raises(LocksmithError):
            engine.encrypt_paths([src], tmp_path / "o", EncryptOptions(password=pw, keyfile=str(kf), **FAST))
    engine.encrypt_paths([src], tmp_path / "o", EncryptOptions(password="pw", keyfile=str(tiny), **FAST))
    enc = engine.encrypt_paths([src], tmp_path / "o", EncryptOptions(keyfile=str(good), **FAST))
    assert engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(keyfile=str(good))).path.read_text() == "data"


def test_output_inside_source_folder_refused(tmp_path):
    src = tmp_path / "docs"
    (src / "nested").mkdir(parents=True)
    (src / "a.txt").write_text("a")
    for out in (src, src / "nested", src / "new-sub"):
        with pytest.raises(LocksmithError, match="inside"):
            engine.encrypt_paths([src], out, EncryptOptions(password="pw", **FAST))
    assert sorted(p.name for p in src.iterdir()) == ["a.txt", "nested"]


def test_verify_catches_corruption_on_disk(tmp_path, monkeypatch):
    real = engine.create_private

    class Corrupting(io.RawIOBase):
        def __init__(self, f):
            self.f, self.n = f, 0

        def write(self, b):
            b = bytearray(b)
            if self.n <= 3000 < self.n + len(b):
                b[3000 - self.n] ^= 0xFF
            self.n += len(b)
            return self.f.write(bytes(b))

        def fileno(self):
            return self.f.fileno()

        def flush(self):
            self.f.flush()

        def close(self):
            self.f.close()

    monkeypatch.setattr(engine, "create_private", lambda p: Corrupting(real(p)))
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(10_000))
    with pytest.raises(CorruptedError):
        engine.encrypt_paths([src], tmp_path / "out", EncryptOptions(password="pw", **FAST), verify=True)
    assert not any((tmp_path / "out").iterdir()), "an unverified file must not be kept"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows uses inherited access lists, not mode bits")
def test_decrypted_output_is_private(tmp_path):
    enc = _encrypt(tmp_path)
    res = engine.decrypt_path(enc, tmp_path / "d", PW)
    assert stat.S_IMODE(res.path.stat().st_mode) == 0o600


def test_create_private_never_follows_or_reuses(tmp_path, needs_symlinks):
    target = tmp_path / "victim"
    target.write_text("original")
    link = tmp_path / "planted"
    link.symlink_to(target)
    for path in (link, target):
        with pytest.raises(FileExistsError):
            engine.create_private(path)
    assert target.read_text() == "original"


def test_unicode_password_normalisation(tmp_path):
    nfc, nfd = "café-pässwörd", "café-pässwörd"
    src = tmp_path / "f"
    src.write_text("x")
    enc = engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(password=nfc, **FAST))
    assert engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password=nfd)).path.read_text() == "x"


def test_fresh_randomness_per_file(tmp_path):
    a, b = (_split(_encrypt(tmp_path / str(i)).read_bytes())[0] for i in range(2)
            if not (tmp_path / str(i)).mkdir())
    for field in ("np", "salt", "kc"):
        assert a[field] != b[field]
    assert a["slots"][0]["salt"] != b["slots"][0]["salt"]


def test_recipient_only_rejects_passwords(tmp_path):
    store = keys.KeyStore(tmp_path / "cfg")
    ident = store.generate("me")
    src = tmp_path / "f"
    src.write_text("x")
    enc = engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(recipients=[ident.public_raw], **FAST))
    with pytest.raises(WrongKeyError):
        engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password="guess"))


# ── key pairs & key store ────────────────────────────────────────────────────

@pytest.mark.parametrize("content", ["not json", "[]", "null", '{"identities": "x"}',
                                     '{"identities": [1, {"name": 5}], "contacts": [{}]}'])
def test_damaged_keystore_never_crashes_or_loses_data(tmp_path, content):
    d = tmp_path / "cfg"
    d.mkdir()
    (d / "keys.json").write_text(content)
    store = keys.KeyStore(d)
    assert store.problem
    store.generate("new")
    saved = json.loads((d / "keys.json").read_text())
    if content.startswith('{"identities": [1'):
        assert 1 in saved["identities"] and {"name": 5} in saved["identities"]
    elif content == '{"identities": "x"}':
        assert "x" in saved["identities"]
    else:
        assert any(p.name.startswith("keys.json.unreadable-") for p in d.iterdir()) or content.startswith("{")


def test_keystore_tolerates_newer_fields(tmp_path):
    store = keys.KeyStore(tmp_path)
    store.generate("me")
    data = json.loads(store.path.read_text())
    data["identities"][0]["future_field"] = True
    store.path.write_text(json.dumps(data))
    again = keys.KeyStore(tmp_path)
    assert again.problem is None and again.identities[0].name == "me"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows uses inherited access lists, not mode bits")
def test_keystore_file_permissions(tmp_path):
    store = keys.KeyStore(tmp_path / "cfg")
    store.generate("me")
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    out = tmp_path / "backup.json"
    store.export_identity(store.identities[0], out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert not [p for p in store.dir.iterdir() if p.name.endswith(".tmp")]


def test_export_over_symlink_does_not_write_through(tmp_path, needs_symlinks):
    store = keys.KeyStore(tmp_path / "cfg")
    store.generate("me")
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    link = tmp_path / "export.json"
    link.symlink_to(victim)
    store.export_identity(store.identities[0], link)
    assert victim.read_text() == "untouched" and not link.is_symlink()


def test_import_rejects_mismatched_keypair(tmp_path):
    store = keys.KeyStore(tmp_path / "a")
    a, b = store.generate("a"), store.generate("b")
    backup = tmp_path / "backup.json"
    store.export_identity(a, backup)
    data = json.loads(backup.read_text())
    data["public"] = b.public  # someone else's public key with my private key
    backup.write_text(json.dumps(data))
    with pytest.raises(LocksmithError):
        keys.KeyStore(tmp_path / "b").import_identity(backup)


@pytest.mark.parametrize("content", ["{}", "[]", '{"locksmith-identity": 1}', '{"locksmith-identity": 2}',
                                     "garbage", '{"locksmith-identity": 1, "name": "x", "public": "locksmith1AAAA",'
                                     ' "created": 0}',
                                     pytest.param("[" * 200_000, id="deeply-nested")])
def test_import_garbage(tmp_path, content):
    f = tmp_path / "b.json"
    f.write_text(content)
    with pytest.raises(LocksmithError):
        keys.KeyStore(tmp_path / "cfg").import_identity(f)


def test_locked_identity_checks_pair_on_unlock(tmp_path):
    store = keys.KeyStore(tmp_path)
    a = store.generate("a", passphrase="secret")
    b = store.generate("b")
    a.public = b.public
    with pytest.raises(LocksmithError, match="does not match"):
        a.private_raw("secret")


def test_identity_passphrase_unicode(tmp_path):
    ident = keys.KeyStore(tmp_path).generate("u", passphrase="päss")
    assert ident.private_raw("päss")


def test_damaged_identity_does_not_block_others(tmp_path):
    store = keys.KeyStore(tmp_path)
    good = store.generate("good")
    bad = store.generate("bad")
    bad.private = "!!!"
    assert store.unlocked_private_keys() == [good.private_raw()]


def _fake_tpm(monkeypatch):
    """A reversible stand-in for systemd-creds, so sealing is testable without a TPM."""
    monkeypatch.setattr(keys, "tpm_seal", lambda data: b"SEALED:" + data)
    monkeypatch.setattr(keys, "tpm_unseal", lambda blob: blob.removeprefix(b"SEALED:"))


def _refuse(*_):
    raise LocksmithError("The TPM refused the request.")


@pytest.mark.parametrize("fail", ["seal", "unseal-check", "save"])
@pytest.mark.parametrize("passphrase", [None, "pass"])
def test_failed_upgrade_of_sealed_identity_changes_nothing(tmp_path, monkeypatch, fail, passphrase):
    """A sealed identity whose upgrade fails must never end up stored unsealed."""
    _fake_tpm(monkeypatch)
    store = keys.KeyStore(tmp_path)
    ident = store.seal(store.generate("me", passphrase=passphrase, post_quantum=False))
    before = dataclasses.asdict(ident)
    if fail == "seal":
        monkeypatch.setattr(keys, "tpm_seal", _refuse)
    elif fail == "unseal-check":   # the TPM seals, but does not give the same data back
        monkeypatch.setattr(keys, "tpm_seal", lambda data: b"BROKEN:" + data)
    else:
        monkeypatch.setattr(keys, "write_secret_file", lambda *a: _refuse())
    with pytest.raises(LocksmithError):
        store.upgrade(ident, passphrase)
    assert dataclasses.asdict(ident) == before
    assert ident.sealed and ident.private is None and ident.locked is None and not ident.is_post_quantum

    monkeypatch.undo()
    _fake_tpm(monkeypatch)
    store.add_contact("Friend", keys.KeyStore(tmp_path / "f").generate("f").public)
    reloaded = keys.KeyStore(tmp_path).identities[0]
    assert dataclasses.asdict(reloaded) == before
    assert reloaded.private_raw(passphrase)


@pytest.mark.parametrize("passphrase", [None, "pass"])
def test_upgrade_of_sealed_identity_stays_sealed(tmp_path, monkeypatch, passphrase):
    _fake_tpm(monkeypatch)
    store = keys.KeyStore(tmp_path)
    ident = store.seal(store.generate("me", passphrase=passphrase, post_quantum=False))
    x25519 = ident.private_raw(passphrase)
    store.upgrade(ident, passphrase)
    reloaded = keys.KeyStore(tmp_path).identities[0]
    assert dataclasses.asdict(reloaded) == dataclasses.asdict(ident)
    assert reloaded.sealed and reloaded.private is None and reloaded.locked is None
    assert reloaded.is_post_quantum and reloaded.is_locked == bool(passphrase)
    assert reloaded.private_raw(passphrase)[:32] == x25519


@pytest.mark.parametrize("raw", [bytes(32), b"\x01" + bytes(31),
                                 bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")])
def test_low_order_public_keys_rejected(tmp_path, raw):
    text = keys.PUBKEY_PREFIX + base64.urlsafe_b64encode(raw + hashlib.sha256(raw).digest()[:4]).decode()
    with pytest.raises(LocksmithError):
        keys.KeyStore(tmp_path).add_contact("evil", text)


@pytest.mark.parametrize("text", ["", "locksmith1", "locksmith1!!!!", "locksmith2abc", "locksmith1" + "A" * 400])
def test_public_key_parsing_garbage(text):
    with pytest.raises(LocksmithError):
        keys.decode_public(text)


# ── settings ─────────────────────────────────────────────────────────────────

def test_hostile_settings_fall_back_to_defaults(tmp_path, monkeypatch, config_home):
    from locksmith.ui import settings as smod
    (tmp_path / "locksmith").mkdir(exist_ok=True)
    (tmp_path / "locksmith" / "settings.json").write_text(json.dumps({
        "suite": "des", "preset": ["x"], "kdf": {"a": 1}, "chunk_size": 1, "threads": True,
        "padding": None, "compression": 5, "hide_name": "yes", "theme": "neon", "unknown": 1,
        "level": "max", "armor": True,
    }))
    s = smod.Settings()
    for key in ("suite", "preset", "kdf", "chunk_size", "threads", "padding", "compression",
                "hide_name", "theme"):
        assert s[key] == smod.DEFAULTS[key], key
    assert s["level"] == "max" and s["armor"] is True
    with pytest.raises(ValueError):
        s["suite"] = "des"
    opts = EncryptOptions(suite=s["suite"], kdf=s["kdf"], preset=s["preset"], compression=s["compression"],
                          level=s["level"], chunk_size=s["chunk_size"], padding=s["padding"],
                          threads=s["threads"], password="pw")
    engine.validate_options(opts)


def test_settings_not_json_object(tmp_path, monkeypatch, config_home):
    from locksmith.ui import settings as smod
    (tmp_path / "locksmith").mkdir(exist_ok=True)
    for content in ("[]", "null", "\xff", '"str"'):
        (tmp_path / "locksmith" / "settings.json").write_text(content)
        assert smod.Settings()["suite"] == smod.DEFAULTS["suite"]


# ── tools ────────────────────────────────────────────────────────────────────

def test_shred_does_not_follow_symlinks(tmp_path, needs_symlinks):
    outside = tmp_path / "outside.txt"
    outside.write_text("precious")
    d = tmp_path / "victim"
    (d / "sub").mkdir(parents=True)
    (d / "file").write_text("x")
    (d / "link-file").symlink_to(outside)
    (d / "link-dir").symlink_to(tmp_path)
    tools.shred(d)
    assert not d.exists() and outside.read_text() == "precious"
    # A link given directly is refused (N2): removing it would report a shred while the
    # data it points to stays. Both are left as they were.
    link = tmp_path / "top-link"
    link.symlink_to(outside)
    with pytest.raises(LocksmithError, match="is a link"):
        tools.shred(link)
    assert link.is_symlink() and outside.read_text() == "precious"


@pytest.mark.parametrize("shares", [
    [], ["garbage"], ["locksmithshare-2-1-ab-000000"],
])
def test_shamir_garbage(shares):
    with pytest.raises(LocksmithError):
        tools.shamir_combine(shares)


def test_shamir_edge_cases():
    shares = tools.shamir_split(b"s3cret", 2, 3)
    with pytest.raises(LocksmithError):
        tools.shamir_combine([shares[0], shares[0]])  # duplicates don't count twice
    tampered = shares[1][:-8] + ("0" if shares[1][-8] != "0" else "1") + shares[1][-7:]
    with pytest.raises(LocksmithError):
        tools.shamir_combine([shares[0], tampered])
    other = tools.shamir_split(b"longer secret", 2, 3)
    with pytest.raises(LocksmithError):
        tools.shamir_combine([shares[0], other[1]])
    for k, n in ((1, 3), (4, 3), (2, 256), (0, 0)):
        with pytest.raises(LocksmithError):
            tools.shamir_split(b"x", k, n)
    # Any k-1 shares are consistent with every possible secret byte (information-theoretic hiding).
    assert tools.shamir_combine(tools.shamir_split(bytes(range(256)), 3, 5)[2:]) == bytes(range(256))


def test_join_parts_edge_cases(tmp_path):
    for names in (["a.part001", "a.part003"], ["a.part001", "b.part002"], ["a.bin"], []):
        paths = []
        for n in names:
            (tmp_path / n).write_bytes(b"x")
            paths.append(tmp_path / n)
        with pytest.raises(LocksmithError):
            tools.join_parts(paths)


def _parts(tmp_path, data: bytes) -> list[Path]:
    data = b"LOCKED\x00\x02" + data[8:]   # Join only rebuilds encrypted files
    (tmp_path / "big.bin").write_bytes(data)
    (tmp_path / "parts").mkdir()
    return tools.split_file(tmp_path / "big.bin", 4000, tmp_path / "parts")


def test_failed_join_leaves_no_output(tmp_path, monkeypatch):
    parts = _parts(tmp_path, os.urandom(10_000))
    real_open = open

    def failing_open(path, *a, **k):
        if Path(path) == parts[1]:
            raise OSError(5, "Input/output error")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", failing_open)
    out = tmp_path / "joined"
    out.mkdir()
    with pytest.raises(OSError):
        tools.join_parts(parts, out)
    assert list(out.iterdir()) == []


def test_join_is_made_durable(tmp_path, monkeypatch):
    parts = _parts(tmp_path, os.urandom(10_000))
    data = (tmp_path / "big.bin").read_bytes()
    synced = []
    monkeypatch.setattr(tools, "fsync_dir", synced.append)
    target = tools.join_parts(parts, tmp_path / "parts")
    assert target.read_bytes() == data and synced == [tmp_path / "parts"]
    assert sorted(p.name for p in (tmp_path / "parts").iterdir()) == sorted(
        [target.name, *(p.name for p in parts)])


@pytest.mark.parametrize("kind", ["file", "dir", "bundle"])
def test_output_folder_synced_before_returning(tmp_path, monkeypatch, kind):
    """Callers shred originals or delete the source as soon as these return, so the
    rename into the output folder must already be durable."""
    synced = []
    monkeypatch.setattr(engine, "fsync_dir", lambda p: synced.append(Path(p)))
    src = tmp_path / "src"
    (src / "folder").mkdir(parents=True)
    (src / "folder" / "a.txt").write_text("a", encoding="utf-8")
    (src / "b.txt").write_text("b", encoding="utf-8")
    paths = {"file": [src / "b.txt"], "dir": [src / "folder"], "bundle": [src / "folder", src / "b.txt"]}[kind]
    opts = EncryptOptions(password="pw", **FAST)
    enc = engine.encrypt_paths(paths, tmp_path / "enc", opts)
    assert synced == [tmp_path / "enc"]
    synced.clear()
    res = engine.decrypt_path(enc, tmp_path / "dec", PW)
    assert synced == [tmp_path / "dec"] and res.path.parent == tmp_path / "dec"


def test_password_generator_properties():
    for length in (1, 2, 3, 4, 8, 64):
        pw = tools.generate_password(length)
        assert len(pw) == length
    pw = tools.generate_password(200, avoid_ambiguous=True)
    assert not set(pw) & tools.AMBIGUOUS
    assert tools.generate_password(10, lower=False, upper=False, digits=False, symbols=False)
    assert len({tools.generate_password(16) for _ in range(200)}) == 200


def test_hash_matches_hashlib(tmp_path):
    f = tmp_path / "h"
    f.write_bytes(os.urandom(5 << 20))
    for alg in tools.HASHES:
        assert tools.hash_file(f, alg) == hashlib.new(alg, f.read_bytes()).hexdigest()


def test_timestamp_edge(tmp_path):
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, b"x")],
                  {"name": "t", "kind": "file", "comp": "none", "mtime": 10**20})
    assert engine.decrypt_path(evil, tmp_path / "o", PW).path.read_bytes() == b"x"
    assert time.time() > 0


def test_armor_size_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "MAX_ARMOR_INPUT", 1000)
    monkeypatch.setattr(engine, "MAX_ARMOR_TEXT", 5000)
    src = tmp_path / "big"
    src.write_bytes(os.urandom(2000))
    with pytest.raises(LocksmithError, match="armor"):
        engine.encrypt_paths([src], tmp_path / "o", EncryptOptions(password="pw", armor=True, **FAST))
    huge = tmp_path / "huge.locked.txt"
    huge.write_text(engine.ARMOR_BEGIN + "\n" + "A" * 6000 + "\n" + engine.ARMOR_END)
    with pytest.raises(LocksmithError):
        engine.decrypt_path(huge, tmp_path / "d", PW)
    with pytest.raises(LocksmithError):
        engine.dearmor("x" * 6000)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux protections")
def test_hardening_applies():
    import resource

    from locksmith import hardening
    st = hardening.harden()
    assert st.ok, st.problems
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows protections")
def test_windows_hardening_reports_only_verified_protection():
    from locksmith import hardening
    st = hardening.harden()
    assert st.ok == st.injection_blocked
    if not st.injection_blocked:  # e.g. Wine: must say so, never claim protection
        assert any("did not accept" in p for p in st.problems)
    assert hardening.block_network() is False and any("not available on Windows" in p for p in st.problems)


def test_windows_file_names(monkeypatch, tmp_path):
    """Received names that Windows cannot create safely are sanitised, and such
    archive entries are skipped (checked on every platform by simulating Windows)."""
    monkeypatch.setattr(osutil, "IS_WINDOWS", True)
    monkeypatch.setattr(engine, "IS_WINDOWS", True)
    for bad, good in (("report:secret.txt", "report_secret.txt"), ("CON", "_CON"), ("nul.txt", "_nul.txt"),
                      ("a<b>c|d?.pdf", "a_b_c_d_.pdf"), ("trailing. ", "trailing"), ("com1.log", "_com1.log")):
        assert engine.safe_name(bad) == good, bad
    assert engine.safe_name("ordinary name.txt") == "ordinary name.txt"
    assert osutil.windows_unsafe("a:b") and osutil.windows_unsafe("LPT1") and not osutil.windows_unsafe("notes")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in ("folder/ok.txt", "folder/stream:hidden", "folder/CON", "folder/aux.txt"):
            info = tarfile.TarInfo(name)
            info.size = 2
            tar.addfile(info, io.BytesIO(b"hi"))
    archive = tmp_path / "a.tar"
    archive.write_bytes(buf.getvalue())
    skipped = engine.extract_archive(archive, tmp_path / "out").skipped
    assert sorted(skipped) == ["folder/CON", "folder/aux.txt", "folder/stream:hidden"]
    assert (tmp_path / "out" / "folder" / "ok.txt").read_bytes() == b"hi"


def _tar(tmp_path, entries: list[tuple[str, bytes | None]], links: dict[str, str] | None = None) -> Path:
    """A tar of files (bytes), folders (None) and symlinks (``links``: name -> target)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            if name in (links or {}):
                info.type, info.linkname = tarfile.SYMTYPE, links[name]
                tar.addfile(info)
            elif data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    archive = tmp_path / "a.tar"
    archive.write_bytes(buf.getvalue())
    return archive


def test_names_differing_in_case_never_overwrite_on_windows(tmp_path, monkeypatch):
    """Notes.txt and notes.txt are one file on Windows: the first is kept and the second reported.
    Simulated here on every platform, and real under the Windows test run."""
    monkeypatch.setattr(osutil, "IS_WINDOWS", True)
    monkeypatch.setattr(engine, "IS_WINDOWS", True)
    archive = _tar(tmp_path, [("folder/Notes.txt", b"first"), ("folder/notes.txt", b"second"),
                              ("folder/NOTES.TXT", b"third"), ("folder/other.txt", b"other")])
    skipped = engine.extract_archive(archive, tmp_path / "out").skipped
    assert skipped == ["folder/notes.txt", "folder/NOTES.TXT"]
    assert (tmp_path / "out" / "folder" / "Notes.txt").read_bytes() == b"first"
    assert sorted(p.name for p in (tmp_path / "out" / "folder").iterdir()) == ["Notes.txt", "other.txt"]


def test_exact_duplicate_names_never_overwrite(tmp_path):
    archive = _tar(tmp_path, [("a.txt", b"first"), ("dir", None), ("dir/b.txt", b"b"), ("a.txt", b"second"),
                              ("dir/b.txt", b"again")])
    skipped = engine.extract_archive(archive, tmp_path / "out").skipped
    assert skipped == ["a.txt", "dir/b.txt"]
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"first"
    assert (tmp_path / "out" / "dir" / "b.txt").read_bytes() == b"b"


def test_repeated_folders_merge_without_being_reported(tmp_path, monkeypatch):
    """A folder listed twice (or, on Windows, as Docs and docs) overwrites nothing."""
    archive = _tar(tmp_path, [("d", None), ("d/x.txt", b"x"), ("d", None), ("d/y.txt", b"y"),
                              ("Docs/a.txt", b"a"), ("docs/b.txt", b"b")])
    assert engine.extract_archive(archive, tmp_path / "out").skipped == []
    monkeypatch.setattr(engine, "IS_WINDOWS", True)
    assert engine.extract_archive(archive, tmp_path / "out-win").skipped == []
    assert (tmp_path / "out-win" / "d" / "x.txt").read_bytes() == b"x"


def test_folder_link_cannot_reach_an_earlier_file(tmp_path, needs_symlinks):
    """alias -> real, then alias/x.txt, would overwrite real/x.txt through the link."""
    archive = _tar(tmp_path, [("real/x.txt", b"first"), ("alias", None), ("alias/x.txt", b"second"),
                              ("alias/new.txt", b"new")], links={"alias": "real"})
    skipped = engine.extract_archive(archive, tmp_path / "out").skipped
    assert skipped == ["alias/x.txt"]
    assert (tmp_path / "out" / "real" / "x.txt").read_bytes() == b"first"
    assert (tmp_path / "out" / "real" / "new.txt").read_bytes() == b"new"


def test_console_device_names_are_reserved(monkeypatch):
    """CONIN$ and CONOUT$ are console devices on Windows, like CON."""
    for name in ("CONIN$", "conout$.txt", "Conin$.log"):
        assert osutil.windows_unsafe(name), name
    assert not osutil.windows_unsafe("conin.txt") and not osutil.windows_unsafe("console$")
    monkeypatch.setattr(osutil, "IS_WINDOWS", True)
    assert engine.safe_name("CONIN$") == "_CONIN$"
    assert engine.safe_name("conout$.txt") == "_conout$.txt"


@pytest.mark.skipif(sys.platform != "win32", reason="real Windows file names")
def test_console_device_names_safe_on_windows(tmp_path):
    for name in ("CONIN$", "CONOUT$"):
        safe = engine.safe_name(name)
        assert not osutil.windows_unsafe(safe)
        (tmp_path / safe).write_bytes(b"x")
        assert (tmp_path / safe).read_bytes() == b"x"


# ── abuse by a sender: names, metadata and archive layout ────────────────────

@pytest.mark.parametrize("name, good", [
    (".bash_profile", "bash_profile"), (".ssh", "ssh"), ("...", "decrypted"), (". .", "decrypted"),
    ("invoice‮fdp.exe", "invoicefdp.exe"), ("a​b⁦c.txt", "abc.txt"), ("line\nbreak", "linebreak"),
    ("é" * 300, "é" * 120),
])
def test_names_cannot_hide_or_disguise_files(name, good):
    assert engine.safe_name(name) == good


def test_hidden_folder_name_is_not_planted(tmp_path):
    """A folder named ".ssh" decrypted into a home folder must not become ~/.ssh."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(".ssh/authorized_keys")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"key"))
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, buf.getvalue())],
                  {"name": ".ssh", "kind": "dir", "comp": "none"}, chunk=len(buf.getvalue()) + 64)
    home = tmp_path / "home"
    res = engine.decrypt_path(evil, home, PW)
    assert res.path.name == "ssh" and not (home / ".ssh").exists()
    assert (res.path / "authorized_keys").read_bytes() == b"key"


@pytest.mark.parametrize("meta", [{"name": "x", "kind": "file", "comp": []},
                                  {"name": "x", "kind": ["dir"], "comp": {"a": 1}, "note": 7, "mtime": True}])
def test_mistyped_metadata_is_ignored(tmp_path, meta):
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, b"payload")], meta)
    res = engine.decrypt_path(evil, tmp_path / "out", PW)
    assert res.path.read_bytes() == b"payload"
    assert all(not isinstance(v, (list, dict, bool)) for v in res.meta.values())


def test_folder_whose_top_entry_is_a_symlink_is_not_unwrapped(tmp_path, needs_symlinks):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        link = tarfile.TarInfo("Photos")
        link.type, link.linkname = tarfile.SYMTYPE, "sibling"
        tar.addfile(link)
        d = tarfile.TarInfo("sibling")
        d.type = tarfile.DIRTYPE
        tar.addfile(d)
    evil = _forge(tmp_path, [_frame(engine.KIND_RAW, buf.getvalue())],
                  {"name": "Photos", "kind": "dir", "comp": "none"}, chunk=len(buf.getvalue()) + 64)
    out = tmp_path / "out"
    (out / "sibling").mkdir(parents=True)
    res = engine.decrypt_path(evil, out, PW)
    assert res.path.is_dir() and not res.path.is_symlink()
    assert res.path.parent == out


def test_dangling_symlink_is_never_replaced(tmp_path, needs_symlinks):
    (tmp_path / "report.txt").symlink_to(tmp_path / "missing")
    assert engine.unique_path(tmp_path / "report.txt").name == "report (1).txt"


def test_lzma_dictionary_bomb_rejected(tmp_path):
    """A header declaring a huge dictionary must fail before it is allocated."""
    import lzma
    big = lzma.compress(b"x", format=lzma.FORMAT_XZ,
                        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 30}])
    with pytest.raises(CorruptedError):
        compress.CODECS["lzma"].decompress(big, 4096)
    assert compress.CODECS["lzma"].decompress(lzma.compress(b"ok", preset=6), 4096) == b"ok"


def test_message_decompression_bomb_rejected(tmp_path, monkeypatch):
    """Every chunk is within its own cap, but the total must not expand without limit in memory."""
    src = tmp_path / "zeros"
    with open(src, "wb") as f:
        f.truncate(256 << 20)
    opts = EncryptOptions(password="pw", compression="zstd", chunk_size=64 << 20, **FAST)
    blob = engine.encrypt_paths([src], tmp_path / "enc", opts).read_bytes()
    assert len(blob) < 1 << 20
    zstd = compress.CODECS["zstd"]
    opened = []
    monkeypatch.setitem(compress.CODECS, "zstd", dataclasses.replace(
        zstd, new_decompressor=lambda: (opened.append(1), zstd.new_decompressor())[1]))
    with pytest.raises(CorruptedError, match="larger than"):
        engine.decrypt_bytes(blob, PW)
    assert len(opened) < 4  # stopped before building the full output


def test_message_at_the_limit_round_trips():
    opts = EncryptOptions(password="pw", compression="zstd", chunk_size=64 << 20, **FAST)
    data = bytes(engine.MAX_ARMOR_INPUT)
    assert engine.decrypt_bytes(engine.encrypt_bytes(data, opts), PW).data == data
    with pytest.raises(LocksmithError, match="limited"):
        engine.encrypt_bytes(data + b"x", opts)


def test_armored_folder_limit_counts_archive_overhead(tmp_path, monkeypatch):
    """Files under the limit can make an archive over it; that must not be written as
    a message that cannot be opened again."""
    folder = tmp_path / "many"
    folder.mkdir()
    for i in range(40):  # non-ASCII names need extra PAX headers in the archive
        (folder / f"ü{i}.txt").write_bytes(b"")
    assert engine._tree_size(folder) < 48 << 10
    monkeypatch.setattr(engine, "MAX_ARMOR_INPUT", 48 << 10)
    opts = EncryptOptions(password="pw", armor=True, chunk_size=256 << 10, **FAST)
    with pytest.raises(LocksmithError, match="limited"):
        engine.encrypt_paths([folder], tmp_path / "enc", opts)
    assert not list((tmp_path / "enc").iterdir())


@pytest.mark.parametrize("share", ["locksmithshare-2-300-ab-000000", "locksmithshare-999-1-ab-000000",
                                   "locksmithshare-2-0-ab-000000", "locksmithshare-2-1-abc-000000"])
def test_malformed_shares_are_reported(share):
    with pytest.raises(LocksmithError, match="right format"):
        tools.shamir_combine([share, share])


def test_shares_with_different_thresholds_rejected():
    a = tools.shamir_split(b"secret", 2, 3)
    b = tools.shamir_split(b"secret", 3, 3)
    with pytest.raises(LocksmithError, match="different secrets"):
        tools.shamir_combine([a[0], b[1], b[2]])


def test_shares_from_same_length_secrets_rejected():
    a = tools.shamir_split(b"secret A", 2, 3)
    b = tools.shamir_split(b"secret B", 2, 3)
    with pytest.raises(LocksmithError, match="different secrets"):
        tools.shamir_combine([a[0], b[1]])


def _reshare(share, data):
    """Replace a share's data and recompute its typo check, as a deliberate forger would."""
    prefix, k, x, split_id, _, _ = share.split("-")
    body = bytes([int(k), int(x)]) + bytes.fromhex(split_id) + data
    return f"{prefix}-{k}-{x}-{split_id}-{data.hex()}-{hashlib.sha256(body).hexdigest()[:6]}"


def test_altered_share_with_valid_checksum_rejected():
    shares = tools.shamir_split(b"s3cret", 2, 3)
    data = bytearray.fromhex(shares[1].split("-")[4])
    data[0] ^= 1
    forged = _reshare(shares[1], bytes(data))
    with pytest.raises(LocksmithError, match="fit together"):
        tools.shamir_combine([shares[0], forged])
    # With an extra share, the disagreement is caught even before the tag check.
    with pytest.raises(LocksmithError, match="fit together"):
        tools.shamir_combine([shares[0], shares[2], forged])
    with pytest.raises(LocksmithError, match="twice"):
        tools.shamir_combine([shares[0], shares[1], forged])
    assert tools.shamir_combine([shares[2], shares[0], shares[1]]) == b"s3cret"


def test_old_format_shares_still_combine():
    old = ["locksmithshare-2-1-60714d9e165fd1a51310-bf5073",
           "locksmithshare-2-2-71563647b9111cc789bc-bd2f36",
           "locksmithshare-2-3-7e4b1ff9dc2bae10ffd8-56887e"]
    assert tools.shamir_combine(old[1:]) == b"old secret"
    assert tools.shamir_combine(old) == b"old secret"
    with pytest.raises(LocksmithError, match="different secrets"):
        tools.shamir_combine([old[0], tools.shamir_split(b"old secret", 2, 3)[1]])


def test_shred_refuses_hard_linked_file(tmp_path):
    f = tmp_path / "a"
    f.write_bytes(b"plain")
    try:
        os.link(f, tmp_path / "b")
    except (OSError, NotImplementedError):
        pytest.skip("hard links are not available")
    with pytest.raises(LocksmithError, match="hard links"):
        tools.shred(f)
    assert (tmp_path / "b").read_bytes() == b"plain"


def test_keyfile_covered_by_inputs(tmp_path):
    vault = tmp_path / "vault"
    (vault / "sub").mkdir(parents=True)
    key = vault / "sub" / "key.bin"
    key.write_bytes(b"k" * 32)
    other = tmp_path / "other.txt"
    other.write_text("x", encoding="utf-8")
    assert tools.covered_by(key, [key])
    assert tools.covered_by(key, [other, vault])
    assert tools.covered_by(key, [tmp_path / "vault" / "sub" / ".." / "sub"])
    assert not tools.covered_by(key, [other])
    assert not tools.covered_by(other, [vault])
    assert not tools.covered_by(tmp_path / "missing", [vault])


def test_keyfile_covered_through_symlink(tmp_path, needs_symlinks):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "key.bin").write_bytes(b"k" * 32)
    link = tmp_path / "key-link"
    link.symlink_to(vault / "key.bin")
    assert tools.covered_by(link, [vault])
    assert tools.covered_by(link, [vault / "key.bin"])


def test_keyfile_covered_through_hard_link(tmp_path):
    vault = tmp_path / "vault"
    (vault / "deep").mkdir(parents=True)
    key = tmp_path / "key.bin"
    key.write_bytes(b"k" * 32)
    try:
        os.link(key, vault / "deep" / "copy")
    except (OSError, NotImplementedError):
        pytest.skip("hard links are not available")
    assert tools.covered_by(key, [vault])
    assert tools.covered_by(key, [vault / "deep" / "copy"])
    assert not tools.covered_by(key, [tmp_path / "vault" / "deep" / "nothing"])


def test_split_never_overwrites(tmp_path):
    src = tmp_path / "f.locked"
    src.write_bytes(os.urandom(3000))
    victim = tmp_path / "f.locked.part002"
    victim.write_bytes(b"keep me")
    with pytest.raises(FileExistsError):
        tools.split_file(src, 1000)
    assert victim.read_bytes() == b"keep me"


@pytest.mark.skipif(sys.platform != "win32", reason="Mark of the Web is a Windows feature")
def test_mark_of_the_web_carries_over(tmp_path):
    """A downloaded .locked file's zone mark reaches what it decrypts to, so a received
    program or macro document still gets SmartScreen and Protected View."""
    mark = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    src = tmp_path / "in"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "run.exe").write_bytes(b"MZ")
    enc = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    try:
        with open(f"{enc}:Zone.Identifier", "wb") as f:
            f.write(mark)
    except OSError:
        pytest.skip("this file system has no alternate data streams")
    res = engine.decrypt_path(enc, tmp_path / "dec", PW)
    with open(f"{res.path / 'sub' / 'run.exe'}:Zone.Identifier", "rb") as f:
        assert f.read() == mark


def _pasted(tmp_path, armor_from: Path) -> bytes:
    out = engine.encrypt_paths([armor_from], tmp_path / "enc", EncryptOptions(password="pw", armor=True, **FAST))
    return engine.dearmor(out.read_text(encoding="utf-8"))


def test_pasted_files_and_folders_are_written_like_decrypted_files(tmp_path, monkeypatch):
    """N7: a pasted message goes through the same core path as a file: a missing output
    folder is created (not swapped for the home folder), a folder is unwrapped one level as
    decrypt_path does, and everything written gets the internet zone mark."""
    marked = []
    monkeypatch.setattr(engine, "mark_untrusted", lambda target: marked.append(Path(target)))
    # Marks aren't what this compares; Wine would list them as files ("run.exe:Zone.Identifier").
    monkeypatch.setattr(engine, "mark_output", lambda *a, **k: None)
    src = tmp_path / "proj"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "run.exe").write_bytes(b"MZ")
    (src / "a.txt").write_text("a", encoding="utf-8")
    out = tmp_path / "not" / "there yet"
    res = engine.decrypt_pasted(_pasted(tmp_path, src), out, PW)
    assert res.path == out / "proj" and (out / "proj" / "sub" / "run.exe").read_bytes() == b"MZ"
    assert res.complete and marked == [res.path]
    from_file = engine.decrypt_path(next((tmp_path / "enc").iterdir()), tmp_path / "from-file", PW)
    assert sorted(p.relative_to(from_file.path) for p in from_file.path.rglob("*")) == \
        sorted(p.relative_to(res.path) for p in res.path.rglob("*"))

    single = tmp_path / "run.exe"
    single.write_bytes(b"MZ program")
    res = engine.decrypt_pasted(_pasted(tmp_path, single), out, PW)
    assert res.path == out / "run.exe" and res.path.read_bytes() == b"MZ program" and marked[-1] == res.path


def test_pasted_text_stays_in_memory(tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "mark_untrusted", lambda target: pytest.fail("nothing was written"))
    blob = engine.encrypt_bytes(b"hello", EncryptOptions(password="pw", **FAST), kind="text")
    res = engine.decrypt_pasted(blob, tmp_path / "out", PW)
    assert res.path is None and res.data == b"hello" and not (tmp_path / "out").exists()


def test_pasted_content_keeps_the_in_memory_cap(tmp_path, monkeypatch):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(5000))
    blob = _pasted(tmp_path, big)
    monkeypatch.setattr(engine, "MAX_ARMOR_INPUT", 4096)
    with pytest.raises(LocksmithError):
        engine.decrypt_pasted(blob, tmp_path / "out", PW)
    assert not list((tmp_path / "out").iterdir())   # no .part left behind


def test_mark_untrusted_writes_the_internet_zone_to_every_file(tmp_path, monkeypatch):
    if sys.platform != "win32":
        monkeypatch.setattr(osutil, "IS_WINDOWS", True)   # "name:Zone.Identifier" is an ordinary file here
    folder = tmp_path / "proj"
    (folder / "sub").mkdir(parents=True)
    files = [folder / "a.txt", folder / "sub" / "run.exe"]
    for f in files:
        f.write_bytes(b"x")
    try:
        osutil.mark_untrusted(folder)
        marks = [Path(f"{f}:Zone.Identifier").read_bytes() for f in files]
    except OSError:
        pytest.skip("this file system has no alternate data streams")
    assert marks == [b"[ZoneTransfer]\r\nZoneId=3\r\n"] * 2


@pytest.mark.skipif(sys.platform != "win32", reason="Mark of the Web is a Windows feature")
def test_pasted_messages_get_the_mark_of_the_web(tmp_path):
    """N7 on Windows: every file decrypted from pasted text has ZoneId=3."""
    probe = tmp_path / "probe"
    probe.write_bytes(b"")
    try:
        with open(f"{probe}:Zone.Identifier", "wb"):
            pass
    except OSError:
        pytest.skip("this file system has no alternate data streams")
    src = tmp_path / "proj"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "run.exe").write_bytes(b"MZ")
    single = tmp_path / "macro.docm"
    single.write_bytes(b"PK")
    for item in (src, single):
        res = engine.decrypt_pasted(_pasted(tmp_path, item), tmp_path / "dec", PW)
        # Wine keeps a stream as a file named "name:Zone.Identifier"; real Windows never lists it.
        written = ([p for p in res.path.rglob("*") if p.is_file() and ":" not in p.name] if res.path.is_dir()
                   else [res.path])
        assert written
        for f in written:
            with open(f"{f}:Zone.Identifier", "rb") as m:
                assert b"ZoneId=3" in m.read()


# ── damaged config, decrypted permissions, crash leftovers ───────────────────

def test_deeply_nested_key_file_is_backed_up(tmp_path):
    (tmp_path / "keys.json").write_text("[" * 200_000, encoding="utf-8")
    store = keys.KeyStore(tmp_path)
    assert store.problem and store.identities == []
    assert list(tmp_path.glob("keys.json.unreadable-*"))


def test_mistyped_identity_is_kept_and_blocks_nothing(tmp_path):
    store = keys.KeyStore(tmp_path)
    good = store.generate("good", post_quantum=False)
    store.generate("bad", post_quantum=False)
    data = json.loads((tmp_path / "keys.json").read_text(encoding="utf-8"))
    data["identities"][1].update(sealed=123, private=None)
    (tmp_path / "keys.json").write_text(json.dumps(data), encoding="utf-8")
    store = keys.KeyStore(tmp_path)
    assert [i.name for i in store.identities] == ["good"] and store.problem
    assert store.unlocked_private_keys() == [good.private_raw()]
    store.save()  # the bad entry is written back untouched
    assert json.loads((tmp_path / "keys.json").read_text(encoding="utf-8"))["identities"][1]["sealed"] == 123


def test_share_with_oversized_numbers_is_reported():
    with pytest.raises(LocksmithError, match="right format"):
        tools.shamir_combine(["locksmithshare2-" + "9" * 5000 + "-1-00000000-aa-000000"] * 2)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_decrypted_folder_is_private(tmp_path):
    src = tmp_path / "docs"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "a.txt").write_text("secret", encoding="utf-8")
    (src / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    for p, mode in ((src, 0o755), (src / "sub", 0o755), (src / "sub" / "a.txt", 0o644), (src / "run.sh", 0o755)):
        os.chmod(p, mode)
    out = engine.decrypt_path(engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST)),
                              tmp_path / "dec", PW).path
    modes = {p.relative_to(out).as_posix(): stat.S_IMODE(p.stat().st_mode) for p in [out, *out.rglob("*")]}
    assert modes == {".": 0o700, "sub": 0o700, "sub/a.txt": 0o600, "run.sh": 0o700}


def test_crash_leftovers_are_shredded_on_next_start(tmp_path, monkeypatch):
    from locksmith.core import scratch
    monkeypatch.setattr(scratch, "_journal", tmp_path / "scratch.json")
    left = tmp_path / ".locksmith-0123456789ab.part"
    staging = tmp_path / ".locksmith-ba9876543210"
    (staging / "x").mkdir(parents=True)
    (staging / "x" / "plain.txt").write_text("plain", encoding="utf-8")
    other = tmp_path / "Documents"
    other.mkdir()
    for p in (left, staging, other):
        scratch._update(lambda entries, p=p: [*entries, str(p)])  # as if a run was killed mid-way
    left.write_text("plaintext", encoding="utf-8")
    assert scratch.clean_leftovers() == 2
    assert not left.exists() and not staging.exists()
    assert other.exists()  # only Locksmith's own temporary names are ever removed
    assert not (tmp_path / "scratch.json").exists()


def test_decrypt_journals_its_temporary_files(tmp_path, monkeypatch):
    from locksmith.core import scratch
    journal = tmp_path / "scratch.json"
    monkeypatch.setattr(scratch, "_journal", journal)
    src = tmp_path / "docs"
    src.mkdir()
    (src / "a.txt").write_text("a", encoding="utf-8")
    locked = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    seen = []
    real = engine.extract_archive
    monkeypatch.setattr(engine, "extract_archive",
                        lambda a, d, **kw: (seen.append(json.loads(journal.read_text(encoding="utf-8"))), real(a, d, **kw))[1])
    engine.decrypt_path(locked, tmp_path / "dec", PW)
    assert [Path(p).name for p in seen[0]][0].endswith(".part") and len(seen[0]) == 2
    assert not journal.exists()  # everything was cleaned up, so nothing is listed


# ── archive headers (folder files) ───────────────────────────────────────────

def _bare_header(tmp_path, kind: bytes, size: int) -> Path:
    """An archive whose first header declares ``size`` bytes of metadata, followed by
    that many zero bytes (sparse on disk) and an ordinary member."""
    head = tarfile.TarInfo("x")
    head.type, head.size = kind, size
    path = tmp_path / "crafted.tar"
    with open(path, "wb") as f:
        f.write(head.tobuf(format=tarfile.GNU_FORMAT))
        f.truncate(f.tell() + -(-size // 512) * 512)
        f.seek(0, os.SEEK_END)
        f.write(tarfile.TarInfo("y").tobuf(format=tarfile.GNU_FORMAT) + bytes(1024))
    return path


@pytest.mark.parametrize("kind", [tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK, tarfile.XHDTYPE,
                                  tarfile.XGLTYPE])
def test_oversized_archive_header_rejected_before_reading(tmp_path, kind):
    import tracemalloc
    archive = _bare_header(tmp_path, kind, 64 << 20)
    tracemalloc.start()
    try:
        with pytest.raises(CorruptedError, match="oversized header"):
            engine.extract_archive(archive, tmp_path / "out")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 << 20
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("pax", [
    {"GNU.sparse.major": "1", "GNU.sparse.minor": "0", "GNU.sparse.name": "s", "GNU.sparse.realsize": "9"},
    {"GNU.sparse.map": "0,5", "GNU.sparse.size": "5"},
    None,  # the old GNU 'S' member type
])
def test_sparse_archive_members_rejected(tmp_path, pax):
    path = tmp_path / "sparse.tar"
    if pax is None:
        path = _bare_header(tmp_path, tarfile.GNUTYPE_SPARSE, 0)
    else:
        # Format 1.0 would read as many map numbers as it declares from the member's data.
        data = b"999999999\n" + b"1\n" * 4096
        info = tarfile.TarInfo("s")
        info.size, info.pax_headers = len(data), pax
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(info, io.BytesIO(data))
    with pytest.raises(CorruptedError, match="sparse"):
        engine.extract_archive(path, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_folders_with_long_and_non_ascii_names_still_extract(tmp_path):
    src = tmp_path / ("folder-" + "d" * 110)
    deep = src / ("ü" * 60) / ("n" * 120 + ".txt")
    deep.parent.mkdir(parents=True)
    deep.write_text("long", encoding="utf-8")
    locked = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    out = engine.decrypt_path(locked, tmp_path / "dec", PW).path
    assert (out / deep.relative_to(src)).read_text(encoding="utf-8") == "long"


# ── key commitment, decoy slots ──────────────────────────────────────────────

def test_commitment_mismatch_reads_as_wrong_key():
    """A slot that unwraps to a key failing the commitment counts as not opening."""
    a = engine.encrypt_bytes(b"a", EncryptOptions(password="pw", **FAST))
    b = engine.encrypt_bytes(b"b", EncryptOptions(password="other", **FAST))
    ha, body = _split(a)
    ha["slots"] = _split(b)[0]["slots"]          # b's slot unwraps b's key, which fails a's commitment
    with pytest.raises(WrongKeyError, match="Wrong password"):
        engine.decrypt_bytes(_join(ha, body), DecryptKeys(password="other"))


def test_commitment_mismatch_moves_on_to_the_next_slot():
    a = engine.encrypt_bytes(b"a", EncryptOptions(password="same", **FAST))
    b = engine.encrypt_bytes(b"b", EncryptOptions(password="same", **FAST))
    ha, body = _split(a)
    ha["slots"] = _split(b)[0]["slots"] + ha["slots"]
    # b's slot opens first but fails the commitment; a's own slot then opens. In version 2 the
    # frames don't authenticate the slots (so they can be edited), and the file opens.
    assert engine.decrypt_bytes(_join(ha, body), DecryptKeys(password="same")).data == b"a"


@pytest.mark.parametrize("hybrid", [False, True])
def test_decoy_slots_hide_the_recipient_count(hybrid):
    me = os.urandom(96 if hybrid else 32)
    pub = keys.public_from_private(me)
    blob = engine.encrypt_bytes(b"hi", EncryptOptions(recipients=[pub], hide_recipients=True, **FAST))
    info = engine.inspect_bytes(blob)
    assert info.recipient_slots == 8 and info.post_quantum_slots == (8 if hybrid else 0)
    assert engine.decrypt_bytes(blob, DecryptKeys(identities=[me])).data == b"hi"
    # Decoys look like real slots: same fields, same sizes, a valid ephemeral key.
    slots = _split(blob)[0]["slots"]
    assert len({tuple(sorted((k, len(v)) for k, v in s.items())) for s in slots}) == 1
    assert all(base64.b64decode(s["epk"])[31] < 0x80 for s in slots)
    stranger = os.urandom(96 if hybrid else 32)
    with pytest.raises(WrongKeyError):
        engine.decrypt_bytes(blob, DecryptKeys(identities=[stranger]))


def test_decoy_slots_stay_within_the_slot_limit():
    recipients = [keys.public_from_private(os.urandom(32)) for _ in range(40)]
    blob = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", recipients=recipients, hide_recipients=True,
                                                     **FAST))
    assert len(_split(blob)[0]["slots"]) == engine.MAX_SLOTS
    assert engine.decrypt_bytes(blob, PW).data == b"x"
    plain = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", hide_recipients=True, **FAST))
    assert len(_split(plain)[0]["slots"]) == 1   # no recipients: nothing to hide, no decoys


# ── backup words, identity shares ────────────────────────────────────────────

def test_backup_words_catch_typos_and_restore_nothing_else(tmp_path):
    raw = os.urandom(96)
    words = keys.backup_words(raw)
    rng = random.Random(7)
    for _ in range(200):   # any single changed word is caught by the checksum
        typo = list(words)
        i = rng.randrange(len(typo))
        typo[i] = keys._proquint(rng.randrange(1 << 16))
        if typo != words:
            with pytest.raises(LocksmithError):
                keys.private_from_words(" ".join(typo))
    for bad in ("", " ".join(words[:-1]), " ".join(words + words[:1]), " ".join(["zzzzz"] * 18)):
        with pytest.raises(LocksmithError):
            keys.private_from_words(bad)


def test_identity_and_password_shares_dont_mix():
    raw = os.urandom(32)
    id_shares = keys.identity_shares(raw, 2, 3)
    assert keys.is_identity_secret(tools.shamir_combine(id_shares[:2]))
    with pytest.raises(LocksmithError, match="not an identity"):
        keys.private_from_shares(tools.shamir_split(b"x" * 36, 2, 3)[:2])
    with pytest.raises(LocksmithError, match="different secrets"):
        keys.private_from_shares([id_shares[0], keys.identity_shares(raw, 2, 3)[1]])


def test_restore_refuses_duplicates_and_bad_keys(tmp_path):
    store = keys.KeyStore(tmp_path)
    ident = store.generate("me")
    with pytest.raises(LocksmithError, match="already"):
        store.restore("again", ident.private_raw())
    with pytest.raises(LocksmithError, match="not a valid private key"):
        store.restore("bad", b"\x00" * 33)
    assert len(store.identities) == 1


# ── minisign ─────────────────────────────────────────────────────────────────

def _minisign(data: bytes, prehash=True, comment="timestamp:1\tfile:f", key_id=b"\x01" * 8):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    sig = sk.sign(hashlib.blake2b(data, digest_size=64).digest() if prehash else data)
    text = (f"untrusted comment: <b>trust me</b>\n{base64.b64encode((b'ED' if prehash else b'Ed') + key_id + sig).decode()}"
            f"\ntrusted comment: {comment}\n{base64.b64encode(sk.sign(sig + comment.encode())).decode()}\n")
    pub = base64.b64encode(b"Ed" + key_id + sk.public_key().public_bytes_raw()).decode()
    return text, pub


def test_minisign_rejects_every_kind_of_mismatch(tmp_path):
    from locksmith.core import minisign
    f = tmp_path / "f"
    f.write_bytes(b"release")
    sig, pub = _minisign(b"release")
    ok = minisign.verify_file(f, sig, f"untrusted comment: minisign public key\n{pub}\n")
    assert ok.trusted_comment == "timestamp:1\tfile:f" and "trust me" not in ok.trusted_comment
    other_sig, other_pub = _minisign(b"release", key_id=b"\x02" * 8)
    cases = {
        "different key": (sig, other_pub),
        "same ID, other key": (sig, _minisign(b"release")[1]),
        "altered comment": (sig.replace("file:f", "file:g"), pub),
        "other file": (_minisign(b"other")[0], pub),
        "unknown algorithm": (sig.replace(sig.splitlines()[1], base64.b64encode(
            b"XX" + base64.b64decode(sig.splitlines()[1])[2:]).decode()), pub),
        "not a signature": ("hello", pub),
    }
    for name, (s, p) in cases.items():
        with pytest.raises(LocksmithError):
            minisign.verify_file(f, s, p)
        assert name


def test_minisign_legacy_signatures_are_capped(tmp_path, monkeypatch):
    from locksmith.core import minisign
    f = tmp_path / "f"
    f.write_bytes(b"x" * 2000)
    sig, pub = _minisign(b"x" * 2000, prehash=False)
    assert not minisign.verify_file(f, sig, pub).prehashed
    monkeypatch.setattr(minisign, "MAX_LEGACY_FILE", 1000)
    with pytest.raises(LocksmithError, match="old-style"):
        minisign.verify_file(f, sig, pub)


def test_minisign_reads_only_small_regular_files(tmp_path):
    from locksmith.core import minisign
    (tmp_path / "big.minisig").write_bytes(b"a" * (minisign.MAX_SIGNATURE_FILE + 1))
    with pytest.raises(LocksmithError, match="too large"):
        minisign.read_small(tmp_path / "big.minisig")
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "pipe")
        with pytest.raises(LocksmithError, match="not a regular file"):
            minisign.read_small(tmp_path / "pipe")   # would block forever if opened normally


# ── checksum manifests, comparing files ──────────────────────────────────────

def test_manifest_entries_cannot_leave_the_folder(tmp_path, needs_symlinks):
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    (folder / "link").symlink_to(tmp_path / "secret.txt")
    digest = hashlib.sha256(b"outside").hexdigest()
    text = "".join(f"SHA256 ({name}) = {digest}\n" for name in
                   ("../secret.txt", str(tmp_path / "secret.txt"), "link", "./a.txt", "a.txt/../../secret.txt"))
    report = tools.verify_manifest(text, folder)
    assert report.matched == [] and len(report.invalid) == 5 and not report.ok


def test_manifest_reports_every_difference(tmp_path):
    folder = tmp_path / "folder"
    (folder / "sub").mkdir(parents=True)
    for name in ("a.txt", "sub/b.txt", "c.txt"):
        (folder / name).write_text(name, encoding="utf-8")
    manifest = tools.make_manifest(folder, "blake2b")
    assert tools.verify_manifest(manifest, folder).ok
    (folder / "a.txt").write_text("changed", encoding="utf-8")
    (folder / "c.txt").unlink()
    (folder / "new.txt").write_text("new", encoding="utf-8")
    md5 = "MD5 (sub/b.txt) = " + hashlib.md5(b"sub/b.txt").hexdigest() + "\n"
    r = tools.verify_manifest(manifest + manifest.splitlines()[0] + "\n" + md5 + "garbage\n", folder)
    assert (r.changed, r.missing, r.extra) == (["a.txt"], ["c.txt"], ["new.txt"])
    assert len(r.invalid) == 3 and r.matched == ["sub/b.txt"]
    with pytest.raises(LocksmithError):
        tools.make_manifest(folder, "md5")


@pytest.mark.skipif(sys.platform == "win32" or not shutil.which("sha256sum"), reason="needs GNU sha256sum")
def test_manifest_is_checked_by_sha256sum(tmp_path):
    import subprocess
    folder = tmp_path / "folder"
    folder.mkdir()
    for name in ("plain.txt", "with space.txt", "back\\slash", "new\nline", "paren) = x"):
        (folder / name).write_text(name, encoding="utf-8")
    (folder / "SHA256SUMS").write_text(tools.make_manifest(folder, "sha256"), encoding="utf-8")
    out = subprocess.run(["sha256sum", "--strict", "-c", "SHA256SUMS"], cwd=folder, capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.count(": OK") == 5, out.stdout + out.stderr
    assert tools.verify_manifest((folder / "SHA256SUMS").read_text(encoding="utf-8"), folder,
                                 exclude=folder / "SHA256SUMS").ok


def test_compare_files(tmp_path):
    a, b, c, d = (tmp_path / n for n in "abcd")
    a.write_bytes(b"x" * 10_000_000)
    b.write_bytes(b"x" * 10_000_000)
    c.write_bytes(b"x" * 9_999_999 + b"y")
    d.write_bytes(b"x")
    assert tools.same_contents(a, b) and not tools.same_contents(a, c) and not tools.same_contents(a, d)
    if hasattr(os, "mkfifo"):
        os.mkfifo(tmp_path / "pipe")
        with pytest.raises(LocksmithError):
            tools.same_contents(a, tmp_path / "pipe")


@pytest.mark.skipif(sys.platform == "win32", reason="Windows names are always Unicode")
def test_manifest_keeps_names_that_are_not_utf8(tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    with open(os.path.join(os.fsencode(folder), b"caf\xe9.txt"), "wb") as f:
        f.write(b"latin-1 name")
    text = tools.make_manifest(folder, "sha256")
    keys.write_secret_file(tmp_path / "SUMS", text.encode("utf-8", "surrogateescape"))
    assert b"(caf\xe9.txt)" in (tmp_path / "SUMS").read_bytes()   # the name's own bytes, as sha256sum writes
    again = tools.read_text(tmp_path / "SUMS", tools.MAX_MANIFEST, "a manifest")
    assert tools.verify_manifest(again, folder).ok


@pytest.mark.skipif(sys.platform != "win32", reason="Windows device names")
def test_manifest_never_opens_windows_devices(tmp_path):
    text = "".join(f"SHA256 ({n}) = {'0' * 64}\n" for n in ("CON", "COM1", "nul.txt", "a:stream", "x\\y"))
    assert len(tools.verify_manifest(text, tmp_path).invalid) == 5


def test_minisign_comment_is_checked_byte_for_byte(tmp_path):
    from locksmith.core import minisign
    f = tmp_path / "f"
    f.write_bytes(b"data")
    # A trusted comment that isn't UTF-8 is signed, and must be checked, as raw bytes.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    s = sk.sign(hashlib.blake2b(b"data", digest_size=64).digest())
    comment = b"caf\xe9"
    raw = (b"untrusted comment: x\n" + base64.b64encode(b"ED" + bytes(8) + s) + b"\ntrusted comment: " + comment
           + b"\n" + base64.b64encode(sk.sign(s + comment)) + b"\n")
    (tmp_path / "f.minisig").write_bytes(raw)
    pub = base64.b64encode(b"Ed" + bytes(8) + sk.public_key().public_bytes_raw()).decode()
    v = minisign.verify_file(f, minisign.read_small(tmp_path / "f.minisig"), pub)
    assert v.trusted_comment.encode("utf-8", "surrogateescape") == comment


# ── 2026-10-01 re-audit: N2, N5, N6, N8 ──────────────────────────────────────

@pytest.mark.parametrize("target", ["file", "folder"])
def test_encrypting_a_link_is_refused(tmp_path, needs_symlinks, target):
    """N2: a link given directly would encrypt (or only store) the link, and shredding would
    remove just the link while the plaintext stayed."""
    real = tmp_path / "real"
    if target == "file":
        real.write_text("plaintext", encoding="utf-8")
    else:
        real.mkdir()
        (real / "inside.txt").write_text("plaintext", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    out = tmp_path / "out"
    with pytest.raises(LocksmithError, match="is a link"):
        engine.encrypt_paths([link], out, EncryptOptions(password="pw", **FAST), verify=True)
    assert not out.exists() or not any(out.iterdir())
    assert link.is_symlink() and real.exists()


def test_links_inside_a_folder_are_still_stored(tmp_path, needs_symlinks):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("a", encoding="utf-8")
    (src / "rel").symlink_to("a.txt")
    enc = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    res = engine.decrypt_path(enc, tmp_path / "dec", PW)
    assert (res.path / "rel").is_symlink() and os.readlink(res.path / "rel") == "a.txt"


def test_disk_guard_stops_before_filling_the_disk(tmp_path, monkeypatch):
    """N5: decryption stops while free space remains, and leaves nothing behind."""
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")
    enc = _encrypt(tmp_path, os.urandom(3 << 20))
    monkeypatch.setattr(engine.shutil, "disk_usage", lambda p: usage(100 << 30, 99 << 30, 4 << 20))
    out = tmp_path / "dec"
    with pytest.raises(LocksmithError, match="before the disk filled up"):
        engine.decrypt_path(enc, out, PW)
    assert list(out.iterdir()) == []   # no .part file and no output


def test_disk_guard_reserve(tmp_path, monkeypatch):
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")
    for total, free, reserve in ((100 << 30, 50 << 30, 2 << 30),     # 2% of the disk
                                 (10 << 30, 9 << 30, 1 << 30),       # at least 1 GiB
                                 (10 << 30, 600 << 20, 300 << 20)):  # never more than half of what is free
        monkeypatch.setattr(engine.shutil, "disk_usage", lambda p, t=total, f=free: usage(t, t - f, f))
        guard = engine._DiskGuard(tmp_path)
        assert guard.reserve == reserve
        guard.need(free - reserve)
        with pytest.raises(LocksmithError):
            guard.need(free - reserve + 1)


def test_disk_guard_checks_each_extracted_member(tmp_path, monkeypatch):
    """N5: a folder's members are checked before each is written (the archive is on disk too)."""
    from collections import namedtuple
    usage = namedtuple("usage", "total used free")
    archive = _tar(tmp_path, [("d", None), ("d/small.txt", b"x"), ("d/big.bin", bytes(5 << 20))])
    monkeypatch.setattr(engine.shutil, "disk_usage", lambda p: usage(100 << 30, 0, 8 << 20))
    guard = engine._DiskGuard(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(LocksmithError, match="before the disk filled up"):
        engine.extract_archive(archive, out, space=guard)
    assert not out.exists()


def test_one_unwritable_member_does_not_lose_the_folder(tmp_path):
    """N6: a name valid on Windows (90 CJK characters, 270 UTF-8 bytes) is over Linux's limit.
    It is skipped and reported; everything else is extracted and the result isn't complete."""
    long_name = "漢" * 90
    archive = _tar(tmp_path, [("d", None), ("d/good.txt", b"good"), (f"d/{long_name}.txt", b"long")])
    ext = engine.extract_archive(archive, tmp_path / "out")
    assert (tmp_path / "out" / "d" / "good.txt").read_bytes() == b"good"
    if osutil.IS_WINDOWS:   # 94 UTF-16 units: fine there
        assert ext.skipped == []
    else:
        assert ext.skipped == [f"d/{long_name}.txt"]


def test_long_member_name_makes_decrypt_incomplete(tmp_path, monkeypatch):
    """N6 through decrypt_path: the folder opens, the long name is reported, the source is kept."""
    long_name = "漢" * 90 + ".txt"
    src = tmp_path / "proj"
    src.mkdir()
    (src / "good.txt").write_text("good", encoding="utf-8")
    real_add = tarfile.TarFile.add

    def add(self, name, arcname=None, *a, **kw):   # the long name can't exist on this disk: add it to the archive
        real_add(self, name, arcname, *a, **kw)
        if arcname != "proj":
            return
        info = tarfile.TarInfo(f"proj/{long_name}")
        info.size = 4
        self.addfile(info, io.BytesIO(b"long"))
    monkeypatch.setattr(tarfile.TarFile, "add", add)
    enc = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    monkeypatch.setattr(tarfile.TarFile, "add", real_add)
    monkeypatch.setattr(engine, "_name_too_long", lambda part: part == long_name)   # as on Linux, everywhere
    res = engine.decrypt_path(enc, tmp_path / "dec", PW)
    assert (res.path / "good.txt").read_text(encoding="utf-8") == "good"
    assert res.skipped == [f"proj/{long_name}"] and not res.complete


def test_member_that_fails_to_be_created_is_skipped(tmp_path, monkeypatch):
    """N6: an OSError on one member skips it (removing anything partly written) instead of
    deleting what was already extracted."""
    archive = _tar(tmp_path, [("d", None), ("d/a.txt", b"a"), ("d/bad.txt", b"partial"), ("d/z.txt", b"z")])
    real = tarfile.TarFile.makefile

    def makefile(self, tarinfo, targetpath):
        if tarinfo.name.endswith("bad.txt"):
            with open(targetpath, "wb") as f:
                f.write(b"par")
            raise OSError(errno.EIO, "I/O error")
        return real(self, tarinfo, targetpath)
    monkeypatch.setattr(tarfile.TarFile, "makefile", makefile)
    ext = engine.extract_archive(archive, tmp_path / "out")
    assert ext.skipped == ["d/bad.txt"]
    assert sorted(p.name for p in (tmp_path / "out" / "d").iterdir()) == ["a.txt", "z.txt"]


def test_full_disk_while_extracting_aborts(tmp_path, monkeypatch):
    archive = _tar(tmp_path, [("d", None), ("d/a.txt", b"a"), ("d/b.txt", b"b")])

    def makefile(self, tarinfo, targetpath):
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(tarfile.TarFile, "makefile", makefile)
    with pytest.raises(LocksmithError, match="unpack"):
        engine.extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_case_insensitive_destination_on_linux(tmp_path, monkeypatch):
    """N8: FAT and exFAT drives (and casefolded folders) ignore case on Linux too, so a second
    name differing only in case is skipped there, never written over the first."""
    monkeypatch.setattr(engine, "_ignores_case", lambda folder: True)
    archive = _tar(tmp_path, [("folder/Notes.txt", b"first"), ("folder/notes.txt", b"second")])
    ext = engine.extract_archive(archive, tmp_path / "out")
    assert ext.skipped == ["folder/notes.txt"]
    assert (tmp_path / "out" / "folder" / "Notes.txt").read_bytes() == b"first"


def test_case_collision_makes_decrypt_incomplete(tmp_path, monkeypatch):
    src = tmp_path / "proj"
    src.mkdir()
    (src / "Notes.txt").write_text("first", encoding="utf-8")
    try:
        (src / "notes.txt").write_text("second", encoding="utf-8")
    except OSError:
        pytest.skip("this file system ignores case")
    if len(list(src.iterdir())) != 2:
        pytest.skip("this file system ignores case")
    enc = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    monkeypatch.setattr(engine, "_ignores_case", lambda folder: True)
    res = engine.decrypt_path(enc, tmp_path / "dec", PW)
    assert len(res.skipped) == 1 and not res.complete


def test_case_probe(tmp_path, monkeypatch):
    """The probe answers for the real file system and leaves nothing behind."""
    if not osutil.IS_WINDOWS:
        (tmp_path / "probe").touch()
        expected = (tmp_path / "PROBE").exists()
        (tmp_path / "probe").unlink()
        assert engine._ignores_case(tmp_path) is expected
    assert list(tmp_path.iterdir()) == []
    monkeypatch.setattr(engine, "IS_WINDOWS", False)
    monkeypatch.setattr(engine, "open_new", lambda p: (_ for _ in ()).throw(OSError(errno.EACCES, "denied")))
    assert engine._ignores_case(tmp_path)   # can't tell: assume it does, which only reports collisions


def test_disk_guard_without_free_space_information(tmp_path, monkeypatch):
    """Some network and FUSE file systems can't report free space: decryption goes on unguarded."""
    def fail(path):
        raise OSError(errno.ENOSYS, "not supported")
    enc = _encrypt(tmp_path)
    monkeypatch.setattr(engine.shutil, "disk_usage", fail)
    assert engine.decrypt_path(enc, tmp_path / "dec", PW).path.exists()


# ── 2026-10-05 audit: low-severity items (security-audit.md A6–A15) ──────────

def test_mail_text_cannot_add_mail_fields(tmp_path, monkeypatch):
    """A14: a file name in the subject can't smuggle cc= or attachment= into the mail client."""
    from locksmith.ui import host
    seen = []
    monkeypatch.setattr(host, "IS_WINDOWS", False)
    monkeypatch.setattr(host, "launch", lambda args: seen.append(args) or True)
    host.compose_email("Encrypted file: x',cc='a@example.com',attachment='%2Fetc%2Fpasswd\n.locked",
                       "I will send the password", tmp_path / "f.locked")
    args = seen[0]
    for flag in ("--subject", "--body"):
        text = args[args.index(flag) + 1]
        assert not set("'\",&%\\;\n") & set(text), text
    assert "a@example.com" in args[args.index("--subject") + 1]   # the name stays readable


def test_folder_archives_never_name_the_owner(tmp_path):
    """A10: without metadata removal, times are kept but owner names and ids are not."""
    folder = tmp_path / "proj"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "a.txt").write_text("a")
    with engine._TarStream([(folder, "proj")]) as stream, \
            tarfile.open(fileobj=io.BytesIO(stream.read()), mode="r:") as tar:
        members = tar.getmembers()
    assert len(members) == 3
    for m in members:
        assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "", ""), m.name
    assert int(members[-1].mtime) == int((folder / "sub" / "a.txt").stat().st_mtime)   # times are kept


def test_plaintext_of_a_failed_decryption_is_shredded(tmp_path, monkeypatch):
    """A11: chunks decrypted before a later one fails are overwritten, not just unlinked."""
    from locksmith.core import scratch
    enc = _encrypt(tmp_path, data=os.urandom(64 << 10), chunk_size=1 << 10, compression="none")
    blob = bytearray(enc.read_bytes())
    blob[-5] ^= 1   # the last frame fails, after earlier ones were written
    enc.write_bytes(blob)
    shredded, real = [], tools.shred
    monkeypatch.setattr(tools, "shred", lambda p, *a, **k: (shredded.append(Path(p)), real(p, *a, **k))[1])
    out = tmp_path / "out"
    with pytest.raises(CorruptedError):
        engine.decrypt_path(enc, out, PW, threads=1)
    assert [p.name.endswith(".part") for p in shredded] == [True]
    assert list(out.iterdir()) == []
    # Above the limit, the plaintext is only deleted, so cancelling a huge file isn't slow.
    monkeypatch.setattr(scratch, "SHRED_LIMIT", 100)
    big = tmp_path / ".locksmith-000000000000.part"
    big.write_bytes(bytes(1000))
    scratch.discard(big)
    assert not big.exists() and len(shredded) == 1


def test_folders_are_not_unpacked_on_a_python_with_tarfile_bypasses(tmp_path, monkeypatch):
    """A13: a Python whose tarfile filter has known bypasses refuses folders before decrypting."""
    for bad in ((3, 12, 3), (3, 12, 10), (3, 13, 0), (3, 13, 3)):
        with pytest.raises(LocksmithError, match="can't unpack folders safely"):
            engine._check_tarfile(bad)
    for good in ((3, 12, 11), (3, 13, 4), (3, 14, 0), (3, 15, 1)):
        engine._check_tarfile(good)
    folder = tmp_path / "proj"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    enc = engine.encrypt_paths([folder], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    real = engine._check_tarfile
    monkeypatch.setattr(engine, "_check_tarfile", lambda version=(3, 12, 3): real(version))
    with pytest.raises(LocksmithError, match="can't unpack folders safely"):
        engine.decrypt_path(enc, tmp_path / "out", PW)
    assert not (tmp_path / "out").exists()   # refused before anything was decrypted
    with pytest.raises(LocksmithError, match="can't unpack folders safely"):
        engine.extract_archive(tmp_path / "any.tar", tmp_path / "dest")


def test_display_text_cannot_fake_a_line_or_reorder_it():
    """A6: sender text shown beside status lines stays on its line and in its order."""
    shown = tools.display_text("Quarterly\r\n✓  Signed with the key you saved as Bob x\x00\x1b[31m")
    assert "\n" not in shown and "\r" not in shown and " " not in shown and "\x00" not in shown
    assert "\x1b" not in shown
    assert tools.display_text("invoice‮fdp.exe") == "invoicefdp.exe"
    assert tools.display_text("⁧abc⁩‏") == "abc"
    assert tools.display_text("می‌خواهم 👩‍💻") == "می‌خواهم 👩‍💻"   # joiners kept
    assert tools.display_text("a" * 600, 500) == "a" * 500 + "…"


def test_kdf_settings_beyond_every_preset_are_flagged():
    """A12: what Locksmith writes never asks; what only a crafted file asks for does."""
    for name in kdf.KDFS:
        for preset in kdf.PRESETS:
            assert not kdf.beyond_presets(name, kdf.params_for(name, preset))
    assert kdf.beyond_presets("argon2id", {"m": 2 << 20, "t": 6, "p": 4})
    assert kdf.beyond_presets("argon2id", {"m": 1 << 20, "t": 16, "p": 4})
    assert kdf.beyond_presets("scrypt", {"n": 2**21, "r": 8, "p": 1})
    assert kdf.beyond_presets("pbkdf2-sha512", {"i": 20_000_000})
    assert not kdf.beyond_presets("unknown", {"i": 1})


# ── 2026-10-05 audit: High and Medium items (A1–A5) and the rest ──────────────

def test_unknown_signer_fingerprint_is_only_a_claim(tmp_path, monkeypatch):
    """A3: a signature can name any key; an unsaved signer's fingerprint is never shown as the signer."""
    from locksmith.core import signing
    from locksmith.ui.pages.common import signature_text
    alice = keys.KeyStore(tmp_path / "a").generate("Alice")
    reader = keys.KeyStore(tmp_path / "r").generate("Reader")
    real_sign = signing.sign_locked

    def forged(private, fixed, digest, created=None):   # names Alice's key, signs nothing
        head = signing.HEAD.pack(signing.MAGIC, 1, 1_700_000_000, signing.key_id(alice.key_raw), 0)
        return head + os.urandom(signing.ED_LEN + signing.ML_LEN)
    monkeypatch.setattr(signing, "sign_locked", forged)
    blob = engine.encrypt_bytes(b"pay X", EncryptOptions(recipients=[reader.public_raw], signer=reader.private_raw()))
    monkeypatch.setattr(signing, "sign_locked", real_sign)
    res = engine.decrypt_bytes(blob, DecryptKeys(identities=[reader.private_raw()]))
    text = signature_text(res.signature, {})
    assert "claims" in text and "Nothing was checked" in text and not text.startswith("Signed by")
    sig_file = tmp_path / "f.lsig"
    target = tmp_path / "f"
    target.write_bytes(b"x")
    sig_file.write_text(signing.sign_file(target, reader.private_raw()))
    with pytest.raises(signing.UnknownSignerError, match="nothing has been verified. It claims"):
        signing.verify_file(target, sig_file.read_text(), [alice.key_raw])


def test_join_rebuilds_only_encrypted_files_and_keeps_their_mark(tmp_path, monkeypatch):
    """A4: Join can't turn marked parts of a program into an unmarked program."""
    from locksmith.core import osutil
    program = tmp_path / "Invoice.exe"
    program.write_bytes(b"MZ" + os.urandom(3000))
    (tmp_path / "parts").mkdir()
    parts = tools.split_file(program, 1000, tmp_path / "parts")
    with pytest.raises(LocksmithError, match="Join only puts encrypted files back together"):
        tools.join_parts(parts, tmp_path)
    assert not (tmp_path / "parts" / "Invoice.exe").exists()

    mark = b"[ZoneTransfer]\r\nZoneId=3\r\n"
    marked = {tmp_path / "x.locked.part002"}
    written = {}
    monkeypatch.setattr(osutil, "zone_mark", lambda p: mark if Path(p) in marked else None)
    monkeypatch.setattr(osutil, "_write_zone_mark", lambda target, m: written.update({Path(target): m}))
    enc = tmp_path / "x.locked"
    enc.write_bytes(b"LOCKED\x00\x02" + os.urandom(2500))
    parts = tools.split_file(enc, 1000)
    joined = tools.join_parts(parts, tmp_path / "parts")
    assert joined.read_bytes() == enc.read_bytes() and written[joined] == mark   # from the one marked part
    marked.add(enc)
    for p in parts:
        p.unlink()
    assert all(written[p] == mark for p in tools.split_file(enc, 1000))   # parts inherit their source's mark


def _crafted_lpar(target: Path, content: bytes, k: int, m: int, block: int = 4096) -> Path:
    """Recovery data that says ``target`` should be ``content``, with any layout (the A2 attack)."""
    from locksmith.core import parity
    lay = parity.Layout(len(content), block, k, m)
    data_hashes = [b"\xff" * 16] * lay.blocks
    parity_blocks = [bytes(block)] * (lay.stripes * m)   # wrong parity is fine: the layout check comes first
    meta = parity._meta(lay, target.name, hashlib.sha256(content).digest(), data_hashes,
                        [hashlib.sha256(p).digest()[:16] for p in parity_blocks])
    ck = hashlib.sha256(meta).digest()
    lpar = target.with_name(target.name + ".lpar")
    lpar.write_bytes(parity.MAGIC + struct.pack(">I", len(meta)) + meta + ck + b"".join(parity_blocks) + meta + ck
                     + struct.pack(">I", len(meta)) + parity.END_MAGIC)
    return lpar


def test_recovery_data_with_a_layout_locksmith_never_writes_is_refused(tmp_path):
    """A2: k = m = 1 would let a sidecar rebuild every block of a file as anything."""
    from locksmith.core import parity
    victim = tmp_path / "contract.pdf"
    victim.write_bytes(b"%PDF genuine\n" * 2000)
    for k, m, block in ((1, 1, 4096), (20, 4, 8192), (200, 3, 4096)):
        _crafted_lpar(victim, b"MZ evil\n" * 3000, k, m, block)
        with pytest.raises(LocksmithError, match="damaged beyond use"):
            parity.repair(victim)
    assert victim.read_bytes() == b"%PDF genuine\n" * 2000


def test_repair_keeps_encrypted_files_encrypted_and_marked(tmp_path, monkeypatch):
    """A2: a sidecar that would rebuild a .locked header into something else is refused, and a
    repaired file keeps the damaged original's Mark of the Web."""
    from locksmith.core import osutil, parity
    enc = _encrypt(tmp_path, data=os.urandom(40_000), compression="none")
    good = enc.read_bytes()
    other = tmp_path / "other"
    other.write_bytes(b"MZ" + bytes(4094) + good[4096:])   # the same file with its first block replaced
    lpar = parity.create(other, "20", out=enc.with_name(enc.name + ".lpar"))
    with pytest.raises(LocksmithError, match="wouldn't be a valid encrypted file"):
        parity.repair(enc, lpar)
    assert enc.read_bytes() == good and not list(tmp_path.glob("**/*.damaged"))

    parity.create(enc, "20", out=lpar)
    damaged = bytearray(good)
    damaged[100:200] = bytes(100)
    enc.write_bytes(bytes(damaged))
    written = {}
    monkeypatch.setattr(osutil, "zone_mark", lambda p: b"mark" if Path(p).name.endswith(".damaged") else None)
    monkeypatch.setattr(osutil, "_write_zone_mark", lambda t, m: written.update({Path(t): m}))
    rep = parity.check(enc, lpar)
    assert rep.repairable and rep.sha256 == hashlib.sha256(good).hexdigest() and 0 < rep.rebuilt_fraction < 0.2
    parity.repair(enc, lpar)
    assert enc.read_bytes() == good and written == {enc: b"mark"}


def test_passphrases_can_be_added_changed_and_removed(tmp_path):
    """A5: an identity created without a passphrase can get one later, and it is counted until then."""
    store = keys.KeyStore(tmp_path / "k")
    ident = store.generate("Me")
    raw = ident.private_raw()
    assert store.unprotected == [ident]
    store.set_passphrase(ident, None, "first passphrase")
    assert ident.is_locked and store.unprotected == [] and "private" not in json.dumps(
        keys.KeyStore(tmp_path / "k").identities[0].locked)
    with pytest.raises(WrongKeyError):
        store.set_passphrase(ident, "wrong", "second")
    store.set_passphrase(ident, "first passphrase", "second passphrase")
    again = keys.KeyStore(tmp_path / "k").identities[0]
    assert again.private_raw("second passphrase") == raw and again.private is None
    store.set_passphrase(ident, "second passphrase", None)
    assert keys.KeyStore(tmp_path / "k").identities[0].private_raw() == raw


def test_windows_keys_move_out_of_the_roaming_profile(tmp_path, monkeypatch):
    """A5: Windows keeps keys in %LOCALAPPDATA%; an older version's %APPDATA% folder is moved there."""
    monkeypatch.setattr(osutil, "IS_WINDOWS", True)
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    old = tmp_path / "Roaming" / "locksmith"
    old.mkdir(parents=True)
    (old / "keys.json").write_text('{"identities": []}')
    folder = keys.config_dir()
    assert folder == tmp_path / "Local" / "locksmith"
    assert (folder / "keys.json").read_text() == '{"identities": []}' and not old.exists()
    old.mkdir()   # a folder made again later is left alone: the local one wins
    assert keys.config_dir() == folder and old.exists()


def test_spliced_signing_keys_never_show_as_verified(tmp_path, monkeypatch):
    """A1: a key pairing Alice's encryption key with Mallory's signing keys can be saved as an update,
    but its signatures aren't ✓ until the user marks the new fingerprint as checked."""
    from locksmith.core import signing
    from locksmith.ui.pages.common import saved_signers, signature_text
    reader = keys.KeyStore(tmp_path / "r")
    me = reader.generate("Reader")
    alice = keys.KeyStore(tmp_path / "a").generate("Alice")
    mallory = keys.KeyStore(tmp_path / "m").generate("Mallory")
    contact = reader.add_contact("Alice", keys.encode_public(alice.public_raw))
    reader.mark_checked(contact)   # the user checked Alice's old fingerprint
    spliced = alice.public_raw + mallory.key_raw[keys.HYBRID_PUBLIC_LEN:]
    reader.update_contact_key(contact, keys.encode_public(spliced))
    assert not contact.checked and not keys.KeyStore(tmp_path / "r").contacts[0].checked

    monkeypatch.setattr(signing, "public_key", lambda private: spliced)   # Mallory's modified client
    blob = engine.encrypt_bytes(b"x", EncryptOptions(recipients=[me.public_raw], signer=mallory.private_raw()))
    monkeypatch.undo()
    names = saved_signers(reader)
    res = engine.decrypt_bytes(blob, DecryptKeys(identities=[me.private_raw()], verifiers=list(names)))
    text = signature_text(res.signature, names)
    assert res.signature.verified and not text.startswith("✓") and "haven't marked as checked" in text
    reader.mark_checked(contact)
    assert signature_text(res.signature, saved_signers(reader)).startswith("✓  Signed with the key you saved as Alice")
    # Once checked with signing keys, a contact's signing keys can't be swapped again.
    with pytest.raises(LocksmithError, match="different signing keys"):
        reader.update_contact_key(contact, keys.encode_public(alice.key_raw))


def test_contact_check_flag_is_only_ever_true_by_confirmation(tmp_path):
    store = keys.KeyStore(tmp_path)
    c = store.add_contact("Bob", keys.KeyStore(tmp_path / "b").generate("Bob").key_text)
    assert not c.checked
    data = json.loads(store.path.read_text())
    data["contacts"][0]["checked"] = "yes"
    store.path.write_text(json.dumps(data))
    assert keys.KeyStore(tmp_path).contacts[0].checked is False


def test_fingerprints_are_128_bits_and_extend_the_old_ones(tmp_path):
    """A8: 32 hex digits; the 20 digits shown before are still their first five groups."""
    from locksmith.core import signing
    ident = keys.KeyStore(tmp_path).generate("Me")
    fp = keys.fingerprint(ident.key_raw)
    digest = hashlib.sha256(ident.key_raw).hexdigest().upper()
    assert fp.replace(" ", "") == digest[:32] and len(fp.split()) == 8
    assert fp.startswith(" ".join(digest[i:i + 4] for i in range(0, 20, 4)))
    sig = signing.parse(signing.sign_file(tmp_path / "keys.json", ident.private_raw()))
    assert sig.fingerprint == fp


def test_shares_hide_the_secret_length():
    """A15: v3 shares of a 1-byte and a 30-byte password look the same size; v1 and v2 still combine."""
    short, longer = tools.shamir_split(b"a", 2, 3), tools.shamir_split(b"x" * 30, 2, 3)
    assert all(s.startswith("locksmithshare3-") for s in short + longer)
    assert {len(s) for s in short} == {len(s) for s in longer}
    assert len(tools.shamir_split(b"x" * 31, 2, 2)[0]) > len(short[0])   # the next 32-byte block
    assert tools.shamir_combine(short[:2]) == b"a" and tools.shamir_combine(longer[1:]) == b"x" * 30
    v2 = ["locksmithshare2-2-1-b2a5bd73-4f90d9e19b16f5038af06a9901e0cba19d-5c8554",
          "locksmithshare2-2-2-b2a5bd73-046dc94c828967a9937f492914f1a8d419-26ea5f",
          "locksmithshare2-2-3-b2a5bd73-3dcf30de7cfce0cf6df3a1b0eefe890e65-d64be6"]
    assert tools.shamir_combine(v2[1:]) == b"v2 secret"
    with pytest.raises(LocksmithError, match="different secrets"):
        tools.shamir_combine([v2[0], tools.shamir_split(b"v2 secret", 2, 3)[1]])
    with pytest.raises(LocksmithError, match="4096"):
        tools.shamir_split(bytes(4097), 2, 3)
    raw = bytes(range(96))   # identity shares are v3 too and still restore
    assert keys.private_from_shares(keys.identity_shares(raw, 2, 3)[:2]) == raw


def test_decoys_hide_how_many_of_each_kind():
    """A9: mixed kinds are each rounded up, so no kind's real count shows; RSA decoys are the
    same size as the real RSA slot and look like real ciphertexts."""
    from pathlib import Path as _P

    from locksmith.core import sshkeys
    hybrid = [keys.public_from_private(os.urandom(96)) for _ in range(2)]
    classical = keys.public_from_private(me := os.urandom(32))
    rsa_line = (_P(__file__).parent / "interop" / "sshkeys" / "id_rsa3072.pub").read_text(encoding="utf-8")
    rsa_raw = sshkeys.parse_recipient(rsa_line).raw
    blob = engine.encrypt_bytes(b"x", EncryptOptions(recipients=[*hybrid, classical, rsa_raw], hide_recipients=True,
                                                     **FAST))
    shapes = [engine._slot_shape(s) for s in _split(blob)[0]["slots"]]
    assert sorted({s: shapes.count(s) for s in shapes}.items()) == [
        (("ssh-rsa", 384), 8), (("x25519", 0), 8), (("x25519-mlkem768", 0), 8)]
    assert engine.decrypt_bytes(blob, DecryptKeys(identities=[me])).data == b"x"
    # Without a known key of that size (a kept slot), decoys use a throwaway key of the same size.
    assert len(engine._throwaway_rsa(256)) == 1 and engine._throwaway_rsa(1024) == []


# ── 2026-10-12 audit: Low items (B5–B12) ──────────────────────────────────────

@pytest.mark.parametrize("pw", ["Summer2024!", "January2025", "Liverpool1!", "Tr0ub4dor&3", "Fluffy1990!",
                                "P@ssw0rd", "Welcome1!", "qwerty123", "hunter2"])
def test_strength_meter_sees_common_patterns(pw):
    """B5: word + year/digits + symbol, l33t spellings and keyboard runs rate as weak, so the
    weak-password warning appears (the old estimate called the first five Strong or Fair)."""
    assert tools.strength_label(tools.estimate_entropy(pw))[0] <= 1


def test_strength_meter_still_trusts_random_passwords():
    """B5: the pattern estimate doesn't drag down what Locksmith generates."""
    assert min(tools.estimate_entropy(tools.generate_password(32)) for _ in range(100)) >= 90
    assert min(tools.estimate_entropy(tools.generate_password(24)) for _ in range(100)) >= 64
    assert min(tools.estimate_entropy(tools.generate_passphrase(6)) for _ in range(100)) >= 64


def test_unaddressed_signed_file_reports_how_it_was_opened():
    """B7: a reader can tell a signed file without a list was opened with one of their keys (so it could
    have been addressed, and may have been passed on) from one opened with a password."""
    signer, reader = os.urandom(96), os.urandom(96)
    from locksmith.core import signing
    blob = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", recipients=[keys.public_from_private(reader)],
                                                     signer=signer, **FAST))
    verifiers = [signing.public_key(signer)]
    by_key = engine.decrypt_bytes(blob, DecryptKeys(identities=[reader], verifiers=verifiers))
    assert by_key.signature.verified and by_key.intent is None and by_key.opened_with_key
    assert not engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=verifiers)).opened_with_key


def test_fingerprint_check_needs_the_whole_fingerprint(tmp_path):
    """B9: a prefix (which a key's maker can grind to match) never counts; spaces and hex case don't
    matter; the owner's key QR text or the whole key also match; SSH fingerprints keep their case."""
    store = keys.KeyStore(tmp_path / "store")
    owner = keys.KeyStore(tmp_path / "owner").generate("Alice")
    c = store.add_contact("Alice", owner.key_text)
    fp = c.fingerprint
    assert c.fingerprint_matches(fp) and c.fingerprint_matches(fp.lower().replace(" ", ""))
    assert not c.fingerprint_matches(fp[:24]) and not c.fingerprint_matches("") and not c.fingerprint_matches(fp + "0")
    assert c.fingerprint_matches(keys.qr_text(owner.key_raw)) and c.fingerprint_matches(owner.key_text)
    other = keys.KeyStore(tmp_path / "other").generate("Mallory")
    assert not c.fingerprint_matches(keys.fingerprint(other.key_raw)) and not c.fingerprint_matches(other.key_text)
    line = (Path(__file__).parent / "interop" / "sshkeys" / "id_ed25519.pub").read_text(encoding="utf-8")
    ssh = store.add_contact("Bob", line)
    assert ssh.fingerprint_matches(ssh.fingerprint) and ssh.fingerprint_matches(ssh.fingerprint[len("SHA256:"):])
    assert not ssh.fingerprint_matches(ssh.fingerprint.lower())


def test_mark_output_marks_unmarked_programs_unless_trusted(tmp_path, monkeypatch):
    """B10: output of an unmarked encrypted file gets the internet zone on its programs (not on
    documents) unless a trusted key signed it; a marked source still passes its own mark on."""
    monkeypatch.setattr(osutil, "IS_WINDOWS", True)   # "name:Zone.Identifier" is an ordinary file here
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    for name in ("sub/run.exe", "notes.txt", "deck.pptm", "call.rdp"):
        (out / name).write_bytes(b"x")
    source = tmp_path / "x.locked"
    source.write_bytes(b"LOCKED")

    def marked():   # each file's stream, not a glob: Windows refuses a pattern holding ":"
        return [n for n in ("sub/run.exe", "notes.txt", "deck.pptm", "call.rdp") if os.path.exists(f"{out / n}:Zone.Identifier")]

    osutil.mark_output(source, out, trusted=True)
    assert marked() == []
    osutil.mark_output(source, out, trusted=False)
    assert marked() == ["sub/run.exe", "deck.pptm", "call.rdp"]
    assert Path(f"{out / 'sub' / 'run.exe'}:Zone.Identifier").read_bytes() == osutil.INTERNET_ZONE_MARK
    mark = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.com/\r\n"
    Path(f"{source}:Zone.Identifier").write_bytes(mark)
    osutil.mark_output(source, out / "notes.txt", trusted=True)   # inherited whatever the signer
    assert Path(f"{out / 'notes.txt'}:Zone.Identifier").read_bytes() == mark


def test_decrypted_folder_programs_are_marked_unless_a_trusted_key_signed_them(tmp_path, monkeypatch):
    """B10 end to end: decrypt_path passes whether the signer is trusted to mark_output."""
    from locksmith.core import signing
    monkeypatch.setattr(osutil, "IS_WINDOWS", True)
    src = tmp_path / "src"
    src.mkdir()
    (src / "run.exe").write_bytes(b"MZ")
    (src / "notes.txt").write_bytes(b"hi")
    signer = os.urandom(96)
    key = signing.public_key(signer)
    for trusted in (False, True):
        enc = engine.encrypt_paths([src], tmp_path / f"enc{trusted}", EncryptOptions(password="pw", signer=signer,
                                                                                       **FAST))
        res = engine.decrypt_path(enc, tmp_path / f"dec{trusted}", DecryptKeys(
            password="pw", verifiers=[key], trusted=[key] if trusted else []))
        assert Path(f"{res.path / 'run.exe'}:Zone.Identifier").exists() is not trusted
        assert not Path(f"{res.path / 'notes.txt'}:Zone.Identifier").exists()


def test_program_extension_list_covers_recent_attack_types():
    """B10: types used to run code or reach out from a double-click ask first on Open."""
    for name in ("a.rdp", "a.theme", "a.search-ms", "a.diagcab", "a.one", "a.iso", "a.vhdx", "a.docm", "a.XLSM",
                 "a.wsc", "a.mhtml", "a.flatpakref", "a.pyz"):
        assert osutil.opens_as_program(name), name
    assert not osutil.opens_as_program("a.docx") and not osutil.opens_as_program("a.pdf")


def test_access_change_rsa_decoys_use_known_keys(tmp_path, monkeypatch):
    """B11: hiding the recipients of a file with a kept RSA recipient makes its RSA decoys for a known
    key of that size, so none is larger than the real recipient's modulus; without one, it falls back
    to a throwaway key."""
    from locksmith.core import sshkeys
    here = Path(__file__).parent / "interop" / "sshkeys"
    rsa_raw = sshkeys.parse_recipient((here / "id_rsa3072.pub").read_text(encoding="utf-8")).raw
    modulus = sshkeys.rsa_public(rsa_raw).public_numbers().n
    other = keys.public_from_private(os.urandom(32))
    throwaway = []
    monkeypatch.setattr(engine, "_throwaway_rsa", lambda size: (throwaway.append(size), [])[1])

    path = _encrypt(tmp_path, recipients=[rsa_raw])
    engine.change_access(path, PW, engine.AccessChange(add_recipients=[other], hide_recipients=True))
    assert throwaway == [384]   # no known key: the old fallback (stubbed out here)

    (tmp_path / "b").mkdir()
    path = _encrypt(tmp_path / "b", recipients=[rsa_raw])
    engine.change_access(path, PW, engine.AccessChange(add_recipients=[other], hide_recipients=True,
                                                       known_recipients=[rsa_raw]))
    assert throwaway == [384]
    rsa = [s for s in _split(path.read_bytes())[0]["slots"] if s["t"] == "ssh-rsa"]
    assert len(rsa) == 8 and all(int.from_bytes(base64.b64decode(s["c"]), "big") < modulus for s in rsa)
    ident = sshkeys.load_identity((here / "id_rsa3072").read_bytes())
    assert engine.decrypt_path(path, tmp_path / "out", DecryptKeys(ssh=[ident])).path.read_bytes()


@pytest.mark.parametrize(("name", "head", "joined"), [
    ("x.bat", engine.ARMOR_BEGIN.encode() + b"\r\nstart calc.exe\r\n", "x.bat.locked.txt"),
    ("big.bin", b"LOCKED\x00\x02", "big.bin.locked"),
    ("photo.age", b"age-encryption.org/v1\n", "photo.age"),
    ("notes.LOCKED", b"LOCKED\x00\x02", "notes.LOCKED"),
])
def test_join_names_its_output_as_an_encrypted_file(tmp_path, name, head, joined):
    """B12: the output name comes from the parts and the check from their content, so a name that isn't
    an encrypted file's gets the matching extension and can't become a runnable x.bat."""
    (tmp_path / name).write_bytes(head + os.urandom(2500))
    (tmp_path / "parts").mkdir()
    parts = tools.split_file(tmp_path / name, 1000, tmp_path / "parts")
    assert tools.join_parts(parts, tmp_path / "parts").name == joined


# ── 2026-10-13: Medium items (B1–B4) and smaller notes ───────────────────────

def test_folder_links_stay_inside_the_kept_folder(tmp_path, needs_symlinks):
    """B1: a folder's links are checked against the folder that is kept, not the staging folder around
    it, so "photos/ssh -> ../.ssh" can't end up pointing at ~/.ssh beside the decrypted folder. Links
    inside the folder still work, and in a bundle, links between its items do too."""
    src = tmp_path / "sender"
    photos = src / "photos"
    (photos / "sub").mkdir(parents=True)
    (photos / "a.txt").write_text("hello", encoding="utf-8")
    os.symlink("../.ssh", photos / "ssh")             # leaves the kept folder once it is moved out
    os.symlink("../../.ssh", photos / "deep")         # leaves the staging folder: the filter's job
    os.symlink("a.txt", photos / "alias")
    os.symlink("../a.txt", photos / "sub" / "up")
    os.symlink("..", photos / "sub" / "top")          # the folder itself
    enc = engine.encrypt_paths([photos], tmp_path / "enc", EncryptOptions(password="pw", **FAST))
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("PRIVATE KEY", encoding="utf-8")
    res = engine.decrypt_path(enc, home, PW)
    assert not os.path.lexists(res.path / "ssh") and not os.path.lexists(res.path / "deep")
    assert sorted(res.skipped) == ["photos/deep", "photos/ssh"] and not res.complete
    assert all(os.path.islink(res.path / n) for n in ("alias", "sub/up", "sub/top"))   # links inside are kept
    if not osutil.IS_WINDOWS:   # Wine can't follow a relative "../" link
        assert (res.path / "sub" / "up").read_text(encoding="utf-8") == "hello"
        assert (res.path / "sub" / "top" / "a.txt").read_text(encoding="utf-8") == "hello"

    other = src / "other"
    other.mkdir()
    (other / "f.txt").write_text("in the bundle", encoding="utf-8")
    os.symlink("../other/f.txt", src / "photos" / "next")
    enc = engine.encrypt_paths([photos, other], tmp_path / "enc2", EncryptOptions(password="pw", **FAST),
                               bundle_name="both")
    res = engine.decrypt_path(enc, tmp_path / "out", PW)
    assert os.path.islink(res.path / "photos" / "next")
    if not osutil.IS_WINDOWS:
        assert (res.path / "photos" / "next").read_text(encoding="utf-8") == "in the bundle"
    # A bundle keeps every item, so its links are checked against the bundle folder: "../.ssh" stays inside it.
    assert res.skipped == ["photos/deep"]
    assert os.path.realpath(res.path / "photos" / "ssh").startswith(os.path.realpath(res.path) + os.sep)


def test_recovery_data_is_no_more_readable_than_its_file(tmp_path):
    """B2: an unencrypted file's sidecar can rebuild it, so it gets the file's read permissions, not 0644."""
    from locksmith.core import parity
    if osutil.IS_WINDOWS:
        pytest.skip("POSIX modes")
    private = tmp_path / "diary.txt"
    private.write_bytes(b"the safe code is 4711 " * 400)
    os.chmod(private, 0o600)
    assert stat.S_IMODE(parity.create(private).stat().st_mode) == 0o600
    shared = tmp_path / "x.locked"
    shared.write_bytes(b"LOCKED\x00\x02" + os.urandom(5000))
    os.chmod(shared, 0o644)
    assert stat.S_IMODE(parity.create(shared).stat().st_mode) == 0o644


def test_shredding_a_file_shreds_its_recovery_data(tmp_path, monkeypatch):
    """B2: the sidecar of a shredded file goes with it (overwritten, not just deleted)."""
    from locksmith.core import parity
    f = tmp_path / "diary.txt"
    f.write_bytes(b"secret " * 1000)
    side = parity.create(f)
    keep = tmp_path / "other.txt"
    keep.write_bytes(b"x")
    overwritten = []
    real = tools._shred
    monkeypatch.setattr(tools, "_shred", lambda p, *a: (overwritten.append(Path(p).name), real(p, *a))[1])
    tools.shred(f, recovery_data=True)
    assert not f.exists() and not side.exists() and overwritten == ["diary.txt", "diary.txt.lpar"]
    tools.shred(keep, recovery_data=True)   # no sidecar: nothing else touched
    assert overwritten[-1] == "other.txt"
    g = tmp_path / "g.txt"
    g.write_bytes(b"y")
    side = parity.create(g)
    tools.shred(g)   # without the flag (temporary plaintext, for one), only the file
    assert side.exists()


def test_stripping_metadata_leaves_out_when_the_file_was_made():
    """Smaller note: with metadata stripped, neither the metadata nor the signature says when the file
    was encrypted; without it, both do as before."""
    from locksmith.core import signing
    signer = os.urandom(96)
    verifiers = [signing.public_key(signer)]
    for strip in (True, False):
        blob = engine.encrypt_bytes(b"x", EncryptOptions(password="pw", signer=signer, strip_metadata=strip, **FAST))
        res = engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=verifiers))
        assert res.signature.verified
        assert ("created" in res.meta) is not strip and (res.signature.created == 0) is strip
