"""Mutation fuzzing of every parser that reads input from someone else.

The invariant: any input may only produce a LocksmithError (or succeed), never another
exception. Each target mutates a valid seed input with a fixed random seed, so a failure
is reproducible from its target name and iteration number.

The normal test run uses a small budget. For a long run:

    LOCKSMITH_FUZZ=20000 .venv/bin/pytest tests/test_fuzz.py -x
"""

import base64
import hashlib
import io
import json
import os
import random
import struct
import tarfile

import fileformat
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from locksmith.core import engine, keys, metadata, minisign, signing, sshsig, tools
from locksmith.core.engine import DecryptKeys, EncryptOptions
from locksmith.core.errors import LocksmithError

ITERATIONS = int(os.environ.get("LOCKSMITH_FUZZ", "150"))
INTERESTING = [b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\x7f\xff\xff\xff", b"\x80\x00\x00\x00",
               b"\x00\x00\x00\x01", b"\x00\x10\x00\x00"]


def mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(7)
        pos = rng.randrange(len(b) + 1)
        if op == 0 and b:
            b[min(pos, len(b) - 1)] ^= 1 << rng.randrange(8)
        elif op == 1 and b:
            b[min(pos, len(b) - 1)] = rng.randrange(256)
        elif op == 2:
            b[pos:pos] = rng.randbytes(rng.randint(1, 16))
        elif op == 3 and b:
            del b[pos:pos + rng.randint(1, 32)]
        elif op == 4 and b:
            start = rng.randrange(len(b))
            b[pos:pos] = b[start:start + rng.randint(1, 64)]
        elif op == 5:
            b[pos:pos + 4] = rng.choice(INTERESTING)
        else:
            b[pos:] = b""   # truncate
    return bytes(b)


def mutate_text(rng: random.Random, text: str) -> str:
    return mutate(rng, text.encode()).decode("utf-8", errors="replace")


def fuzz(name: str, seed, fn, convert=mutate):
    rng = random.Random(f"{name}-{ITERATIONS}")
    for i in range(ITERATIONS):
        sample = seed(rng) if callable(seed) else convert(rng, seed)
        try:
            fn(sample)
        except LocksmithError:
            pass
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"{name}, iteration {i}: {type(e).__name__}: {e}\ninput: {sample!r:.400}") from e


# ── seeds ────────────────────────────────────────────────────────────────────

FAST = dict(kdf="pbkdf2-sha512", preset="fast")


@pytest.fixture(scope="module")
def ident():
    return os.urandom(32)


@pytest.fixture(scope="module")
def recipient_file(ident):
    pub = keys.public_from_private(ident)
    return engine.encrypt_bytes(b"hello fuzz " * 300, EncryptOptions(recipients=[pub], chunk_size=1024,
                                                                   compression="zlib", **FAST))


def _forge(ident: bytes, frames: list[bytes], meta_raw: bytes, chunk=1024) -> bytes:
    """A correctly encrypted message whose frame plaintexts and metadata we choose."""
    opts = EncryptOptions(recipients=[keys.public_from_private(ident)], chunk_size=chunk, **FAST)
    return fileformat.forge(opts, {"kind": "file"}, frames, meta_raw)


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ── file format ──────────────────────────────────────────────────────────────

def test_fuzz_header_parser(recipient_file):
    fuzz("header", recipient_file[:2048], engine.inspect_bytes)


def test_fuzz_header_json_structure(recipient_file):
    """Swap header values for values of other types and shapes, keeping valid JSON."""
    header, _ = fileformat.split(recipient_file)
    header.pop("_fixed_raw")
    odd = [None, True, 0, -1, 2**63, 1.5, "", "x" * 100, "AAAA", [], {}, [1, 2], {"t": "pw"}]

    def sample(rng):
        h = json.loads(json.dumps(header))
        for _ in range(rng.randint(1, 3)):
            target, key = h, rng.choice(list(h))
            if isinstance(h[key], dict) and h[key] and rng.random() < 0.5:
                target, key = h[key], rng.choice(list(h[key]))
            elif isinstance(h[key], list) and h[key] and rng.random() < 0.5:
                slot = rng.choice(h[key])
                if isinstance(slot, dict) and slot:
                    target, key = slot, rng.choice(list(slot))
            target[key] = json.loads(json.dumps(rng.choice(odd)))  # a fresh copy each time
        return fileformat.join(h, b"")

    fuzz("header-json", sample, engine.inspect_bytes)


def test_fuzz_whole_file_decrypt(recipient_file, ident):
    fuzz("decrypt", recipient_file, lambda b: engine.decrypt_bytes(b, DecryptKeys(identities=[ident])))


def test_fuzz_signed_file(ident):
    signer = os.urandom(96)
    blob = engine.encrypt_bytes(b"signed fuzz " * 300, EncryptOptions(
        recipients=[keys.public_from_private(ident)], chunk_size=1024, signer=signer, **FAST))
    dk = DecryptKeys(identities=[ident], verifiers=[signing.public_key(signer)])
    assert engine.decrypt_bytes(blob, dk).signature.verified
    fuzz("signed-file", blob, lambda b: engine.decrypt_bytes(b, dk))


def test_fuzz_signature_frames(ident):
    """A sender holding the file key controls the signature frames' contents completely."""
    signer = os.urandom(96)
    public = signing.public_key(signer)
    seed = signing.sign_locked(signer, b"{}", bytes(64))
    meta = b'{"name":"a.txt","kind":"file","comp":"none"}'

    def sample(rng):
        sig = mutate(rng, seed)
        size = rng.choice([1024, 4096])
        parts = [sig[i:i + size] for i in range(0, len(sig), size)] or [b""]
        return _forge(ident, [engine.FRAME_HDR.pack(0, 2) + b"hi",
                              *(engine.FRAME_HDR.pack(engine.KIND_SIG, len(p)) + p for p in parts)], meta, size)

    fuzz("signature-frames", sample,
         lambda b: engine.decrypt_bytes(b, DecryptKeys(identities=[ident], verifiers=[public])))


def test_fuzz_authenticated_plaintext(ident):
    """A sender holding a valid key controls frame contents and metadata completely."""
    frames = [engine.FRAME_HDR.pack(1, 0) + b"", engine.FRAME_HDR.pack(0, 5) + b"hello",
              engine.FRAME_HDR.pack(2, 0) + bytes(16)]
    zlib_frame = engine.FRAME_HDR.pack(1, 0) + tools.hashlib.sha256(b"").digest()
    metas = [b'{"name":"a.txt","kind":"file","comp":"zlib","size":5}', b'{"kind":"dir","comp":"none"}']

    def sample(rng):
        fr = [mutate(rng, rng.choice(frames + [zlib_frame])) for _ in range(rng.randint(1, 3))]
        meta = mutate(rng, rng.choice(metas)) if rng.random() < 0.5 else rng.choice(metas)
        return _forge(ident, fr, meta)

    fuzz("plaintext", sample, lambda b: engine.decrypt_bytes(b, DecryptKeys(identities=[ident])))


def test_fuzz_folder_archive(tmp_path):
    seed = _tar({"proj/a.txt": b"a" * 600, "proj/sub/b.txt": b"b", "proj/" + "n" * 150: b"long"})
    counter = iter(range(10**9))

    def run(data):
        path = tmp_path / "x.tar"
        path.write_bytes(data)
        engine.extract_archive(path, tmp_path / f"out{next(counter)}")

    fuzz("archive", seed, run)


def test_fuzz_armor(recipient_file):
    fuzz("armor", engine.armor(recipient_file[:600]), engine.dearmor, mutate_text)


# ── keys, shares and backups ─────────────────────────────────────────────────

def test_fuzz_public_keys():
    private = os.urandom(96)
    for raw in (os.urandom(32), keys.public_from_private(private),
                keys.public_from_private(private) + keys.verify_key(private)):
        fuzz(f"public-key-{len(raw)}", keys.encode_public(raw), keys.decode_public, mutate_text)


def test_fuzz_shares_and_words():
    shares = "\n".join(tools.shamir_split(b"secret password", 2, 3))
    fuzz("shares", shares, lambda t: tools.shamir_combine(t.split()), mutate_text)
    v2 = ("locksmithshare2-2-1-b2a5bd73-4f90d9e19b16f5038af06a9901e0cba19d-5c8554\n"
          "locksmithshare2-2-2-b2a5bd73-046dc94c828967a9937f492914f1a8d419-26ea5f")   # still read
    fuzz("shares-v2", v2, lambda t: tools.shamir_combine(t.split()), mutate_text)
    id_shares = "\n".join(keys.identity_shares(os.urandom(32), 2, 3))
    fuzz("identity-shares", id_shares, lambda t: keys.private_from_shares(t.split()), mutate_text)
    fuzz("words", " ".join(keys.backup_words(os.urandom(96))), keys.private_from_words, mutate_text)


def test_fuzz_identity_backup(tmp_path):
    store = keys.KeyStore(tmp_path / "src")
    ident = store.generate("me", post_quantum=False)
    store.export_identity(ident, tmp_path / "backup.json")
    seed = (tmp_path / "backup.json").read_text(encoding="utf-8")
    target = keys.KeyStore(tmp_path / "dst")

    def run(text):
        (tmp_path / "evil.json").write_text(text, encoding="utf-8")
        try:
            target.import_identity(tmp_path / "evil.json")
        finally:
            target.identities.clear()

    fuzz("identity-backup", seed, run, mutate_text)


def test_fuzz_key_store(tmp_path):
    src = keys.KeyStore(tmp_path / "seed")
    src.generate("me", post_quantum=False)
    src.generate("signer")   # hybrid, with its cached verify keys
    src.add_contact("friend", keys.encode_public(keys.public_from_private(os.urandom(32))))
    private = os.urandom(96)
    src.add_contact("signing friend", keys.encode_public(keys.public_from_private(private) + keys.verify_key(private)))
    seed = (tmp_path / "seed" / "keys.json").read_text(encoding="utf-8")
    counter = iter(range(10**9))

    def run(text):
        d = tmp_path / f"s{next(counter)}"
        d.mkdir()
        (d / "keys.json").write_text(text, encoding="utf-8")
        store = keys.KeyStore(d)
        store.unlocked_private_keys()
        store.save()

    fuzz("key-store", seed, run, mutate_text)


# ── tools ────────────────────────────────────────────────────────────────────

def test_fuzz_minisign(tmp_path):
    sk = Ed25519PrivateKey.generate()
    key_id, f = os.urandom(8), tmp_path / "f"
    f.write_bytes(b"signed data")
    sig = sk.sign(hashlib.blake2b(b"signed data", digest_size=64).digest())
    comment = "timestamp:1\tfile:f"
    sig_text = ("untrusted comment: x\n" + base64.b64encode(b"ED" + key_id + sig).decode() + "\ntrusted comment: "
                + comment + "\n" + base64.b64encode(sk.sign(sig + comment.encode())).decode() + "\n")
    pub = base64.b64encode(b"Ed" + key_id + sk.public_key().public_bytes_raw()).decode()
    assert minisign.verify_file(f, sig_text, pub).trusted_comment == comment
    fuzz("minisign-sig", sig_text, lambda t: minisign.verify_file(f, t, pub), mutate_text)
    fuzz("minisign-key", pub, lambda t: minisign.verify_file(f, sig_text, t), mutate_text)


def test_fuzz_signing(tmp_path):
    private = os.urandom(96)
    public = keys.public_from_private(private) + keys.verify_key(private)
    f = tmp_path / "f"
    f.write_bytes(b"signed data")
    text = signing.sign_file(f, private, "a comment ✓")
    assert signing.verify_file(f, text, [public]).comment == "a comment ✓"
    blob = base64.b64decode("".join(text.split()[3:-3]))
    fuzz("signing-blob", blob, lambda b: signing.verify_file(f, signing.armor(b), [public]))
    fuzz("signing-text", text, lambda t: signing.verify_file(f, t, [public]), mutate_text)


def test_fuzz_sshsig():
    folder = os.path.join(os.path.dirname(__file__), "interop", "sshsig")
    f = os.path.join(folder, "message.bin")
    for name in ("ed25519", "rsa3072", "ecdsa256"):
        sig_text = sshsig.read_small(os.path.join(folder, f"{name}.sig"))
        pub = sshsig.read_small(os.path.join(folder, f"{name}.pub"))
        assert sshsig.verify_file(f, sig_text, pub).namespace == "file"
        blob = base64.b64decode("".join(sig_text.split()[3:-3]))

        def armored(b: bytes, pub=pub):
            return sshsig.verify_file(f, f"{sshsig.ARMOR_BEGIN}\n{base64.b64encode(b).decode()}\n"
                                         f"{sshsig.ARMOR_END}", pub)

        fuzz(f"sshsig-blob-{name}", blob, armored)
        fuzz(f"sshsig-text-{name}", sig_text, lambda t, pub=pub: sshsig.verify_file(f, t, pub), mutate_text)
        fuzz(f"sshsig-key-{name}", pub, lambda t, s=sig_text: sshsig.verify_file(f, s, t), mutate_text)


def test_fuzz_manifest(tmp_path):
    folder = tmp_path / "folder"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_text("a", encoding="utf-8")
    (folder / "sub" / "b.txt").write_text("b", encoding="utf-8")
    seed = tools.make_manifest(folder, "sha256") + "\\SHA512 (x\\\\y) = " + "0" * 128 + "\n"
    fuzz("manifest", seed, lambda t: tools.verify_manifest(t, folder), mutate_text)


@pytest.mark.parametrize("kind", ["jpeg", "png", "webp"])
def test_fuzz_image_metadata(tmp_path, kind):
    seeds = {
        "jpeg": (b"\xff\xd8" + b"\xff\xe0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00"
                 + b"\xff\xe1\x00\x1eExif\x00\x00MM\x00\x2a\x00\x00\x00\x08\x00\x01\x01\x12\x00\x03\x00\x00"
                 + b"\x00\x01\x00\x06\x00\x00" + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x12\x34\xff\xd9"),
        "png": (b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 13) + b"IHDR" + bytes(13) + bytes(4)
                + struct.pack(">I", 4) + b"tEXt" + b"abcd" + bytes(4) + struct.pack(">I", 0) + b"IEND" + bytes(4)),
        "webp": (b"RIFF" + struct.pack("<I", 4 + 18 + 12) + b"WEBP" + b"VP8X" + struct.pack("<I", 10) + bytes(10)
                 + b"EXIF" + struct.pack("<I", 4) + b"abcd"),
    }
    path = tmp_path / f"img.{kind}"

    def run(data):
        path.write_bytes(data)
        plan = metadata.plan_for(path)
        if plan is not None:
            with metadata.PlanReader(path, plan.plan) as r:
                r.read()

    fuzz(f"image-{kind}", seeds[kind], run)


def test_fuzz_icc_profile():
    """ICC profiles come from whoever made the image: scrubbing returns a profile or None, never crashes."""
    tag = b"desc" + bytes(4) + struct.pack(">I", 5) + b"name\x00"
    header = bytearray(128)
    header[36:40] = b"acsp"
    table = struct.pack(">I", 2) + struct.pack(">4sII", b"desc", 156, len(tag)) + struct.pack(">4sII", b"dmnd", 156,
                                                                                             len(tag))
    seed = bytearray(header + table + tag)
    seed[:4] = struct.pack(">I", len(seed))
    assert metadata.scrub_icc(bytes(seed)) is not None

    def run(data):
        out = metadata.scrub_icc(data)
        assert out is None or len(out) == len(data)

    fuzz("icc", bytes(seed), run)


# ── age files, SSH recipients, changed slots ─────────────────────────────────

def test_fuzz_age_file():
    """age headers, stanzas and payloads, read with every kind of key we hold."""
    from locksmith.core import age
    sk, hybrid = os.urandom(32), os.urandom(96)
    blobs = []
    for recipient in (age.Recipient("X25519", keys.public_from_private(sk)),
                      age.recipient_for(keys.public_from_private(hybrid))):
        out = io.BytesIO()
        age.encrypt_stream(io.BytesIO(os.urandom(100) + b"x" * 70_000), out, [recipient])
        blobs.append(out.getvalue())
    out = io.BytesIO()
    age.encrypt_stream(io.BytesIO(b"pw"), out, [], "pw", work_factor=1)
    blobs.append(out.getvalue())
    k = age.Keys(identities=[sk, hybrid], passphrase="pw")
    rng0 = random.Random("age-seeds")
    fuzz("age file", lambda rng: mutate(rng, rng0.choice(blobs)),
         lambda b: age.decrypt_stream(io.BytesIO(b), io.BytesIO(), k))


def test_fuzz_age_armor_and_keys():
    from locksmith.core import age
    text = age.armor(os.urandom(500)).encode()
    fuzz("age armor", text, age.dearmor)
    fuzz("age recipient", age.recipient_text(keys.public_from_private(os.urandom(96))),
         age.parse_recipient_key, mutate_text)
    fuzz("age identity", "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX",
         age.parse_identity, mutate_text)


def test_fuzz_ssh_recipients():
    from pathlib import Path

    from locksmith.core import sshkeys
    here = Path(__file__).parent / "interop" / "sshkeys"
    for name in ("id_ed25519.pub", "id_rsa3072.pub"):
        fuzz(f"ssh recipient {name}", (here / name).read_text(encoding="utf-8"), sshkeys.parse_recipient, mutate_text)
    for name in ("id_ed25519", "id_ed25519_protected", "id_rsa3072_protected.pem"):
        fuzz(f"ssh private key {name}", (here / name).read_bytes(), lambda b: sshkeys.load_identity(b, "x"))


def test_fuzz_rsa_slots(ident):
    """A file with an ssh-rsa slot, mutated, read by an RSA identity."""
    from pathlib import Path

    from locksmith.core import sshkeys
    here = Path(__file__).parent / "interop" / "sshkeys"
    rsa = sshkeys.parse_recipient((here / "id_rsa3072.pub").read_text(encoding="utf-8"))
    rsa_ident = sshkeys.load_identity(sshkeys.read_private(here / "id_rsa3072"))
    blob = engine.encrypt_bytes(b"x" * 3000, EncryptOptions(recipients=[rsa.raw, keys.public_from_private(ident)]))
    k = DecryptKeys(identities=[ident], ssh=[rsa_ident])
    fuzz("rsa slots", blob, lambda b: engine.decrypt_bytes(b, k))


def test_fuzz_openpgp():
    from pathlib import Path

    from locksmith.core import openpgp
    here = Path(__file__).parent / "interop" / "openpgp"
    msg = here / "message.bin"
    for sig, key in (("ed25519.sig", "ed25519.gpg"), ("rsa-subkey.sig", "rsa.gpg"), ("p256.sig.asc", "p256.asc")):
        sig_data = (here / sig).read_bytes() if (here / sig).exists() else (here / "ed25519.sig.asc").read_bytes()
        key_data = (here / key).read_bytes()
        fuzz(f"openpgp key {key}", key_data, lambda k, s=sig_data: openpgp.verify_file(msg, s, k))
        fuzz(f"openpgp signature {sig}", sig_data, lambda s, k=key_data: openpgp.verify_file(msg, s, k))


def test_fuzz_qr_reader():
    """The QR reader takes photos from anywhere: damaged grids and images may only fail cleanly."""
    import segno

    from locksmith.core import qrdecode
    text = keys.paper_qr_text(os.urandom(96))
    grid = [[int(bool(v)) for v in row] for row in segno.make(text, error="q").matrix]
    flat = bytes(v for row in grid for v in row)
    n = len(grid)

    def from_flat(rng):
        b = bytearray(flat)
        for _ in range(rng.randint(1, 120)):
            b[rng.randrange(len(b))] ^= 1
        return [list(b[i * n:(i + 1) * n]) for i in range(n)]

    def decode_grid(g):
        try:
            qrdecode.decode_grid(g)
        except qrdecode._Fail:
            pass
    fuzz("qr grid", from_flat, decode_grid)

    scale, quiet = 2, 4
    side = (n + 2 * quiet) * scale
    image = bytearray([230]) * side * side
    for y in range(n):
        for x in range(n):
            if grid[y][x]:
                for dy in range(scale):
                    start = ((y + quiet) * scale + dy) * side + (x + quiet) * scale
                    image[start:start + scale] = bytes([20]) * scale

    def damaged(rng):
        b = bytearray(image)
        for _ in range(rng.randint(1, 1500)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        return bytes(b)
    fuzz("qr image", damaged, lambda px: qrdecode.decode(side, side, px))


def test_fuzz_recovery_data(tmp_path):
    from locksmith.core import parity
    f = tmp_path / "data.bin"
    f.write_bytes(os.urandom(60_000))
    good = parity.create(f, "20").read_bytes()
    side = tmp_path / "mutated.lpar"

    def run(blob):
        side.write_bytes(blob)
        parity.check(f, side)
    fuzz("recovery data", good, run)
