"""age files (locksmith/core/age.py): the C2SP CCTV test kit made by the age authors
(tests/interop/age-cctv), and round trips with Locksmith's own keys."""

import hashlib
import io
import zlib
from pathlib import Path

import pytest

from locksmith.core import age
from locksmith.core.errors import WrongKeyError

KIT = Path(__file__).parent / "interop" / "age-cctv" / "testdata"
VECTORS = sorted(p.name for p in KIT.iterdir())
EXPECT = {"header failure": age.AgeHeaderError, "HMAC failure": age.AgeMacError,
          "payload failure": age.AgePayloadError, "armor failure": age.AgeArmorError, "no match": WrongKeyError}


def _vector(name: str) -> tuple[dict, bytes]:
    raw = (KIT / name).read_bytes()
    head, _, body = raw.partition(b"\n\n")
    fields: dict[str, list[str]] = {}
    for line in head.decode().splitlines():
        key, _, value = line.partition(": ")
        fields.setdefault(key, []).append(value)
    if fields.get("compressed") == ["zlib"]:
        body = zlib.decompress(body)
    return fields, body


@pytest.mark.parametrize("name", VECTORS)
def test_cctv_vector(name):
    fields, body = _vector(name)
    keys = age.Keys(identities=[age.parse_identity(i) for i in fields.get("identity", [])],
                    passphrase=(fields.get("passphrase") or [None])[0])
    out = io.BytesIO()
    expect = fields["expect"][0]
    try:
        blob = age.dearmor(body) if fields.get("armored") == ["yes"] else body
        age.decrypt_stream(io.BytesIO(blob), out, keys)
    except Exception as e:  # noqa: BLE001
        assert expect != "success", f"{name}: {type(e).__name__}: {e}"
        assert isinstance(e, EXPECT[expect]), f"{name}: expected {expect}, got {type(e).__name__}: {e}"
    else:
        assert expect == "success", f"{name}: decrypted, but expected {expect}"
    if "payload" in fields:
        assert hashlib.sha256(out.getvalue()).hexdigest() == fields["payload"][0], name


# ── keys ─────────────────────────────────────────────────────────────────────

SPEC_KEYS = __import__("json").loads((KIT.parent / "spec-keys.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("kind", ["pq", "x25519"])
def test_spec_example_keys_map_onto_locksmith_keys(kind):
    """An age identity becomes a Locksmith private key whose public key is the same age recipient:
    for post-quantum keys, X-Wing's expansion gives exactly Locksmith's hybrid layout."""
    from locksmith.core import keys
    raw = age.parse_identity(SPEC_KEYS[f"{kind}_identity"])
    assert len(raw) == (96 if kind == "pq" else 32)
    public = keys.public_from_private(raw)
    assert age.recipient_text(public) == SPEC_KEYS[f"{kind}_recipient"]
    assert age.parse_recipient_key(SPEC_KEYS[f"{kind}_recipient"]) == public


def test_bech32_typos_are_caught():
    good = SPEC_KEYS["x25519_recipient"]
    for bad in (good[:-1] + ("q" if good[-1] != "q" else "p"), good.upper()[:10] + good[10:], good + "x", "age1",
                "age1" + "q" * 70):
        with pytest.raises(age.LocksmithError):
            age.parse_recipient_key(bad)
    assert age.parse_recipient_key(good.upper()) == age.parse_recipient_key(good)   # all upper case is allowed
    with pytest.raises(age.LocksmithError):
        age.parse_identity(good)


# ── writing ──────────────────────────────────────────────────────────────────

def _roundtrip(data: bytes, recipients, keys: age.Keys, passphrase=None) -> bytes:
    out = io.BytesIO()
    age.encrypt_stream(io.BytesIO(data), out, recipients, passphrase, work_factor=10)
    plain = io.BytesIO()
    age.decrypt_stream(io.BytesIO(out.getvalue()), plain, keys)
    return plain.getvalue()


@pytest.mark.parametrize("size", [0, 1, age.CHUNK - 1, age.CHUNK, age.CHUNK + 1, 3 * age.CHUNK])
def test_chunk_boundaries(size):
    import os
    data = os.urandom(size)
    sk = os.urandom(32)
    from locksmith.core.keys import public_from_private
    assert _roundtrip(data, [age.Recipient("X25519", public_from_private(sk))], age.Keys(identities=[sk])) == data


def test_post_quantum_and_classical_locksmith_identities():
    import os

    from locksmith.core.keys import public_from_private
    hybrid, classical = os.urandom(96), os.urandom(32)
    data = b"pq"
    assert _roundtrip(data, [age.recipient_for(public_from_private(hybrid))], age.Keys(identities=[hybrid])) == data
    # A hybrid identity also opens an X25519 stanza for its classical half.
    assert _roundtrip(data, [age.Recipient("X25519", public_from_private(hybrid)[:32])],
                      age.Keys(identities=[hybrid])) == data
    with pytest.raises(WrongKeyError):
        _roundtrip(data, [age.recipient_for(public_from_private(hybrid))], age.Keys(identities=[classical]))
    with pytest.raises(age.LocksmithError, match="mix"):
        _roundtrip(data, [age.recipient_for(public_from_private(hybrid)),
                          age.recipient_for(public_from_private(classical))], age.Keys())


def test_passphrase():
    assert _roundtrip(b"pw", [], age.Keys(passphrase="correct horse"), passphrase="correct horse") == b"pw"
    with pytest.raises(WrongKeyError):
        _roundtrip(b"pw", [], age.Keys(passphrase="wrong"), passphrase="correct horse")
    with pytest.raises(age.LocksmithError, match="not both"):
        _roundtrip(b"pw", [age.Recipient("X25519", bytes(32))], age.Keys(), passphrase="x")


def test_ssh_stanzas_match_age():
    from locksmith.core import sshkeys
    ssh = Path(__file__).parent / "interop" / "sshkeys"
    for name in ("id_ed25519", "id_rsa3072"):
        pub = sshkeys.parse_recipient((ssh / f"{name}.pub").read_text(encoding="utf-8"))
        rcpt = age.recipient_for(pub.raw, pub.blob if name == "id_ed25519" else None)
        out = io.BytesIO()
        age.encrypt_stream(io.BytesIO(b"ssh"), out, [rcpt])
        header = age.read_header(io.BytesIO(out.getvalue()))
        st = header.stanzas[0]
        assert st.type == rcpt.kind.encode() and st.args[1] == age._ssh_tag(pub.blob)
        ident = sshkeys.load_identity(sshkeys.read_private(ssh / name))
        plain = io.BytesIO()
        age.decrypt_stream(io.BytesIO(out.getvalue()), plain, age.Keys(ssh=[ident]))
        assert plain.getvalue() == b"ssh"


def test_armor_round_trip_and_strictness():
    blob = bytes(range(256)) * 3
    text = age.armor(blob)
    assert age.dearmor(text.encode()) == blob
    assert age.dearmor(b"\n  " + text.replace("\n", "\r\n").encode() + b"  \n") == blob
    lines = text.splitlines()
    for bad in ("\n".join(lines[:1] + [lines[1][:-1]] + lines[2:]),        # a short line before the last
                "\n".join(lines[:1] + ["Comment: x", ""] + lines[1:]),     # headers
                text.replace(age.ARMOR_END, "-----END PGP MESSAGE-----"),
                "x" + text):
        with pytest.raises(age.AgeArmorError):
            age.dearmor(bad.encode())


def test_files_and_folders(tmp_path):
    import os
    sk = os.urandom(32)
    from locksmith.core.keys import public_from_private
    rcpt = [age.Recipient("X25519", public_from_private(sk))]
    src = tmp_path / "report.pdf"
    src.write_bytes(b"%PDF " + os.urandom(100_000))
    enc = age.encrypt_paths([src], tmp_path / "enc", rcpt, verify=True)
    assert enc.name == "report.pdf.age" and age.is_age_file(enc)
    res = age.decrypt_path(enc, tmp_path / "dec", age.Keys(identities=[sk]))
    assert res.path.name == "report.pdf" and res.path.read_bytes() == src.read_bytes()
    folder = tmp_path / "proj"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "a.txt").write_text("a", encoding="utf-8")
    enc = age.encrypt_paths([folder], tmp_path / "enc", rcpt, armored=True)
    assert enc.name == "proj.tar.age" and enc.read_bytes().startswith(age.ARMOR_BEGIN.encode())
    res = age.decrypt_path(enc, tmp_path / "dec", age.Keys(identities=[sk]))
    import tarfile
    with tarfile.open(res.path) as tar:
        assert "proj/sub/a.txt" in tar.getnames()
    assert age.inspect(enc).stanza_types == ["X25519"]


def test_wrong_key_or_damage_writes_nothing(tmp_path):
    import os
    sk = os.urandom(32)
    from locksmith.core.keys import public_from_private
    src = tmp_path / "a.txt"
    src.write_bytes(b"x" * 200_000)
    enc = age.encrypt_paths([src], tmp_path / "enc", [age.Recipient("X25519", public_from_private(sk))])
    out = tmp_path / "dec"
    with pytest.raises(WrongKeyError):
        age.decrypt_path(enc, out, age.Keys(identities=[os.urandom(32)]))
    data = bytearray(enc.read_bytes())
    data[-100] ^= 1
    enc.write_bytes(bytes(data))
    with pytest.raises(age.AgePayloadError):
        age.decrypt_path(enc, out, age.Keys(identities=[sk]))
    assert list(out.iterdir()) == []


def test_verify_catches_corruption_on_disk(tmp_path, monkeypatch):
    import os
    src = tmp_path / "a.bin"
    src.write_bytes(os.urandom(200_000))
    real = age.encrypt_stream

    def corrupt(src_, out, *a, **k):
        key = real(src_, out, *a, **k)
        out.seek(-50, os.SEEK_END)
        out.write(b"\x00" * 10)
        return key
    monkeypatch.setattr(age, "encrypt_stream", corrupt)
    with pytest.raises(age.AgePayloadError):
        age.encrypt_paths([src], tmp_path / "enc", [age.Recipient("X25519", os.urandom(32))], verify=True)
    assert list((tmp_path / "enc").iterdir()) == []


@pytest.mark.parametrize("name", ["ed25519", "rsa3072"])
def test_rage_ssh_files(name):
    """ssh-ed25519 and ssh-rsa stanzas written by rage (tests/interop/age-rage) open with the SSH key."""
    from locksmith.core import sshkeys
    here = KIT.parent.parent / "age-rage"
    ident = sshkeys.load_identity(sshkeys.read_private(KIT.parent.parent / "sshkeys" / f"id_{name}"))
    out = io.BytesIO()
    age.decrypt_stream(io.BytesIO((here / f"{name}.age").read_bytes()), out, age.Keys(ssh=[ident]))
    assert out.getvalue() == (here / "message.txt").read_bytes()
