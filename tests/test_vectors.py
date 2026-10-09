"""Committed test vectors (tests/vectors) must keep opening, with the engine and with an
second reader written from docs/FORMAT.md. A failure here means this build can no
longer read files an earlier one wrote, or the specification no longer matches."""

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
import spec_reader

from locksmith.core import engine
from locksmith.core.engine import DecryptKeys

HERE = Path(__file__).parent / "vectors"
VECTORS = json.loads((HERE / "vectors.json").read_text(encoding="utf-8"))


def _unlock(v: dict, tmp_path: Path) -> tuple[dict, DecryptKeys]:
    keyfile = bytes.fromhex(VECTORS["keyfile"]) if v["unlock"].get("keyfile") else None
    ident = v["unlock"].get("identity")
    raw = bytes.fromhex(VECTORS["identities"][ident]) if ident else None
    spec = {"password": v["unlock"].get("password"), "keyfile": keyfile, "identity": raw}
    path = None
    if keyfile is not None:
        path = tmp_path / "keyfile"
        path.write_bytes(keyfile)
    return spec, DecryptKeys(password=spec["password"], keyfile=path and str(path), identities=[raw] if raw else [])


def _blob(v: dict) -> bytes:
    data = (HERE / v["file"]).read_bytes()
    return spec_reader.dearmor(data.decode()) if v["file"].endswith(".txt") else data


@pytest.mark.parametrize("v", VECTORS["files"], ids=[v["name"] for v in VECTORS["files"]])
def test_vector_opens_with_the_specification(v, tmp_path):
    spec, _ = _unlock(v, tmp_path)
    r = spec_reader.read(_blob(v), **spec)
    assert r["dek"].hex() == v["dek"]
    assert r["header"]["suite"] == v["suite"] and len(r["header"]["slots"]) == v["slots"]
    assert {k: r["meta"][k] for k in v["meta"]} == v["meta"]
    assert hashlib.sha256(r["content"]).hexdigest() == v["content_sha256"]


@pytest.mark.parametrize("v", VECTORS["files"], ids=[v["name"] for v in VECTORS["files"]])
def test_vector_opens_with_the_engine(v, tmp_path):
    spec, keys = _unlock(v, tmp_path)
    if v["meta"]["kind"] != "dir":
        res = engine.decrypt_bytes(_blob(v), keys)
        assert hashlib.sha256(res.data).hexdigest() == v["content_sha256"]
        return
    res = engine.decrypt_path(HERE / v["file"], tmp_path / "out", keys)
    archive = tarfile.open(fileobj=io.BytesIO(spec_reader.read(_blob(v), **spec)["content"]))
    files = [m for m in archive.getmembers() if m.isfile()]
    assert files
    for m in files:
        inside = Path(*Path(m.name).parts[1:])   # the top-level folder is unwrapped into res.path
        assert (res.path / inside).read_bytes() == archive.extractfile(m).read()


@pytest.mark.parametrize("vectors", ["v1", "v2"])
def test_every_suite_and_codec_has_a_vector(vectors):
    from locksmith.core import compress
    from locksmith.core.ciphers import SUITES
    files = (VECTORS if vectors == "v1" else V2)["files"]
    covered = {v["suite"] for v in files}
    codecs = {v["meta"]["comp"] for v in files}
    assert set(SUITES) <= covered, f"no vector for {set(SUITES) - covered}"
    assert set(compress.CODECS) <= codecs, f"no vector for {set(compress.CODECS) - codecs}"


# ── format version 2 (FORMAT.md §1–7, §15) ───────────────────────────────────

V2 = json.loads((HERE / "v2-vectors.json").read_text(encoding="utf-8"))


def _signer_public() -> bytes:
    return spec_reader.public3(bytes.fromhex(VECTORS["identities"][V2["signer"]]))


@pytest.mark.parametrize("v", V2["files"], ids=[v["name"] for v in V2["files"]])
def test_v2_vector_opens_with_the_specification(v, tmp_path):
    spec, _ = _unlock(v, tmp_path)
    blob = _blob(v)
    assert blob[:8] == b"LOCKED\x00\x02"
    r = spec_reader.read(blob, **spec, verifiers=(_signer_public(),))
    assert r["dek"].hex() == v["dek"]
    assert r["header"]["suite"] == v["suite"] and len(r["slots"]) == v["slots"]
    assert {k: r["meta"][k] for k in v["meta"]} == v["meta"]
    assert hashlib.sha256(r["content"]).hexdigest() == v["content_sha256"]
    if v["signed_at"] is None:
        assert r["signature"] is None
    else:
        assert r["signature"]["status"] == "valid" and r["signature"]["created"] == v["signed_at"]
        assert spec_reader.read(blob, **spec)["signature"]["status"] == "unknown"   # signer not trusted


@pytest.mark.parametrize("v", V2["files"], ids=[v["name"] for v in V2["files"]])
def test_v2_vector_opens_with_the_engine(v, tmp_path):
    spec, keys = _unlock(v, tmp_path)
    keys.verifiers = [_signer_public()]
    if v["meta"]["kind"] != "dir":
        res = engine.decrypt_bytes(_blob(v), keys)
        assert hashlib.sha256(res.data).hexdigest() == v["content_sha256"]
    else:
        res = engine.decrypt_path(HERE / v["file"], tmp_path / "out", keys)
        assert (res.path / "readme.txt").exists() and (res.path / "docs" / "data.bin").exists()
    if v["signed_at"] is None:
        assert res.signature is None
    else:
        assert res.signature.verified and res.signature.key == _signer_public()
        assert res.signature.created == v["signed_at"]


# ── signing keys and detached signatures (FORMAT.md §9, §13, §14) ────────────

SIGS = json.loads((HERE / "signatures.json").read_text(encoding="utf-8"))
SIGNER = bytes.fromhex(VECTORS["identities"][SIGS["signer"]])


def test_signing_keys_follow_the_specification():
    ed_seed, ml_seed = spec_reader.signing_seeds(SIGNER)
    assert (ed_seed.hex(), ml_seed.hex()) == (SIGS["ed25519_seed"], SIGS["ml_dsa_65_seed"])
    public = spec_reader.public3(SIGNER)
    assert public[1216:1248].hex() == SIGS["ed25519_public"]
    assert hashlib.sha256(public[1248:]).hexdigest() == SIGS["ml_dsa_65_public_sha256"]
    assert spec_reader.encode_public(public) == SIGS["public_key"]
    assert spec_reader.decode_public(SIGS["public_key"]) == public
    # The vector holds the 20-digit fingerprint of Locksmith 4: the first five groups of today's 32 digits.
    assert spec_reader.fingerprint(public).startswith(SIGS["fingerprint"] + " ")
    assert len(spec_reader.fingerprint(public)) == 39
    assert spec_reader.qr_payload(public) == SIGS["qr"]


def test_signing_keys_derive_as_specified():
    from locksmith.core import keys
    ed, ml = keys.signing_keys(SIGNER)
    assert (ed.private_bytes_raw().hex(), ml.private_bytes_raw().hex()) == (SIGS["ed25519_seed"],
                                                                            SIGS["ml_dsa_65_seed"])
    public = keys.public_from_private(SIGNER) + keys.verify_key(SIGNER)
    assert keys.encode_public(public) == SIGS["public_key"]
    assert keys.decode_public(SIGS["public_key"]) == public
    assert keys.fingerprint(public) == spec_reader.fingerprint(public)
    assert keys.fingerprint(public).startswith(SIGS["fingerprint"] + " ")
    assert keys.qr_text(public) == SIGS["qr"]
    assert keys.encryption_part(public) == keys.public_from_private(SIGNER)


@pytest.mark.parametrize("s", SIGS["signatures"], ids=[s["file"] for s in SIGS["signatures"]])
def test_signature_vector_verifies_with_the_specification(s):
    text = (HERE / s["signature"]).read_text(encoding="utf-8")
    key, sig = spec_reader.verify_signature(text, (HERE / s["file"]).read_bytes(),
                                            [spec_reader.decode_public(SIGS["public_key"])])
    assert (sig.comment, sig.created) == (s["comment"], s["created"])


@pytest.mark.parametrize("s", SIGS["signatures"], ids=[s["file"] for s in SIGS["signatures"]])
def test_signature_vector_verifies_with_locksmith(s):
    from locksmith.core import keys, signing
    text = signing.read_small(HERE / s["signature"])
    v = signing.verify_file(HERE / s["file"], text, [keys.decode_public(SIGS["public_key"])])
    assert (v.comment, v.created) == (s["comment"], s["created"])
    assert v.fingerprint == spec_reader.fingerprint(keys.decode_public(SIGS["public_key"]))


def test_locksmith_signatures_verify_with_the_specification(tmp_path):
    from locksmith.core import signing
    f = tmp_path / "f"
    f.write_bytes(b"made by Locksmith\n")
    text = signing.sign_file(f, SIGNER, "cross-check ✓", created=1234)
    key, sig = spec_reader.verify_signature(text, f.read_bytes(), [spec_reader.public3(SIGNER)])
    assert (sig.comment, sig.created) == ("cross-check ✓", 1234)


# ── the recipient list (FORMAT.md §7) ────────────────────────────────────────

ADDRESSED = json.loads((HERE / "addressed-vectors.json").read_text(encoding="utf-8"))


def test_addressed_vector_lists_the_classical_identity():
    classical = bytes.fromhex(VECTORS["identities"]["classical"])
    assert ADDRESSED["to"] == [spec_reader.recipient_entry(spec_reader.encryption_key(classical)).hex()]


@pytest.mark.parametrize("reader", ADDRESSED["readers"], ids=[r["reader"] for r in ADDRESSED["readers"]])
def test_addressed_vector_tells_each_reader_the_same(reader, tmp_path):
    blob = (HERE / ADDRESSED["file"]).read_bytes()
    spec, keys = _unlock(reader, tmp_path)
    signer = spec_reader.public3(bytes.fromhex(VECTORS["identities"][ADDRESSED["signer"]]))
    r = spec_reader.read(blob, **spec, verifiers=(signer,))
    own = [spec_reader.encryption_key(spec["identity"])] if spec.get("identity") else []
    assert hashlib.sha256(r["content"]).hexdigest() == ADDRESSED["content_sha256"]
    assert spec_reader.addressed(r, own) == reader["intent"]
    keys.verifiers = [signer]
    res = engine.decrypt_bytes(blob, keys)
    assert res.signature.verified and res.intent == reader["intent"]
