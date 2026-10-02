"""Committed test vectors (tests/vectors) must keep opening, with the engine and with an
independent reader written from docs/FORMAT.md. A failure here means this build can no
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


def test_every_suite_and_codec_has_a_vector():
    from locksmith.core import compress
    from locksmith.core.ciphers import SUITES
    covered = {v["suite"] for v in VECTORS["files"]}
    codecs = {v["meta"]["comp"] for v in VECTORS["files"]}
    assert set(SUITES) <= covered, f"no vector for {set(SUITES) - covered}"
    assert set(compress.CODECS) <= codecs, f"no vector for {set(compress.CODECS) - codecs}"
