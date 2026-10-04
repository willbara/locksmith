"""Recovery data (locksmith/core/parity.py, FORMAT.md §17)."""

import os
import random

import pytest

from locksmith.core import parity
from locksmith.core.errors import LocksmithError


def _make(tmp_path, size: int, level="5", seed=0):
    rng = random.Random(seed)
    f = tmp_path / "archive.locked"
    f.write_bytes(rng.randbytes(size))
    lpar = parity.create(f, level)
    return f, lpar, f.read_bytes()


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097, 100_000, 3_000_000])
@pytest.mark.parametrize("level", sorted(parity.LEVELS))
def test_intact_files_check_out(tmp_path, size, level):
    f, lpar, _ = _make(tmp_path, size, level)
    assert lpar.name == "archive.locked.lpar"
    assert parity.check(f).intact
    rec = parity.read_recovery(lpar)
    assert rec.lay.size == size and rec.name == "archive.locked"


def _damage_blocks(data: bytes, lay, blocks) -> bytes:
    out = bytearray(data)
    for b in blocks:
        start = b * lay.block
        end = min(len(out), start + lay.block)
        if start < end:
            out[start + random.randrange(end - start)] ^= 0xFF
    return bytes(out)


@pytest.mark.parametrize("level", sorted(parity.LEVELS))
def test_scattered_damage_up_to_m_blocks_per_stripe(tmp_path, level):
    f, lpar, original = _make(tmp_path, 2_000_000, level, seed=1)
    lay = parity.read_recovery(lpar).lay
    rng = random.Random(2)
    bad = []
    for j in range(lay.stripes):   # m damaged blocks in every stripe
        members = [t * lay.stripes + j for t in range(lay.k) if t * lay.stripes + j < lay.blocks]
        bad += rng.sample(members, min(lay.m, len(members)))
    f.write_bytes(_damage_blocks(original, lay, bad))
    r = parity.repair(f)
    assert sorted(r.damaged) == sorted(bad) and r.repaired == f
    assert f.read_bytes() == original
    assert r.kept.name == "archive.locked.damaged" and r.kept.read_bytes() != original


def test_a_burst_of_the_redundancy_size_is_repaired(tmp_path):
    f, lpar, original = _make(tmp_path, 3_000_000, "10", seed=3)
    lay = parity.read_recovery(lpar).lay
    # Anywhere in the file, a burst one block shorter than m blocks of every stripe touches no
    # stripe more than m times (one m·S blocks long touches m·S + 1 blocks unless it is aligned).
    burst = (lay.m * lay.stripes - 1) * lay.block
    data = bytearray(original)
    data[500_000:500_000 + burst] = bytes(burst)
    f.write_bytes(bytes(data))
    parity.repair(f)
    assert f.read_bytes() == original


def test_too_much_damage_changes_nothing(tmp_path):
    f, lpar, original = _make(tmp_path, 500_000, "5", seed=4)
    lay = parity.read_recovery(lpar).lay
    members = [t * lay.stripes for t in range(lay.k) if t * lay.stripes < lay.blocks]
    damaged = _damage_blocks(original, lay, members[:lay.m + 1])
    f.write_bytes(damaged)
    assert parity.check(f).unrepairable == 1
    with pytest.raises(LocksmithError, match="too large"):
        parity.repair(f)
    assert f.read_bytes() == damaged and sorted(p.name for p in tmp_path.iterdir()) == sorted(
        ["archive.locked", "archive.locked.lpar"])


def test_truncated_and_extended_files(tmp_path):
    f, _, original = _make(tmp_path, 300_000, "10", seed=5)
    f.write_bytes(original[:-5000])
    assert not parity.check(f).size_matches
    parity.repair(f)
    assert f.read_bytes() == original
    (tmp_path / "archive.locked.damaged").unlink()
    f.write_bytes(original + b"appended")
    r = parity.check(f)
    assert not r.intact and r.damaged == [] and r.repairable
    parity.repair(f)
    assert f.read_bytes() == original


def test_damaged_recovery_data(tmp_path):
    f, lpar, original = _make(tmp_path, 400_000, "5", seed=6)
    side = bytearray(lpar.read_bytes())
    side[20] ^= 1                        # the first copy of the description: the last one is used
    rec_len = len(side)
    side[rec_len // 2] ^= 1              # one parity block: no longer used, the rest still are
    lpar.write_bytes(bytes(side))
    lay = parity.read_recovery(lpar).lay
    f.write_bytes(_damage_blocks(original, lay, [0, lay.stripes + 1]))
    parity.repair(f)
    assert f.read_bytes() == original
    side[-30] ^= 1                       # both copies: nothing can be trusted
    lpar.write_bytes(bytes(side))
    with pytest.raises(LocksmithError, match="damaged beyond use"):
        parity.read_recovery(lpar)


def test_not_recovery_data(tmp_path):
    other = tmp_path / "x.lpar"
    other.write_bytes(os.urandom(500))
    with pytest.raises(LocksmithError, match="not Locksmith recovery data"):
        parity.read_recovery(other)


def test_cauchy_code_is_mds():
    """Any square submatrix of the Cauchy matrix inverts, so any m losses per stripe are repairable."""
    rng = random.Random(7)
    for k, m in parity.LEVELS.values():
        for _ in range(30):
            size = rng.randint(1, m)
            rows, cols = rng.sample(range(m), size), rng.sample(range(k), size)
            parity._solve([[parity.coefficient(i, t, m) for t in cols] for i in rows])


# ── the committed vector (tests/vectors/recovery) ────────────────────────────

def test_recovery_vector_matches_the_specification(tmp_path):
    import shutil
    from pathlib import Path

    import spec_reader
    folder = Path(__file__).parent / "vectors" / "recovery"
    data, lpar = (folder / "sample.bin").read_bytes(), (folder / "sample.bin.lpar").read_bytes()
    info = spec_reader.read_recovery(data, lpar)
    assert (info["k"], info["m"], info["blocks"]) == (20, 4, 13)
    shutil.copy(folder / "sample.bin", tmp_path / "sample.bin")
    shutil.copy(folder / "sample.bin.lpar", tmp_path / "sample.bin.lpar")
    assert parity.check(tmp_path / "sample.bin").intact
    damaged = bytearray(data)
    for b in (0, 5, 9, 12):   # four blocks of the one stripe
        damaged[b * 4096] ^= 0x55
    (tmp_path / "sample.bin").write_bytes(bytes(damaged))
    parity.repair(tmp_path / "sample.bin")
    assert (tmp_path / "sample.bin").read_bytes() == data


def test_recovery_from_spec_matches_written_parity(tmp_path):
    """Recovery data Locksmith writes now, multi-stripe, checked byte by byte by the second reader."""
    import spec_reader
    f, lpar, data = _make(tmp_path, 300_000, "20", seed=9)
    assert spec_reader.read_recovery(data, lpar.read_bytes())["stripes"] == 4
