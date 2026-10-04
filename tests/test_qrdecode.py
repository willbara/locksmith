"""The pure-Python QR reader (locksmith/core/qrdecode.py) used to restore paper backups."""

import math
import os
import random

import pytest
import segno

from locksmith.core import keys, qrdecode
from locksmith.core.errors import LocksmithError


def _rs_encode(data: list[int], nsym: int) -> list[int]:
    gen = [1]
    for i in range(nsym):
        nxt = [0] * (len(gen) + 1)
        for j, g in enumerate(gen):
            nxt[j] ^= g
            nxt[j + 1] ^= qrdecode._mul(g, qrdecode._pow(i))
        gen = nxt
    msg = data + [0] * nsym
    for i in range(len(data)):
        if msg[i]:
            coef = msg[i]
            for j in range(1, len(gen)):
                msg[i + j] ^= qrdecode._mul(gen[j], coef)
    return data + msg[len(data):]


def test_reed_solomon_corrects_up_to_half_the_ecc():
    rng = random.Random(1)
    for _ in range(300):
        nsym = rng.choice([7, 10, 16, 22, 28, 30])
        cw = _rs_encode([rng.randrange(256) for _ in range(rng.randint(5, 120))], nsym)
        bad = list(cw)
        for p in rng.sample(range(len(cw)), rng.randint(0, nsym // 2)):
            bad[p] ^= rng.randrange(1, 256)
        assert qrdecode.rs_correct(bad, nsym) == cw


def test_reed_solomon_refuses_too_many_errors():
    rng = random.Random(2)
    refused = 0
    for _ in range(200):
        cw = _rs_encode([rng.randrange(256) for _ in range(40)], 16)
        bad = list(cw)
        for p in rng.sample(range(len(cw)), 12):
            bad[p] ^= rng.randrange(1, 256)
        try:
            assert qrdecode.rs_correct(bad, 16) != cw
        except qrdecode._Fail:
            refused += 1
    assert refused > 150   # almost always detected; never "corrected" to the original by luck


def test_block_table_and_patterns_match_segno():
    import segno.consts as c
    for v in range(1, 41):
        for level, index in (("L", 0), ("M", 1), ("Q", 2), ("H", 3)):
            seg = {"L": c.ERROR_LEVEL_L, "M": c.ERROR_LEVEL_M, "Q": c.ERROR_LEVEL_Q, "H": c.ERROR_LEVEL_H}[level]
            ec, n1, d1, n2, d2 = qrdecode._BLOCKS[v - 1][index]
            groups = [(n1, d1)] + ([(n2, d2)] if n2 else [])
            assert [(g.num_blocks, g.num_data) for g in c.ECC[v][seg]] == groups
            assert all(g.num_total - g.num_data == ec for g in c.ECC[v][seg])
        if v > 1:
            assert tuple(qrdecode.alignment_positions(v)) == c.ALIGNMENT_POS[v - 2]


@pytest.mark.parametrize("version", [1, 2, 6, 7, 10, 20, 27, 40])
@pytest.mark.parametrize("level", "lmqh")
def test_every_version_and_level(version, level):
    rng = random.Random(version * 7 + ord(level))
    text = "".join(rng.choice("ABCDEFGH0123456789 abcxyz:/-✓") for _ in range(4000))
    lo, hi = 1, len(text)   # the longest text that fits this version and level
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            segno.make(text[:mid], error=level, version=version, boost_error=False)
            lo = mid
        except segno.DataOverflowError:
            hi = mid - 1
    size = lo
    q = segno.make(text[:size], error=level, version=version, boost_error=False)
    grid = [[int(bool(v)) for v in row] for row in q.matrix]
    assert qrdecode.decode_grid(grid) == text[:size]


def _photo(text: str, scale=5, angle=0.0, skew=0.0, noise=0, seed=1, invert=False):
    """A QR code as a camera sees it: corners moved to a rotated, skewed quadrilateral (a
    projective transform), uneven light and noise."""
    rnd = random.Random(seed)
    m = [[int(bool(v)) for v in row] for row in segno.make(text, error="m", micro=False).matrix]
    n, quiet = len(m), 4
    big = n + 2 * quiet
    side = big * scale
    w = h = int(side * 1.6)
    corners = []
    for ux, uy in ((0, 0), (big, 0), (big, big), (0, big)):
        x, y = (ux - big / 2) * scale, (uy - big / 2) * scale
        x, y = x * math.cos(angle) - y * math.sin(angle), x * math.sin(angle) + y * math.cos(angle)
        corners.append((w / 2 + x + rnd.uniform(-skew, skew) * side, h / 2 + y + rnd.uniform(-skew, skew) * side))
    inv = qrdecode._homography(corners, [(0, 0), (big, 0), (big, big), (0, big)])
    px = bytearray(w * h)
    for y in range(h):
        for x in range(w):
            u, v = qrdecode._apply(inv, x + 0.5, y + 0.5)
            iu, iv = math.floor(u) - quiet, math.floor(v) - quiet
            dark = (0 <= iu < n and 0 <= iv < n and m[iv][iu]) != invert
            val = (30 if dark else 225) + (rnd.randint(-noise, noise) if noise else 0) + int(50 * x / w)
            px[y * w + x] = max(0, min(255, val))
    return w, h, bytes(px)


@pytest.mark.parametrize("seed", range(12))
def test_photographed_codes(seed):
    rng = random.Random(seed)
    text = keys.paper_qr_text(os.urandom(rng.choice([32, 96])))
    w, h, px = _photo(text, scale=rng.choice([3, 4, 6]), angle=rng.uniform(-3.1, 3.1), skew=rng.uniform(0, 0.08),
                      noise=rng.choice([0, 25]), seed=seed)
    assert qrdecode.decode(w, h, px) == text


def test_light_on_dark_codes():
    text = keys.paper_qr_text(os.urandom(32))
    assert qrdecode.decode(*_photo(text, invert=True)) == text


@pytest.mark.parametrize("image", [
    (10, 10, bytes(100)), (64, 64, os.urandom(64 * 64)), (100, 100, bytes([200]) * 10_000), (0, 0, b""),
    (10, 10, bytes(99)), (3000, 3000, bytes(1)),
])
def test_images_without_a_code(image):
    with pytest.raises(LocksmithError):
        qrdecode.decode(*image)


def test_paper_text():
    for n in (32, 96):
        raw = os.urandom(n)
        text = keys.paper_qr_text(raw)
        assert text.startswith("LOCKSMITH-ID1:") and set(text[14:]) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        assert keys.private_from_paper(text) == raw and keys.private_from_paper(" " + text.lower()) == raw
        # The QR code holds exactly the bytes of the backup words.
        assert keys.private_from_words(" ".join(keys.backup_words(raw))) == raw
        typo = text[:20] + ("A" if text[20] != "A" else "B") + text[21:]
        with pytest.raises(LocksmithError, match="checksum"):
            keys.private_from_paper(typo)
    with pytest.raises(LocksmithError):
        keys.private_from_paper("LOCKSMITH-ID1:ABC")
