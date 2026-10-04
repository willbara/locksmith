"""Read a QR code from a photo or scan, in pure Python (for restoring a paper backup).

The input is a grayscale image: width, height and one byte per pixel, row by row (the UI
loads and scales it with Qt; nothing here touches Qt). The steps are the usual ones:
adaptive binarization, finding the three finder patterns, estimating the version and an
alignment pattern, a perspective transform, sampling the modules, reading the format and
version information (BCH-corrected), unmasking, de-interleaving, Reed-Solomon correction and
parsing the segments. One code per image; numeric, alphanumeric and byte segments (ECI
designators are skipped). Kanji and structured-append codes are refused.
"""

from __future__ import annotations

import itertools
import math
import re

from .errors import LocksmithError

NOT_FOUND = "No QR code was found in the image. Use a sharp, well-lit picture where the whole code is visible."
MAX_PIXELS = 4_000_000

# Reed-Solomon blocks per version, for levels L, M, Q, H: ECC codewords per block, then
# (number of blocks, data codewords per block) for the two block groups (ISO/IEC 18004 table 9).
_BLOCK_TABLE = """
    7 1 19 0 0 | 10 1 16 0 0 | 13 1 13 0 0 | 17 1 9 0 0
    10 1 34 0 0 | 16 1 28 0 0 | 22 1 22 0 0 | 28 1 16 0 0
    15 1 55 0 0 | 26 1 44 0 0 | 18 2 17 0 0 | 22 2 13 0 0
    20 1 80 0 0 | 18 2 32 0 0 | 26 2 24 0 0 | 16 4 9 0 0
    26 1 108 0 0 | 24 2 43 0 0 | 18 2 15 2 16 | 22 2 11 2 12
    18 2 68 0 0 | 16 4 27 0 0 | 24 4 19 0 0 | 28 4 15 0 0
    20 2 78 0 0 | 18 4 31 0 0 | 18 2 14 4 15 | 26 4 13 1 14
    24 2 97 0 0 | 22 2 38 2 39 | 22 4 18 2 19 | 26 4 14 2 15
    30 2 116 0 0 | 22 3 36 2 37 | 20 4 16 4 17 | 24 4 12 4 13
    18 2 68 2 69 | 26 4 43 1 44 | 24 6 19 2 20 | 28 6 15 2 16
    20 4 81 0 0 | 30 1 50 4 51 | 28 4 22 4 23 | 24 3 12 8 13
    24 2 92 2 93 | 22 6 36 2 37 | 26 4 20 6 21 | 28 7 14 4 15
    26 4 107 0 0 | 22 8 37 1 38 | 24 8 20 4 21 | 22 12 11 4 12
    30 3 115 1 116 | 24 4 40 5 41 | 20 11 16 5 17 | 24 11 12 5 13
    22 5 87 1 88 | 24 5 41 5 42 | 30 5 24 7 25 | 24 11 12 7 13
    24 5 98 1 99 | 28 7 45 3 46 | 24 15 19 2 20 | 30 3 15 13 16
    28 1 107 5 108 | 28 10 46 1 47 | 28 1 22 15 23 | 28 2 14 17 15
    30 5 120 1 121 | 26 9 43 4 44 | 28 17 22 1 23 | 28 2 14 19 15
    28 3 113 4 114 | 26 3 44 11 45 | 26 17 21 4 22 | 26 9 13 16 14
    28 3 107 5 108 | 26 3 41 13 42 | 30 15 24 5 25 | 28 15 15 10 16
    28 4 116 4 117 | 26 17 42 0 0 | 28 17 22 6 23 | 30 19 16 6 17
    28 2 111 7 112 | 28 17 46 0 0 | 30 7 24 16 25 | 24 34 13 0 0
    30 4 121 5 122 | 28 4 47 14 48 | 30 11 24 14 25 | 30 16 15 14 16
    30 6 117 4 118 | 28 6 45 14 46 | 30 11 24 16 25 | 30 30 16 2 17
    26 8 106 4 107 | 28 8 47 13 48 | 30 7 24 22 25 | 30 22 15 13 16
    28 10 114 2 115 | 28 19 46 4 47 | 28 28 22 6 23 | 30 33 16 4 17
    30 8 122 4 123 | 28 22 45 3 46 | 30 8 23 26 24 | 30 12 15 28 16
    30 3 117 10 118 | 28 3 45 23 46 | 30 4 24 31 25 | 30 11 15 31 16
    30 7 116 7 117 | 28 21 45 7 46 | 30 1 23 37 24 | 30 19 15 26 16
    30 5 115 10 116 | 28 19 47 10 48 | 30 15 24 25 25 | 30 23 15 25 16
    30 13 115 3 116 | 28 2 46 29 47 | 30 42 24 1 25 | 30 23 15 28 16
    30 17 115 0 0 | 28 10 46 23 47 | 30 10 24 35 25 | 30 19 15 35 16
    30 17 115 1 116 | 28 14 46 21 47 | 30 29 24 19 25 | 30 11 15 46 16
    30 13 115 6 116 | 28 14 46 23 47 | 30 44 24 7 25 | 30 59 16 1 17
    30 12 121 7 122 | 28 12 47 26 48 | 30 39 24 14 25 | 30 22 15 41 16
    30 6 121 14 122 | 28 6 47 34 48 | 30 46 24 10 25 | 30 2 15 64 16
    30 17 122 4 123 | 28 29 46 14 47 | 30 49 24 10 25 | 30 24 15 46 16
    30 4 122 18 123 | 28 13 46 32 47 | 30 48 24 14 25 | 30 42 15 32 16
    30 20 117 4 118 | 28 40 47 7 48 | 30 43 24 22 25 | 30 10 15 67 16
    30 19 118 6 119 | 28 18 47 31 48 | 30 34 24 34 25 | 30 20 15 61 16"""
_BLOCKS = [[tuple(map(int, e.split())) for e in line.split("|")] for line in _BLOCK_TABLE.strip().splitlines()]
_LEVELS = {1: "L", 0: "M", 3: "Q", 2: "H"}       # format bits -> level
_LEVEL_INDEX = {"L": 0, "M": 1, "Q": 2, "H": 3}
_ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


class _Fail(Exception):
    pass


# ── GF(256) and Reed-Solomon (primitive polynomial 0x11D, generator 2) ────────

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a: int, b: int) -> int:
    if b == 0:
        raise _Fail
    return 0 if a == 0 else _EXP[(_LOG[a] - _LOG[b]) % 255]


def _pow(e: int) -> int:
    return _EXP[e % 255]


def _eval(poly_low_first: list[int], x: int) -> int:
    y = 0
    for c in reversed(poly_low_first):
        y = _mul(y, x) ^ c
    return y


def rs_correct(block: list[int], nsym: int) -> list[int]:
    """Correct up to nsym // 2 byte errors in ``block`` (data then ECC, highest degree first).
    Raises _Fail when there are more errors than that."""
    n = len(block)
    synd = [0] * nsym
    for j in range(nsym):
        a = _pow(j)
        s = 0
        for c in block:
            s = _mul(s, a) ^ c
        synd[j] = s
    if not any(synd):
        return block
    # Berlekamp-Massey: the error locator, lowest degree first.
    loc, prev, length, shift, last = [1], [1], 0, 1, 1
    for i in range(nsym):
        d = synd[i]
        for k in range(1, length + 1):
            if k < len(loc):
                d ^= _mul(loc[k], synd[i - k])
        if d == 0:
            shift += 1
            continue
        coef = _div(d, last)
        new = loc + [0] * max(0, len(prev) + shift - len(loc))
        for k, p in enumerate(prev):
            new[k + shift] ^= _mul(coef, p)
        if 2 * length <= i:
            prev, length, last, shift = loc, i + 1 - length, d, 1
        else:
            shift += 1
        loc = new
    while len(loc) > 1 and loc[-1] == 0:
        loc.pop()
    if len(loc) - 1 != length or 2 * length > nsym:
        raise _Fail
    # Chien search: degree p is wrong where loc(alpha^-p) == 0.
    positions = [p for p in range(n) if _eval(loc, _pow(-p)) == 0]
    if len(positions) != length:
        raise _Fail
    # Forney (first consecutive root alpha^0): e = X * omega(X^-1) / loc'(X^-1).
    omega = [0] * nsym
    for i, s in enumerate(synd):
        for k, c in enumerate(loc):
            if i + k < nsym:
                omega[i + k] ^= _mul(s, c)
    deriv = [loc[k] if k % 2 else 0 for k in range(1, len(loc))]
    out = list(block)
    for p in positions:
        x = _pow(p)
        xinv = _pow(-p)
        den = _eval(deriv, xinv)
        out[n - 1 - p] ^= _mul(x, _div(_eval(omega, xinv), den))
    for j in range(nsym):   # what it corrected must now be a codeword
        a, s = _pow(j), 0
        for c in out:
            s = _mul(s, a) ^ c
        if s:
            raise _Fail
    return out


# ── format and version information ───────────────────────────────────────────

def _bch(value: int, bits: int, generator: int) -> int:
    rem = value
    glen = generator.bit_length()
    for _ in range(glen - 1):
        rem = (rem << 1) ^ ((rem >> (glen - 2)) * generator)
    return value << (glen - 1) | rem


_FORMATS = {(_bch(data, 5, 0x537) ^ 0x5412): data for data in range(32)}
_VERSIONS = {_bch(v, 6, 0x1F25): v for v in range(7, 41)}


def _closest(value: int, table: dict[int, int], limit: int) -> int | None:
    best = min(table, key=lambda code: bin(code ^ value).count("1"))
    return table[best] if bin(best ^ value).count("1") <= limit else None


def alignment_positions(version: int) -> list[int]:
    if version == 1:
        return []
    count = version // 7 + 2
    step = (version * 8 + count * 3 + 5) // (count * 4 - 4) * 2
    return [6] + [version * 4 + 10 - i * step for i in reversed(range(count - 1))]


def _function_map(version: int) -> list[list[bool]]:
    size = 17 + 4 * version
    f = [[False] * size for _ in range(size)]

    def rect(x0, y0, w, h):
        for y in range(max(0, y0), min(size, y0 + h)):
            for x in range(max(0, x0), min(size, x0 + w)):
                f[y][x] = True
    for x, y in ((0, 0), (size - 8, 0), (0, size - 8)):
        rect(x, y, 8, 8)         # finder patterns and separators
    rect(6, 0, 1, size)
    rect(0, 6, size, 1)          # timing
    pos = alignment_positions(version)
    for ax, ay in itertools.product(pos, pos):
        if (ax, ay) not in ((6, 6), (6, pos[-1]), (pos[-1], 6)):
            rect(ax - 2, ay - 2, 5, 5)
    rect(8, 0, 1, 9)
    rect(0, 8, 9, 1)             # format information, first copy
    rect(size - 8, 8, 8, 1)
    rect(8, size - 8, 1, 8)      # second copy (and the dark module)
    if version >= 7:
        rect(size - 11, 0, 3, 6)
        rect(0, size - 11, 6, 3)
    return f


_MASKS = [
    lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0, lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0, lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0, lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


def _read_format(grid) -> tuple[str, int]:
    size = len(grid)
    a = b = 0
    for i in range(6):
        a |= grid[i][8] << i
    a |= grid[7][8] << 6 | grid[8][8] << 7 | grid[8][7] << 8
    for i in range(9, 15):
        a |= grid[8][14 - i] << i
    for i in range(8):
        b |= grid[8][size - 1 - i] << i
    for i in range(8, 15):
        b |= grid[size - 15 + i][8] << i
    for value in (a, b):
        data = _closest(value, _FORMATS, 3)
        if data is not None:
            return _LEVELS[data >> 3], data & 7
    raise _Fail


def _read_version(grid) -> int | None:
    size = len(grid)
    a = b = 0
    for i in range(18):
        x, y = size - 11 + i % 3, i // 3
        a |= grid[y][x] << i
        b |= grid[x][y] << i
    for value in (a, b):
        v = _closest(value, _VERSIONS, 3)
        if v is not None:
            return v
    return None


def decode_grid(grid: list[list[int]]) -> str:
    """Decode a sampled grid of modules (1 = dark)."""
    size = len(grid)
    version = (size - 17) // 4
    if size != 17 + 4 * version or not 1 <= version <= 40:
        raise _Fail
    level, mask = _read_format(grid)
    func = _function_map(version)
    masked = _MASKS[mask]
    bits = []
    for right in range(size - 1, 0, -2):
        if right <= 6:
            right -= 1
        for vert in range(size):
            for j in range(2):
                x = right - j
                upward = ((right + 1) & 2) == 0
                y = size - 1 - vert if upward else vert
                if not func[y][x]:
                    bits.append(grid[y][x] ^ masked(x, y))
    codewords = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits) - 7, 8)]
    ec, n1, d1, n2, d2 = _BLOCKS[version - 1][_LEVEL_INDEX[level]]
    sizes = [d1] * n1 + [d2] * n2
    total = sum(sizes) + ec * len(sizes)
    if len(codewords) < total:
        raise _Fail
    blocks: list[list[int]] = [[] for _ in sizes]
    pos = 0
    for i in range(max(sizes)):
        for b, s in enumerate(sizes):
            if i < s:
                blocks[b].append(codewords[pos])
                pos += 1
    for _ in range(ec):
        for b in range(len(sizes)):
            blocks[b].append(codewords[pos])
            pos += 1
    data = []
    for b, s in zip(blocks, sizes, strict=True):
        data += rs_correct(b, ec)[:s]
    return _parse(data, version)


def _parse(data: list[int], version: int) -> str:
    bits = "".join(f"{b:08b}" for b in data)
    pos = 0

    def take(n):
        nonlocal pos
        if pos + n > len(bits):
            raise _Fail
        pos += n
        return int(bits[pos - n:pos], 2)
    tier = 0 if version <= 9 else 1 if version <= 26 else 2
    out = bytearray()
    text = []
    while pos + 4 <= len(bits):
        mode = take(4)
        if mode == 0:
            break
        if mode == 1:      # numeric
            count = take((10, 12, 14)[tier])
            digits = ""
            while count >= 3:
                digits += f"{take(10):03d}"
                count -= 3
            if count == 2:
                digits += f"{take(7):02d}"
            elif count == 1:
                digits += str(take(4))
            out += digits.encode()
        elif mode == 2:    # alphanumeric
            count = take((9, 11, 13)[tier])
            chars = ""
            while count >= 2:
                v = take(11)
                if v >= 45 * 45:
                    raise _Fail
                chars += _ALNUM[v // 45] + _ALNUM[v % 45]
                count -= 2
            if count:
                v = take(6)
                if v >= 45:
                    raise _Fail
                chars += _ALNUM[v]
            out += chars.encode()
        elif mode == 4:    # bytes
            count = take((8, 16, 16)[tier])
            out += bytes(take(8) for _ in range(count))
        elif mode == 7:    # ECI designator: skipped (byte segments are read as UTF-8)
            first = take(8)
            if first & 0x80:
                take(8 if first & 0x40 == 0 else 16)
        elif mode in (5, 9):   # FNC1
            if mode == 9:
                take(8)
        else:
            raise LocksmithError("This QR code uses an encoding Locksmith can't read.")
    text.append(out.decode("utf-8") if _utf8(out) else out.decode("latin-1"))
    return "".join(text)


def _utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


# ── finding the code in an image ─────────────────────────────────────────────

_TABLES: dict[int, bytes] = {}


def _table(threshold: int) -> bytes:
    t = _TABLES.get(threshold)
    if t is None:
        t = _TABLES[threshold] = bytes(1 if v <= threshold else 0 for v in range(256))
    return t


def binarize(width: int, height: int, gray: bytes, global_threshold: bool = False) -> list[bytes]:
    """Rows of 0 (light) and 1 (dark). Each 8x8 block is thresholded at the mean of the 5x5 blocks
    around it, which copes with uneven light; ``global_threshold`` uses one threshold instead."""
    if global_threshold:
        hist = [0] * 256
        for v in gray:
            hist[v] += 1
        total, s = len(gray), sum(i * c for i, c in enumerate(hist))
        best, sb, wb, threshold = 0.0, 0, 0, 127
        for t in range(256):   # Otsu
            wb += hist[t]
            if wb == 0 or wb == total:
                continue
            sb += t * hist[t]
            mb, mf = sb / wb, (s - sb) / (total - wb)
            between = wb * (total - wb) * (mb - mf) ** 2
            if between > best:
                best, threshold = between, t
        table = _table(threshold)
        return [gray[y * width:(y + 1) * width].translate(table) for y in range(height)]
    bs = 8
    bw, bh = -(-width // bs), -(-height // bs)
    avg = [[0] * bw for _ in range(bh)]
    for by in range(bh):
        y0, y1 = by * bs, min(height, by * bs + bs)
        for bx in range(bw):
            x0, x1 = bx * bs, min(width, bx * bs + bs)
            rows = [gray[y * width + x0:y * width + x1] for y in range(y0, y1)]
            lo, hi = min(min(r) for r in rows), max(max(r) for r in rows)
            mean = sum(sum(r) for r in rows) // ((y1 - y0) * (x1 - x0))
            if hi - lo <= 24:   # flat: probably all light or all dark, see what its neighbours say
                mean = lo // 2
                if by and bx:
                    around = (avg[by - 1][bx] + 2 * avg[by][bx - 1] + avg[by - 1][bx - 1]) // 4
                    if lo < around:
                        mean = around
            avg[by][bx] = mean
    out = []
    for by in range(bh):
        y0, y1 = by * bs, min(height, by * bs + bs)
        thresholds = []
        for bx in range(bw):
            ys = range(max(0, by - 2), min(bh, by + 3))
            xs = range(max(0, bx - 2), min(bw, bx + 3))
            thresholds.append(sum(avg[y][x] for y in ys for x in xs) // (len(ys) * len(xs)))
        for y in range(y0, y1):
            row = gray[y * width:(y + 1) * width]
            out.append(b"".join(row[bx * bs:bx * bs + bs].translate(_table(t)) for bx, t in enumerate(thresholds)))
    return out


_RUN = re.compile(rb"\x01+|\x00+")


def _runs(line: bytes) -> list[tuple[int, int, int]]:
    return [(m.start(), m.end() - m.start(), line[m.start()]) for m in _RUN.finditer(line)]


def _ratio_ok(lengths, pattern) -> float | None:
    total = sum(lengths)
    unit = total / sum(pattern)
    if unit < 1:
        return None
    for length, p in zip(lengths, pattern, strict=True):
        if abs(length - p * unit) > p * unit * 0.6 + 0.5:
            return None
    return unit


def _line_runs(get, center: int, limit: int, pattern) -> tuple[float, float] | None:
    """Around index ``center`` of a line read by ``get``, the runs of ``pattern`` (dark in the
    middle): returns the refined center and the unit size, or None."""
    if not 0 <= center < limit or not get(center):
        return None
    half = len(pattern) // 2
    counts = [0] * len(pattern)
    i = center
    for k in range(half, -1, -1):
        colour = (half - k + 1) % 2   # dark at the middle, alternating outwards
        while i >= 0 and get(i) == colour:
            counts[k] += 1
            i -= 1
        if counts[k] == 0 or counts[k] > pattern[k] * 40:
            return None
    i = center + 1
    for k in range(half, len(pattern)):
        colour = (k - half + 1) % 2
        while i < limit and get(i) == colour:
            counts[k] += 1
            i += 1
        if counts[k] == 0 and k != half:
            return None
    unit = _ratio_ok(counts, pattern)
    if unit is None:
        return None
    end = i
    return end - sum(counts[half + 1:]) - counts[half] / 2.0, unit


def _finders(rows: list[bytes], width: int, height: int) -> list[list[float]]:
    found: list[list[float]] = []   # x, y, unit, count
    step = max(1, height // 400)
    for y in range(0, height, step):
        runs = _runs(rows[y])
        for i in range(len(runs) - 4):
            if runs[i][2] != 1:
                continue
            five = runs[i:i + 5]
            if _ratio_ok([r[1] for r in five], (1, 1, 3, 1, 1)) is None:
                continue
            cx = five[2][0] + five[2][1] / 2.0
            v = _line_runs(lambda yy, cx=cx: rows[yy][int(cx)], y, height, (1, 1, 3, 1, 1))
            if v is None:
                continue
            cy, unit_v = v
            h = _line_runs(lambda xx, cy=cy: rows[int(cy)][xx], int(cx), width, (1, 1, 3, 1, 1))
            if h is None:
                continue
            cx, unit_h = h
            unit = (unit_v + unit_h) / 2
            if abs(unit_v - unit_h) > unit * 0.5 or unit < 1.5:   # smaller modules can't be sampled reliably
                continue
            for f in found:
                if abs(f[0] - cx) <= unit * 2 and abs(f[1] - cy) <= unit * 2 and abs(f[2] - unit) <= unit * 0.5:
                    n = f[3]
                    f[0], f[1], f[2], f[3] = (f[0] * n + cx) / (n + 1), (f[1] * n + cy) / (n + 1), \
                        (f[2] * n + unit) / (n + 1), n + 1
                    break
            else:
                found.append([cx, cy, unit, 1])
    return found


def _dist(a, b) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


def _run_along(rows, width, height, start, toward, max_steps: int) -> float:
    """From ``start`` (a finder center) toward ``toward``: the distance to the end of the
    dark, light, dark runs (3.5 modules of a finder pattern), measured along the grid's own axis,
    so rotation doesn't stretch it as it does a scan line."""
    dx, dy = toward[0] - start[0], toward[1] - start[1]
    length = math.hypot(dx, dy)
    if length == 0:
        return 0.0
    dx, dy = dx / length, dy / length
    state, last = 0, 1   # 0: center dark, 1: light ring, 2: dark ring
    for step in range(max_steps):
        x, y = int(start[0] + dx * step), int(start[1] + dy * step)
        if not (0 <= x < width and 0 <= y < height):
            return 0.0
        v = rows[y][x]
        if v != last:
            state += 1
            last = v
            if state == 3:
                return step
    return 0.0


def _module_size(rows, width, height, a, b, c) -> float:
    sizes = []
    for p, q in ((a, b), (b, a), (a, c), (c, a)):
        both = _run_along(rows, width, height, p, q, int(p[2] * 10)) + \
            _run_along(rows, width, height, p, (2 * p[0] - q[0], 2 * p[1] - q[1]), int(p[2] * 10))
        if both:
            sizes.append(both / 7.0)
    return sum(sizes) / len(sizes) if sizes else (a[2] + b[2] + c[2]) / 3


def _triples(found):
    """Candidate (top-left, top-right, bottom-left) triples, most plausible first."""
    ranked = sorted(found, key=lambda f: -f[3])[:12]
    scored = []
    for trio in itertools.combinations(ranked, 3):
        units = [f[2] for f in trio]
        if max(units) > min(units) * 1.6:
            continue
        pairs = sorted(((_dist(p, q), r) for p, q, r in ((trio[0], trio[1], trio[2]), (trio[0], trio[2], trio[1]),
                                                          (trio[1], trio[2], trio[0]))), key=lambda t: t[0])
        (d1, _), (d2, _), (d3, corner) = pairs
        if d1 < 7 * min(units):
            continue
        score = abs(d1 - d2) / d2 + abs(d1 * d1 + d2 * d2 - d3 * d3) / (d3 * d3)
        others = [f for f in trio if f is not corner]
        b, c = others
        cross = (b[0] - corner[0]) * (c[1] - corner[1]) - (b[1] - corner[1]) * (c[0] - corner[0])
        if cross < 0:
            b, c = c, b
        scored.append((score - 0.01 * sum(f[3] for f in trio), corner, b, c))
    scored.sort(key=lambda t: t[0])
    return [(a, b, c) for _, a, b, c in scored[:4]]


def _homography(src, dst):
    """The 3x3 projective transform taking the four ``src`` points to ``dst`` (both (x, y))."""
    rows, rhs = [], []
    for (x, y), (u, v) in zip(src, dst, strict=True):
        rows.append([x, y, 1, 0, 0, 0, -u * x, -u * y])
        rhs.append(u)
        rows.append([0, 0, 0, x, y, 1, -v * x, -v * y])
        rhs.append(v)
    n = 8
    m = [r + [b] for r, b in zip(rows, rhs, strict=True)]
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(m[r][col]))
        if abs(m[piv][col]) < 1e-12:
            raise _Fail
        m[col], m[piv] = m[piv], m[col]
        for r in range(n):
            if r != col:
                f = m[r][col] / m[col][col]
                for k in range(col, n + 1):
                    m[r][k] -= f * m[col][k]
    h = [m[i][n] / m[i][i] for i in range(n)] + [1.0]
    return h


def _apply(h, x, y):
    w = h[6] * x + h[7] * y + h[8]
    return (h[0] * x + h[1] * y + h[2]) / w, (h[3] * x + h[4] * y + h[5]) / w


def _ring(get, center: int, limit: int, unit: float) -> float | None:
    """Along one line through ``center``: a dark run of about one module, light runs of about one
    module on both sides, and dark beyond them (the alignment pattern's outer ring, which may
    run on into dark modules around it). Returns the refined center, or None."""
    def ok(n):
        return abs(n - unit) <= unit * 0.6 + 1

    if not 0 <= center < limit or not get(center):
        return None
    lo = center
    while lo > 0 and get(lo - 1):
        lo -= 1
    hi = center
    while hi < limit - 1 and get(hi + 1):
        hi += 1
    if not ok(hi - lo + 1):
        return None
    sides = []
    for step, start in ((-1, lo - 1), (1, hi + 1)):
        i, light = start, 0
        while 0 <= i < limit and not get(i) and light <= unit * 3:
            light += 1
            i += step
        dark = 0
        while 0 <= i < limit and get(i) and dark < unit:
            dark += 1
            i += step
        if not ok(light) or dark < unit * 0.5:
            return None
        sides.append(light)
    return (lo + hi) / 2.0


def _alignments(rows, width, height, guess, unit) -> list[tuple[float, float]]:
    """Alignment patterns near ``guess``, nearest first: a dark module ringed by light, then by dark."""
    found: list[tuple[float, float]] = []
    radius = int(unit * 7) + 2
    gx, gy = int(guess[0]), int(guess[1])
    for y in range(max(0, gy - radius), min(height, gy + radius)):
        row = rows[y]
        for x in range(max(0, gx - radius), min(width, gx + radius)):
            if not row[x] or (x and row[x - 1]):
                continue   # only the start of each dark run
            cx = _ring(lambda i, row=row: row[i], x, width, unit)
            if cx is None:
                continue
            cy = _ring(lambda i, cx=cx: rows[i][int(cx)], y, height, unit)
            if cy is None:
                continue
            cx2 = _ring(lambda i, cy=cy: rows[int(cy)][i], int(cx), width, unit)
            if cx2 is None:
                continue
            point = (cx2 + 0.5, cy + 0.5)
            if all(math.hypot(point[0] - p[0], point[1] - p[1]) > unit for p in found):
                found.append(point)
    found.sort(key=lambda p: math.hypot(p[0] - guess[0], p[1] - guess[1]))
    return found[:3]


def _sample(rows, width, height, h, size):
    grid = []
    for y in range(size):
        line = []
        for x in range(size):
            px, py = _apply(h, x + 0.5, y + 0.5)
            ix, iy = int(px), int(py)
            if not (0 <= ix < width and 0 <= iy < height):
                raise _Fail
            line.append(rows[iy][ix])
        grid.append(line)
    return grid


def _attempt(rows, width, height) -> str | None:
    for a, b, c in _triples(_finders(rows, width, height)):
        unit = _module_size(rows, width, height, a, b, c)
        estimate = (_dist(a, b) + _dist(a, c)) / 2 / unit + 7
        base = int(round((estimate - 17) / 4))
        for version in sorted({v for v in range(base - 2, base + 3) if 1 <= v <= 40}, key=lambda v: abs(v - base)):
            size = 17 + 4 * version
            src = [(3.5, 3.5), (size - 3.5, 3.5), (3.5, size - 3.5)]
            dst = [(a[0], a[1]), (b[0], b[1]), (c[0], c[1])]
            corners = [((size - 3.5, size - 3.5), (b[0] + c[0] - a[0], b[1] + c[1] - a[1]))]
            if version >= 2:
                k = (size - 10) / (size - 7)
                guess = (a[0] + k * (b[0] - a[0] + c[0] - a[0]), a[1] + k * (b[1] - a[1] + c[1] - a[1]))
                for found in reversed(_alignments(rows, width, height, guess, unit)):
                    corners.insert(0, ((size - 6.5, size - 6.5), found))
            for s4, d4 in corners:
                try:
                    h = _homography(src + [s4], dst + [d4])
                    grid = _sample(rows, width, height, h, size)
                    if version >= 7 and _read_version(grid) not in (version, None):
                        continue
                    return decode_grid(grid)
                except (_Fail, ZeroDivisionError, IndexError, ValueError):
                    continue
    return None


def decode(width: int, height: int, gray: bytes) -> str:
    """The text of the QR code in a grayscale image (one byte per pixel, rows top to bottom)."""
    if width <= 0 or height <= 0 or len(gray) != width * height or width * height > MAX_PIXELS:
        raise LocksmithError("That image can't be read.")
    for global_threshold in (False, True):
        rows = binarize(width, height, gray, global_threshold)
        for candidate in (rows, [r.translate(bytes((1, 0)) + bytes(254)) for r in rows]):   # also light-on-dark
            text = _attempt(candidate, width, height)
            if text is not None:
                return text
    raise LocksmithError(NOT_FOUND)
