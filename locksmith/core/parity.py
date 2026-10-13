"""Recovery data for long-term archives (docs/FORMAT.md §17): a sidecar ``name.lpar`` file
that can repair a damaged copy of ``name``.

The file is cut into blocks of B bytes. Block b belongs to stripe ``b mod S`` at position
``b div S``, so each stripe's k blocks are spread evenly over the whole file. Every stripe gets
m parity blocks from a systematic Reed-Solomon (Cauchy) code over GF(256): any m damaged blocks
of a stripe can be rebuilt from the rest. Per-block hashes tell which blocks are damaged. A
contiguous run of damage up to m·S - 1 blocks long (about m/k of the file), wherever it starts,
touches each stripe at most m times, so it is repaired; so is scattered damage of up to m blocks
per stripe.

The sidecar keeps its description (sizes, hashes) twice, at its start and end, each with its own
checksum; damaged parity blocks are recognised by their hashes and simply not used. Recovery
data protects against decay of the storage, not against tampering: everything a repair checks
against (the block hashes and the final SHA-256) comes from the sidecar, so whoever can change the
sidecar alone decides what up to m/k of the file is rebuilt as. Readers therefore accept only the
layouts Locksmith writes, the UI shows what a repair would rebuild and asks first, a repaired
Locksmith or age file must still parse as one, and the repaired file keeps the original's Mark of
the Web. Locksmith files are authenticated by their own encryption when opened.

Parity is not encryption: it is made of the file's own bytes. A file of at most m blocks (16 KiB at
most levels) can be rebuilt from its sidecar alone, and a larger one partly, with each block's hash
confirming guesses. So a sidecar is never readable by anyone the file isn't readable by, shredding a
file shreds its sidecar too, and the UI warns before making recovery data for an unencrypted file
(audit B2).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .errors import CancelledError, LocksmithError

MAGIC = b"LOCKPAR\x01"
END_MAGIC = b"LOCKPAR\x02"
EXTENSION = ".lpar"
HASH_LEN = 16
MIN_BLOCK, MAX_BLOCK = 4096, 1 << 20
TARGET_BLOCKS = 65536
PASS_MEMORY = 256 << 20     # parity held in memory per pass while creating
# Redundancy: (data blocks k, parity blocks m) per stripe.
LEVELS = {"1": (200, 2), "5": (80, 4), "10": (40, 4), "20": (20, 4)}
LABELS = {"1": "1% (bit rot)", "5": "5% (recommended)", "10": "10%", "20": "20% (unreliable media)"}

Progress = Callable[[float | None, str], None]

# ── GF(256), polynomial 0x11D ────────────────────────────────────────────────

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i], _LOG[_x] = _x, _i
    _x = (_x << 1) ^ (0x11D if _x & 0x80 else 0)
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def gf_mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError
    return _EXP[255 - _LOG[a]]


_MUL_TABLES = [bytes(gf_mul(c, v) for v in range(256)) for c in range(256)]


def coefficient(i: int, t: int, m: int) -> int:
    """The Cauchy matrix entry for parity block i and stripe position t: 1 / (i XOR (m + t))."""
    return gf_inv(i ^ (m + t))


def _scale(block: bytes, c: int) -> int:
    """c · block, as an integer (so XOR of blocks is one big-integer XOR)."""
    return int.from_bytes(block.translate(_MUL_TABLES[c]) if c != 1 else block, "big")


def _solve(matrix: list[list[int]]) -> list[list[int]]:
    """The inverse of a square matrix over GF(256)."""
    n = len(matrix)
    a = [row[:] + [int(i == j) for j in range(n)] for i, row in enumerate(matrix)]
    for col in range(n):
        piv = next((r for r in range(col, n) if a[r][col]), None)
        if piv is None:
            raise LocksmithError("The recovery data can't rebuild these blocks.")
        a[col], a[piv] = a[piv], a[col]
        inv = gf_inv(a[col][col])
        a[col] = [gf_mul(v, inv) for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                f = a[r][col]
                a[r] = [x ^ gf_mul(f, y) for x, y in zip(a[r], a[col], strict=True)]
    return [row[n:] for row in a]


# ── layout ───────────────────────────────────────────────────────────────────

@dataclass
class Layout:
    size: int
    block: int
    k: int
    m: int

    @property
    def blocks(self) -> int:
        return -(-self.size // self.block)

    @property
    def stripes(self) -> int:
        return max(1, -(-self.blocks // self.k))

    def stripe_of(self, b: int) -> tuple[int, int]:
        return b % self.stripes, b // self.stripes


def layout_for(size: int, level: str) -> Layout:
    if level not in LEVELS:
        raise LocksmithError("Unknown amount of recovery data.")
    k, m = LEVELS[level]
    block = max(MIN_BLOCK, min(MAX_BLOCK, -(-size // TARGET_BLOCKS)))
    block = -(-block // MIN_BLOCK) * MIN_BLOCK
    return Layout(size, block, k, m)


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()[:HASH_LEN]


def _read_block(f, lay: Layout, b: int) -> bytes:
    """Data block b, padded with zeros to the block size (blocks past the end are all zeros)."""
    if b * lay.block >= lay.size:
        return bytes(lay.block)
    f.seek(b * lay.block)
    data = f.read(min(lay.block, lay.size - b * lay.block))
    return data + bytes(lay.block - len(data))


class _Checker:
    def __init__(self, progress, cancel):
        self.progress, self.cancel = progress, cancel

    def __call__(self, frac, stage):
        if self.cancel is not None and self.cancel.is_set():
            raise CancelledError()
        if self.progress:
            self.progress(frac, stage)


# ── creating ─────────────────────────────────────────────────────────────────

def create(path: Path, level: str = "5", out: Path | None = None, progress: Progress | None = None,
           cancel: threading.Event | None = None) -> Path:
    """Write recovery data for ``path`` to ``out`` (by default ``path`` + ``.lpar``)."""
    from .engine import create_private
    from .osutil import fsync_dir
    path = Path(path)
    out = Path(out) if out else path.with_name(path.name + EXTENSION)
    report = _Checker(progress, cancel)
    with open(path, "rb") as f:
        size = f.seek(0, os.SEEK_END)
        lay = layout_for(size, level)
        n, S, k, m, B = lay.blocks, lay.stripes, lay.k, lay.m, lay.block
        coeffs = [[coefficient(i, t, m) for t in range(k)] for i in range(m)]
        data_hashes: list[bytes] = [b""] * n
        parity_hashes: list[bytes] = [b""] * (S * m)
        whole = hashlib.sha256()
        tmp = out.with_name(f".{out.name}.{secrets.token_hex(4)}.part")
        per_pass = max(1, PASS_MEMORY // (m * B))
        meta_len = None
        try:
            with create_private(tmp) as w:
                meta = _meta(lay, path.name, b"\0" * 32, data_hashes, parity_hashes)
                w.write(MAGIC + struct.pack(">I", len(meta)) + meta + bytes(32))   # placeholder, rewritten below
                meta_len = len(meta)
                parity_start = w.tell()
                done = 0
                for j0 in range(0, S, per_pass):
                    j1 = min(S, j0 + per_pass)
                    acc = [[0] * m for _ in range(j1 - j0)]
                    for t in range(k):
                        b0 = t * S + j0
                        if b0 * B >= size:
                            break
                        f.seek(b0 * B)
                        run = f.read((j1 - j0) * B)
                        for jj in range(j1 - j0):
                            b = b0 + jj
                            if b >= n:
                                break
                            blk = run[jj * B:(jj + 1) * B]
                            data_hashes[b] = _h(blk)
                            blk += bytes(B - len(blk))
                            for i in range(m):
                                acc[jj][i] ^= _scale(blk, coeffs[i][t])
                        done += len(run)
                        report(done / max(size, 1) * 0.99, "Computing recovery data")
                    w.seek(parity_start + j0 * m * B)
                    for jj in range(j1 - j0):
                        for i in range(m):
                            blk = acc[jj][i].to_bytes(B, "big")
                            parity_hashes[(j0 + jj) * m + i] = _h(blk)
                            w.write(blk)
                f.seek(0)
                while chunk := f.read(4 << 20):
                    whole.update(chunk)
                meta = _meta(lay, path.name, whole.digest(), data_hashes, parity_hashes)
                if len(meta) != meta_len:
                    raise LocksmithError("Recovery data could not be written.")
                checksum = hashlib.sha256(meta).digest()
                w.seek(0)
                w.write(MAGIC + struct.pack(">I", len(meta)) + meta + checksum)
                w.seek(0, os.SEEK_END)
                w.write(meta + checksum + struct.pack(">I", len(meta)) + END_MAGIC)
                w.flush()
                os.fsync(w.fileno())
            os.replace(tmp, out)
            # No more readable than the file it describes: the owner can always write it, others may
            # read it only where they can read the file (audit B2).
            os.chmod(out, 0o600 | (stat.S_IMODE(os.stat(path).st_mode) & 0o044))
            fsync_dir(out.parent)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    report(1.0, "Done")
    return out


def _meta(lay: Layout, name: str, digest: bytes, data_hashes, parity_hashes) -> bytes:
    header = json.dumps({"v": 1, "size": lay.size, "block": lay.block, "k": lay.k, "m": lay.m,
                         "sha256": digest.hex(), "name": name}, separators=(",", ":")).encode()
    table = b"".join(h or bytes(HASH_LEN) for h in data_hashes) + b"".join(h or bytes(HASH_LEN) for h in parity_hashes)
    return struct.pack(">I", len(header)) + header + table


# ── reading the sidecar ──────────────────────────────────────────────────────

@dataclass
class Recovery:
    lay: Layout
    name: str
    sha256: bytes
    data_hashes: list[bytes]
    parity_hashes: list[bytes]
    parity_start: int


def _parse_meta(meta: bytes) -> tuple[Layout, str, bytes, list[bytes], list[bytes]]:
    (hlen,) = struct.unpack(">I", meta[:4])
    header = json.loads(meta[4:4 + hlen])
    if not isinstance(header, dict) or header.get("v") != 1:
        raise ValueError
    size, block, k, m = (header[x] for x in ("size", "block", "k", "m"))
    for v in (size, block, k, m):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError
    if not 0 <= size < 1 << 50 or (k, m) not in LEVELS.values():
        raise ValueError
    # Only the layouts Locksmith writes: (k, m) from LEVELS and the block size it picks for the size.
    # A crafted sidecar could otherwise choose k = m = 1 and have every block rebuilt from its parity.
    lay = Layout(size, block, k, m)
    level = next(name for name, km in LEVELS.items() if km == (k, m))
    if block != layout_for(size, level).block:
        raise ValueError
    digest = bytes.fromhex(header["sha256"])
    name = header.get("name") if isinstance(header.get("name"), str) else ""
    table = meta[4 + hlen:]
    n, p = lay.blocks, lay.stripes * m
    if len(digest) != 32 or len(table) != (n + p) * HASH_LEN:
        raise ValueError
    hashes = [table[i * HASH_LEN:(i + 1) * HASH_LEN] for i in range(n + p)]
    return lay, name, digest, hashes[:n], hashes[n:]


MAX_META = 64 << 20


def read_recovery(path: Path) -> Recovery:
    """The sidecar's description, from whichever of its two copies is intact."""
    bad = LocksmithError("The recovery data is damaged beyond use (both copies of its description).")
    with open(path, "rb") as f:
        total = f.seek(0, os.SEEK_END)
        copies = []
        f.seek(0)
        head = f.read(12)
        if head[:8] == MAGIC:
            (n,) = struct.unpack(">I", head[8:12])
            if n <= MAX_META and 12 + n + 32 <= total:
                copies.append((f.read(n), f.read(32), 12 + n + 32))
        if total >= 12:
            f.seek(total - 12)
            tail = f.read(12)
            (n,) = struct.unpack(">I", tail[:4])
            if tail[4:] == END_MAGIC and n <= MAX_META and n + 32 + 12 <= total:
                f.seek(total - 12 - 32 - n)
                copies.append((f.read(n), f.read(32), None))
        for meta, checksum, start in copies:
            if hashlib.sha256(meta).digest() != checksum:
                continue
            try:
                lay, name, digest, data_hashes, parity_hashes = _parse_meta(meta)
            except (ValueError, KeyError, TypeError, struct.error, RecursionError):
                continue
            parity_start = start if start is not None else 12 + len(meta) + 32
            if parity_start + len(parity_hashes) * lay.block + len(meta) + 32 + 12 != total:
                continue
            return Recovery(lay, name, digest, data_hashes, parity_hashes, parity_start)
    if not copies:
        raise LocksmithError("That is not Locksmith recovery data.")
    raise bad


# ── checking and repairing ───────────────────────────────────────────────────

@dataclass
class Report:
    intact: bool
    damaged: list[int] = field(default_factory=list)   # data blocks that don't match
    unrepairable: int = 0                              # stripes with more damage than parity
    size_matches: bool = True
    repaired: Path | None = None
    kept: Path | None = None                           # the damaged original, kept beside it
    blocks: int = 0                                    # data blocks in the file the sidecar describes
    sha256: str = ""                                   # what a repair must produce, as the sidecar says

    @property
    def rebuilt_fraction(self) -> float:
        """How much of the file a repair would write from the recovery data."""
        return len(self.damaged) / max(self.blocks, 1)

    @property
    def repairable(self) -> bool:
        return not self.intact and self.unrepairable == 0


def check(path: Path, lpar: Path | None = None, progress: Progress | None = None,
          cancel: threading.Event | None = None) -> Report:
    path = Path(path)
    rec = read_recovery(Path(lpar) if lpar else path.with_name(path.name + EXTENSION))
    report = _Checker(progress, cancel)
    lay = rec.lay
    damaged = []
    with open(path, "rb") as f:
        actual = f.seek(0, os.SEEK_END)
        f.seek(0)
        whole = hashlib.sha256()
        for b in range(lay.blocks):
            blk = f.read(min(lay.block, lay.size - b * lay.block))
            whole.update(blk)
            if len(blk) < min(lay.block, lay.size - b * lay.block) or _h(blk) != rec.data_hashes[b]:
                damaged.append(b)
            if b % 64 == 0:
                report(b / max(lay.blocks, 1), "Checking")
    intact = not damaged and actual == lay.size and whole.digest() == rec.sha256
    if not damaged and not intact and actual == lay.size:
        damaged = list(range(lay.blocks))   # hashes matched but the whole didn't: can't say where
    result = Report(intact, damaged, size_matches=actual == lay.size, blocks=lay.blocks, sha256=rec.sha256.hex())
    if not intact:
        good_parity = _good_parity(path, rec, lpar)
        per_stripe: dict[int, int] = {}
        for b in damaged:
            per_stripe[lay.stripe_of(b)[0]] = per_stripe.get(lay.stripe_of(b)[0], 0) + 1
        result.unrepairable = sum(1 for j, bad in per_stripe.items()
                                  if bad > sum(good_parity[j * lay.m + i] for i in range(lay.m)))
    report(1.0, "Checked")
    return result


def _good_parity(path: Path, rec: Recovery, lpar: Path | None) -> list[bool]:
    lay = rec.lay
    out = []
    with open(Path(lpar) if lpar else path.with_name(path.name + EXTENSION), "rb") as f:
        f.seek(rec.parity_start)
        for h in rec.parity_hashes:
            out.append(_h(f.read(lay.block)) == h)
    return out


def repair(path: Path, lpar: Path | None = None, progress: Progress | None = None,
           cancel: threading.Event | None = None) -> Report:
    """Rebuild a damaged file. The repaired file takes the original name once its SHA-256 matches;
    the damaged original is kept beside it as ``name.damaged``. Nothing changes when the damage is
    more than the recovery data can repair."""
    from .engine import create_private, unique_path
    from .osutil import copy_zone_identifier, fsync_dir
    path = Path(path)
    lpar_path = Path(lpar) if lpar else path.with_name(path.name + EXTENSION)
    result = check(path, lpar_path, progress, cancel)
    if result.intact:
        return result
    if result.unrepairable:
        raise LocksmithError(f"The damage is too large to repair: {result.unrepairable} part"
                             f"{'s' if result.unrepairable != 1 else ''} of the file lost more blocks than the "
                             "recovery data can rebuild. Nothing was changed.")
    rec = read_recovery(lpar_path)
    lay = rec.lay
    report = _Checker(progress, cancel)
    good_parity = _good_parity(path, rec, lpar_path)
    damaged = set(result.damaged)
    fixed: dict[int, bytes] = {}
    stripes = sorted({lay.stripe_of(b)[0] for b in damaged})
    with open(path, "rb") as f, open(lpar_path, "rb") as p:
        for done, j in enumerate(stripes):
            report(done / len(stripes), "Repairing")
            members = [t * lay.stripes + j for t in range(lay.k)]
            lost = [t for t, b in enumerate(members) if b in damaged]
            rows = [i for i in range(lay.m) if good_parity[j * lay.m + i]][:len(lost)]
            syndromes = []
            for i in rows:
                p.seek(rec.parity_start + (j * lay.m + i) * lay.block)
                s = int.from_bytes(p.read(lay.block), "big")
                for t, b in enumerate(members):
                    if t not in lost:
                        s ^= _scale(_read_block(f, lay, b), coefficient(i, t, lay.m))
                syndromes.append(s)
            inverse = _solve([[coefficient(i, t, lay.m) for t in lost] for i in rows])
            for a, t in enumerate(lost):
                value = 0
                for r, s in enumerate(syndromes):
                    c = inverse[a][r]
                    if c:
                        value ^= _scale(s.to_bytes(lay.block, "big"), c)
                fixed[members[t]] = value.to_bytes(lay.block, "big")
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.part")
    whole = hashlib.sha256()
    try:
        with open(path, "rb") as f, create_private(tmp) as out:
            for b in range(lay.blocks):
                want = min(lay.block, lay.size - b * lay.block)
                blk = fixed[b][:want] if b in fixed else _read_block(f, lay, b)[:want]
                whole.update(blk)
                out.write(blk)
            out.flush()
            os.fsync(out.fileno())
        if whole.digest() != rec.sha256:
            raise LocksmithError("The repair didn't reproduce the original file, so nothing was changed.")
        _check_still_encrypted(path, tmp)
        kept = unique_path(path.with_name(path.name + ".damaged"))
        os.replace(path, kept)
        try:
            os.replace(tmp, path)
        except BaseException:
            os.replace(kept, path)   # put the original back rather than leave neither in place
            raise
        copy_zone_identifier(kept, path)   # a repaired download is still a download
        fsync_dir(path.parent)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    result.repaired, result.kept = path, kept
    report(1.0, "Repaired")
    return result


def _check_still_encrypted(original: Path, repaired: Path):
    """A Locksmith or age file must still be one after repair. A sidecar that rebuilt its header
    into something else came from someone else, not from storage decay."""
    from . import age, engine
    with open(original, "rb") as f:
        was = f.read(64)
    with open(repaired, "rb") as f:
        now = f.read(64)
    try:
        if engine.looks_encrypted(was) or engine.looks_encrypted(now) or \
                was.lstrip().startswith(engine.ARMOR_BEGIN.encode()):
            engine.inspect(repaired)
        elif age.is_age(was) or age.is_age(now):
            age.inspect(repaired)
    except (LocksmithError, OSError) as e:
        raise LocksmithError("The repaired file wouldn't be a valid encrypted file, so the recovery data doesn't "
                             "belong to it. Nothing was changed.") from e
