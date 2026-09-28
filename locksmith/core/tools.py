"""Password generation, strength estimation, checksums, Shamir secret sharing,
shredding and file splitting."""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import secrets
import stat
import string
import threading
from collections.abc import Callable
from pathlib import Path

from .errors import CancelledError, LocksmithError
from .osutil import open_new


def same_secret(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time equality for secrets (passwords, checksums, key material).
    Works for any Unicode text, unlike hmac.compare_digest on str."""
    a = a.encode() if isinstance(a, str) else a
    b = b.encode() if isinstance(b, str) else b
    return hmac.compare_digest(a, b)

# ── passwords ────────────────────────────────────────────────────────────────

AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?~"


def generate_password(length=24, lower=True, upper=True, digits=True, symbols=True,
                      avoid_ambiguous=False) -> str:
    pools = [p for p, on in ((string.ascii_lowercase, lower), (string.ascii_uppercase, upper),
                             (string.digits, digits), (SYMBOLS, symbols)) if on]
    if not pools:
        pools = [string.ascii_lowercase]
    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]
    alphabet = "".join(pools)
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if length < len(pools) or all(any(c in p for c in pw) for p in pools):
            return pw


_CONS = "bdfghjklmnprstvz"
_VOWELS = "aeiou"


def generate_passphrase(words=6, separator="-") -> str:
    """Pronounceable random words (CVCVC). Each word carries ~16.6 bits."""
    def word():
        return "".join(secrets.choice(_CONS if i % 2 == 0 else _VOWELS) for i in range(5))
    parts = [word() for _ in range(words)]
    i = secrets.randbelow(words)
    parts[i] = parts[i].capitalize() + str(secrets.randbelow(10))
    return separator.join(parts)


def passphrase_entropy(words: int) -> float:
    return words * (3 * math.log2(len(_CONS)) + 2 * math.log2(len(_VOWELS))) + math.log2(10 * words)


_COMMON = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou",
           "monkey", "dragon", "abc123", "111111", "secret", "master", "login"}


def estimate_entropy(pw: str) -> float:
    """Rough, conservative entropy estimate in bits."""
    if not pw:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", pw):
        pool += 26
    if re.search(r"[A-Z]", pw):
        pool += 26
    if re.search(r"\d", pw):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        pool += 33
    # Penalise repeats and runs: count "effective" characters.
    effective = 0.0
    prev = None
    for i, c in enumerate(pw):
        if c == prev:
            effective += 0.25
        elif i and abs(ord(c) - ord(pw[i - 1])) == 1:
            effective += 0.5
        else:
            effective += 1
        prev = c
    bits = effective * math.log2(max(pool, 2))
    lowered = pw.lower()
    if any(w in lowered for w in _COMMON):
        bits *= 0.4
    return bits


def strength_label(bits: float) -> tuple[int, str]:
    if bits < 28:
        return 0, "Very weak"
    if bits < 45:
        return 1, "Weak"
    if bits < 64:
        return 2, "Fair"
    if bits < 90:
        return 3, "Strong"
    return 4, "Excellent"


def crack_time(bits: float, guesses_per_sec: float = 1e10) -> str:
    seconds = 2 ** max(bits - 1, 0) / guesses_per_sec
    for unit, size in (("centuries", 3.15e9), ("years", 3.15e7), ("days", 86400),
                       ("hours", 3600), ("minutes", 60)):
        if seconds >= size:
            value = seconds / size
            if unit == "centuries" and value > 1e6:
                return "longer than the universe has existed" if value > 1.4e8 else \
                    f"{value:.1e} centuries"
            return f"{value:,.0f} {unit}"
    return "instantly" if seconds < 1 else f"{seconds:.0f} seconds"


# ── checksums ────────────────────────────────────────────────────────────────

HASHES = {
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b-512",
    "blake2s": "BLAKE2s-256",
    "md5": "MD5 (legacy)",
}


def hash_file(path: Path, algorithm: str,
              progress: Callable[[float], None] | None = None,
              cancel: threading.Event | None = None) -> str:
    h = hashlib.new(algorithm)
    size = max(os.path.getsize(path), 1)
    done = 0
    with open(path, "rb") as f:
        while block := f.read(4 << 20):
            if cancel and cancel.is_set():
                raise CancelledError()
            h.update(block)
            done += len(block)
            if progress:
                progress(done / size)
    return h.hexdigest()


# ── Shamir secret sharing over GF(256) ───────────────────────────────────────

def _gf_tables():
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= (x << 1) ^ (0x11B if x & 0x80 else 0)  # multiply by generator 3
        x &= 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _gf_tables()


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a, b):
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[(_LOG[a] - _LOG[b]) % 255]


def shamir_split(secret: bytes, threshold: int, shares: int) -> list[str]:
    if not 2 <= threshold <= shares <= 255:
        raise LocksmithError("Need 2 ≤ threshold ≤ shares ≤ 255.")
    if not secret:
        raise LocksmithError("Nothing to split.")
    coeffs = [[b] + [secrets.randbelow(256) for _ in range(threshold - 1)] for b in secret]
    out = []
    for x in range(1, shares + 1):
        ys = bytearray()
        for poly in coeffs:
            y = 0
            for c in reversed(poly):  # Horner
                y = _mul(y, x) ^ c
            ys.append(y)
        body = bytes([threshold, x]) + bytes(ys)
        check = hashlib.sha256(body).hexdigest()[:6]
        out.append(f"locksmithshare-{threshold}-{x}-{body[2:].hex()}-{check}")
    return out


def shamir_combine(texts: list[str]) -> bytes:
    points = {}
    threshold = None
    for text in texts:
        text = text.strip()
        if not text:
            continue
        m = re.fullmatch(r"locksmithshare-(\d+)-(\d+)-([0-9a-f]+)-([0-9a-f]{6})", text)
        if not m:
            raise LocksmithError("One of the shares is not in the right format.")
        k, x, hexdata, check = int(m[1]), int(m[2]), m[3], m[4]
        if not (2 <= k <= 255 and 1 <= x <= 255) or len(hexdata) % 2:
            raise LocksmithError("One of the shares is not in the right format.")
        body = bytes([k, x]) + bytes.fromhex(hexdata)
        if not same_secret(hashlib.sha256(body).hexdigest()[:6], check):
            raise LocksmithError(f"Share #{x} has a typo (checksum mismatch).")
        if threshold is not None and k != threshold:
            raise LocksmithError("The shares belong to different secrets.")
        threshold = k
        points[x] = bytes.fromhex(hexdata)
    if threshold is None:
        raise LocksmithError("Paste at least two shares.")
    if len(points) < threshold:
        raise LocksmithError(f"Need {threshold} different shares, got {len(points)}.")
    xs = list(points)[:threshold]
    length = len(points[xs[0]])
    if any(len(points[x]) != length for x in xs):
        raise LocksmithError("The shares belong to different secrets.")
    secret = bytearray()
    for i in range(length):
        acc = 0
        for xj in xs:
            num, den = 1, 1
            for xm in xs:
                if xm != xj:
                    num = _mul(num, xm)
                    den = _mul(den, xm ^ xj)
            acc ^= _mul(points[xj][i], _div(num, den))
        secret.append(acc)
    return bytes(secret)


# ── shredding ────────────────────────────────────────────────────────────────

def shred(path: Path, passes: int = 1, cancel: threading.Event | None = None):
    """Best-effort overwrite then delete. Not reliable on SSDs or on
    copy-on-write filesystems such as btrfs, where old blocks may survive."""
    path = Path(path)
    if path.is_dir() and not path.is_symlink():
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                shred(Path(root) / name, passes, cancel)
            for name in dirs:
                p = Path(root) / name
                p.unlink() if p.is_symlink() else p.rmdir()
        path.rmdir()
        return
    if path.is_symlink() or not path.is_file():
        path.unlink(missing_ok=True)
        return
    # O_NOFOLLOW: if the file is swapped for a symlink after the check above, fail
    # rather than overwrite whatever the link points to.
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
        os.close(fd)
        # Overwriting would also destroy the other names; unlinking alone would leave the
        # data readable through them. Neither is what "shred" promises, so stop.
        raise LocksmithError(f"{path.name} was not shredded: it has other hard links or is not "
                             "a regular file. Remove the other links first.")
    size = st.st_size
    with os.fdopen(fd, "r+b", buffering=0) as f:
        for _ in range(passes):
            f.seek(0)
            left = size
            while left > 0:
                if cancel and cancel.is_set():
                    raise CancelledError()
                n = min(left, 1 << 20)
                f.write(os.urandom(n))
                left -= n
            os.fsync(f.fileno())
    scrambled = path.with_name(secrets.token_hex(8))
    os.replace(path, scrambled)
    scrambled.unlink()


# ── split / join ─────────────────────────────────────────────────────────────

def split_file(path: Path, part_size: int, out_dir: Path | None = None) -> list[Path]:
    path = Path(path)
    out_dir = Path(out_dir) if out_dir else path.parent
    parts = []
    with open(path, "rb") as f:
        n = 1
        while block := f.read(part_size):
            part = out_dir / f"{path.name}.part{n:03d}"
            with os.fdopen(open_new(part), "wb") as out:  # never overwrites or follows a link
                out.write(block)
            parts.append(part)
            n += 1
    return parts


def join_parts(parts: list[Path], out_dir: Path | None = None) -> Path:
    parts = sorted((Path(p) for p in parts), key=lambda p: p.name)
    if not parts:
        raise LocksmithError("Choose the parts to join.")
    m = re.fullmatch(r"(.+)\.part(\d{3,})", parts[0].name)
    if not m:
        raise LocksmithError("Parts should be named like “file.locksmith.part001”.")
    base = m[1]
    numbers = []
    for p in parts:
        pm = re.fullmatch(r"(.+)\.part(\d{3,})", p.name)
        if not pm or pm[1] != base:
            raise LocksmithError("All parts must come from the same file.")
        numbers.append(int(pm[2]))
    if numbers != list(range(1, len(numbers) + 1)):
        raise LocksmithError("Some parts are missing: they must be numbered 1…N without gaps.")
    out_dir = Path(out_dir) if out_dir else parts[0].parent
    from .engine import unique_path
    target = unique_path(out_dir / base)
    with os.fdopen(open_new(target), "wb") as out:
        for p in parts:
            with open(p, "rb") as f:
                while block := f.read(4 << 20):
                    out.write(block)
    return target
