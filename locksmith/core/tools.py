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
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from .errors import CancelledError, LocksmithError
from .osutil import IS_WINDOWS, fsync_dir, is_link, open_new, windows_unsafe


def same_secret(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time equality for secrets (passwords, checksums, key material).
    Works for any Unicode text, unlike hmac.compare_digest on str."""
    a = a.encode() if isinstance(a, str) else a
    b = b.encode() if isinstance(b, str) else b
    return hmac.compare_digest(a, b)

# Characters that reorder the text around them (bidi overrides, embeddings and isolates):
# "invoice\u202efdp.exe" displays as "invoiceexe.pdf".
_BIDI_CONTROLS = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def display_text(text: str, limit: int = 500) -> str:
    """Text from a file, an archive or a signer (a note, a name, an OpenPGP user ID), made safe to
    show next to Locksmith's own status lines: line breaks become spaces, so it can't add a line
    that looks like one ("✓ Signed with…"); control and bidi characters are dropped, so it can't
    reorder what is shown; and long text is cut. Other formatting characters (such as the zero-width
    joiners Persian and emoji need) are kept."""
    out = []
    for c in text:
        if c in "\n\r\t\v\f\x85\u2028\u2029":
            out.append(" ")
        elif c not in _BIDI_CONTROLS and unicodedata.category(c) not in ("Cc", "Cs"):
            out.append(c)
    shown = "".join(out)
    return shown if len(shown) <= limit else shown[:limit] + "…"


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


def open_regular(path: Path) -> BinaryIO:
    """Open a regular file for reading, following links. Anything else (a FIFO, a device)
    is refused: opening a FIFO would block forever and a device can read without end.
    O_NONBLOCK makes the open itself return at once, before the type is checked."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise LocksmithError(f"{Path(path).name} is not a regular file.")
    return os.fdopen(fd, "rb")


def read_text(path: Path, limit: int, what: str) -> str:
    """Read a small text file (a signature, a key, a manifest), refusing anything larger
    than ``limit`` or not a regular file. Bytes that aren't UTF-8 are kept as surrogates
    (``surrogateescape``), so file names and signed text survive byte for byte."""
    with open_regular(path) as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise LocksmithError(f"{Path(path).name} is too large to be {what}.")
    return data.decode("utf-8", "surrogateescape")


def hash_file(path: Path, algorithm: str,
              progress: Callable[[float], None] | None = None,
              cancel: threading.Event | None = None) -> str:
    h = hashlib.new(algorithm)
    with open_regular(path) as f:
        size = max(os.fstat(f.fileno()).st_size, 1)
        done = 0
        while block := f.read(4 << 20):
            if cancel and cancel.is_set():
                raise CancelledError()
            h.update(block)
            done += len(block)
            if progress:
                progress(done / size)
    return h.hexdigest()


def same_contents(a: Path, b: Path, progress: Callable[[float], None] | None = None,
                  cancel: threading.Event | None = None) -> bool:
    """Compare two files byte for byte (no hash, so no collision can fool it)."""
    with open_regular(a) as fa, open_regular(b) as fb:
        size = os.fstat(fa.fileno()).st_size
        if size != os.fstat(fb.fileno()).st_size:
            return False
        done = 0
        while True:
            if cancel and cancel.is_set():
                raise CancelledError()
            x, y = fa.read(4 << 20), fb.read(4 << 20)
            if x != y:
                return False
            if not x:
                return True
            done += len(x)
            if progress:
                progress(done / max(size, 1))


# ── folder manifests ─────────────────────────────────────────────────────────
#
# One line per file in the BSD "tag" format that `sha256sum --tag` and `cksum` write
# and check: "SHA256 (path/inside/folder) = hex". A name holding a backslash or a line
# break is escaped as coreutils does: the line starts with "\" and those characters
# become "\\", "\n" and "\r". MD5 is not offered: its collisions are cheap to make,
# so an MD5 manifest cannot show that files were not swapped. File names on Linux are
# bytes: names that aren't UTF-8 are carried as surrogates, so write a manifest with
# ``manifest.encode("utf-8", "surrogateescape")`` and read it with ``read_text``.

MANIFEST_TAGS = {"sha256": "SHA256", "sha512": "SHA512", "sha3_256": "SHA3-256", "sha3_512": "SHA3-512",
                 "blake2b": "BLAKE2b", "blake2s": "BLAKE2s"}
_TAG_ALGS = {v: k for k, v in MANIFEST_TAGS.items()}
MAX_MANIFEST = 64 << 20
_MANIFEST_LINE = re.compile(r"(\\)?([A-Za-z0-9-]+) \((.*)\) = ([0-9a-fA-F]+)")


@dataclass
class ManifestReport:
    matched: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)   # contents differ from the manifest
    missing: list[str] = field(default_factory=list)   # listed but not there, or not a regular file
    extra: list[str] = field(default_factory=list)     # in the folder but not listed
    invalid: list[str] = field(default_factory=list)   # lines that could not be used, with why

    @property
    def ok(self) -> bool:
        return bool(self.matched) and not (self.changed or self.missing or self.extra or self.invalid)


def _escape(name: str) -> tuple[str, bool]:
    if not any(c in name for c in "\\\n\r"):
        return name, False
    return name.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r"), True


def _unescape(name: str) -> str | None:
    out, i = [], 0
    while i < len(name):
        c = name[i]
        if c == "\\":
            nxt = name[i + 1:i + 2]
            if nxt not in ("\\", "n", "r"):
                return None
            out.append({"\\": "\\", "n": "\n", "r": "\r"}[nxt])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _folder_files(folder: Path, exclude: set[Path]) -> list[str]:
    """Regular files under ``folder`` as relative POSIX paths. Links are not followed."""
    found = []
    exclude = {p.resolve() for p in exclude}
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for name in sorted(files):
            path = Path(root) / name
            if path.is_symlink() or not path.is_file() or (exclude and path.resolve() in exclude):
                continue
            found.append(path.relative_to(folder).as_posix())
    return found


def make_manifest(folder: Path, algorithm: str = "sha256", exclude: Path | None = None,
                  progress: Callable[[float], None] | None = None,
                  cancel: threading.Event | None = None) -> str:
    """Checksum every regular file under ``folder``. Links are left out: their target
    may lie outside the folder. ``exclude`` is the manifest's own path, if inside."""
    if algorithm not in MANIFEST_TAGS:
        raise LocksmithError("Manifests use SHA-256, SHA-512, SHA-3 or BLAKE2.")
    folder = Path(folder)
    names = _folder_files(folder, {Path(exclude)} if exclude else set())
    lines = []
    for i, rel in enumerate(names):
        digest = hash_file(folder / rel, algorithm, cancel=cancel)
        name, escaped = _escape(rel)
        lines.append(f"{'\\' if escaped else ''}{MANIFEST_TAGS[algorithm]} ({name}) = {digest}")
        if progress:
            progress((i + 1) / len(names))
    return "".join(line + "\n" for line in lines)


def _manifest_target(folder: Path, name: str) -> Path | None:
    """The file a manifest entry names, or None if the entry could reach outside the folder."""
    parts = name.split("/")
    if (not name or "\x00" in name or name.startswith("/") or any(p in ("", ".", "..") for p in parts)
            or (IS_WINDOWS and any(windows_unsafe(p) for p in parts))):   # drives, streams, devices
        return None
    target = folder.joinpath(*parts)
    # A link inside the folder may point anywhere; only follow it if it stays inside.
    if not os.path.realpath(target).startswith(os.path.join(os.path.realpath(folder), "")):
        return None
    return target


def verify_manifest(text: str, folder: Path, exclude: Path | None = None,
                    progress: Callable[[float], None] | None = None,
                    cancel: threading.Event | None = None) -> ManifestReport:
    """Check ``folder`` against a manifest that may come from anyone. Entries can only
    name regular files inside the folder; anything else is reported, never read."""
    if len(text) > MAX_MANIFEST:
        raise LocksmithError(f"Manifests over {MAX_MANIFEST >> 20} MiB are not supported.")
    folder = Path(folder)
    report = ManifestReport()
    entries: dict[str, tuple[str, str]] = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = _MANIFEST_LINE.fullmatch(line)
        name = m and (_unescape(m[3]) if m[1] else m[3])
        alg = m and _TAG_ALGS.get(m[2])
        if not m or name is None:
            report.invalid.append(f"line {n}: not a checksum line")
        elif alg is None:
            report.invalid.append(f"line {n}: {m[2]} is not accepted" + (" (MD5 is broken)" if m[2] == "MD5" else ""))
        elif len(m[4]) != hashlib.new(alg).digest_size * 2:
            report.invalid.append(f"line {n}: the checksum has the wrong length")
        elif _manifest_target(folder, name) is None:
            report.invalid.append(f"line {n}: “{name}” is outside the folder")
        elif name in entries:
            report.invalid.append(f"line {n}: “{name}” is listed twice")
        else:
            entries[name] = (alg, m[4].lower())
    for i, (name, (alg, expected)) in enumerate(entries.items()):
        try:
            actual = hash_file(_manifest_target(folder, name), alg, cancel=cancel)
        except (OSError, LocksmithError) as e:
            if isinstance(e, CancelledError):
                raise
            report.missing.append(name)
        else:
            (report.matched if same_secret(actual, expected) else report.changed).append(name)
        if progress:
            progress((i + 1) / len(entries))
    listed = set(entries)
    report.extra = [f for f in _folder_files(folder, {Path(exclude)} if exclude else set()) if f not in listed]
    return report


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


# Share text formats. Both end in a 6-hex-digit typo check over the share's fields.
#   locksmithshare-<k>-<x>-<data>-<check>          v1, still read
#   locksmithshare2-<k>-<x>-<id>-<data>-<check>    v2, written
# v2 adds a random split ID shared by every share of one split, and splits the secret
# followed by a tag (a hash of the ID and secret), so mixed or altered shares are caught.
_SHARE_V1 = re.compile(r"locksmithshare-([0-9]{1,3})-([0-9]{1,3})-()([0-9a-f]+)-([0-9a-f]{6})")
_SHARE_V2 = re.compile(r"locksmithshare2-([0-9]{1,3})-([0-9]{1,3})-([0-9a-f]{8})-([0-9a-f]+)-([0-9a-f]{6})")
_SPLIT_ID = 4
_TAG = 8


def _share_tag(split_id: bytes, secret: bytes) -> bytes:
    return hashlib.sha256(b"locksmith/share/v2" + split_id + secret).digest()[:_TAG]


def _interpolate(points: dict[int, bytes], xs: list[int], at: int) -> bytes:
    """Evaluate, at x = `at`, the polynomials through the shares at `xs` (one per byte)."""
    out = bytearray(len(points[xs[0]]))
    for xj in xs:
        num, den = 1, 1
        for xm in xs:
            if xm != xj:
                num = _mul(num, at ^ xm)
                den = _mul(den, xj ^ xm)
        weight = _div(num, den)
        for i, y in enumerate(points[xj]):
            out[i] ^= _mul(y, weight)
    return bytes(out)


def shamir_split(secret: bytes, threshold: int, shares: int) -> list[str]:
    if not 2 <= threshold <= shares <= 255:
        raise LocksmithError("Need 2 ≤ threshold ≤ shares ≤ 255.")
    if not secret:
        raise LocksmithError("Nothing to split.")
    split_id = secrets.token_bytes(_SPLIT_ID)
    data = secret + _share_tag(split_id, secret)
    coeffs = [[b] + [secrets.randbelow(256) for _ in range(threshold - 1)] for b in data]
    out = []
    for x in range(1, shares + 1):
        ys = bytearray()
        for poly in coeffs:
            y = 0
            for c in reversed(poly):  # Horner
                y = _mul(y, x) ^ c
            ys.append(y)
        body = bytes([threshold, x]) + split_id + bytes(ys)
        check = hashlib.sha256(body).hexdigest()[:6]
        out.append(f"locksmithshare2-{threshold}-{x}-{split_id.hex()}-{ys.hex()}-{check}")
    return out


def shamir_combine(texts: list[str]) -> bytes:
    points: dict[int, bytes] = {}
    split = None  # (format, threshold, split ID) of the first share; the rest must match
    for text in texts:
        text = text.strip()
        if not text:
            continue
        m = _SHARE_V2.fullmatch(text) or _SHARE_V1.fullmatch(text)
        if not m:
            raise LocksmithError("One of the shares is not in the right format.")
        k, x, split_id, hexdata, check = int(m[1]), int(m[2]), bytes.fromhex(m[3]), m[4], m[5]
        if not (2 <= k <= 255 and 1 <= x <= 255) or len(hexdata) % 2:
            raise LocksmithError("One of the shares is not in the right format.")
        data = bytes.fromhex(hexdata)
        if not same_secret(hashlib.sha256(bytes([k, x]) + split_id + data).hexdigest()[:6], check):
            raise LocksmithError(f"Share #{x} has a typo (checksum mismatch).")
        if split is not None and (m.re, k, split_id) != split:
            raise LocksmithError("The shares belong to different secrets.")
        split = (m.re, k, split_id)
        if x in points and not same_secret(points[x], data):
            raise LocksmithError(f"Share #{x} was given twice with different contents.")
        points[x] = data
    if split is None:
        raise LocksmithError("Paste at least two shares.")
    version, threshold, split_id = split
    if len(points) < threshold:
        raise LocksmithError(f"Need {threshold} different shares, got {len(points)}.")
    lengths = {len(d) for d in points.values()}
    if len(lengths) > 1 or (version is _SHARE_V2 and lengths.pop() <= _TAG):
        raise LocksmithError("The shares belong to different secrets.")
    xs = list(points)[:threshold]
    mismatch = LocksmithError("The shares don't fit together: one is damaged or belongs to a "
                              "different secret.")
    # Shares beyond the threshold must lie on the same polynomials.
    for x in list(points)[threshold:]:
        if not same_secret(_interpolate(points, xs, x), points[x]):
            raise mismatch
    data = _interpolate(points, xs, 0)
    if version is _SHARE_V1:
        return data
    secret, tag = data[:-_TAG], data[-_TAG:]
    if not same_secret(_share_tag(split_id, secret), tag):
        raise mismatch
    return secret


# ── shredding ────────────────────────────────────────────────────────────────

def shred(path: Path, passes: int = 1, cancel: threading.Event | None = None):
    """Best-effort overwrite then delete. Not reliable on SSDs or on
    copy-on-write filesystems such as btrfs, where old blocks may survive.

    A link given directly is refused: removing it would leave the data it points to in
    place while looking shredded. Links inside a folder are only unlinked, which is right
    for them: what they point to is not part of the folder."""
    path = Path(path)
    if is_link(path):
        raise LocksmithError(f"{path.name} is a link. Add the file or folder it points to instead.")
    _shred(path, passes, cancel)


def _shred(path: Path, passes: int, cancel: threading.Event | None):
    if path.is_dir() and not is_link(path):
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                _shred(Path(root) / name, passes, cancel)
            for name in dirs:
                p = Path(root) / name
                _remove_link(p) if is_link(p) else p.rmdir()
        path.rmdir()
        return
    if is_link(path):
        _remove_link(path)
        return
    if not path.is_file():
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


def _remove_link(path: Path):
    """Remove a link itself, never what it points to. Windows removes junctions and links
    to folders as folders; rmdir on them deletes only the link."""
    try:
        path.unlink()
    except (IsADirectoryError, PermissionError):
        if not IS_WINDOWS:
            raise
        os.rmdir(path)


def covered_by(path: Path, inputs: list[Path]) -> bool:
    """Whether ``path`` is one of ``inputs`` or inside one of them, also when it is
    reached through a symlink or is a hard link to a file in an input folder.
    Shredding the inputs would then destroy it."""
    try:
        target = Path(path).resolve()
        st = target.stat()
    except OSError:
        return False
    # Compare file identities as well as paths, so case-insensitive names and other
    # spellings of the same folder still match.
    chain = set()
    for q in (target, *target.parents):
        try:
            s = q.stat()
        except OSError:
            continue
        if s.st_ino:
            chain.add((s.st_dev, s.st_ino))
    for p in inputs:
        p = Path(p)
        try:
            root, s = p.resolve(), p.stat()
        except OSError:
            continue
        if target == root or target.is_relative_to(root) or (s.st_ino and (s.st_dev, s.st_ino) in chain):
            return True
        # Another name for the same file can sit anywhere in an input folder.
        if st.st_nlink > 1 and st.st_ino and stat.S_ISDIR(s.st_mode):
            for dirpath, _, files in os.walk(p):
                for name in files:
                    try:
                        f = os.lstat(os.path.join(dirpath, name))
                    except OSError:
                        continue
                    if (f.st_dev, f.st_ino) == (st.st_dev, st.st_ino):
                        return True
    return False


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
    # Build under a temporary name, so a failed join never leaves a truncated file
    # under the real name.
    tmp = out_dir / f".{base}.{secrets.token_hex(4)}.part"
    try:
        with os.fdopen(open_new(tmp), "wb") as out:
            for p in parts:
                with open(p, "rb") as f:
                    while block := f.read(4 << 20):
                        out.write(block)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    fsync_dir(out_dir)
    return target
