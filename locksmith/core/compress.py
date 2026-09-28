"""Per-chunk compression codecs.

Each chunk is compressed independently, which lets chunks be compressed in
parallel and keeps every chunk decodable on its own.
"""

from __future__ import annotations

import bz2
import lzma
import zlib
from collections.abc import Callable
from dataclasses import dataclass

from .errors import CorruptedError

try:
    from compression import zstd as _zstd  # Python 3.14+
except ImportError:
    # Same API for older Pythons. Required, not optional: a build without
    # Zstandard could not open files made by a build with it.
    from backports import zstd as _zstd


@dataclass(frozen=True)
class Codec:
    id: str
    label: str
    levels: dict[str, int]
    compress: Callable[[bytes, int], bytes]
    new_decompressor: Callable[[], object]

    def decompress(self, data: bytes, limit: int) -> bytes:
        """Decompress one complete stream, refusing to produce more than ``limit``
        bytes so a crafted chunk cannot expand into gigabytes of memory."""
        d = self.new_decompressor()
        try:
            out = d.decompress(data, limit + 1)
        except Exception as e:  # each codec raises its own error type
            raise CorruptedError("A compressed chunk is damaged.") from e
        if len(out) > limit:
            raise CorruptedError("A compressed chunk expands beyond its declared size.")
        if not d.eof or d.unused_data or getattr(d, "unconsumed_tail", b""):
            raise CorruptedError("A compressed chunk is damaged.")
        return out


LEVELS = {"fast": "Fast", "balanced": "Balanced", "max": "Maximum"}

CODECS: dict[str, Codec] = {}

CODECS["zstd"] = Codec(
    "zstd", "Zstandard",
    {"fast": 1, "balanced": 6, "max": 19},
    lambda d, lvl: _zstd.compress(d, level=lvl),
    _zstd.ZstdDecompressor,
)

CODECS["zlib"] = Codec(
    "zlib", "Deflate (zlib)",
    {"fast": 1, "balanced": 6, "max": 9},
    lambda d, lvl: zlib.compress(d, lvl),
    zlib.decompressobj,
)
CODECS["lzma"] = Codec(
    "lzma", "LZMA / XZ",
    {"fast": 1, "balanced": 4, "max": 6},
    lambda d, lvl: lzma.compress(d, preset=lvl),
    lzma.LZMADecompressor,
)
CODECS["bz2"] = Codec(
    "bz2", "bzip2",
    {"fast": 1, "balanced": 6, "max": 9},
    lambda d, lvl: bz2.compress(d, lvl),
    bz2.BZ2Decompressor,
)

DEFAULT_CODEC = "zstd"

# Extensions whose contents are already compressed; "auto" mode skips them.
PRECOMPRESSED = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".heic", ".mp3", ".aac",
    ".ogg", ".opus", ".flac", ".m4a", ".mp4", ".mkv", ".webm", ".mov", ".avi",
    ".zip", ".7z", ".rar", ".gz", ".xz", ".bz2", ".zst", ".br", ".lz4", ".locked",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub", ".apk", ".jar",
    ".appimage", ".deb", ".rpm", ".iso", ".pdf",
}
