"""Lossless metadata stripping for JPEG, PNG and WebP images.

Only the parts an image needs to display correctly are kept (an allowlist):
pixel data, colour profile, transparency, animation. Everything else is dropped:
EXIF (camera, GPS location, dates, serial numbers), XMP, IPTC, comments,
thumbnails, C2PA content credentials and unknown chunks. Pixels are never
re-encoded, so image quality is untouched. The EXIF orientation is kept in a
minimal new EXIF block so photos do not appear rotated.

Stripping works as a *plan*: a list of byte ranges to copy from the file and
small byte strings to insert. The plan is computed from the headers only, then
streamed, so large images are never loaded into memory and the original file
is never modified.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from pathlib import Path

from .errors import LocksmithError

# A plan item is either (offset, length) into the source file, or bytes to insert.
Plan = list


@dataclass
class Stripped:
    kind: str
    plan: Plan
    size: int
    removed: int   # bytes of metadata removed


def detect(head: bytes) -> str | None:
    if head[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def plan_for(path: Path) -> Stripped | None:
    """Return a stripping plan, or None if the format is not supported."""
    path = Path(path)
    with open(path, "rb") as f:
        kind = detect(f.read(12))
        if kind is None:
            return None
        size = f.seek(0, io.SEEK_END)
        f.seek(0)
        try:
            plan = {"jpeg": _plan_jpeg, "png": _plan_png, "webp": _plan_webp}[kind](f, size)
        except (struct.error, ValueError, IndexError) as e:
            raise LocksmithError(f"Could not remove metadata from {path.name}: the {kind.upper()} file "
                               "is damaged. Turn off metadata removal to encrypt it as it is.") from e
    out = sum(len(p) if isinstance(p, bytes) else p[1] for p in plan)
    return Stripped(kind, plan, out, size - out)


class PlanReader(io.RawIOBase):
    """Streams the stripped image described by a plan."""

    def __init__(self, path: Path, plan: Plan):
        super().__init__()
        self._f = open(path, "rb")
        self._items = list(plan)
        self._buf = b""

    def readable(self):
        return True

    def read(self, n=-1):
        out = bytearray()
        while n < 0 or len(out) < n:
            if not self._buf:
                if not self._items:
                    break
                item = self._items.pop(0)
                if isinstance(item, bytes):
                    self._buf = item
                else:
                    off, length = item
                    if length > (4 << 20):  # stream large ranges in pieces
                        self._items.insert(0, (off + (4 << 20), length - (4 << 20)))
                        length = 4 << 20
                    self._f.seek(off)
                    self._buf = self._f.read(length)
                    if len(self._buf) != length:
                        raise LocksmithError("An image changed while it was being encrypted.")
            take = len(self._buf) if n < 0 else min(n - len(out), len(self._buf))
            out += self._buf[:take]
            self._buf = self._buf[take:]
        return bytes(out)

    def close(self):
        self._f.close()
        super().close()


# ── JPEG ─────────────────────────────────────────────────────────────────────

def _read(f, off, n) -> bytes:
    f.seek(off)
    data = f.read(n)
    if len(data) != n:
        raise ValueError("truncated")
    return data


# Segments a decoder needs, besides the APPn kept below (rewritten to their fixed fields,
# except the colour profile): SOFn, DHT and DAC (C0-CF), DQT, DNL, DRI, DHP and EXP (DB-DF).
# Anything else (other APPn, COM, JPGn extensions) is dropped.
JPEG_KEEP = set(range(0xC0, 0xD0)) | set(range(0xDB, 0xE0))


def _plan_jpeg(f, size) -> Plan:
    plan: Plan = [(0, 2)]  # SOI
    pos = 2
    scanned = False
    rewritten: set[str] = set()   # JFIF and Adobe segments are kept once
    while pos < size:
        if _read(f, pos, 1) != b"\xff":
            raise ValueError("expected a marker")
        while _read(f, pos + 1, 1) == b"\xff":  # fill bytes
            pos += 1
        marker = _read(f, pos + 1, 1)[0]
        if marker == 0xD9:
            # EOI: the image ends here. Whatever follows is dropped: appended previews and
            # second images carry their own EXIF and GPS, and so can motion-photo video.
            plan.append((pos, 2))
            return plan
        if 0xD0 <= marker <= 0xD7 or marker == 0x01:
            plan.append((pos, 2))
            pos += 2
            continue
        (length,) = struct.unpack(">H", _read(f, pos + 2, 2))
        if length < 2:
            raise ValueError("bad segment length")
        end = pos + 2 + length
        if end > size:
            raise ValueError("truncated segment")
        if marker == 0xDA:
            # Start of scan: keep its header and compressed data. Progressive images have
            # several scans, with tables (and possibly metadata) between them.
            scan_end = _scan_end(f, end, size)
            plan.append((pos, scan_end - pos))
            pos, scanned = scan_end, True
            continue
        body = _read(f, pos + 4, min(length - 2, 64 << 10)) if marker in (0xE0, 0xE1, 0xE2, 0xEE) else b""
        if marker == 0xE1 and body.startswith(b"Exif\x00\x00") and not scanned:
            # Replace the whole EXIF block, in place, by one holding only the orientation.
            orientation = _read_orientation(_read(f, pos + 4, length - 2)[6:])
            if orientation and orientation != 1:
                plan.append(_exif_orientation(orientation))
        elif marker == 0xE0 and "jfif" not in rewritten and body.startswith(b"JFIF\x00") and len(body) >= 14:
            # JFIF: only its version, density units and densities, never its thumbnail.
            # JFXX (an extension holding a whole thumbnail JPEG) and other APP0 are dropped.
            rewritten.add("jfif")
            plan.append(_segment(0xE0, body[:12] + b"\x00\x00"))
        elif marker == 0xEE and "adobe" not in rewritten and body.startswith(b"Adobe") and len(body) >= 12:
            # Adobe: its fixed 12 bytes (version, flags, colour transform), nothing after them.
            rewritten.add("adobe")
            plan.append(_segment(0xEE, body[:12]))
        elif (marker == 0xE2 and body.startswith(b"ICC_PROFILE\x00")) or marker in JPEG_KEEP:  # colour profile
            plan.append((pos, end - pos))
        pos = end
    if not scanned:
        raise ValueError("no image data")
    return plan  # truncated after its image data: keep what is there, as viewers do


def _segment(marker: int, payload: bytes) -> bytes:
    return bytes((0xFF, marker)) + struct.pack(">H", len(payload) + 2) + payload


def _scan_end(f, pos: int, size: int) -> int:
    """Offset of the marker that ends the compressed data starting at ``pos``. Inside
    it, 0xFF is only followed by 0x00 (a stuffed byte), a restart marker (D0-D7) or
    another 0xFF (fill before a marker)."""
    while pos < size - 1:
        f.seek(pos)
        block = f.read(min(1 << 20, size - pos))
        i = block.find(b"\xff")
        while 0 <= i < len(block) - 1:
            nxt = block[i + 1]
            if nxt not in (0x00, 0xFF) and not 0xD0 <= nxt <= 0xD7:
                return pos + i
            i = block.find(b"\xff", i + 1)
        # An 0xFF at the very end of the block is examined again with the next byte.
        pos += len(block) - 1 if i == len(block) - 1 else len(block)
    return size


def _read_orientation(tiff: bytes) -> int | None:
    try:
        endian = {b"II": "<", b"MM": ">"}[tiff[:2]]
        if struct.unpack(endian + "H", tiff[2:4])[0] != 42:
            return None
        (ifd,) = struct.unpack(endian + "I", tiff[4:8])
        (count,) = struct.unpack(endian + "H", tiff[ifd:ifd + 2])
        for i in range(min(count, 512)):
            e = ifd + 2 + 12 * i
            tag, typ, n = struct.unpack(endian + "HHI", tiff[e:e + 8])
            if tag == 0x0112 and typ == 3 and n == 1:
                value = struct.unpack(endian + "H", tiff[e + 8:e + 10])[0]
                return value if 1 <= value <= 8 else None
    except (KeyError, struct.error):
        return None
    return None


def _exif_orientation(value: int) -> bytes:
    """A minimal APP1 EXIF segment holding only the orientation tag."""
    tiff = (b"MM\x00\x2a" + struct.pack(">I", 8) + struct.pack(">H", 1)
            + struct.pack(">HHIHH", 0x0112, 3, 1, value, 0) + struct.pack(">I", 0))
    payload = b"Exif\x00\x00" + tiff
    return b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload


# ── PNG ──────────────────────────────────────────────────────────────────────

# sPLT is left out: it carries a free-text palette name, and no decoder needs it.
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT",
            b"bKGD", b"hIST", b"cICP", b"mDCv", b"cLLi", b"acTL", b"fcTL", b"fdAT"}


def _plan_png(f, size) -> Plan:
    plan: Plan = [(0, 8)]
    pos = 8
    while pos < size:
        length, ctype = struct.unpack(">I4s", _read(f, pos, 8))
        end = pos + 12 + length
        if end > size:
            raise ValueError("truncated chunk")
        if ctype in PNG_KEEP:
            plan.append((pos, end - pos))
        pos = end
        if ctype == b"IEND":
            return plan  # anything after IEND is not part of the image
    raise ValueError("missing IEND")


# ── WebP ─────────────────────────────────────────────────────────────────────

WEBP_KEEP = {b"VP8 ", b"VP8L", b"VP8X", b"ICCP", b"ANIM", b"ALPH"}
ANMF_KEEP = {b"ALPH", b"VP8 ", b"VP8L"}   # an animation frame's image; it may also hold unknown chunks


def _plan_webp(f, size) -> Plan:
    (riff_size,) = struct.unpack("<I", _read(f, 4, 4))
    end_of_riff = min(size, 8 + riff_size)
    chunks: Plan = []
    pos = 12
    while pos + 8 <= end_of_riff:
        fourcc, length = struct.unpack("<4sI", _read(f, pos, 8))
        padded = length + (length & 1)
        if pos + 8 + padded > end_of_riff:
            raise ValueError("truncated chunk")
        if fourcc == b"VP8X":
            data = bytearray(_read(f, pos + 8, length))
            data[0] &= ~0x0C & 0xFF      # clear the EXIF (0x08) and XMP (0x04) flags
            chunks.append(_read(f, pos, 8) + bytes(data) + (b"\x00" if length & 1 else b""))
        elif fourcc == b"ANMF":
            chunks.extend(_webp_frame(f, pos, length))
        elif fourcc in WEBP_KEEP:
            chunks.append((pos, 8 + padded))
        pos += 8 + padded
    body = sum(len(c) if isinstance(c, bytes) else c[1] for c in chunks)
    return [b"RIFF" + struct.pack("<I", 4 + body) + b"WEBP", *chunks]


def _webp_frame(f, pos: int, length: int) -> Plan:
    """An ANMF chunk rebuilt with only its 16-byte frame header and image sub-chunks."""
    if length < 16:
        raise ValueError("short animation frame")
    end = pos + 8 + length
    parts: Plan = [(pos + 8, 16)]
    sub = pos + 24
    while sub + 8 <= end:
        fourcc, n = struct.unpack("<4sI", _read(f, sub, 8))
        padded = n + (n & 1)
        if sub + 8 + padded > end:
            raise ValueError("truncated frame chunk")
        if fourcc in ANMF_KEEP:
            parts.append((sub, 8 + padded))
        sub += 8 + padded
    body = sum(len(c) if isinstance(c, bytes) else c[1] for c in parts)
    return [b"ANMF" + struct.pack("<I", body), *parts]
