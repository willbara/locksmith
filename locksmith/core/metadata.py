"""Lossless metadata stripping for JPEG, PNG and WebP images.

Only the parts an image needs to display correctly are kept (an allowlist):
pixel data, colour profile, transparency, animation. A colour profile is kept without what
identifies a device or a moment: its creation date, device maker, model and creator fields and
device-description tags are cleared in place, so its colours are unchanged. Everything else is dropped:
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
import zlib
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


# ── ICC colour profiles ──────────────────────────────────────────────────────

ICC_HEADER = 128
MAX_ICC = 4 << 20
# Header fields that say when and on what a profile was made: date and time; device maker, model and
# attributes; creator and profile ID (a hash of the original, which zero marks as not computed).
_ICC_CLEARED = ((24, 36), (48, 64), (80, 100))
# Tags naming the device (maker and model descriptions) or holding free-form metadata.
_ICC_DEVICE_TAGS = {b"dmnd", b"dmdd", b"meta"}


def scrub_icc(profile: bytes) -> bytes | None:
    """An ICC profile, the same size, without what identifies a device or a moment (audit I7).
    Device tags keep their place in the tag table under a signature no reader knows, with their
    bytes zeroed unless a kept tag shares them. None when it isn't a well-formed profile: then it
    is dropped, as unknown data always is."""
    if not ICC_HEADER + 4 <= len(profile) <= MAX_ICC or profile[36:40] != b"acsp" \
            or struct.unpack(">I", profile[:4])[0] != len(profile):
        return None
    out = bytearray(profile)
    for start, end in _ICC_CLEARED:
        out[start:end] = bytes(end - start)
    (count,) = struct.unpack(">I", out[128:132])
    if 132 + 12 * count > len(out):
        return None
    entries = []
    for i in range(count):
        pos = 132 + 12 * i
        sig, off, size = struct.unpack(">4sII", out[pos:pos + 12])
        if off + size > len(out):
            return None
        entries.append((pos, sig, off, size))
    kept = [(off, off + size) for _, sig, off, size in entries if sig not in _ICC_DEVICE_TAGS]
    for pos, sig, off, size in entries:
        if sig in _ICC_DEVICE_TAGS:
            out[pos:pos + 4] = bytes(4)
            if not any(a < off + size and off < b for a, b in kept):
                out[off:off + size] = bytes(size)
    return bytes(out)


class _IccChunk:
    """A JPEG ICC segment in a plan, replaced once every segment of the profile has been seen."""

    def __init__(self, header: bytes, data: bytes):
        self.header, self.data = header, data   # "ICC_PROFILE\0" seq count, and this chunk's bytes


def _resolve_icc(plan: Plan) -> Plan:
    """Put the scrubbed profile back into the plan's ICC segments, chunk for chunk, or drop them all
    when they don't form one complete, well-formed profile."""
    chunks = [item for item in plan if isinstance(item, _IccChunk)]
    if not chunks:
        return plan
    by_seq = {c.header[12]: c for c in chunks}
    counts = {c.header[13] for c in chunks}
    scrubbed = None
    if len(counts) == 1 and len(by_seq) == len(chunks) and set(by_seq) == set(range(1, counts.pop() + 1)):
        ordered = [by_seq[i] for i in sorted(by_seq)]
        scrubbed = scrub_icc(b"".join(c.data for c in ordered))
    if scrubbed is None:
        return [item for item in plan if not isinstance(item, _IccChunk)]
    pieces, pos = {}, 0
    for c in ordered:
        pieces[id(c)] = _segment(0xE2, c.header + scrubbed[pos:pos + len(c.data)])
        pos += len(c.data)
    return [pieces[id(item)] if isinstance(item, _IccChunk) else item for item in plan]


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
    return _resolve_icc(_plan_jpeg_segments(f, size))


def _plan_jpeg_segments(f, size) -> Plan:
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
        elif marker == 0xE2 and body.startswith(b"ICC_PROFILE\x00"):
            if not scanned and length - 2 > 14:   # a colour profile chunk: scrubbed once all are seen
                whole = _read(f, pos + 4, length - 2)
                plan.append(_IccChunk(whole[:14], whole[14:]))
        elif marker in JPEG_KEEP:
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
        if ctype == b"iCCP":
            chunk = _png_iccp(_read(f, pos + 8, length))
            if chunk is not None:
                plan.append(chunk)
        elif ctype in PNG_KEEP:
            plan.append((pos, end - pos))
        pos = end
        if ctype == b"IEND":
            return plan  # anything after IEND is not part of the image
    raise ValueError("missing IEND")


def _png_iccp(data: bytes) -> bytes | None:
    """An iCCP chunk rebuilt with a neutral profile name (the name is free text) and the scrubbed
    profile, or None to drop it."""
    sep = data.find(b"\x00")
    if not 1 <= sep <= 79 or data[sep + 1:sep + 2] != b"\x00":
        return None
    d = zlib.decompressobj()
    try:
        profile = d.decompress(data[sep + 2:], MAX_ICC + 1)
    except zlib.error:
        return None
    if not d.eof or len(profile) > MAX_ICC:
        return None
    scrubbed = scrub_icc(profile)
    if scrubbed is None:
        return None
    body = b"ICC profile\x00\x00" + zlib.compress(scrubbed, 9)
    return struct.pack(">I", len(body)) + b"iCCP" + body + struct.pack(">I", zlib.crc32(b"iCCP" + body))


# ── WebP ─────────────────────────────────────────────────────────────────────

WEBP_KEEP = {b"VP8 ", b"VP8L", b"VP8X", b"ANIM", b"ALPH"}   # ICCP is kept scrubbed
ANMF_KEEP = {b"ALPH", b"VP8 ", b"VP8L"}   # an animation frame's image; it may also hold unknown chunks


def _plan_webp(f, size) -> Plan:
    (riff_size,) = struct.unpack("<I", _read(f, 4, 4))
    end_of_riff = min(size, 8 + riff_size)
    chunks: Plan = []
    pos = 12
    vp8x = None   # its index in chunks, to clear the ICC flag if the profile is dropped
    icc_kept = False
    while pos + 8 <= end_of_riff:
        fourcc, length = struct.unpack("<4sI", _read(f, pos, 8))
        padded = length + (length & 1)
        if pos + 8 + padded > end_of_riff:
            raise ValueError("truncated chunk")
        if fourcc == b"VP8X":
            data = bytearray(_read(f, pos + 8, length))
            data[0] &= ~0x0C & 0xFF      # clear the EXIF (0x08) and XMP (0x04) flags
            vp8x = len(chunks)
            chunks.append(_read(f, pos, 8) + bytes(data) + (b"\x00" if length & 1 else b""))
        elif fourcc == b"ICCP":
            scrubbed = scrub_icc(_read(f, pos + 8, length)) if not icc_kept else None
            if scrubbed is not None:
                icc_kept = True
                chunks.append(b"ICCP" + struct.pack("<I", length) + scrubbed + (b"\x00" if length & 1 else b""))
        elif fourcc == b"ANMF":
            chunks.extend(_webp_frame(f, pos, length))
        elif fourcc in WEBP_KEEP:
            chunks.append((pos, 8 + padded))
        pos += 8 + padded
    if vp8x is not None and not icc_kept:
        head = bytearray(chunks[vp8x])
        head[8] &= ~0x20 & 0xFF          # no profile kept: clear the ICC flag
        chunks[vp8x] = bytes(head)
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
