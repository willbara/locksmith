"""Lossless image metadata stripping."""

import io
import os
import struct
import tarfile
import time
import zlib

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QBuffer, QByteArray, QIODevice  # noqa: E402
from PySide6.QtGui import QColor, QImage  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from locksmith.core import engine, metadata  # noqa: E402
from locksmith.core.engine import DecryptKeys, EncryptOptions  # noqa: E402
from locksmith.core.errors import LocksmithError  # noqa: E402

# A full QApplication: other test modules build widgets in the same process.
_app = QApplication.instance() or QApplication([])
FAST = dict(kdf="pbkdf2-sha512", preset="fast")
SECRETS = [b"GPS-SECRET", b"XMP-SECRET", b"COMMENT-SECRET", b"IPTC-SECRET", b"TEXT-SECRET",
           b"EXIF-SECRET", b"C2PA-SECRET", b"TRAILER-SECRET", b"MPF-SECRET", b"PRIVATE-SECRET"]


def _image(fmt: str) -> tuple[bytes, QImage]:
    img = QImage(64, 48, QImage.Format.Format_RGB32)
    for y in range(48):
        for x in range(64):
            img.setPixelColor(x, y, QColor((x * 4) % 256, (y * 5) % 256, (x * y) % 256))
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    assert img.save(buf, fmt, 100 if fmt == "JPG" else -1)
    return bytes(buf.data()), img


def _decode(data: bytes) -> QImage:
    img = QImage()
    assert img.loadFromData(QByteArray(data)), "stripped image no longer decodes"
    return img


def _exif(orientation: int) -> bytes:
    text = b"GPS-SECRET camera serial 12345\x00"
    ifd_len = 2 + 2 * 12 + 4
    tiff = (b"MM\x00\x2a" + struct.pack(">I", 8) + struct.pack(">H", 2)
            + struct.pack(">HHIHH", 0x0112, 3, 1, orientation, 0)
            + struct.pack(">HHII", 0x010E, 2, len(text), 8 + ifd_len)
            + struct.pack(">I", 0) + text)
    return b"Exif\x00\x00" + tiff


def _seg(marker: int, payload: bytes) -> bytes:
    return bytes([0xFF, marker]) + struct.pack(">H", len(payload) + 2) + payload


def _roundtrip(tmp_path, name: str, data: bytes) -> tuple[bytes, dict]:
    src = tmp_path / name
    src.write_bytes(data)
    stats = {}
    enc = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", strip_metadata=True, **FAST),
                               stats=stats)
    res = engine.decrypt_path(enc, tmp_path / "dec", DecryptKeys(password="pw"))
    assert src.read_bytes() == data, "the original file must never be modified"
    return res.path.read_bytes(), stats


def test_jpeg(tmp_path):
    jpg, _ = _image("JPG")
    extra = (_seg(0xE1, _exif(6)) + _seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x>XMP-SECRET</x>")
             + _seg(0xED, b"Photoshop 3.0\x00IPTC-SECRET") + _seg(0xFE, b"COMMENT-SECRET")
             + _seg(0xE2, b"ICC_PROFILE\x00\x01\x01fake-profile") + _seg(0xE2, b"MPF\x00MPF-SECRET")
             + _seg(0xE9, b"PRIVATE-SECRET"))
    evil = jpg[:2] + extra + jpg[2:] + b"TRAILER-SECRET-video"
    out, stats = _roundtrip(tmp_path, "photo.jpg", evil)
    assert stats == {"stripped": 1}
    for s in SECRETS[:4] + [b"MPF-SECRET", b"PRIVATE-SECRET"]:
        assert s not in out, s
    assert b"ICC_PROFILE" in out, "colour profile must be kept"
    assert b"TRAILER-SECRET" not in out and out.endswith(b"\xff\xd9"), "nothing after the image is kept"
    sos = jpg.index(b"\xff\xda")
    assert jpg[sos:] in out, "compressed image data must be byte-identical"
    app1 = out.index(b"Exif\x00\x00")
    assert metadata._read_orientation(out[app1 + 6:]) == 6, "orientation must survive"
    assert app1 < out.index(b"\xff\xdb"), "orientation EXIF stays near the start of the file"
    _decode(out)


def test_jpeg_appended_image_and_between_scan_metadata_dropped(tmp_path):
    """An appended second JPEG (MPF, previews, gain maps) carries its own EXIF and GPS;
    metadata can also sit between the scans of a progressive image."""
    jpg, _ = _image("JPG")
    sos = jpg.index(b"\xff\xda")
    second = jpg[:2] + _seg(0xE1, _exif(1)) + jpg[2:]
    evil = jpg[:-2] + _seg(0xFE, b"COMMENT-SECRET") + _seg(0xE1, _exif(1)) + jpg[-2:] + second
    out, _ = _roundtrip(tmp_path, "p.jpg", evil)
    assert b"GPS-SECRET" not in out and b"COMMENT-SECRET" not in out
    assert out.count(b"\xff\xd8") == 1 and jpg[sos:-2] in out
    _decode(out)


def test_progressive_jpeg_keeps_every_scan(tmp_path):
    from PySide6.QtGui import QImageWriter
    _, img = _image("JPG")
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    w = QImageWriter(buf, b"jpg")
    w.setProgressiveScanWrite(True)
    w.setQuality(90)
    assert w.write(img)
    jpg = bytes(buf.data())
    assert jpg.count(b"\xff\xda") > 1, "Qt did not write a progressive JPEG"
    evil = jpg[:2] + _seg(0xE1, _exif(1)) + jpg[2:] + b"TRAILER-SECRET"
    out, _ = _roundtrip(tmp_path, "prog.jpg", evil)
    assert out == jpg, "a clean progressive image must pass through byte-identical"
    assert _decode(out).pixelColor(10, 10) == _decode(jpg).pixelColor(10, 10)


def test_jpeg_without_rotation_gets_no_exif(tmp_path):
    jpg, _ = _image("JPG")
    out, _ = _roundtrip(tmp_path, "p.jpg", jpg[:2] + _seg(0xE1, _exif(1)) + jpg[2:])
    assert b"Exif" not in out and b"GPS-SECRET" not in out


def _png_chunk(ctype: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data))


def test_png(tmp_path):
    png, img = _image("PNG")
    iend = png.rindex(b"IEND") - 4
    extra = (_png_chunk(b"tEXt", b"Comment\x00TEXT-SECRET") + _png_chunk(b"eXIf", b"MM\x00*EXIF-SECRET")
             + _png_chunk(b"tIME", b"\x07\xea\x09\x1b\x0c\x00\x00") + _png_chunk(b"caBX", b"C2PA-SECRET")
             + _png_chunk(b"prVt", b"PRIVATE-SECRET") + _png_chunk(b"iTXt", b"XML\x00\x00\x00\x00\x00XMP-SECRET")
             + _png_chunk(b"gAMA", struct.pack(">I", 45455)))
    evil = png[:iend] + extra + png[iend:] + b"TRAILER-SECRET"
    out, stats = _roundtrip(tmp_path, "shot.png", evil)
    assert stats == {"stripped": 1}
    for s in SECRETS:
        assert s not in out, s
    assert b"gAMA" in out
    assert _decode(out).convertToFormat(QImage.Format.Format_RGB32) == img


def _webp_chunk(fourcc: bytes, data: bytes) -> bytes:
    return fourcc + struct.pack("<I", len(data)) + data + (b"\x00" if len(data) & 1 else b"")


def test_webp(tmp_path):
    simple, _ = _image("WEBP")
    image_chunk = simple[12:]
    vp8x = bytes([0x0C, 0, 0, 0]) + (63).to_bytes(3, "little") + (47).to_bytes(3, "little")
    body = (b"WEBP" + _webp_chunk(b"VP8X", vp8x) + image_chunk
            + _webp_chunk(b"EXIF", b"MM\x00*EXIF-SECRET") + _webp_chunk(b"XMP ", b"<x>XMP-SECRET</x>")
            + _webp_chunk(b"PRIV", b"PRIVATE-SECRET"))
    evil = b"RIFF" + struct.pack("<I", len(body)) + body
    out, stats = _roundtrip(tmp_path, "img.webp", evil)
    assert stats == {"stripped": 1}
    for s in SECRETS:
        assert s not in out, s
    assert struct.unpack("<I", out[4:8])[0] == len(out) - 8, "RIFF size must be updated"
    assert out[out.index(b"VP8X") + 8] & 0x0C == 0, "EXIF/XMP flags must be cleared"
    assert image_chunk in out
    if QImage().loadFromData(QByteArray(simple)):
        assert _decode(out).size() == _decode(simple).size()


def test_unsupported_files_pass_through(tmp_path):
    data = b"GIF89a" + os.urandom(500)
    out, stats = _roundtrip(tmp_path, "anim.gif", data)
    assert out == data and stats == {"unchanged": 1}


def test_damaged_image_refused_not_leaked(tmp_path):
    src = tmp_path / "broken.jpg"
    src.write_bytes(b"\xff\xd8\xff\xe1\x00\x40Exif\x00\x00GPS-SECRET")  # truncated
    with pytest.raises(LocksmithError, match="damaged"):
        engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="pw", strip_metadata=True, **FAST))
    assert not (tmp_path / "enc").exists() or not any((tmp_path / "enc").iterdir())


def test_file_time_not_stored(tmp_path):
    src = tmp_path / "a.png"
    src.write_bytes(_image("PNG")[0])
    os.utime(src, (1_000_000_000, 1_000_000_000))
    enc = engine.encrypt_paths([src], tmp_path / "e", EncryptOptions(password="pw", strip_metadata=True, **FAST))
    res = engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password="pw"))
    assert "mtime" not in res.meta and res.path.stat().st_mtime > 1_500_000_000


def test_folder_is_stripped_and_anonymised(tmp_path):
    folder = tmp_path / "Trip"
    (folder / "day1").mkdir(parents=True)
    jpg, _ = _image("JPG")
    (folder / "day1" / "beach.jpg").write_bytes(jpg[:2] + _seg(0xE1, _exif(3)) + jpg[2:])
    (folder / "notes.txt").write_text("hello")
    os.utime(folder / "notes.txt", (1_000_000_000, 1_000_000_000))
    stats = {}
    stream = engine._TarStream([(folder, "Trip")], strip=True, stats=stats)
    raw = b"".join(iter(lambda: stream.read(65536), b""))
    stream.close()
    assert stats == {"stripped": 1, "unchanged": 1}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        for m in tar.getmembers():
            assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "", ""), m.name
            assert m.mtime > time.time() - 3600, m.name
        beach = tar.extractfile("Trip/day1/beach.jpg").read()
    assert b"GPS-SECRET" not in beach
    assert metadata._read_orientation(beach[beach.index(b"Exif\x00\x00") + 6:]) == 3
    _decode(beach)
    enc = engine.encrypt_paths([folder], tmp_path / "e", EncryptOptions(password="pw", strip_metadata=True, **FAST))
    res = engine.decrypt_path(enc, tmp_path / "d", DecryptKeys(password="pw"))
    assert (res.path / "notes.txt").read_text() == "hello"


def test_plan_reader_streams_in_small_reads(tmp_path):
    jpg, _ = _image("JPG")
    src = tmp_path / "p.jpg"
    src.write_bytes(jpg[:2] + _seg(0xFE, b"COMMENT-SECRET") + jpg[2:])
    plan = metadata.plan_for(src)
    with metadata.PlanReader(src, plan.plan) as r:
        pieces = b"".join(iter(lambda: r.read(7), b""))
    with metadata.PlanReader(src, plan.plan) as r:
        assert pieces == r.read() and len(pieces) == plan.size and plan.removed > 0
