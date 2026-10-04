"""A printable paper backup of an identity: its QR code and backup words on one A4 page.

The page is the private key, without any passphrase. It is rendered in memory and saved by
the caller like any other secret file (owner-only), never through a print dialog or spooler.
"""

from __future__ import annotations

import time

import segno
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QMarginsF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QImage, QPageLayout, QPageSize, QPainter, QPdfWriter, QPen

from .. import __version__
from ..core import keys
from .theme import font

DPI = 300
A4 = (2480, 3508)   # pixels at 300 dpi


def _text(p: QPainter, rect: QRectF, text: str, size: float, weight=QFont.Weight.Normal, mono=False,
          flags=Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextWordWrap, color="black") -> float:
    """Draw ``text`` in ``rect`` and return the height it took."""
    p.setFont(font(int(size), weight, mono))
    p.setPen(QColor(color))
    bound = p.boundingRect(rect, int(flags), text)
    p.drawText(rect, int(flags), text)
    return bound.height()


def paint_page(p: QPainter, width: int, height: int, ident_name: str, fingerprint: str, created: int, raw: bytes):
    """Paint the backup page for the raw private key ``raw`` onto a ``width`` x ``height`` page."""
    u = width / A4[0]
    margin = 180 * u
    inner = width - 2 * margin
    p.fillRect(QRectF(0, 0, width, height), QColor("white"))
    y = margin
    y += _text(p, QRectF(margin, y, inner, 200 * u), "Locksmith identity backup", 70 * u, QFont.Weight.DemiBold)
    y += 20 * u
    when = time.strftime("%d %B %Y", time.localtime(created))
    kind = "post-quantum (X25519 + ML-KEM-768, signs files)" if len(raw) == keys.HYBRID_PRIVATE_LEN else \
        "classical (X25519)"
    for line in (f"Identity: {ident_name}", f"Fingerprint: {fingerprint}", f"Created: {when}   ·   Kind: {kind}"):
        y += _text(p, QRectF(margin, y, inner, 120 * u), line, 40 * u) + 8 * u
    y += 30 * u
    warning = ("This page is the private key itself, without any passphrase. Anyone who has it, or a photo of it, "
               "can open every file encrypted to this identity and sign as it. Keep it somewhere safe and offline, "
               "like cash or a passport, and destroy it if you stop using this identity.")
    box = QRectF(margin, y, inner, 300 * u)
    p.setFont(font(int(36 * u)))
    need = p.boundingRect(box.adjusted(40 * u, 30 * u, -40 * u, 0), int(Qt.TextFlag.TextWordWrap), warning).height()
    box.setHeight(need + 60 * u)
    p.setPen(QPen(QColor("black"), 6 * u))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawRect(box)
    _text(p, box.adjusted(40 * u, 30 * u, -40 * u, -30 * u), warning, 36 * u)
    y += box.height() + 60 * u

    # The QR code: the same bytes as the words, for restoring by photo or scan.
    qr = segno.make(keys.paper_qr_text(raw), error="q", micro=False)
    matrix = [[bool(v) for v in row] for row in qr.matrix]
    n = len(matrix)
    side = min(inner * 0.55, 1150 * u)
    cell = side / (n + 8)
    left = margin + (inner - side) / 2
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("black"))
    for row, line in enumerate(matrix):
        for col, dark in enumerate(line):
            if dark:
                p.drawRect(QRectF(left + (col + 4) * cell, y + (row + 4) * cell, cell + 0.6, cell + 0.6))
    y += side + 40 * u

    words = keys.backup_words(raw)
    columns = 5 if len(words) > 20 else 3
    rows = -(-len(words) // columns)
    y += _text(p, QRectF(margin, y, inner, 100 * u), f"Backup words ({len(words)})", 40 * u, QFont.Weight.DemiBold)
    y += 20 * u
    col_w = inner / columns
    line_h = 62 * u
    for i, word in enumerate(words):
        col, row = divmod(i, rows)
        _text(p, QRectF(margin + col * col_w, y + row * line_h, col_w, line_h), f"{i + 1:>2}. {word}", 38 * u,
              mono=True, flags=Qt.AlignmentFlag.AlignLeft)
    y += rows * line_h + 40 * u
    _text(p, QRectF(margin, y, inner, 300 * u),
          "To restore: open Locksmith, go to Keys → Restore, and scan the QR code from a photo or scan of this page "
          "(Scan QR code…), or type the words. Either one is enough; both hold the same key.", 34 * u, color="#333333")
    _text(p, QRectF(margin, height - margin, inner, 80 * u), f"Made by Locksmith {__version__}", 28 * u,
          color="#666666")


def render_pdf(ident_name: str, fingerprint: str, created: int, raw: bytes) -> bytes:
    """The page as a one-page A4 PDF, in memory."""
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    writer = QPdfWriter(buffer)
    writer.setResolution(DPI)
    writer.setPageLayout(QPageLayout(QPageSize(QPageSize.PageSizeId.A4), QPageLayout.Orientation.Portrait,
                                     QMarginsF(0, 0, 0, 0)))
    writer.setTitle("Locksmith identity backup")
    writer.setCreator("Locksmith")
    p = QPainter(writer)
    paint_page(p, writer.width(), writer.height(), ident_name, fingerprint, created, raw)
    p.end()
    buffer.close()
    return bytes(buffer.data())


def render_image(ident_name: str, fingerprint: str, created: int, raw: bytes, scale: float = 0.5) -> QImage:
    """The page as an image (for previews and tests)."""
    w, h = int(A4[0] * scale), int(A4[1] * scale)
    img = QImage(w, h, QImage.Format.Format_RGB32)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    paint_page(p, w, h, ident_name, fingerprint, created, raw)
    p.end()
    return img


def gray_pixels(img: QImage, max_side: int = 1600) -> tuple[int, int, bytes]:
    """An image as 8-bit grayscale, scaled down to at most ``max_side`` pixels, for qrdecode."""
    if img.isNull():
        raise ValueError("empty image")
    if max(img.width(), img.height()) > max_side:
        img = img.scaled(max_side, max_side, Qt.AspectRatioMode.KeepAspectRatio,
                         Qt.TransformationMode.SmoothTransformation)
    gray = img.convertToFormat(QImage.Format.Format_Grayscale8)
    w, h, stride = gray.width(), gray.height(), gray.bytesPerLine()
    data = bytes(gray.constBits())
    return w, h, b"".join(data[y * stride:y * stride + w] for y in range(h))


def load_image(data: bytes) -> QImage:
    img = QImage()
    img.loadFromData(QByteArray(data))
    return img
