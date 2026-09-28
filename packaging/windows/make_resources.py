"""Write locksmith.ico (multi-size, from the SVG) and version_info.txt for the .exe."""

import os
import re
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QBuffer, QIODevice, Qt  # noqa: E402
from PySide6.QtGui import QGuiApplication, QImage, QPainter  # noqa: E402
from PySide6.QtSvg import QSvgRenderer  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
app = QGuiApplication(sys.argv[:1])

# Icon: PNG-compressed entries (supported since Windows Vista) at every standard size.
renderer = QSvgRenderer(str(ROOT / "locksmith" / "assets" / "locksmith.svg"))
entries = []
for size in (16, 20, 24, 32, 40, 48, 64, 128, 256):
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(p)
    p.end()
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    entries.append((size, bytes(buf.data())))
header = struct.pack("<HHH", 0, 1, len(entries))
offset = 6 + 16 * len(entries)
table, blobs = b"", b""
for size, png in entries:
    dim = 0 if size >= 256 else size
    table += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
    blobs += png
(OUT / "locksmith.ico").write_bytes(header + table + blobs)

# Version resource shown in the file's Properties → Details.
version = re.search(r'__version__ = "([^"]+)"', (ROOT / "locksmith" / "__init__.py").read_text()).group(1)
nums = tuple(int(x) for x in version.split(".")) + (0,)
(OUT / "version_info.txt").write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}, mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('ProductName', 'Locksmith'),
      StringStruct('FileDescription', 'Locksmith file encryption'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('ProductVersion', '{version}'),
      StringStruct('OriginalFilename', 'Locksmith.exe'),
      StringStruct('InternalName', 'Locksmith')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")
print("resources written for version", version)
