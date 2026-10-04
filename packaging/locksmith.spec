# PyInstaller spec: one-folder build that becomes the AppImage payload.
#
# Portability rule: bundle only what we ship ourselves (the standalone Python,
# the Qt/PySide6 wheel, cryptography and other Python packages). Libraries
# every desktop Linux already provides (glibc, libstdc++, graphics drivers,
# Wayland, X11, fonts, D-Bus, GLib) come from the host. Bundling copies of them
# from the build machine would tie the AppImage to its glibc and can clash
# with the host's graphics stack.
import os
import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent
PYTHON_HOME = Path(sys.base_prefix).resolve()
VENV = Path(sys.prefix).resolve()

# Small X11 helper libraries Qt's xcb backend needs that minimal installs often
# lack. They only use old, stable glibc symbols.
HOST_LIBS_TO_BUNDLE = {
    "libxcb-image.so.0", "libxcb-render-util.so.0", "libxcb-util.so.1", "libxcb-icccm.so.4",
    "libxcb-keysyms.so.1",
}
# libxcb-cursor (required by Qt >= 6.5 on X11) is taken from a pinned Debian 12
# package by the build script instead of the build host, because some distros
# build it against a newer glibc than we target.
XCB_CURSOR = os.environ.get("LOCKSMITH_XCB_CURSOR")

# Qt libraries only used by plugins we drop.
QT_LIBS_DROP = {"libQt6EglFSDeviceIntegration.so.6", "libQt6EglFsKmsSupport.so.6", "libQt6Network.so.6"}

# Qt plugins that are needed. Everything else in these folders is dropped.
QT_PLUGINS_KEEP = {
    "platforms": {"libqwayland.so", "libqwayland-generic.so", "libqwayland-egl.so", "libqxcb.so",
                  "libqoffscreen.so"},
    "imageformats": {"libqsvg.so", "libqjpeg.so", "libqwebp.so"},   # photos of a paper backup
    "iconengines": {"libqsvgicon.so"},
}
# platformthemes: the GTK theme pulls in all of GTK, and the portal theme cannot
# work in a hardened (non-dumpable) process. Qt's built-in themes are used.
QT_PLUGIN_DIRS_DROP = {"platformthemes", "egldeviceintegrations", "generic", "tls", "networkinformation", "sqldrivers",
                       "multimedia", "printsupport", "qmltooling"}


def ours(src: str) -> bool:
    p = Path(src).resolve()
    return p.is_relative_to(PYTHON_HOME) or p.is_relative_to(VENV)


def keep_binary(dest: str, src: str) -> bool:
    if Path(dest).name in QT_LIBS_DROP or Path(dest).name == "libxcb-cursor.so.0":
        return False
    parts = Path(dest).parts
    if "plugins" in parts:
        folder = parts[parts.index("plugins") + 1]
        if folder in QT_PLUGIN_DIRS_DROP:
            return False
        if folder in QT_PLUGINS_KEEP and Path(dest).name not in QT_PLUGINS_KEEP[folder]:
            return False
    return ours(src) or Path(dest).name in HOST_LIBS_TO_BUNDLE


a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "locksmith" / "assets"), "locksmith/assets")],
    hiddenimports=["compression.zstd", "segno"],
    excludes=[
        "tkinter", "unittest", "pydoc", "doctest", "pytest", "PyInstaller", "sqlite3",
        "PySide6.QtNetwork", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtSql",
        "PySide6.QtTest", "PySide6.QtXml", "PySide6.QtOpenGL", "PySide6.QtPdf",
        "PySide6.QtMultimedia", "PySide6.QtWebEngineCore", "PySide6.QtConcurrent",
    ],
    noarchive=False,
)

dropped = sorted({Path(d).name for d, s, _ in a.binaries if not keep_binary(d, s)})
a.binaries = [b for b in a.binaries if keep_binary(b[0], b[1])]
if XCB_CURSOR:
    a.binaries.append(("libxcb-cursor.so.0", XCB_CURSOR, "BINARY"))
a.datas = [d for d in a.datas if not ("plugins" in Path(d[0]).parts and not keep_binary(d[0], d[1]))]
if os.environ.get("LOCKSMITH_SPEC_VERBOSE"):
    print("Left to the host system:", ", ".join(dropped))

pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="locksmith",
    console=False,
    strip=True,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=True, upx=False, name="locksmith")
