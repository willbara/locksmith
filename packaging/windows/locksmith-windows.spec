# PyInstaller spec for the Windows build: one Locksmith .exe.
# Run by packaging/build_windows.sh (Windows Python under Wine) or on Windows itself.
import os
from pathlib import Path

ROOT = Path(SPECPATH).parent.parent
WIN = Path(SPECPATH)

# Qt plugins the app needs; everything else in these folders is dropped.
QT_PLUGINS_KEEP = {
    "platforms": {"qwindows.dll", "qoffscreen.dll"},     # offscreen: for --self-test
    "imageformats": {"qsvg.dll"},
    "iconengines": {"qsvgicon.dll"},
}
QT_PLUGIN_DIRS_DROP = {"styles", "tls", "networkinformation", "generic", "platforminputcontexts",
                       "sqldrivers", "multimedia", "printsupport", "qmltooling", "platformthemes"}
# Never bundled: icuuc.dll is part of Windows 10 1903+ (the Wine build uses a stub);
# the rest are Qt pieces Locksmith does not use.
DROP = {"icuuc.dll", "icuin.dll", "icu.dll", "opengl32sw.dll", "qt6network.dll", "qt6pdf.dll", "qt6qml.dll",
        "qt6qmlmodels.dll", "qt6qmlmeta.dll", "qt6qmlworkerscript.dll", "qt6quick.dll", "qt6opengl.dll",
        "qt6virtualkeyboard.dll", "qt6dbus.dll"}


def keep(dest: str) -> bool:
    p = Path(dest.replace("\\", "/"))
    if p.name.lower() in DROP:
        return False
    parts = [x.lower() for x in p.parts]
    if "plugins" in parts:
        folder = parts[parts.index("plugins") + 1]
        if folder in QT_PLUGIN_DIRS_DROP:
            return False
        if folder in QT_PLUGINS_KEEP and p.name.lower() not in QT_PLUGINS_KEEP[folder]:
            return False
    return True


a = Analysis(
    [str(ROOT / "run.py")],
    pathex=[str(ROOT)],
    datas=[(str(ROOT / "locksmith" / "assets"), "locksmith/assets")],
    hiddenimports=["compression.zstd", "segno"],
    excludes=["tkinter", "unittest", "pydoc", "doctest", "pytest", "PyInstaller", "sqlite3",
              "PySide6.QtNetwork", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtSql", "PySide6.QtTest",
              "PySide6.QtXml", "PySide6.QtOpenGL", "PySide6.QtPdf", "PySide6.QtMultimedia",
              "PySide6.QtWebEngineCore", "PySide6.QtConcurrent", "PySide6.QtDBus"],
    noarchive=False,
)
a.binaries = [b for b in a.binaries if keep(b[0])]
a.datas = [d for d in a.datas if keep(d[0])]
if os.environ.get("LOCKSMITH_SPEC_VERBOSE"):
    print("Bundled binaries:", ", ".join(sorted(Path(b[0]).name for b in a.binaries)))

pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas,
    [("X utf8_mode=1", None, "OPTION")],   # UTF-8 text I/O regardless of the Windows code page
    name="Locksmith",
    icon=str(WIN / "locksmith.ico"),
    version=str(WIN / "version_info.txt"),
    console=False,
    upx=False,
    strip=False,
)
