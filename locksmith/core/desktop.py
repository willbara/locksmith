"""Desktop integration: open .locked files with Locksmith, and "Encrypt with Locksmith" in the
file manager's right-click menu.

Linux (for the current user only, under ~/.local/share): a desktop entry with the
application/x-locksmith type, its MIME definition and icon, and menu entries for GNOME Files
(a script under Scripts), KDE Dolphin (a service menu) and Cinnamon's Nemo (an action).
Windows (HKEY_CURRENT_USER only): the .locked association and "Encrypt with Locksmith" for files
and folders. Every file and key written is marked as Locksmith's, so removing it never touches
anything else. Nothing is installed for other users and nothing needs administrator rights.
"""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from .errors import LocksmithError
from .osutil import IS_WINDOWS

MARKER = "Written by Locksmith"
MIME_TYPE = "application/x-locksmith"
ASSETS = Path(__file__).resolve().parent.parent / "assets"


def command() -> list[str]:
    """How the desktop starts this Locksmith: the AppImage, the frozen .exe, or Python with the
    package (when run from source). From source, Python runs isolated (-I): "python -m" would
    otherwise import modules from the working directory first, and file managers start programs
    in the folder being browsed, so a json.py there would run inside Locksmith (audit B4)."""
    if os.environ.get("APPIMAGE"):
        return [os.environ["APPIMAGE"]]
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-I", "-m", "locksmith"]


def desktop_quote(arg: str) -> str:
    """One argument of an Exec line (Desktop Entry spec, "The Exec key"): quoted, with the
    characters special inside quotes escaped, then escaped again as a desktop file string."""
    if any(c in arg for c in "\n\r\0"):
        raise LocksmithError("Locksmith's path contains a line break, which a desktop file can't hold.")
    quoted = '"' + "".join("\\" + c if c in '"`$\\' else c for c in arg) + '"'
    return quoted.replace("\\", "\\\\").replace("%", "%%")


def _exec(args: list[str], field: str) -> str:
    return " ".join(desktop_quote(a) for a in args) + f" {field}"


def data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")


@dataclass
class Integration:
    files: dict[Path, tuple[str, bool]]   # path -> (content, executable)


def linux_files(base: Path | None = None, cmd: list[str] | None = None) -> Integration:
    base = Path(base) if base else data_home()
    cmd = cmd or command()
    encrypt = _exec(cmd + ["--encrypt"], "%F")
    desktop = f"""[Desktop Entry]
# {MARKER}
Type=Application
Name=Locksmith
GenericName=File Encryption
Comment=Encrypt, decrypt and share files securely
Exec={_exec(cmd, "%F")}
Icon=locksmith
Terminal=false
Categories=Utility;Security;
Keywords=encrypt;decrypt;security;aes;chacha;password;share;
MimeType={MIME_TYPE};
StartupWMClass=locksmith
"""
    mime = f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- {MARKER} -->
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="{MIME_TYPE}">
    <comment>Locksmith encrypted file</comment>
    <magic priority="60">
      <match type="string" offset="0" value="LOCKED"/>
    </magic>
    <glob pattern="*.locked"/>
  </mime-type>
</mime-info>
"""
    # GNOME Files runs scripts in the folder being browsed and passes the selected names relative to it,
    # so a file named "-platformpluginpath" would arrive as an option. Make every name absolute and pass
    # them after "--" (audit B3).
    script = f"""#!/bin/sh
# {MARKER}: "Encrypt with Locksmith" in the Files right-click menu (Scripts).
# The names arrive relative to the folder being browsed: make them absolute, so none reads as an option.
here=$(pwd)
for f; do
    case "$f" in /*) ;; *) f="$here/$f" ;; esac
    set -- "$@" "$f"
    shift
done
exec {" ".join(shlex.quote(a) for a in cmd)} --encrypt -- "$@"
"""
    service = f"""[Desktop Entry]
# {MARKER}
Type=Service
MimeType=all/allfiles;inode/directory;
Actions=encrypt
X-KDE-ServiceTypes=KonqPopupMenu/Plugin
X-KDE-Priority=TopLevel

[Desktop Action encrypt]
Name=Encrypt with Locksmith
Icon=locksmith
Exec={encrypt}
"""
    nemo = f"""[Nemo Action]
# {MARKER}
Name=Encrypt with Locksmith
Comment=Encrypt the selected files and folders with Locksmith
Exec={encrypt}
Icon-Name=locksmith
Selection=notnone
Extensions=any;
"""
    icon = (ASSETS / "locksmith.svg").read_text(encoding="utf-8")
    if MARKER not in icon:
        icon = icon.replace("<svg", f"<!-- {MARKER} -->\n<svg", 1)
    return Integration({
        base / "applications" / "locksmith.desktop": (desktop, False),
        base / "mime" / "packages" / "locksmith.xml": (mime, False),
        base / "icons" / "hicolor" / "scalable" / "apps" / "locksmith.svg": (icon, False),
        base / "nautilus" / "scripts" / "Encrypt with Locksmith": (script, True),
        base / "kio" / "servicemenus" / "locksmith-encrypt.desktop": (service, True),
        base / "nemo" / "actions" / "locksmith-encrypt.nemo_action": (nemo, False),
    })


def _ours(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8") as f:
            return MARKER in f.read(4096)
    except (OSError, UnicodeDecodeError):
        return False


def install_linux(base: Path | None = None, cmd: list[str] | None = None) -> list[Path]:
    """Write the integration files. A file of the same name that Locksmith didn't write is left
    alone (and reported by raising), never overwritten."""
    plan = linux_files(base, cmd)
    foreign = [p for p in plan.files if os.path.lexists(p) and not _ours(p)]
    if foreign:
        raise LocksmithError(f"{foreign[0]} already exists and wasn't written by Locksmith, so it was left alone. "
                             "Nothing was changed.")
    for path, (content, executable) in plan.files.items():
        _write(path, content, executable)
    return list(plan.files)


def _write(path: Path, content: str, executable: bool):
    from .keys import write_secret_file
    path.parent.mkdir(parents=True, exist_ok=True)
    write_secret_file(path, content)
    os.chmod(path, 0o755 if executable else 0o644)


def refresh_linux(base: Path | None = None, cmd: list[str] | None = None) -> list[Path]:
    """Bring an integration this same program installed up to date, so a fix to its files reaches users
    without reinstalling (Locksmith 5.0 and earlier: a GNOME Files script that passed relative names,
    and from source a command that imported from the browsed folder, audit B3 and B4). Integration that
    points at another program (another AppImage, or source instead of the AppImage) is left alone, as is
    any file Locksmith didn't write. Returns the files rewritten."""
    cmd = cmd or command()
    plan = linux_files(base, cmd)
    entry, (wanted, _) = next(iter(plan.files.items()))   # the application entry
    try:
        current = entry.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    exec_line = next((line for line in current.splitlines() if line.startswith("Exec=")), "")
    if MARKER not in current or not exec_line.startswith("Exec=" + desktop_quote(cmd[0]) + " "):
        return []
    rewritten = []
    for path, (content, executable) in plan.files.items():
        if os.path.lexists(path) and (path.is_symlink() or not _ours(path)):
            continue
        try:
            if path.read_text(encoding="utf-8") == content:
                continue
        except (OSError, UnicodeDecodeError):
            pass
        _write(path, content, executable)
        rewritten.append(path)
    return rewritten


def uninstall_linux(base: Path | None = None) -> list[Path]:
    removed = []
    for path in linux_files(base, ["locksmith"]).files:
        if os.path.lexists(path) and not path.is_symlink() and _ours(path):
            path.unlink()
            removed.append(path)
    return removed


def installed_linux(base: Path | None = None) -> bool:
    return _ours(next(iter(linux_files(base, ["locksmith"]).files)))


def refresh_commands(base: Path | None = None) -> list[list[str]]:
    """Programs that refresh the desktop's caches afterwards (each optional, best effort)."""
    base = Path(base) if base else data_home()
    return [["update-mime-database", str(base / "mime")],
            ["update-desktop-database", str(base / "applications")],
            ["xdg-mime", "default", "locksmith.desktop", MIME_TYPE]]


# ── Windows ──────────────────────────────────────────────────────────────────

PROG_ID = "Locksmith.EncryptedFile"
VERB = "Locksmith.Encrypt"


def windows_keys(exe: str) -> dict[str, dict[str, str]]:
    """Registry keys under HKEY_CURRENT_USER\\Software\\Classes and their values ("" is the default)."""
    q = f'"{exe}"'
    return {
        ".locked": {"": PROG_ID, "Locksmith": MARKER},
        PROG_ID: {"": "Locksmith encrypted file", "Locksmith": MARKER},
        PROG_ID + r"\DefaultIcon": {"": f"{q},0"},
        PROG_ID + r"\shell\open\command": {"": f'{q} "%1"'},
        rf"*\shell\{VERB}": {"MUIVerb": "Encrypt with Locksmith", "Icon": f"{q},0", "Locksmith": MARKER},
        rf"*\shell\{VERB}\command": {"": f'{q} --encrypt "%1"'},
        rf"Directory\shell\{VERB}": {"MUIVerb": "Encrypt with Locksmith", "Icon": f"{q},0", "Locksmith": MARKER},
        rf"Directory\shell\{VERB}\command": {"": f'{q} --encrypt "%1"'},
    }


class _Registry:
    """HKEY_CURRENT_USER\\Software\\Classes through winreg (only exists on Windows)."""

    def __init__(self):
        import winreg
        self.w = winreg
        self.root = winreg.HKEY_CURRENT_USER

    def _path(self, key: str) -> str:
        return "Software\\Classes\\" + key

    def get(self, key: str, name: str) -> str | None:
        try:
            with self.w.OpenKey(self.root, self._path(key)) as k:
                return self.w.QueryValueEx(k, name)[0]
        except OSError:
            return None

    def set(self, key: str, values: dict[str, str]):
        with self.w.CreateKey(self.root, self._path(key)) as k:
            for name, value in values.items():
                self.w.SetValueEx(k, name, 0, self.w.REG_SZ, value)

    def delete_tree(self, key: str):
        try:
            with self.w.OpenKey(self.root, self._path(key), 0, self.w.KEY_ALL_ACCESS) as k:
                while True:
                    try:
                        child = self.w.EnumKey(k, 0)
                    except OSError:
                        break
                    self.delete_tree(key + "\\" + child)
            self.w.DeleteKey(self.root, self._path(key))
        except OSError:
            pass


def _ours_windows(reg, key: str) -> bool:
    return reg.get(key, "Locksmith") == MARKER


def install_windows(reg=None, exe: str | None = None):
    if not getattr(sys, "frozen", False) and exe is None:
        raise LocksmithError("Only the built Locksmith .exe can be added to Explorer.")
    reg = reg or _Registry()
    exe = exe or sys.executable
    current = reg.get(".locked", "")
    if current not in (None, PROG_ID):
        raise LocksmithError(f".locked files already open with another program ({current}), so that was left "
                             "alone. Nothing was changed.")
    for key, values in windows_keys(exe).items():
        reg.set(key, values)
    _notify()


def uninstall_windows(reg=None):
    reg = reg or _Registry()
    for key in (".locked", PROG_ID, rf"*\shell\{VERB}", rf"Directory\shell\{VERB}"):
        if _ours_windows(reg, key):
            reg.delete_tree(key)
    _notify()


def installed_windows(reg=None) -> bool:
    try:
        reg = reg or _Registry()
    except ImportError:
        return False
    return _ours_windows(reg, rf"*\shell\{VERB}")


def _notify():
    """Tell Explorer the associations changed (SHCNE_ASSOCCHANGED)."""
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        except (AttributeError, OSError):
            pass


def installed() -> bool:
    return installed_windows() if IS_WINDOWS else installed_linux()
