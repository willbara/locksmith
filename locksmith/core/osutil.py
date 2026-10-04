"""Operating-system differences in one place (Linux and Windows)."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

# Create a brand-new file only. O_EXCL refuses an existing path, including a planted
# symlink (on Windows this is CreateFile's CREATE_NEW). The other flags exist only on
# some systems: never follow a final symlink, don't leak the handle into children,
# and use binary mode on Windows.
NEW_FILE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                  | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_BINARY", 0))


def open_new(path: Path | str, mode: int = 0o600) -> int:
    """Create a new file readable only by the owner (on Windows, files inherit the
    parent folder's access list, which is per-user in the user's profile)."""
    return os.open(path, NEW_FILE_FLAGS, mode)


def is_link(path: Path | str) -> bool:
    """A symlink, or on Windows a junction: anything that points somewhere else."""
    path = Path(path)
    return path.is_symlink() or path.is_junction()


def fsync_dir(path: Path) -> bool:
    """Make a rename in ``path`` durable, and say whether that was confirmed. Windows
    has no directory fsync; there the rename itself is journaled by NTFS."""
    if IS_WINDOWS:
        return True
    if not hasattr(os, "O_DIRECTORY"):
        return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        return False
    return True


def fsync_tree(root: Path) -> bool:
    """Flush every regular file and folder under ``root`` (links are not followed), and
    say whether all of it was confirmed. Windows can only flush a file opened for writing."""
    flags = (os.O_RDWR if IS_WINDOWS else os.O_RDONLY) | getattr(os, "O_NOFOLLOW", 0) \
        | getattr(os, "O_BINARY", 0)
    ok = True
    for folder, _, files in os.walk(root):
        for name in files:
            path = os.path.join(folder, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                fd = os.open(path, flags)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                ok = False
        ok = fsync_dir(Path(folder)) and ok
    return ok


INTERNET_ZONE_MARK = b"[ZoneTransfer]\r\nZoneId=3\r\n"


def copy_zone_identifier(source: Path, target: Path):
    """Windows: give decrypted output the source file's Mark of the Web (the
    Zone.Identifier stream that downloads carry). Without it, a program or macro
    document received encrypted would open without SmartScreen or Office Protected
    View. For a folder, every file inside is marked. Best effort, like other
    archivers: file systems without alternate streams (FAT, network shares) skip it."""
    if not IS_WINDOWS:
        return
    try:
        with open(f"{source}:Zone.Identifier", "rb") as f:
            mark = f.read(4096)
    except OSError:
        return  # the source has no mark: nothing to carry over
    _write_zone_mark(target, mark)


def mark_untrusted(target: Path):
    """Windows: mark output that came from someone else, with no file to inherit a mark
    from (a pasted message), as downloaded from the internet. Same rules as above."""
    if IS_WINDOWS:
        _write_zone_mark(target, INTERNET_ZONE_MARK)


def _write_zone_mark(target: Path, mark: bytes):
    files = [Path(root) / name for root, _, names in os.walk(target) for name in names] \
        if Path(target).is_dir() else [Path(target)]
    for path in files:
        if path.is_symlink():
            continue
        try:
            with open(f"{path}:Zone.Identifier", "wb") as f:
                f.write(mark)
        except OSError:
            pass


def config_base() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return Path(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"))


_WINDOWS_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED = re.compile(r"^(con|conin\$|conout\$|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$",
                                re.IGNORECASE)


def windows_unsafe(name: str) -> bool:
    """True if a single path component cannot be created safely on Windows.
    A colon would write into an NTFS alternate data stream; reserved device names
    (CON, CONIN$, NUL, COM1...) and trailing dots or spaces are invalid or ambiguous."""
    return bool(_WINDOWS_BAD_CHARS.search(name) or _WINDOWS_RESERVED.match(name)
                or name.endswith((".", " ")))


def portable_name(name: str) -> str:
    """Make a received file name safe for the local file system."""
    if not IS_WINDOWS:
        return name
    name = _WINDOWS_BAD_CHARS.sub("_", name).rstrip(". ")
    if _WINDOWS_RESERVED.match(name):
        name = "_" + name
    return name or "decrypted"
