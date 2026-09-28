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


def fsync_dir(path: Path):
    """Make a rename in ``path`` durable. Windows has no directory fsync; there the
    rename itself is journaled by NTFS."""
    if IS_WINDOWS or not hasattr(os, "O_DIRECTORY"):
        return
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def config_base() -> Path:
    if IS_WINDOWS:
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    return Path(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"))


_WINDOWS_BAD_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9¹²³]|lpt[0-9¹²³])(\..*)?$", re.IGNORECASE)


def windows_unsafe(name: str) -> bool:
    """True if a single path component cannot be created safely on Windows.
    A colon would write into an NTFS alternate data stream; reserved device names
    (CON, NUL, COM1...) and trailing dots or spaces are invalid or ambiguous."""
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
