"""Temporary plaintext files, recorded so a crash cannot leave them behind.

Decryption writes plaintext to hidden temporary paths in the output folder before
moving it into place. Errors remove them, but a killed process (OOM killer, power
cut, logout) cannot. Each path is recorded in a journal before it is created and
forgotten once it is gone; on the next start, anything still listed is shredded.

The journal is off until ``enable`` is called, so library use and tests never
touch a config folder. Only paths named like Locksmith's own temporary files are
ever removed, so an altered journal cannot be used to delete anything else.
"""

from __future__ import annotations

import json
import re
import shutil
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import LocksmithError

# .locksmith-<12 hex>.part (a file), .locksmith-<12 hex> (a staging folder), .locksmith-<12 hex>.tar
_TEMP_NAME = re.compile(r"\.locksmith-[0-9a-f]{12}(\.part|\.tar)?")

_lock = threading.Lock()
_journal: Path | None = None


def enable(journal: Path):
    global _journal
    _journal = Path(journal)


def _read() -> list[str]:
    try:
        entries = json.loads(_journal.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return []
    return [e for e in entries if isinstance(e, str)] if isinstance(entries, list) else []


def _write(entries: list[str]):
    from .keys import write_secret_file
    if entries:
        write_secret_file(_journal, json.dumps(entries))
    else:
        _journal.unlink(missing_ok=True)


def _update(change):
    if _journal is None:
        return
    with _lock:
        try:
            _write(change(_read()))
        except OSError:
            pass  # best effort: a journal that cannot be written must not stop decryption


@contextmanager
def tracked(path: Path) -> Iterator[Path]:
    """Record ``path`` for the duration of the block. Enter before creating it."""
    entry = str(Path(path).absolute())
    _update(lambda entries: [*entries, entry])
    try:
        yield path
    finally:
        _update(lambda entries: [e for e in entries if e != entry])


def clean_leftovers() -> int:
    """Shred temporary files a previous run left behind. Returns how many were removed."""
    if _journal is None:
        return 0
    with _lock:
        entries = _read()
        try:
            _write([])
        except OSError:
            return 0
    from .tools import shred
    removed = 0
    for entry in entries:
        path = Path(entry)
        if not _TEMP_NAME.fullmatch(path.name) or not path.is_absolute() or not path.exists():
            continue
        try:
            shred(path)
        except (OSError, LocksmithError):
            # Shredding is best effort; removing the plaintext is what matters.
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
        removed += not path.exists()
    return removed
