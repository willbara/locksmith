"""Run blocking work off the UI thread with progress and cancellation."""

from __future__ import annotations

import threading
import traceback
from collections.abc import Callable

from PySide6.QtCore import QThread, Signal

from ..core.errors import CancelledError, LocksmithError


class Task(QThread):
    progress = Signal(float, str)   # fraction (-1 = indeterminate), stage text
    succeeded = Signal(object)
    failed = Signal(str, str)       # message, error class name
    cancelled = Signal()

    _live: set[Task] = set()

    def __init__(self, fn: Callable, parent=None):
        super().__init__(parent)
        self.fn = fn
        self.cancel_event = threading.Event()
        Task._live.add(self)
        self.finished.connect(lambda: Task._live.discard(self))

    def report(self, fraction: float | None, stage: str):
        self.progress.emit(-1.0 if fraction is None else float(fraction), stage)

    def cancel(self):
        self.cancel_event.set()

    def run(self):
        try:
            result = self.fn(self.report, self.cancel_event)
        except CancelledError:
            self.cancelled.emit()
        except LocksmithError as e:
            self.failed.emit(str(e), type(e).__name__)
        except PermissionError as e:
            self.failed.emit(f"Permission denied: {e.filename or e}", "PermissionError")
        except OSError as e:
            where = f" ({e.filename})" if e.filename else ""
            self.failed.emit((e.strerror or str(e)) + where, "OSError")
        except Exception as e:  # noqa: BLE001
            traceback.print_exc()
            self.failed.emit(f"Unexpected error: {e}", type(e).__name__)
        else:
            self.succeeded.emit(result)


def run_task(fn: Callable, on_done=None, on_error=None, on_progress=None, on_cancel=None,
             parent=None) -> Task:
    t = Task(fn, parent)
    if on_done:
        t.succeeded.connect(on_done)
    if on_error:
        t.failed.connect(on_error)
    if on_progress:
        t.progress.connect(on_progress)
    if on_cancel:
        t.cancelled.connect(on_cancel)
    t.start()
    return t
