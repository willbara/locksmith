"""Auto-lock on inactivity and the panic shortcut.

Locking clears every secret the window holds (password fields, generated
passwords, decrypted messages, open dialogs, a secret on the clipboard) and
covers the window until the user returns. Python cannot guarantee freed memory
is overwritten, so this drops every reference Locksmith holds; the process
hardening (locksmith/hardening.py) keeps that memory unreadable to other programs.

A global panic hotkey is not possible: Wayland does not let apps listen for keys
while unfocused, and the portal that offers global shortcuts refuses hardened
processes. The shortcuts work while Locksmith is focused.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QPropertyAnimation, QRectF, Qt, QTimer
from PySide6.QtGui import QFont, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import QApplication, QGraphicsOpacityEffect, QLineEdit, QPlainTextEdit, QWidget

from .theme import EASE, font, pixmap, theme
from .widgets import PasswordField, clear_clipboard_secret

LOCK_SHORTCUT = "Ctrl+L"
PANIC_SHORTCUT = "Ctrl+Shift+L"
INPUT_EVENTS = {QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress, QEvent.Type.MouseMove,
                QEvent.Type.Wheel, QEvent.Type.TouchBegin}


def mark_sensitive(widget: QWidget) -> QWidget:
    """Mark a text widget whose contents must be cleared when the app locks."""
    widget.setProperty("sensitive", True)
    return widget


def clear_secrets(root: QWidget):
    for field in root.findChildren(PasswordField):
        field.clear()
        field.set_visible_text(False)
    for w in root.findChildren(QLineEdit) + root.findChildren(QPlainTextEdit):
        if w.property("sensitive"):
            w.clear()
    for page in root.findChildren(QWidget):
        hook = getattr(type(page), "clear_secrets", None)
        if callable(hook):
            hook(page)
    from . import dialogs
    dialogs.close_all()
    clear_clipboard_secret()


class LockOverlay(QWidget):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.hide()
        parent.installEventFilter(self)

    def eventFilter(self, obj, e):
        if obj is self.parent() and e.type() == QEvent.Type.Resize:
            self.setGeometry(self.parent().rect())
        return False

    def show_locked(self):
        self.setGeometry(self.parent().rect())
        self.show()
        self.raise_()
        self.setFocus()
        if theme.animations:
            eff = QGraphicsOpacityEffect(self)
            self.setGraphicsEffect(eff)
            a = QPropertyAnimation(eff, b"opacity", self)
            a.setDuration(200)
            a.setStartValue(0.0)
            a.setEndValue(1.0)
            a.setEasingCurve(EASE)
            a.finished.connect(lambda: self.setGraphicsEffect(None))
            a.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def unlock(self):
        self.hide()

    def mousePressEvent(self, e):
        self.unlock()

    def keyPressEvent(self, e):
        self.unlock()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), theme.c("bg"))
        cx, cy = self.width() / 2, self.height() / 2 - 40
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(theme.c("accent"))
        p.drawEllipse(QRectF(cx - 32, cy - 32, 64, 64))
        p.drawPixmap(int(cx - 14), int(cy - 14), pixmap("lock", 28, theme.c("on_accent")))
        p.setPen(theme.c("text"))
        p.setFont(font(20, QFont.Weight.DemiBold))
        p.drawText(QRectF(0, cy + 50, self.width(), 30), Qt.AlignmentFlag.AlignHCenter, "Locksmith is locked")
        p.setPen(theme.c("muted"))
        p.setFont(font(13))
        p.drawText(QRectF(40, cy + 86, self.width() - 80, 44), Qt.AlignmentFlag.AlignHCenter | Qt.TextFlag.TextWordWrap,
                   "Passwords and decrypted content were cleared from the window. "
                   "Running tasks keep going.\nClick or press any key to continue.")


class Locker(QObject):
    """Watches for inactivity and handles the lock and panic shortcuts."""

    def __init__(self, window: QWidget, root: QWidget, minutes: int):
        super().__init__(window)
        self.window, self.root = window, root
        self.overlay = LockOverlay(root)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(lambda: self.lock())
        self.set_minutes(minutes)
        QApplication.instance().installEventFilter(self)
        for keys, fn in ((LOCK_SHORTCUT, self.lock), (PANIC_SHORTCUT, self.panic)):
            sc = QShortcut(QKeySequence(keys), window)
            sc.setContext(Qt.ShortcutContext.ApplicationShortcut)
            sc.activated.connect(fn)

    def set_minutes(self, minutes: int):
        self.minutes = minutes
        if minutes > 0:
            self.timer.start(minutes * 60_000)
        else:
            self.timer.stop()

    def eventFilter(self, obj, e):
        if e.type() in INPUT_EVENTS and self.minutes > 0:
            self.timer.start(self.minutes * 60_000)
        return False

    def lock(self):
        clear_secrets(self.window)
        self.overlay.show_locked()

    def panic(self):
        """Clear everything, lock and get the window off the screen at once."""
        self.lock()
        self.window.showMinimized()
