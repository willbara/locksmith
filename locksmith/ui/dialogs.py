"""In-window modal sheets: a dimmed scrim with a card that scales in."""

from __future__ import annotations

from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QEvent,
    QEventLoop,
    QParallelAnimationGroup,
    QPropertyAnimation,
    QRectF,
    Qt,
)
from PySide6.QtGui import QColor, QFont, QImage, QKeySequence, QPainter, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from .theme import font, pixmap, theme
from .widgets import Button, IconButton, LineEdit, PasswordField, copy_secret, label, toast

_host: QWidget | None = None


def close_all():
    """Dismiss every open sheet, e.g. when the app locks."""
    if _host is not None:
        for sheet in _host.findChildren(Sheet):
            sheet.done(None)


def set_host(w: QWidget):
    global _host
    _host = w


class Sheet(QWidget):
    def __init__(self, title: str, caption: str = "", width=520, icon: str | None = None):
        super().__init__(_host)
        self.result_value = None
        self._loop: QEventLoop | None = None
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        self.setGeometry(_host.rect())
        _host.installEventFilter(self)

        self.card = QWidget(self)
        self.card.setObjectName("sheet")
        self.card.setFixedWidth(width)
        self.card.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.card.setStyleSheet(
            f"#sheet {{ background: {theme.p['card']}; border: 1px solid {theme.p['border2']};"
            f" border-radius: 18px; }}")
        lay = QVBoxLayout(self.card)
        lay.setContentsMargins(26, 24, 26, 24)
        lay.setSpacing(14)
        head = QHBoxLayout()
        head.setSpacing(12)
        if icon:
            ic = QLabel()
            ic.setPixmap(pixmap(icon, 22))
            head.addWidget(ic, 0, Qt.AlignmentFlag.AlignTop)
        tl = QVBoxLayout()
        tl.setSpacing(4)
        t = QLabel(title)
        t.setFont(font(17, QFont.Weight.DemiBold))
        tl.addWidget(t)
        if caption:
            c = label(caption, "caption")
            tl.addWidget(c)
        head.addLayout(tl, 1)
        close = IconButton("x", "Close", size=30)
        close.clicked.connect(lambda: self.done(None))
        head.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(head)
        self.body = QVBoxLayout()
        self.body.setSpacing(12)
        lay.addLayout(self.body)
        self.buttons = QHBoxLayout()
        self.buttons.setSpacing(8)
        self.buttons.addStretch(1)
        lay.addSpacing(4)
        lay.addLayout(self.buttons)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self, activated=lambda: self.done(None))
        self._scrim = 0.0

    def add(self, w):
        if isinstance(w, QWidget):
            self.body.addWidget(w)
        else:
            self.body.addLayout(w)
        return w

    def add_button(self, text, value=True, variant="secondary", icon=None, close=True):
        b = Button(text, icon, variant)
        if close:
            b.clicked.connect(lambda: self.done(value))
        self.buttons.addWidget(b)
        return b

    def eventFilter(self, obj, e):
        if obj is _host and e.type() == QEvent.Type.Resize:
            self.setGeometry(_host.rect())
            self._center()
        return False

    def _center(self):
        self.card.adjustSize()
        self.card.move((self.width() - self.card.width()) // 2,
                       max(20, (self.height() - self.card.height()) // 2 - 20))

    def get_scrim(self):
        return self._scrim

    def set_scrim(self, v):
        self._scrim = v
        self.update()

    scrim = Property(float, get_scrim, set_scrim)

    def paintEvent(self, _):
        p = QPainter(self)
        c = QColor(0, 0, 0)
        c.setAlphaF((0.72 if theme.is_dark else 0.38) * self._scrim)
        p.fillRect(self.rect(), c)

    def mousePressEvent(self, e):
        if not self.card.geometry().contains(e.position().toPoint()):
            self.done(None)

    def open(self):
        self.show()
        self.raise_()
        self._center()
        eff = QGraphicsOpacityEffect(self.card)
        self.card.setGraphicsEffect(eff)
        g = QParallelAnimationGroup(self)
        a = QPropertyAnimation(self, b"scrim", self)
        a.setDuration(theme.ms(220))
        a.setStartValue(0.0)
        a.setEndValue(1.0)
        g.addAnimation(a)
        o = QPropertyAnimation(eff, b"opacity", self)
        o.setDuration(theme.ms(220))
        o.setStartValue(0.0)
        o.setEndValue(1.0)
        g.addAnimation(o)
        end = self.card.pos()
        m = QPropertyAnimation(self.card, b"pos", self)
        m.setDuration(theme.ms(320))
        m.setStartValue(end + type(end)(0, 18))
        m.setEndValue(end)
        m.setEasingCurve(QEasingCurve.Type.OutBack)
        g.addAnimation(m)
        g.finished.connect(lambda: self.card.setGraphicsEffect(None))
        g.start()
        first = self.findChild(LineEdit) or self.findChild(QPlainTextEdit)
        if first:
            first.setFocus()

    def exec(self):
        self.open()
        self._loop = QEventLoop()
        self._loop.exec()
        return self.result_value

    def done(self, value):
        if getattr(self, "_closing", False):
            return
        self._closing = True
        self.result_value = value
        eff = QGraphicsOpacityEffect(self.card)
        self.card.setGraphicsEffect(eff)
        g = QParallelAnimationGroup(self)
        a = QPropertyAnimation(self, b"scrim", self)
        a.setDuration(theme.ms(180))
        a.setStartValue(self._scrim)
        a.setEndValue(0.0)
        g.addAnimation(a)
        o = QPropertyAnimation(eff, b"opacity", self)
        o.setDuration(theme.ms(160))
        o.setStartValue(1.0)
        o.setEndValue(0.0)
        g.addAnimation(o)

        def finish():
            _host.removeEventFilter(self)
            self.hide()
            self.deleteLater()
            if self._loop:
                self._loop.quit()

        g.finished.connect(finish)
        g.start()


# ── helpers ──────────────────────────────────────────────────────────────────

def confirm(title, message, ok="Continue", icon="alert", danger=False) -> bool:
    s = Sheet(title, icon=icon)
    s.add(label(message, "subtitle"))
    s.add_button("Cancel", False, "ghost")
    s.add_button(ok, True, "primary")
    return bool(s.exec())


def info(title, message, icon="check"):
    s = Sheet(title, icon=icon)
    s.add(label(message, "subtitle"))
    s.add_button("OK", True, "primary")
    s.exec()


def error(message, title="Something went wrong"):
    info(title, message, icon="alert")


def prompt(title, caption="", placeholder="", text="", secret=False, ok="OK") -> str | None:
    s = Sheet(title, caption)
    if secret:
        field = PasswordField(placeholder, strength=False, generate=False)
        edit = field.edit
        s.add(field)
    else:
        edit = LineEdit(placeholder)
        edit.setText(text)
        s.add(edit)
    edit.returnPressed.connect(lambda: s.done(edit.text()))
    s.add_button("Cancel", None, "ghost")
    b = s.add_button(ok, None, "primary", close=False)
    b.clicked.connect(lambda: s.done(edit.text()))
    return s.exec()


def text_view(title, text, caption="", mono=True, copy=True, width=620, secret=False):
    s = Sheet(title, caption, width=width)
    box = QPlainTextEdit(text)
    box.setReadOnly(True)
    if mono:
        box.setProperty("mono", "true")
    box.setMinimumHeight(220)
    s.add(box)
    if copy:
        c = s.add_button("Copy", None, "secondary", "copy", close=False)
        if secret:
            c.clicked.connect(lambda: (copy_secret(text),
                                       toast("Copied. The clipboard clears in 30 seconds.", "copy")))
        else:
            c.clicked.connect(lambda: (QApplication.clipboard().setText(text), toast("Copied to clipboard", "copy")))
    s.add_button("Done", True, "primary")
    s.exec()


def text_input(title, caption="", placeholder="", ok="OK", width=620) -> str | None:
    s = Sheet(title, caption, width=width)
    box = QPlainTextEdit()
    box.setPlaceholderText(placeholder)
    box.setProperty("mono", "true")
    box.setMinimumHeight(220)
    s.add(box)
    paste = s.add_button("Paste", None, "ghost", "paste", close=False)
    paste.clicked.connect(lambda: box.setPlainText(QApplication.clipboard().text()))
    s.add_button("Cancel", None, "ghost")
    b = s.add_button(ok, None, "primary", close=False)
    b.clicked.connect(lambda: s.done(box.toPlainText()))
    return s.exec()


class QRCode(QWidget):
    def __init__(self, data: str, size=260):
        super().__init__()
        import segno
        qr = segno.make(data, error="m")
        self.matrix = [list(row) for row in qr.matrix]
        self.setFixedSize(size, size)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor("white"))
        p.drawRoundedRect(QRectF(self.rect()), 14, 14)
        n = len(self.matrix)
        quiet = 3
        cell = self.width() / (n + quiet * 2)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.setBrush(QColor("black"))
        for y, row in enumerate(self.matrix):
            for x, v in enumerate(row):
                if v:
                    p.drawRect(QRectF((x + quiet) * cell, (y + quiet) * cell, cell + 0.5, cell + 0.5))

    def image(self, scale=10) -> QImage:
        n = len(self.matrix) + 8
        img = QImage(n * scale, n * scale, QImage.Format.Format_RGB32)
        img.fill(QColor("white"))
        p = QPainter(img)
        for y, row in enumerate(self.matrix):
            for x, v in enumerate(row):
                if v:
                    p.fillRect((x + 4) * scale, (y + 4) * scale, scale, scale, QColor("black"))
        p.end()
        return img


def qr_view(title, data: str, caption=""):
    s = Sheet(title, caption, width=380, icon="qr")
    try:
        qr = QRCode(data, 300)
    except Exception as e:  # noqa: BLE001
        s.add(label(f"Too much data for a QR code ({e}).", "caption"))
    else:
        s.body.addWidget(qr, 0, Qt.AlignmentFlag.AlignHCenter)
        c = s.add_button("Copy image", None, "secondary", "copy", close=False)
        c.clicked.connect(lambda: (QApplication.clipboard().setImage(qr.image()),
                                   toast("QR code copied", "copy")))
    s.add_button("Done", True, "primary")
    s.exec()
