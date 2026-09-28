"""Custom-painted, animated widgets in a monochrome style."""

from __future__ import annotations

import html
import os
import sys
from pathlib import Path

from PySide6.QtCore import (
    QEasingCurve,
    QEvent,
    QParallelAnimationGroup,
    QPoint,
    QPointF,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    QTimer,
    QVariantAnimation,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QAbstractButton,
    QComboBox,
    QFileDialog,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..core import tools
from ..core.keys import write_secret_file
from .theme import EASE, EASE_IN_OUT, font, mix, pixmap, theme

W = QFont.Weight


def _anim(target, prop: bytes, duration: int, start=None, end=None, curve=EASE):
    a = QPropertyAnimation(target, prop, target)
    a.setDuration(theme.ms(duration))
    a.setEasingCurve(curve)
    if start is not None:
        a.setStartValue(start)
    if end is not None:
        a.setEndValue(end)
    return a


class _Hover:
    """Mixin: an animated 0→1 hover value and a press value."""

    def _init_hover(self):
        self._hv = 0.0
        self._pv = 0.0
        self._hover_anim = QVariantAnimation(self)
        self._hover_anim.setEasingCurve(EASE)
        self._hover_anim.valueChanged.connect(self._set_hv)
        self._press_anim = QVariantAnimation(self)
        self._press_anim.setEasingCurve(EASE)
        self._press_anim.valueChanged.connect(self._set_pv)

    def _set_hv(self, v):
        self._hv = float(v)
        self.update()

    def _set_pv(self, v):
        self._pv = float(v)
        self.update()

    def _go_hover(self, to: float, ms=160):
        self._hover_anim.stop()
        self._hover_anim.setDuration(theme.ms(ms))
        self._hover_anim.setStartValue(self._hv)
        self._hover_anim.setEndValue(to)
        self._hover_anim.start()

    def _go_press(self, to: float, ms=110):
        self._press_anim.stop()
        self._press_anim.setDuration(theme.ms(ms))
        self._press_anim.setStartValue(self._pv)
        self._press_anim.setEndValue(to)
        self._press_anim.start()


# ── labels ───────────────────────────────────────────────────────────────────

class Label(QLabel):
    """A QLabel that never renders its text as HTML. Plain QLabels guess, so a file
    name or note chosen by a sender (such as "<h1>Verified</h1>") would be drawn as
    markup. Every label in the app is one of these."""

    def __init__(self, text="", parent=None):
        super().__init__(parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setText(text)


# ── buttons ──────────────────────────────────────────────────────────────────

class Button(QAbstractButton, _Hover):
    """Variants: primary (solid), secondary (outlined), ghost (text only)."""

    def __init__(self, text="", icon: str | None = None, variant="secondary", parent=None,
                 large=False, tooltip: str | None = None):
        super().__init__(parent)
        self._init_hover()
        self.setText(text)
        self._icon = icon
        self.variant = variant
        self.large = large
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFont(font(14 if large else 13, W.DemiBold if large else W.Medium))
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        if tooltip:
            self.setToolTip(tooltip)

    def set_icon_name(self, name: str | None):
        self._icon = name
        self.updateGeometry()
        self.update()

    def sizeHint(self):
        fm = QFontMetrics(self.font())
        h = 48 if self.large else 38
        w = fm.horizontalAdvance(self.text()) + (40 if self.text() else 0)
        if self._icon:
            w += 18 + (8 if self.text() else 0)
        return QSize(max(w, h), h)

    def minimumSizeHint(self):
        return self.sizeHint()

    def enterEvent(self, e):
        self._go_hover(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._go_hover(0.0)
        super().leaveEvent(e)

    def mousePressEvent(self, e):
        self._go_press(1.0)
        super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        self._go_press(0.0, 220)
        super().mouseReleaseEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.isEnabled():
            p.setOpacity(0.35)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        # Subtle press "sink" animation.
        shrink = self._pv * 1.5
        r = r.adjusted(shrink, shrink, -shrink, -shrink)
        radius = 12 if self.large else 10
        hv = self._hv if self.isEnabled() else 0
        if self.variant == "primary":
            bg = mix(theme.c("accent"), theme.c("muted"), hv * 0.22)
            fg = theme.c("on_accent")
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(bg)
        elif self.variant == "secondary":
            bg = mix(theme.c("raised"), theme.c("hover"), hv)
            fg = theme.c("text")
            p.setPen(QPen(mix(theme.c("border"), theme.c("border2"), hv), 1))
            p.setBrush(bg)
        else:
            bg = QColor(theme.c("hover"))
            bg.setAlphaF(hv)
            fg = mix(theme.c("muted"), theme.c("text"), hv) if not self.isChecked() else theme.c("text")
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(bg)
        p.drawRoundedRect(r, radius, radius)

        fm = QFontMetrics(self.font())
        tw = fm.horizontalAdvance(self.text()) if self.text() else 0
        iw = 18 if self._icon else 0
        gap = 8 if (tw and iw) else 0
        x = (self.width() - (tw + iw + gap)) / 2
        if self._icon:
            pm = pixmap(self._icon, 18, fg)
            p.drawPixmap(QPointF(x, (self.height() - 18) / 2), pm)
            x += iw + gap
        if tw:
            p.setPen(fg)
            p.setFont(self.font())
            p.drawText(QRectF(x, 0, tw + 2, self.height()), Qt.AlignmentFlag.AlignVCenter, self.text())


class IconButton(Button):
    def __init__(self, icon: str, tooltip="", parent=None, size=34, variant="ghost"):
        super().__init__("", icon, variant, parent, tooltip=tooltip)
        self._size = size

    def sizeHint(self):
        return QSize(self._size, self._size)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.isEnabled():
            p.setOpacity(0.35)
        bg = QColor(theme.c("hover"))
        bg.setAlphaF(self._hv)
        if self.variant == "secondary":
            p.setPen(QPen(mix(theme.c("border"), theme.c("border2"), self._hv), 1))
            bg = mix(theme.c("raised"), theme.c("hover"), self._hv)
        else:
            p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        s = self._pv * 1.5
        p.drawRoundedRect(r.adjusted(s, s, -s, -s), 9, 9)
        fg = mix(theme.c("muted"), theme.c("text"), self._hv)
        p.drawPixmap(QPointF((self.width() - 18) / 2, (self.height() - 18) / 2),
                     pixmap(self._icon, 18, fg))


class LinkButton(Label):
    clicked = Signal()

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setProperty("role", "caption")
        f = self.font()
        f.setUnderline(True)
        self.setFont(f)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()


# ── toggle ───────────────────────────────────────────────────────────────────

class Toggle(QAbstractButton, _Hover):
    def __init__(self, checked=False, parent=None):
        super().__init__(parent)
        self._init_hover()
        self.setCheckable(True)
        self.setChecked(checked)
        self._pos = 1.0 if checked else 0.0
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(40, 24)
        self._anim = QVariantAnimation(self)
        self._anim.setEasingCurve(QEasingCurve.Type.OutBack)
        self._anim.valueChanged.connect(self._set_pos)
        self.toggled.connect(self._animate)

    def _set_pos(self, v):
        self._pos = float(v)
        self.update()

    def _animate(self, on):
        self._anim.stop()
        self._anim.setDuration(theme.ms(260))
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if on else 0.0)
        self._anim.start()

    def enterEvent(self, e):
        self._go_hover(1.0)

    def leaveEvent(self, e):
        self._go_hover(0.0)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.isEnabled():
            p.setOpacity(0.35)
        t = max(0.0, min(1.0, self._pos))
        track_off = mix(theme.c("border2"), theme.c("faint"), self._hv * 0.6)
        track = mix(track_off, theme.c("accent"), t)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(QRectF(0, 2, 40, 20), 10, 10)
        knob = mix(theme.c("text"), theme.c("on_accent"), t)
        p.setBrush(knob)
        x = 2 + self._pos * 18
        p.drawEllipse(QRectF(x, 4, 16, 16))


class ToggleRow(QWidget):
    toggled = Signal(bool)

    def __init__(self, title, caption="", checked=False, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 6, 0, 6)
        lay.setSpacing(16)
        text = QVBoxLayout()
        text.setSpacing(2)
        t = Label(title)
        t.setFont(font(13, W.Medium))
        text.addWidget(t)
        if caption:
            c = Label(caption)
            c.setProperty("role", "caption")
            c.setWordWrap(True)
            text.addWidget(c)
        lay.addLayout(text, 1)
        self.toggle = Toggle(checked)
        self.toggle.toggled.connect(self.toggled)
        lay.addWidget(self.toggle, 0, Qt.AlignmentFlag.AlignVCenter)

    def isChecked(self):
        return self.toggle.isChecked()

    def setChecked(self, v):
        self.toggle.setChecked(v)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.toggle.toggle()


# ── dropdown ─────────────────────────────────────────────────────────────────

class Dropdown(QComboBox, _Hover):
    """A combobox with a custom face, rotating chevron and fading popup."""

    def __init__(self, items: dict | list | None = None, parent=None):
        super().__init__(parent)
        self._init_hover()
        self._rot = 0.0
        self._rot_anim = QVariantAnimation(self)
        self._rot_anim.setEasingCurve(EASE)
        self._rot_anim.valueChanged.connect(self._set_rot)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(40)
        self.setMinimumWidth(120)
        self.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.view().setCursor(Qt.CursorShape.PointingHandCursor)
        if items:
            self.set_items(items)

    def set_items(self, items: dict | list, keep=True):
        current = self.value() if keep and self.count() else None
        self.blockSignals(True)
        self.clear()
        pairs = items.items() if isinstance(items, dict) else [(i, i) for i in items]
        for data, label in pairs:
            self.addItem(str(label), data)
        self.blockSignals(False)
        if current is not None:
            self.set_value(current)

    def value(self):
        return self.currentData()

    def set_value(self, data):
        i = self.findData(data)
        if i >= 0:
            self.setCurrentIndex(i)

    def _set_rot(self, v):
        self._rot = float(v)
        self.update()

    def _spin(self, to):
        self._rot_anim.stop()
        self._rot_anim.setDuration(theme.ms(220))
        self._rot_anim.setStartValue(self._rot)
        self._rot_anim.setEndValue(to)
        self._rot_anim.start()

    def showPopup(self):
        super().showPopup()
        self._spin(180.0)
        popup = self.view().window()
        if theme.animations and popup is not None:
            popup.setWindowOpacity(0.0)
            a = QPropertyAnimation(popup, b"windowOpacity", popup)
            a.setDuration(160)
            a.setStartValue(0.0)
            a.setEndValue(1.0)
            a.setEasingCurve(EASE)
            a.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)

    def hidePopup(self):
        super().hidePopup()
        self._spin(0.0)

    def enterEvent(self, e):
        self._go_hover(1.0)

    def leaveEvent(self, e):
        self._go_hover(0.0)

    def wheelEvent(self, e):
        # Don't hijack page scrolling.
        if self.hasFocus() and self.view().isVisible():
            super().wheelEvent(e)
        else:
            e.ignore()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if not self.isEnabled():
            p.setOpacity(0.35)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        focus = self.hasFocus() or self.view().isVisible()
        border = theme.c("text") if focus else mix(theme.c("border"), theme.c("border2"), self._hv)
        p.setPen(QPen(border, 1))
        p.setBrush(mix(theme.c("raised"), theme.c("hover"), self._hv * 0.5))
        p.drawRoundedRect(r, 10, 10)
        p.setPen(theme.c("text"))
        p.setFont(self.font())
        text_rect = QRectF(14, 0, self.width() - 44, self.height())
        fm = QFontMetrics(self.font())
        p.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter,
                   fm.elidedText(self.currentText(), Qt.TextElideMode.ElideRight, int(text_rect.width())))
        p.save()
        p.translate(self.width() - 22, self.height() / 2)
        p.rotate(self._rot)
        p.drawPixmap(QPointF(-8, -8), pixmap("chevron", 16, theme.c("muted")))
        p.restore()


class Field(QWidget):
    """A small uppercase label over a control, with an optional caption."""

    def __init__(self, label: str, control, caption: str = "", parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        lab = Label(label.upper())
        lab.setProperty("role", "label")
        lay.addWidget(lab)
        if isinstance(control, QWidget):
            lay.addWidget(control)
        else:
            lay.addLayout(control)
        self.control = control
        self.caption = Label(caption)
        self.caption.setProperty("role", "caption")
        self.caption.setWordWrap(True)
        self.caption.setVisible(bool(caption))
        lay.addWidget(self.caption)

    def set_caption(self, text: str):
        self.caption.setText(text)
        self.caption.setVisible(bool(text))


# ── segmented control ────────────────────────────────────────────────────────

class Segmented(QWidget, _Hover):
    changed = Signal(int)

    def __init__(self, options: list[str], parent=None):
        super().__init__(parent)
        self._init_hover()
        self.options = options
        self._index = 0
        self._x = 0.0
        self._hover_idx = -1
        self.setFixedHeight(40)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFont(font(13, W.Medium))
        self._anim = QVariantAnimation(self)
        self._anim.setEasingCurve(EASE)
        self._anim.valueChanged.connect(lambda v: (setattr(self, "_x", float(v)), self.update()))

    def index(self):
        return self._index

    def setIndex(self, i, animate=True):
        if i == self._index:
            return
        self._index = i
        self._anim.stop()
        if animate:
            self._anim.setDuration(theme.ms(260))
            self._anim.setStartValue(self._x)
            self._anim.setEndValue(float(i))
            self._anim.start()
        else:
            self._x = float(i)
            self.update()
        self.changed.emit(i)

    def sizeHint(self):
        fm = QFontMetrics(self.font())
        w = max(fm.horizontalAdvance(o) for o in self.options) + 36
        return QSize(w * len(self.options) + 8, 40)

    def _seg_w(self):
        return (self.width() - 8) / len(self.options)

    def mouseMoveEvent(self, e):
        i = int((e.position().x() - 4) // self._seg_w())
        if i != self._hover_idx:
            self._hover_idx = i
            self.update()

    def leaveEvent(self, e):
        self._hover_idx = -1
        self.update()

    def mouseReleaseEvent(self, e):
        i = int((e.position().x() - 4) // self._seg_w())
        if 0 <= i < len(self.options):
            self.setIndex(i)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        p.setPen(QPen(theme.c("border"), 1))
        p.setBrush(theme.c("raised"))
        p.drawRoundedRect(r, 11, 11)
        sw = self._seg_w()
        pill = QRectF(4 + self._x * sw, 4, sw, self.height() - 8)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(theme.c("accent"))
        p.drawRoundedRect(pill, 8, 8)
        p.setFont(self.font())
        for i, text in enumerate(self.options):
            seg = QRectF(4 + i * sw, 0, sw, self.height())
            closeness = max(0.0, 1 - abs(self._x - i))
            base = theme.c("text") if i == self._hover_idx else theme.c("muted")
            p.setPen(mix(base, theme.c("on_accent"), closeness))
            p.drawText(seg, Qt.AlignmentFlag.AlignCenter, text)


# ── card & collapsible ───────────────────────────────────────────────────────

class Card(QFrame):
    def __init__(self, title: str = "", caption: str = "", parent=None, spacing=14):
        super().__init__(parent)
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(22, 20, 22, 22)
        self.lay.setSpacing(spacing)
        if title:
            head = QVBoxLayout()
            head.setSpacing(3)
            t = Label(title)
            t.setProperty("role", "h2")
            head.addWidget(t)
            if caption:
                c = Label(caption)
                c.setProperty("role", "caption")
                c.setWordWrap(True)
                head.addWidget(c)
            self.lay.addLayout(head)

    def add(self, w, stretch=0):
        if isinstance(w, QWidget):
            self.lay.addWidget(w, stretch)
        else:
            self.lay.addLayout(w, stretch)
        return w


def divider() -> QFrame:
    d = QFrame()
    d.setObjectName("divider")
    return d


class _CollapseHeader(QWidget, _Hover):
    clicked = Signal()

    def __init__(self, title, caption, icon, parent=None):
        super().__init__(parent)
        self._init_hover()
        self.rot = 0.0
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(64 if caption else 52)
        self.title, self.caption, self.icon = title, caption, icon

    def enterEvent(self, e):
        self._go_hover(1.0)

    def leaveEvent(self, e):
        self._go_hover(0.0)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        x = 22
        if self.icon:
            p.drawPixmap(QPointF(x, (self.height() - 20) / 2), pixmap(self.icon, 20, theme.c("text")))
            x += 34
        p.setPen(theme.c("text"))
        p.setFont(font(15, W.DemiBold))
        if self.caption:
            p.drawText(QRectF(x, 13, self.width() - x - 60, 20), Qt.AlignmentFlag.AlignVCenter, self.title)
            p.setPen(theme.c("muted"))
            p.setFont(font(12))
            p.drawText(QRectF(x, 33, self.width() - x - 60, 18), Qt.AlignmentFlag.AlignVCenter, self.caption)
        else:
            p.drawText(QRectF(x, 0, self.width() - x - 60, self.height()), Qt.AlignmentFlag.AlignVCenter,
                       self.title)
        p.save()
        p.translate(self.width() - 32, self.height() / 2)
        p.rotate(self.rot)
        col = mix(theme.c("muted"), theme.c("text"), self._hv)
        p.drawPixmap(QPointF(-9, -9), pixmap("chevron", 18, col))
        p.restore()


class Collapsible(QFrame):
    """A card whose body slides open and closed."""

    toggled = Signal(bool)

    def __init__(self, title, caption="", icon: str | None = None, expanded=False, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.header = _CollapseHeader(title, caption, icon)
        self.header.clicked.connect(self.toggle)
        outer.addWidget(self.header)
        self.body = QWidget()
        self.body.setObjectName("collapsible-body")
        self.lay = QVBoxLayout(self.body)
        self.lay.setContentsMargins(22, 4, 22, 22)
        self.lay.setSpacing(14)
        outer.addWidget(self.body)
        self._expanded = expanded
        self.body.setMaximumHeight(16777215 if expanded else 0)
        self.header.rot = 180.0 if expanded else 0.0
        self._effect = QGraphicsOpacityEffect(self.body)
        self._effect.setOpacity(1.0 if expanded else 0.0)
        self.body.setGraphicsEffect(self._effect)
        self._effect.setEnabled(not expanded)
        self._group = None

    def add(self, w, stretch=0):
        if isinstance(w, QWidget):
            self.lay.addWidget(w, stretch)
        else:
            self.lay.addLayout(w, stretch)
        return w

    def is_expanded(self):
        return self._expanded

    def toggle(self):
        self.set_expanded(not self._expanded)

    def set_expanded(self, on: bool):
        if on == self._expanded:
            return
        self._expanded = on
        target = self.body.sizeHint().height()
        self._effect.setEnabled(True)
        if self._group:
            self._group.stop()
        g = QParallelAnimationGroup(self)
        h = _anim(self.body, b"maximumHeight", 320, self.body.height() if on else self.body.height(),
                  target if on else 0, EASE_IN_OUT)
        if on:
            h.setStartValue(0 if self.body.maximumHeight() == 0 else self.body.height())
        o = _anim(self._effect, b"opacity", 260, self._effect.opacity(), 1.0 if on else 0.0)
        rot = QVariantAnimation(self)
        rot.setDuration(theme.ms(300))
        rot.setEasingCurve(EASE)
        rot.setStartValue(self.header.rot)
        rot.setEndValue(180.0 if on else 0.0)
        rot.valueChanged.connect(lambda v: (setattr(self.header, "rot", float(v)), self.header.update()))
        for a in (h, o, rot):
            g.addAnimation(a)

        def done():
            if self._expanded:
                self.body.setMaximumHeight(16777215)
                self._effect.setEnabled(False)

        g.finished.connect(done)
        self._group = g
        g.start()
        self.toggled.emit(on)


# ── drop zone & file list ────────────────────────────────────────────────────

def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return ""


class DropZone(QWidget, _Hover):
    dropped = Signal(list)

    def __init__(self, title="Drop files or folders here", caption="or choose them below",
                 folders=True, file_filter="", parent=None):
        super().__init__(parent)
        self._init_hover()
        self._drag = 0.0
        self._drag_anim = QVariantAnimation(self)
        self._drag_anim.setEasingCurve(EASE)
        self._drag_anim.valueChanged.connect(lambda v: (setattr(self, "_drag", float(v)), self.update()))
        self._dash = 0.0
        self._dash_timer = QTimer(self)
        self._dash_timer.setInterval(30)
        self._dash_timer.timeout.connect(self._tick)
        self.file_filter = file_filter
        self.setAcceptDrops(True)
        self.setMinimumHeight(190)
        self.title, self.caption = title, caption

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 70, 20, 22)
        lay.addStretch(1)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addStretch(1)
        self.files_btn = Button("Choose files", "file")
        self.files_btn.clicked.connect(self._choose_files)
        row.addWidget(self.files_btn)
        if folders:
            self.folder_btn = Button("Choose folder", "folder")
            self.folder_btn.clicked.connect(self._choose_folder)
            row.addWidget(self.folder_btn)
        self.extra_row = row
        row.addStretch(1)
        lay.addLayout(row)

    def add_button(self, btn: QWidget):
        self.extra_row.insertWidget(self.extra_row.count() - 1, btn)

    def _tick(self):
        self._dash = (self._dash - 0.6) % 20
        self.update()

    def _animate_drag(self, to):
        self._drag_anim.stop()
        self._drag_anim.setDuration(theme.ms(200))
        self._drag_anim.setStartValue(self._drag)
        self._drag_anim.setEndValue(to)
        self._drag_anim.start()
        if to and theme.animations:
            self._dash_timer.start()
        else:
            self._dash_timer.stop()

    def _choose_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose files", "", self.file_filter)
        if paths:
            self.dropped.emit(paths)

    def _choose_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Choose folder")
        if path:
            self.dropped.emit([path])

    def enterEvent(self, e):
        self._go_hover(1.0)

    def leaveEvent(self, e):
        self._go_hover(0.0)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._animate_drag(1.0)

    def dragLeaveEvent(self, e):
        self._animate_drag(0.0)

    def dropEvent(self, e):
        self._animate_drag(0.0)
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        d = self._drag
        bg = mix(theme.c("card"), theme.c("raised"), max(self._hv * 0.6, d))
        p.setBrush(bg)
        col = mix(mix(theme.c("border2"), theme.c("muted"), self._hv), theme.c("text"), d)
        pen = QPen(col, 1.4)
        pen.setStyle(Qt.PenStyle.CustomDashLine)
        pen.setDashPattern([5, 5])
        pen.setDashOffset(self._dash)
        p.setPen(pen)
        p.drawRoundedRect(r, 18, 18)

        # Icon in a circle, lifting slightly while dragging.
        cy = 44 - 6 * d
        circle = QRectF(self.width() / 2 - 22, cy - 22, 44, 44)
        p.setPen(QPen(mix(theme.c("border2"), theme.c("text"), d), 1))
        p.setBrush(mix(theme.c("raised"), theme.c("accent"), d))
        p.drawEllipse(circle)
        p.drawPixmap(QPointF(self.width() / 2 - 10, cy - 10),
                     pixmap("upload", 20, mix(theme.c("text"), theme.c("on_accent"), d)))
        p.setPen(theme.c("text"))
        p.setFont(font(15, W.DemiBold))
        title = "Release to add" if d > 0.5 else self.title
        p.drawText(QRectF(0, cy + 30, self.width(), 22), Qt.AlignmentFlag.AlignHCenter, title)
        p.setPen(theme.c("muted"))
        p.setFont(font(12))
        p.drawText(QRectF(0, cy + 52, self.width(), 20), Qt.AlignmentFlag.AlignHCenter, self.caption)


class _FileRow(QWidget, _Hover):
    removed = Signal(str)

    def __init__(self, path: str, label: str | None = None, parent=None):
        super().__init__(parent)
        self._init_hover()
        self.path = path
        self.setFixedHeight(48)
        p = Path(path)
        is_dir = p.is_dir()
        self._icon = "folder" if is_dir else "file"
        self._name = label or p.name
        if is_dir:
            self._meta = "Folder"
        else:
            try:
                self._meta = human_size(p.stat().st_size)
            except OSError:
                self._meta = ""
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 8, 0)
        lay.addStretch(1)
        self.rm = IconButton("x", "Remove", size=30)
        self.rm.clicked.connect(lambda: self.removed.emit(self.path))
        lay.addWidget(self.rm)
        # Escaped: tooltips also guess at HTML, and file names can contain markup.
        self.setToolTip(f"<p style='white-space:pre'>{html.escape(path)}</p>")

    def enterEvent(self, e):
        self._go_hover(1.0)

    def leaveEvent(self, e):
        self._go_hover(0.0)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QColor(theme.c("raised"))
        bg.setAlphaF(0.5 + 0.5 * self._hv)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(QRectF(self.rect()), 10, 10)
        p.drawPixmap(QPointF(14, 15), pixmap(self._icon, 18, theme.c("muted")))
        p.setFont(font(13, W.Medium))
        fm = QFontMetrics(p.font())
        meta_w = QFontMetrics(font(12)).horizontalAdvance(self._meta) + 20
        avail = self.width() - 46 - meta_w - 50
        p.setPen(theme.c("text"))
        p.drawText(QRectF(44, 0, avail, self.height()), Qt.AlignmentFlag.AlignVCenter,
                   fm.elidedText(self._name, Qt.TextElideMode.ElideMiddle, int(avail)))
        p.setPen(theme.c("muted"))
        p.setFont(font(12))
        p.drawText(QRectF(self.width() - 50 - meta_w, 0, meta_w, self.height()),
                   Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight, self._meta)


class FileList(QWidget):
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(6)
        self._rows: dict[str, _FileRow] = {}
        self._labels: dict[str, str] = {}
        self.head = QHBoxLayout()
        self.count_label = Label()
        self.count_label.setProperty("role", "caption")
        self.head.addWidget(self.count_label)
        self.head.addStretch(1)
        self.clear_btn = LinkButton("Clear all")
        self.clear_btn.clicked.connect(self.clear)
        self.head.addWidget(self.clear_btn)
        self.lay.addLayout(self.head)
        self.setVisible(False)

    def add(self, paths: list[str], label: str | None = None):
        for path in paths:
            path = os.path.abspath(path)
            if path in self._rows:
                continue
            row = _FileRow(path, label)
            row.removed.connect(self.remove)
            self._rows[path] = row
            self.lay.addWidget(row)
            fade_in(row, 240, rise=6)
        self._refresh()

    def remove(self, path: str):
        row = self._rows.pop(path, None)
        if row:
            row.deleteLater()
        self._refresh()

    def clear(self):
        for row in self._rows.values():
            row.deleteLater()
        self._rows.clear()
        self._refresh()

    def paths(self) -> list[str]:
        return list(self._rows)

    def _refresh(self):
        n = len(self._rows)
        self.count_label.setText(f"{n} item{'s' if n != 1 else ''} selected")
        self.setVisible(n > 0)
        self.changed.emit()


_clipboard_secret: str | None = None


def clear_clipboard_secret():
    """Clear the clipboard now if it still holds a secret Locksmith put there."""
    global _clipboard_secret
    from PySide6.QtWidgets import QApplication
    if _clipboard_secret is not None and tools.same_secret(QApplication.clipboard().text(), _clipboard_secret):
        QApplication.clipboard().clear()
    _clipboard_secret = None


def copy_secret(text: str, seconds: int = 30):
    """Copy a secret: ask clipboard managers not to record it, and clear it after
    a delay unless something else has been copied since."""
    global _clipboard_secret
    from PySide6.QtCore import QMimeData
    from PySide6.QtWidgets import QApplication
    mime = QMimeData()
    mime.setText(text)
    mime.setData("x-kde-passwordManagerHint", b"secret")  # KDE Klipper and compatible managers
    if sys.platform == "win32":
        # Keep secrets out of Windows clipboard history (Win+V), cloud clipboard sync and
        # clipboard monitors. Documented formats; the same approach KeePassXC uses.
        win = 'application/x-qt-windows-mime;value="{}"'
        mime.setData(win.format("ExcludeClipboardContentFromMonitorProcessing"), b"1")
        mime.setData(win.format("CanIncludeInClipboardHistory"), bytes(4))   # DWORD 0
        mime.setData(win.format("CanUploadToCloudClipboard"), bytes(4))      # DWORD 0
    QApplication.clipboard().setMimeData(mime)
    _clipboard_secret = text

    def clear():
        global _clipboard_secret
        cb = QApplication.clipboard()
        ours = _clipboard_secret is not None and tools.same_secret(_clipboard_secret, text)
        if ours and tools.same_secret(cb.text(), text):
            cb.clear()
        if ours:
            _clipboard_secret = None

    QTimer.singleShot(seconds * 1000, clear)


def shake(w: QWidget):
    """Horizontal shake, e.g. after a wrong password."""
    if not theme.animations:
        return
    a = QPropertyAnimation(w, b"pos", w)
    origin = w.pos()
    a.setDuration(420)
    for t, dx in ((0.1, -8), (0.25, 7), (0.4, -6), (0.55, 4), (0.7, -2), (0.85, 1)):
        a.setKeyValueAt(t, origin + QPoint(dx, 0))
    a.setStartValue(origin)
    a.setEndValue(origin)
    a.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)


def fade_in(w: QWidget, ms=260, rise=0, delay=0):
    """Fade (and optionally lift) a widget into view."""
    if not theme.animations:
        return
    eff = QGraphicsOpacityEffect(w)
    eff.setOpacity(0.0)
    w.setGraphicsEffect(eff)
    a = QPropertyAnimation(eff, b"opacity", w)
    a.setDuration(ms)
    a.setStartValue(0.0)
    a.setEndValue(1.0)
    a.setEasingCurve(EASE)
    a.finished.connect(lambda: w.setGraphicsEffect(None))
    QTimer.singleShot(delay, a.start)


# ── password ─────────────────────────────────────────────────────────────────

class StrengthMeter(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(4)
        self._level = 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setEasingCurve(EASE)
        self._anim.valueChanged.connect(lambda v: (setattr(self, "_level", float(v)), self.update()))

    def set_level(self, level: float):
        self._anim.stop()
        self._anim.setDuration(theme.ms(320))
        self._anim.setStartValue(self._level)
        self._anim.setEndValue(float(level))
        self._anim.start()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        n, gap = 5, 6
        w = (self.width() - gap * (n - 1)) / n
        for i in range(n):
            r = QRectF(i * (w + gap), 0, w, 4)
            p.setBrush(theme.c("border"))
            p.drawRoundedRect(r, 2, 2)
            fill = max(0.0, min(1.0, self._level - i))
            if fill > 0:
                p.setBrush(theme.c("text"))
                p.drawRoundedRect(QRectF(r.x(), 0, w * fill, 4), 2, 2)


class LineEdit(QLineEdit):
    """QLineEdit with trailing icon actions."""

    def __init__(self, placeholder="", parent=None, mono=False):
        super().__init__(parent)
        self.setPlaceholderText(placeholder)
        if mono:
            self.setProperty("mono", "true")
        self._buttons: list[IconButton] = []
        self._btn_box = QWidget(self)
        self._btn_lay = QHBoxLayout(self._btn_box)
        self._btn_lay.setContentsMargins(0, 0, 4, 0)
        self._btn_lay.setSpacing(0)

    def add_action(self, icon: str, tooltip: str, slot) -> IconButton:
        b = IconButton(icon, tooltip, size=32)
        b.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        b.clicked.connect(slot)
        self._btn_lay.addWidget(b)
        self._buttons.append(b)
        self.setTextMargins(0, 0, 34 * len(self._buttons), 0)
        self._place()
        return b

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._place()

    def _place(self):
        w = 34 * len(self._buttons) + 4
        self._btn_box.setGeometry(self.width() - w, (self.height() - 32) // 2, w, 32)


class PasswordField(QWidget):
    changed = Signal(str)

    def __init__(self, placeholder="Password", strength=True, generate=True, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.edit = LineEdit(placeholder)
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.edit.setFixedHeight(42)
        self.eye = self.edit.add_action("eye", "Show password", self._toggle_echo)
        if generate:
            self.edit.add_action("refresh", "Generate a strong password", self.generate)
        self.edit.add_action("copy", "Copy", self._copy)
        lay.addWidget(self.edit)
        self.meter = None
        if strength:
            self.meter = StrengthMeter()
            lay.addWidget(self.meter)
            self.info = Label(" ")
            self.info.setProperty("role", "caption")
            lay.addWidget(self.info)
        self.edit.textChanged.connect(self._changed)

    def text(self):
        return self.edit.text()

    def setText(self, t):
        self.edit.setText(t)

    def clear(self):
        self.edit.clear()

    def set_visible_text(self, on: bool):
        self.edit.setEchoMode(QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password)
        self.eye.set_icon_name("eye-off" if on else "eye")

    def _toggle_echo(self):
        self.set_visible_text(self.edit.echoMode() == QLineEdit.EchoMode.Password)

    def generate(self):
        self.setText(tools.generate_password(24))
        self.set_visible_text(True)

    def _copy(self):
        if self.text():
            copy_secret(self.text())
            toast("Copied. The clipboard clears in 30 seconds.", "copy")

    def _changed(self, text):
        if self.meter:
            bits = tools.estimate_entropy(text)
            level, label = tools.strength_label(bits)
            self.meter.set_level(0 if not text else level + 1)
            self.info.setText(" " if not text else
                              f"{label} · ~{bits:.0f} bits · offline crack: {tools.crack_time(bits)}")
        self.changed.emit(text)


class KeyfilePicker(QWidget):
    changed = Signal()

    def __init__(self, allow_generate=True, parent=None):
        super().__init__(parent)
        self.path: str | None = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.label = Label("No keyfile")
        self.label.setProperty("role", "caption")
        self.choose = Button("Keyfile…", "key")
        self.choose.setToolTip("Any file can be a keyfile. Its exact bytes become part of the key.")
        self.choose.clicked.connect(self._choose)
        lay.addWidget(self.choose)
        if allow_generate:
            self.gen = Button("Generate", "plus", variant="ghost")
            self.gen.setToolTip("Create a new random keyfile")
            self.gen.clicked.connect(self._generate)
            lay.addWidget(self.gen)
        lay.addWidget(self.label, 1)
        self.clear_btn = IconButton("x", "Remove keyfile", size=32)
        self.clear_btn.clicked.connect(lambda: self.set_path(None))
        self.clear_btn.setVisible(False)
        lay.addWidget(self.clear_btn)

    def set_path(self, path: str | None):
        self.path = path
        if path:
            self.label.setText(Path(path).name)
            self.label.setProperty("role", "mono")
        else:
            self.label.setText("No keyfile")
            self.label.setProperty("role", "caption")
        self.label.style().unpolish(self.label)
        self.label.style().polish(self.label)
        self.clear_btn.setVisible(bool(path))
        self.changed.emit()

    def _choose(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose keyfile")
        if path:
            self.set_path(path)

    def _generate(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save new keyfile", "locksmith.key")
        if path:
            write_secret_file(Path(path), os.urandom(4096))
            self.set_path(path)
            toast("Keyfile created. Keep a backup: without it the file cannot be opened.", "key")


# ── progress ─────────────────────────────────────────────────────────────────

class ProgressBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(6)
        self._value = 0.0
        self._indeterminate = False
        self._phase = 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setEasingCurve(EASE)
        self._anim.valueChanged.connect(lambda v: (setattr(self, "_value", float(v)), self.update()))
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)

    def _tick(self):
        self._phase = (self._phase + 0.012) % 1.0
        self.update()

    def set_value(self, v: float | None):
        if v is None:
            if not self._indeterminate:
                self._indeterminate = True
                self._timer.start()
            return
        if self._indeterminate:
            self._indeterminate = False
            self._timer.stop()
            self._value = 0.0
        self._anim.stop()
        self._anim.setDuration(theme.ms(220))
        self._anim.setStartValue(self._value)
        self._anim.setEndValue(float(v))
        self._anim.start()

    def reset(self):
        self._anim.stop()
        self._timer.stop()
        self._indeterminate = False
        self._value = 0.0
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(theme.c("border"))
        p.drawRoundedRect(QRectF(self.rect()), 3, 3)
        p.setBrush(theme.c("text"))
        if self._indeterminate:
            w = self.width() * 0.3
            x = -w + (self.width() + w) * QEasingCurve(QEasingCurve.Type.InOutSine).valueForProgress(self._phase)
            path = QPainterPath()
            path.addRoundedRect(QRectF(self.rect()), 3, 3)
            p.setClipPath(path)
            p.drawRoundedRect(QRectF(x, 0, w, self.height()), 3, 3)
        elif self._value > 0:
            p.drawRoundedRect(QRectF(0, 0, max(6.0, self.width() * self._value), self.height()), 3, 3)


class ProgressPanel(QWidget):
    cancel = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 4, 0, 0)
        lay.setSpacing(10)
        top = QHBoxLayout()
        self.stage = Label("Preparing")
        self.stage.setFont(font(13, W.Medium))
        self.percent = Label("")
        self.percent.setProperty("role", "mono")
        top.addWidget(self.stage, 1)
        top.addWidget(self.percent)
        self.cancel_btn = LinkButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel)
        top.addSpacing(12)
        top.addWidget(self.cancel_btn)
        lay.addLayout(top)
        self.bar = ProgressBar()
        lay.addWidget(self.bar)
        self.setVisible(False)

    def start(self):
        self.bar.reset()
        self.stage.setText("Preparing")
        self.percent.setText("")
        self.setVisible(True)
        fade_in(self, 220, rise=4)

    def update_progress(self, fraction: float, stage: str):
        self.stage.setText(stage)
        if fraction < 0:
            self.bar.set_value(None)
            self.percent.setText("")
        else:
            self.bar.set_value(fraction)
            self.percent.setText(f"{fraction * 100:.0f}%")

    def finish(self):
        self.setVisible(False)
        self.bar.reset()


# ── toasts ───────────────────────────────────────────────────────────────────

_toaster = None


def toast(message: str, icon: str = "check", duration=3200):
    if _toaster is not None:
        _toaster.show_toast(message, icon, duration)


class _Toast(QWidget):
    def __init__(self, message, icon, parent):
        super().__init__(parent)
        self.message, self.icon = message, icon
        self.setFont(font(13, W.Medium))
        fm = QFontMetrics(self.font())
        self.setFixedSize(min(fm.horizontalAdvance(message) + 64, 560), 46)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(theme.c("accent"))
        p.drawRoundedRect(QRectF(self.rect()), 23, 23)
        fg = theme.c("on_accent")
        p.drawPixmap(QPointF(16, 14), pixmap(self.icon, 18, fg))
        p.setPen(fg)
        p.setFont(self.font())
        fm = QFontMetrics(self.font())
        p.drawText(QRectF(42, 0, self.width() - 56, self.height()), Qt.AlignmentFlag.AlignVCenter,
                   fm.elidedText(self.message, Qt.TextElideMode.ElideRight, self.width() - 56))


class Toaster(QWidget):
    """Stacks toasts at the bottom centre of its parent."""

    def __init__(self, parent):
        global _toaster
        super().__init__(parent)
        _toaster = self
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._toasts: list[_Toast] = []
        parent.installEventFilter(self)
        self._fit()

    def eventFilter(self, obj, e):
        if e.type() == QEvent.Type.Resize:
            self._fit()
        return False

    def _fit(self):
        self.setGeometry(self.parent().rect())
        self._layout(animate=False)

    def show_toast(self, message, icon, duration):
        t = _Toast(message, icon, self)
        eff = QGraphicsOpacityEffect(t)
        eff.setOpacity(0.0)
        t.setGraphicsEffect(eff)
        self._toasts.append(t)
        x = (self.width() - t.width()) // 2
        t.move(x, self.height() + 10)
        t.show()
        self.raise_()
        self._layout(animate=True)
        fade = QPropertyAnimation(eff, b"opacity", t)
        fade.setDuration(theme.ms(220))
        fade.setStartValue(0.0)
        fade.setEndValue(1.0)
        fade.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
        QTimer.singleShot(duration, lambda: self._dismiss(t))

    def _dismiss(self, t):
        if t not in self._toasts:
            return
        eff = t.graphicsEffect()
        g = QParallelAnimationGroup(t)
        g.addAnimation(_anim(eff, b"opacity", 200, eff.opacity(), 0.0))
        g.addAnimation(_anim(t, b"pos", 220, t.pos(), t.pos() + QPoint(0, 16)))

        def gone():
            if t in self._toasts:
                self._toasts.remove(t)
            t.deleteLater()
            self._layout(animate=True)

        g.finished.connect(gone)
        g.start()

    def _layout(self, animate):
        y = self.height() - 28
        for t in reversed(self._toasts):
            y -= t.height()
            target = QPoint((self.width() - t.width()) // 2, y)
            if animate:
                a = _anim(t, b"pos", 320, t.pos(), target, QEasingCurve.Type.OutBack)
                a.start(QPropertyAnimation.DeletionPolicy.DeleteWhenStopped)
            else:
                t.move(target)
            y -= 8


# ── navigation ───────────────────────────────────────────────────────────────

class NavItem(QAbstractButton, _Hover):
    def __init__(self, text, icon, parent=None):
        super().__init__(parent)
        self._init_hover()
        self.setText(text)
        self._icon = icon
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(42)
        self.setFont(font(13, W.Medium))
        self._sel = 0.0
        self._sel_anim = QVariantAnimation(self)
        self._sel_anim.setEasingCurve(EASE)
        self._sel_anim.valueChanged.connect(lambda v: (setattr(self, "_sel", float(v)), self.update()))
        self.toggled.connect(self._on_toggle)

    def _on_toggle(self, on):
        self._sel_anim.stop()
        self._sel_anim.setDuration(theme.ms(260))
        self._sel_anim.setStartValue(self._sel)
        self._sel_anim.setEndValue(1.0 if on else 0.0)
        self._sel_anim.start()

    def enterEvent(self, e):
        self._go_hover(1.0)

    def leaveEvent(self, e):
        self._go_hover(0.0)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        bg = QColor(theme.c("hover"))
        bg.setAlphaF(self._hv * (1 - self._sel) * 0.9)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(QRectF(self.rect()).adjusted(0, 1, 0, -1), 10, 10)
        fg = mix(mix(theme.c("muted"), theme.c("text"), self._hv), theme.c("on_accent"), self._sel)
        nudge = 2 * self._hv * (1 - self._sel)
        p.drawPixmap(QPointF(14 + nudge, (self.height() - 18) / 2), pixmap(self._icon, 18, fg))
        p.setPen(fg)
        p.setFont(self.font())
        p.drawText(QRectF(44 + nudge, 0, self.width() - 50, self.height()),
                   Qt.AlignmentFlag.AlignVCenter, self.text())


class Sidebar(QWidget):
    changed = Signal(int)

    def __init__(self, items: list[tuple[str, str]], parent=None):
        super().__init__(parent)
        self.setFixedWidth(220)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 22, 14, 18)
        lay.setSpacing(2)
        brand = QHBoxLayout()
        brand.setContentsMargins(8, 0, 0, 0)
        brand.setSpacing(10)
        self.logo = _Logo()
        brand.addWidget(self.logo)
        name = Label("Locksmith")
        name.setFont(font(19, W.DemiBold))
        brand.addWidget(name)
        brand.addStretch(1)
        lay.addLayout(brand)
        lay.addSpacing(26)
        self.items: list[NavItem] = []
        self._pill_y = 0.0
        self._pill_anim = QVariantAnimation(self)
        self._pill_anim.setEasingCurve(QEasingCurve.Type.OutBack)
        self._pill_anim.valueChanged.connect(lambda v: (setattr(self, "_pill_y", float(v)), self.update()))
        for text, icon in items:
            if text == "-":
                lay.addStretch(1)
                continue
            item = NavItem(text, icon)
            index = len(self.items)
            item.clicked.connect(lambda _=False, i=index: self.select(i))
            self.items.append(item)
            lay.addWidget(item)
        self.footer = Label("")
        self.footer.setProperty("role", "faint")
        self.footer.setContentsMargins(10, 12, 0, 0)
        lay.addWidget(self.footer)
        self._current = -1

    def select(self, i: int, animate=True):
        if i == self._current:
            return
        for j, item in enumerate(self.items):
            item.setChecked(i == j)
        target = self.items[i].geometry().y()
        if animate and self._current >= 0 and target > 0:
            self._pill_anim.stop()
            self._pill_anim.setDuration(theme.ms(360))
            self._pill_anim.setStartValue(self._pill_y)
            self._pill_anim.setEndValue(float(target))
            self._pill_anim.start()
        else:
            self._pill_y = float(target)
        self._current = i
        self.update()
        self.changed.emit(i)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self._current >= 0:
            self._pill_y = float(self.items[self._current].geometry().y())

    def showEvent(self, e):
        super().showEvent(e)
        QTimer.singleShot(0, lambda: self.resizeEvent(None) if self._current >= 0 else None)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), theme.c("panel"))
        p.setPen(QPen(theme.c("border"), 1))
        p.drawLine(self.width() - 1, 0, self.width() - 1, self.height())
        if self._current >= 0:
            item = self.items[self._current]
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(theme.c("accent"))
            p.drawRoundedRect(QRectF(item.x(), self._pill_y + 1, item.width(), item.height() - 2), 10, 10)


class _Logo(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(28, 28)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(theme.c("accent"))
        p.drawRoundedRect(QRectF(0, 0, 28, 28), 7, 7)
        # Padlock with a keyhole, matching locksmith/assets/locksmith.svg.
        fg = theme.c("on_accent")
        pen = QPen(fg, 2.2)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        shackle = QPainterPath()
        shackle.moveTo(10.2, 13)
        shackle.lineTo(10.2, 10.3)
        shackle.arcTo(QRectF(10.2, 6.4, 7.6, 7.6), 180, -180)
        shackle.lineTo(17.8, 13)
        p.drawPath(shackle)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(fg)
        p.drawRoundedRect(QRectF(6.8, 12.2, 14.4, 10.6), 2.6, 2.6)
        p.setBrush(theme.c("accent"))
        p.drawEllipse(QPointF(14, 16.4), 1.6, 1.6)
        p.drawRect(QRectF(13.35, 16.4, 1.3, 3.4))


class AnimatedStack(QStackedWidget):
    """Cross-fades and slides pages when switching."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._group = None

    def switch_to(self, i: int):
        if i == self.currentIndex():
            return
        forward = i > self.currentIndex()
        self.setCurrentIndex(i)
        page = self.currentWidget()
        if not theme.animations:
            return
        eff = QGraphicsOpacityEffect(page)
        eff.setOpacity(0.0)
        page.setGraphicsEffect(eff)
        end = page.pos()
        start = end + QPoint(0, 14 if forward else -14)
        if self._group:
            self._group.stop()
        g = QParallelAnimationGroup(self)
        g.addAnimation(_anim(eff, b"opacity", 260, 0.0, 1.0))
        g.addAnimation(_anim(page, b"pos", 340, start, end))
        g.finished.connect(lambda: page.setGraphicsEffect(None))
        self._group = g
        g.start()


# ── page scaffold ────────────────────────────────────────────────────────────

class Page(QWidget):
    """A scrollable page with a centred column, title and subtitle."""

    def __init__(self, title: str, subtitle: str, parent=None):
        super().__init__(parent)
        from PySide6.QtWidgets import QScrollArea
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        outer.addWidget(self.scroll)
        holder = QWidget()
        hl = QHBoxLayout(holder)
        hl.setContentsMargins(40, 40, 40, 60)
        column = QWidget()
        column.setMaximumWidth(780)
        hl.addWidget(column)
        self.scroll.setWidget(holder)
        self.lay = QVBoxLayout(column)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(16)
        t = Label(title)
        t.setProperty("role", "title")
        self.lay.addWidget(t)
        s = Label(subtitle)
        s.setProperty("role", "subtitle")
        s.setWordWrap(True)
        self.lay.addWidget(s)
        self.lay.addSpacing(10)

    def add(self, w, stretch=0):
        if isinstance(w, QWidget):
            self.lay.addWidget(w, stretch)
        else:
            self.lay.addLayout(w, stretch)
        return w

    def finish(self):
        self.lay.addStretch(1)


def hrow(*widgets, spacing=10, stretch_last=False) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        elif isinstance(w, QWidget):
            lay.addWidget(w, 1 if isinstance(w, (Dropdown, Field, QLineEdit)) else 0)
        else:
            lay.addLayout(w)
    return lay


def label(text, role=None, wrap=True) -> Label:
    lab = Label(text)
    if role:
        lab.setProperty("role", role)
    lab.setWordWrap(wrap)
    return lab
