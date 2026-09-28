"""Monochrome theme: palettes, stylesheet, fonts, icons and animation timing."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QByteArray, QEasingCurve, QObject, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QApplication

ASSETS = Path(__file__).resolve().parent.parent / "assets"

DARK = {
    "bg": "#000000",
    "panel": "#060606",
    "card": "#0c0c0c",
    "raised": "#141414",
    "hover": "#1b1b1b",
    "border": "#1f1f1f",
    "border2": "#343434",
    "text": "#fafafa",
    "muted": "#8a8a8a",
    "faint": "#4d4d4d",
    "accent": "#ffffff",
    "on_accent": "#000000",
    "scrim": "#b3000000",
}

LIGHT = {
    "bg": "#ffffff",
    "panel": "#f7f7f7",
    "card": "#ffffff",
    "raised": "#f3f3f3",
    "hover": "#ebebeb",
    "border": "#e6e6e6",
    "border2": "#cfcfcf",
    "text": "#0a0a0a",
    "muted": "#6b6b6b",
    "faint": "#b0b0b0",
    "accent": "#000000",
    "on_accent": "#ffffff",
    "scrim": "#66000000",
}

UI_FONT = "Inter"
MONO_FONT = "JetBrains Mono"


class _Theme(QObject):
    changed = Signal()

    def __init__(self):
        super().__init__()
        self.mode = "dark"
        self.p = dict(DARK)
        self.animations = True

    def c(self, key: str) -> QColor:
        return QColor(self.p[key])

    def ms(self, duration: int) -> int:
        return duration if self.animations else 0

    @property
    def is_dark(self) -> bool:
        return self.p is not LIGHT and self.p["bg"] == DARK["bg"]

    def refresh_system(self):
        """Re-apply "system" mode only if the desktop's preference changed."""
        from .host import system_color_scheme
        scheme = system_color_scheme()
        if scheme is not None and (scheme == "dark") != self.is_dark:
            self.apply("system")

    def apply(self, mode: str):
        self.mode = mode
        if mode == "system":
            from .host import system_color_scheme
            scheme = system_color_scheme()
            if scheme is None:  # no portal answer: fall back to what Qt knows
                scheme = "light" if QApplication.styleHints().colorScheme() == Qt.ColorScheme.Light else "dark"
            dark = scheme != "light"
        else:
            dark = mode == "dark"
        self.p = dict(DARK if dark else LIGHT)
        _icon_cache.clear()
        app = QApplication.instance()
        app.setPalette(palette(self.p))
        app.setStyleSheet(stylesheet(self.p))
        self.changed.emit()
        for w in app.allWidgets():
            w.update()


theme = _Theme()

EASE = QEasingCurve.Type.OutCubic
EASE_IN_OUT = QEasingCurve.Type.InOutCubic


def load_fonts():
    fonts = ASSETS / "fonts"
    for f in sorted(fonts.glob("*.ttf")):
        QFontDatabase.addApplicationFont(str(f))
    font = QFont(UI_FONT)
    font.setPixelSize(13)
    font.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    QApplication.setFont(font)


def font(size: int = 13, weight: QFont.Weight = QFont.Weight.Normal, mono=False) -> QFont:
    f = QFont(MONO_FONT if mono else UI_FONT)
    if mono:
        f.setStyleHint(QFont.StyleHint.Monospace)
    f.setPixelSize(size)
    f.setWeight(weight)
    return f


def palette(p: dict) -> QPalette:
    """Palette for Qt's stock widgets (file dialogs, item views, menus) so they
    match the custom-painted ones."""
    pal = QPalette()
    R = QPalette.ColorRole
    roles = {
        R.Window: "bg", R.WindowText: "text", R.Base: "card", R.AlternateBase: "raised",
        R.Text: "text", R.Button: "raised", R.ButtonText: "text", R.BrightText: "text",
        R.Highlight: "text", R.HighlightedText: "bg", R.ToolTipBase: "raised", R.ToolTipText: "text",
        R.PlaceholderText: "faint", R.Link: "text", R.LinkVisited: "muted",
        R.Light: "border2", R.Midlight: "border", R.Mid: "border2", R.Dark: "faint", R.Shadow: "bg",
    }
    for role, key in roles.items():
        pal.setColor(role, QColor(p[key]))
    for role in (R.WindowText, R.Text, R.ButtonText):
        pal.setColor(QPalette.ColorGroup.Disabled, role, QColor(p["faint"]))
    return pal


def stylesheet(p: dict) -> str:
    return f"""
    * {{ outline: none; }}
    QWidget {{ color: {p['text']}; }}
    QMainWindow, #root {{ background: {p['bg']}; }}
    #content {{ background: {p['bg']}; }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
    QLabel {{ background: transparent; }}
    QLabel[role="title"] {{ font-size: 28px; font-weight: 600; letter-spacing: -0.5px; }}
    QLabel[role="subtitle"] {{ color: {p['muted']}; font-size: 14px; }}
    QLabel[role="h2"] {{ font-size: 15px; font-weight: 600; }}
    QLabel[role="caption"] {{ color: {p['muted']}; font-size: 12px; }}
    QLabel[role="label"] {{ color: {p['muted']}; font-size: 11px; font-weight: 600;
                            letter-spacing: 0.6px; }}
    QLabel[role="mono"] {{ font-family: "{MONO_FONT}"; font-size: 12px; }}
    QLabel[role="faint"] {{ color: {p['faint']}; font-size: 12px; }}
    QLabel a {{ color: {p['text']}; }}

    QFrame#card {{ background: {p['card']}; border: 1px solid {p['border']}; border-radius: 16px; }}
    QFrame#divider {{ background: {p['border']}; border: none; max-height: 1px; min-height: 1px; }}

    QLineEdit, QPlainTextEdit, QTextEdit {{
        background: {p['raised']}; border: 1px solid {p['border']}; border-radius: 10px;
        padding: 0 12px; min-height: 38px; selection-background-color: {p['text']};
        selection-color: {p['bg']};
    }}
    QPlainTextEdit, QTextEdit {{ padding: 10px 12px; }}
    QLineEdit:hover, QPlainTextEdit:hover {{ border-color: {p['border2']}; }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus {{ border-color: {p['text']}; }}
    QLineEdit[mono="true"], QPlainTextEdit[mono="true"] {{ font-family: "{MONO_FONT}"; font-size: 12px; }}
    QLineEdit:read-only {{ color: {p['text']}; }}
    QLineEdit::placeholder {{ color: {p['faint']}; }}

    QComboBox QAbstractItemView {{
        background: {p['raised']}; border: 1px solid {p['border2']}; border-radius: 10px;
        padding: 4px; selection-background-color: {p['hover']}; selection-color: {p['text']};
        outline: none;
    }}
    QComboBox QAbstractItemView::item {{ min-height: 32px; padding: 0 10px; border-radius: 6px; }}
    QComboBox QAbstractItemView::item:hover {{ background: {p['hover']}; }}
    QComboBox QAbstractItemView::item:selected {{ background: {p['hover']}; }}
    QComboBoxPrivateContainer {{ background: {p['raised']}; border: none; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 4px 2px; }}
    QScrollBar::handle:vertical {{ background: {p['border2']}; border-radius: 3px; min-height: 40px; }}
    QScrollBar::handle:vertical:hover {{ background: {p['muted']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px 4px; }}
    QScrollBar::handle:horizontal {{ background: {p['border2']}; border-radius: 3px; min-width: 40px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

    QSlider::groove:horizontal {{ height: 4px; background: {p['border2']}; border-radius: 2px; }}
    QSlider::sub-page:horizontal {{ background: {p['text']}; border-radius: 2px; }}
    QSlider::handle:horizontal {{ background: {p['text']}; width: 16px; height: 16px;
                                  margin: -6px 0; border-radius: 8px; }}

    QToolTip {{ background: {p['raised']}; color: {p['text']}; border: 1px solid {p['border2']};
                border-radius: 6px; padding: 6px 8px; font-size: 12px; }}
    QMenu {{ background: {p['raised']}; border: 1px solid {p['border2']}; border-radius: 10px;
             padding: 4px; }}
    QMenu::item {{ padding: 8px 14px; border-radius: 6px; }}
    QMenu::item:selected {{ background: {p['hover']}; }}
    QDialog, QMessageBox, QFileDialog {{ background: {p['bg']}; }}

    /* Stock widgets, mainly inside Qt's file dialog */
    QTreeView, QListView {{ background: {p['card']}; border: 1px solid {p['border']}; border-radius: 10px;
                            padding: 4px; selection-background-color: {p['text']};
                            selection-color: {p['bg']}; }}
    QTreeView::item, QListView::item {{ padding: 4px 2px; }}
    QTreeView::item:hover, QListView::item:hover {{ background: {p['hover']}; }}
    QHeaderView::section {{ background: {p['card']}; color: {p['muted']}; border: none;
                            border-bottom: 1px solid {p['border']}; padding: 6px 8px; }}
    QPushButton {{ background: {p['raised']}; border: 1px solid {p['border']}; border-radius: 9px;
                   padding: 7px 18px; }}
    QPushButton:hover {{ background: {p['hover']}; border-color: {p['border2']}; }}
    QPushButton:default {{ background: {p['accent']}; color: {p['on_accent']}; border-color: {p['accent']}; }}
    QPushButton:disabled {{ color: {p['faint']}; }}
    QToolButton {{ background: transparent; border: 1px solid transparent; border-radius: 8px; padding: 4px; }}
    QToolButton:hover, QToolButton:checked {{ background: {p['hover']}; border-color: {p['border']}; }}
    QFileDialog QComboBox, QDialog QComboBox {{ background: {p['raised']}; border: 1px solid {p['border']};
                   border-radius: 9px; padding: 6px 10px; min-height: 22px; }}
    """


# ── icons ────────────────────────────────────────────────────────────────────

_PATHS = {
    "lock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    "unlock": '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
    "share": '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/>'
             '<path d="M8.59 13.51l6.83 3.98M15.41 6.51l-6.82 3.98"/>',
    "key": '<circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
    "tool": '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 '
            '7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
    "settings": '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/>',
    "upload": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5M12 3v12"/>',
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    "folder": '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    "x": '<path d="M18 6L6 18M6 6l12 12"/>',
    "eye": '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
    "eye-off": '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 '
               '5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 '
               '3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><path d="M1 1l22 22"/>',
    "refresh": '<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 '
               '14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    "copy": '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 '
            '0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    "chevron": '<path d="M6 9l6 6 6-6"/>',
    "check": '<path d="M20 6L9 17l-5-5"/>',
    "alert": '<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>',
    "mail": '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 6l-10 7L2 6"/>',
    "qr": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>'
          '<rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM21 14v.01M14 21h.01M17 21h4v-4"/>',
    "scissors": '<circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M20 4L8.12 '
                '15.88M14.47 14.48L20 20M8.12 8.12L12 12"/>',
    "message": '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "trash": '<path d="M3 6h18M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6M9 '
             '6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "hash": '<path d="M4 9h16M4 15h16M10 3L8 21M16 3l-2 18"/>',
    "user": '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>',
    "paste": '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>'
             '<rect x="8" y="2" width="8" height="4" rx="1"/>',
    "link": '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 '
            '11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    "zap": '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>',
    "layers": '<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>',
    "fingerprint": '<path d="M12 11c0 3.5-1 6.5-3 9M8 6.5A6 6 0 0 1 18 11c0 2-.2 4-.7 6M5.5 9a7 7 0 0 '
                   '0-.5 2.5c0 2-.5 4-1.5 5.5M12 7a4 4 0 0 0-4 4c0 2.5-.5 5-1.5 7M16 11.5c0 3-.5 '
                   '6-1.5 8.5"/>',
    "chip": '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/>'
            '<path d="M9 2v3M15 2v3M9 19v3M15 19v3M19 9h3M19 15h3M2 9h3M2 15h3"/>',
    "arrow-right": '<path d="M5 12h14M12 5l7 7-7 7"/>',
}


_icon_cache: dict = {}


def pixmap(name: str, size: int = 18, color: QColor | str | None = None, stroke: float = 1.75) -> QPixmap:
    color = QColor(color) if color is not None else theme.c("text")
    app = QApplication.instance()
    dpr = app.devicePixelRatio() if app else 1.0
    key = (name, size, color.name(QColor.NameFormat.HexArgb), stroke, dpr)
    if key in _icon_cache:
        return _icon_cache[key]
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
           f'stroke="{color.name()}" stroke-opacity="{color.alphaF():.3f}" stroke-width="{stroke}" '
           f'stroke-linecap="round" stroke-linejoin="round">{_PATHS[name]}</svg>')
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pm)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(painter, QRectF(0, 0, size * dpr, size * dpr))
    painter.end()
    pm.setDevicePixelRatio(dpr)
    _icon_cache[key] = pm
    return pm


def icon(name: str, size: int = 18, color=None) -> QIcon:
    return QIcon(pixmap(name, size, color))


def app_icon() -> QIcon:
    return QIcon(str(ASSETS / "locksmith.svg"))


def mix(a: QColor, b: QColor, t: float) -> QColor:
    t = max(0.0, min(1.0, t))
    return QColor.fromRgbF(
        a.redF() + (b.redF() - a.redF()) * t,
        a.greenF() + (b.greenF() - a.greenF()) * t,
        a.blueF() + (b.blueF() - a.blueF()) * t,
        a.alphaF() + (b.alphaF() - a.alphaF()) * t,
    )
