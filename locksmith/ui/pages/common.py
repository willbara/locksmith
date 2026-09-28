from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFileDialog, QVBoxLayout, QWidget

from ...core.keys import fingerprint
from .. import host
from ..widgets import Dropdown, LinkButton, ToggleRow, label


def reveal(path: str | Path):
    host.reveal(Path(path))


def open_url(url_or_path: str | Path):
    """Open a local file or folder (given as a path or a file:// URI)."""
    target = str(url_or_path)
    if target.startswith("file://"):
        from PySide6.QtCore import QUrl
        target = QUrl(target).toLocalFile()
    host.open_path(Path(target))


class OutputPicker(Dropdown):
    NEXT_TO = "__next__"
    CHOOSE = "__choose__"

    def __init__(self, next_label="Save next to the original"):
        super().__init__()
        self._dir: str | None = None
        self._next_label = next_label
        self._rebuild()
        self.activated.connect(self._activated)

    def _rebuild(self):
        items = {self.NEXT_TO: self._next_label}
        if self._dir:
            items[self._dir] = self._dir
        items[self.CHOOSE] = "Choose folder…"
        self.set_items(items, keep=False)
        self.set_value(self._dir or self.NEXT_TO)

    def _activated(self, _):
        v = self.value()
        if v == self.CHOOSE:
            d = QFileDialog.getExistingDirectory(self, "Choose output folder", self._dir or "")
            if d:
                self._dir = d
            self._rebuild()

    def directory(self) -> Path | None:
        v = self.value()
        return Path(v) if v not in (self.NEXT_TO, self.CHOOSE) else None


class RecipientPicker(QWidget):
    changed = Signal()
    manage = Signal()

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(0, 0, 0, 0)
        self.lay.setSpacing(2)
        self.rows: list[tuple[ToggleRow, bytes]] = []
        self.reload()

    def reload(self):
        chosen = set(self.selected())
        while self.lay.count():
            item = self.lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.rows = []
        entries = [(f"{i.name}  (you)", i.public_raw) for i in self.store.identities] + \
                  [(c.name, c.public_raw) for c in self.store.contacts]
        if not entries:
            self.lay.addWidget(label("No keys yet. Create your own identity or add a contact’s "
                                     "public key on the Keys page.", "caption"))
        for name, raw in entries:
            kind = "post-quantum" if len(raw) > 32 else "classical"
            row = ToggleRow(name, f"{fingerprint(raw)}  ·  {kind}", raw in chosen)
            row.toggled.connect(self.changed)
            self.rows.append((row, raw))
            self.lay.addWidget(row)
        link = LinkButton("Manage keys and contacts")
        link.clicked.connect(self.manage)
        self.lay.addSpacing(6)
        self.lay.addWidget(link)
        self.changed.emit()

    def selected(self) -> list[bytes]:
        return [raw for row, raw in self.rows if row.isChecked()]
