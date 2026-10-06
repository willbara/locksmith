from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFileDialog, QVBoxLayout, QWidget

from ...core import kdf, keys
from ...core.keys import fingerprint
from .. import dialogs, host
from ..widgets import Dropdown, LinkButton, ToggleRow, label


def show_key_qr(title: str, raw: bytes):
    """A public key as a QR code. A locksmith3 key is too large, so its code holds only its hash."""
    caption = ("This code holds the key's fingerprint, not the key: the key is too large for a QR code. Send "
               "the key as text, and whoever receives it checks it against this code."
               if keys.can_verify(raw) else "")
    dialogs.qr_view(title, keys.qr_text(raw), caption)


# ── signing ──────────────────────────────────────────────────────────────────

NO_SIGNER = "none"


def signer_choices(store) -> dict:
    """"Sign as" choices: not signing, or one of the identities that can sign."""
    return {NO_SIGNER: "Don't sign", **{i: ident.name for i, ident in enumerate(store.identities) if ident.can_sign}}


def unlock_signer(store, choice):
    """The identity chosen to sign and its passphrase, asked for here on the UI thread:
    (None, None) when not signing, or None when the user cancelled."""
    if not isinstance(choice, int) or choice >= len(store.identities):
        return None, None
    ident = store.identities[choice]
    passphrase = None
    if ident.is_locked:
        passphrase = dialogs.prompt("Identity passphrase", f"Unlock “{ident.name}” to sign.", "Passphrase",
                                    secret=True, ok="Sign")
        if not passphrase:
            return None
    return ident, passphrase


def saved_signers(store) -> dict[bytes, str]:
    """Every saved key that can verify a signature, with the name to show for it."""
    names = {c.key_raw: c.name for c in store.contacts}
    names.update({i.key_raw: f"{i.name} (you)" for i in store.identities})
    return {k: v for k, v in names.items() if keys.can_verify(k)}


def signature_text(sig, names: dict[bytes, str], intent: str | None = None) -> str:
    """How a decrypted file's signature is described. Never "from X": a signature shows
    which key signed the content, not who sent the file. ``intent`` is what the signed
    recipient list says about this reader (DecryptResult.intent); it is always neutral, and
    without a list nothing is said about whom the file was meant for."""
    if sig is None:
        return "Not signed"
    if sig.verified:
        text = f"✓  Signed with the key you saved as {names.get(sig.key, 'a saved key')}"
        if intent == "not_listed":
            text += ", but you weren't on its original recipient list"
        elif intent == "password":
            text += ". Addressed to specific people; opened with its password"
        return text
    return f"Signed by a key you haven't saved (fingerprint {sig.fingerprint}), so it can't be checked"


def own_encryption_keys(store) -> list[bytes]:
    """The encryption keys of all the user's identities, locked ones too: checked against a
    signed file's recipient list."""
    return [i.public_raw for i in store.identities]


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

    def __init__(self, store, manage_link: bool = True):
        super().__init__()
        self.store = store
        self.manage_link = manage_link
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
        # Files are encrypted to public_raw; the fingerprint shown is the full key's.
        entries = [(f"{i.name}  (you)", i.public_raw, fingerprint(i.key_raw),
                    "post-quantum" if i.is_post_quantum else "classical") for i in self.store.identities] + \
                  [(c.name, c.public_raw, c.fingerprint, c.kind if c.ssh else
                    "post-quantum" if len(c.public_raw) > 32 else "classical") for c in self.store.contacts]
        if not entries:
            self.lay.addWidget(label("No keys yet. Create your own identity or add a contact’s "
                                     "public key on the Keys page.", "caption"))
        for name, raw, fp, kind in entries:
            row = ToggleRow(name, f"{fp}  ·  {kind}", raw in chosen)
            row.toggled.connect(self.changed)
            self.rows.append((row, raw))
            self.lay.addWidget(row)
        if self.manage_link:
            link = LinkButton("Manage keys and contacts")
            link.clicked.connect(self.manage)
            self.lay.addSpacing(6)
            self.lay.addWidget(link)
        self.changed.emit()

    def selected(self) -> list[bytes]:
        return [raw for row, raw in self.rows if row.isChecked()]


def confirm_kdf_cost(infos) -> bool:
    """Ask before trying a password on files whose key derivation costs more than any preset
    Locksmith writes (``engine.FileInfo``s). True: go ahead."""
    costly = [s for info in infos for s in info.password_slots if kdf.beyond_presets(s["kdf"], s["params"])]
    if not costly:
        return True
    return dialogs.confirm(
        "Unusually slow password check",
        "Checking the password takes more memory and time than any Locksmith setting: "
        + kdf.describe(costly[0]["kdf"], costly[0]["params"])
        + ". Each try can use GiBs of memory and run for minutes, and can't be cancelled while it runs. "
        "Only continue if you expect this file to be that strongly protected.", ok="Check the password")
