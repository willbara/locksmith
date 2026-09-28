from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QMimeData, Qt, QUrl
from PySide6.QtWidgets import QApplication, QFileDialog, QGridLayout, QPlainTextEdit, QVBoxLayout

from ...core import engine, tools
from ...core.engine import DecryptKeys, EncryptOptions
from ...core.errors import LocksmithError
from ...core.keys import fingerprint
from .. import dialogs, host
from ..lock import mark_sensitive
from ..settings import settings
from ..widgets import (
    Button,
    Card,
    Dropdown,
    Field,
    LinkButton,
    Page,
    PasswordField,
    Segmented,
    divider,
    fade_in,
    hrow,
    human_size,
    label,
    toast,
)
from ..workers import run_task
from .common import reveal

PART_SIZES = {
    8 * 1000 * 1000: "8 MB (chat apps)",
    20 * 1000 * 1000: "20 MB (email)",
    100 * 1000 * 1000: "100 MB",
    500 * 1000 * 1000: "500 MB",
    2000 * 1000 * 1000: "2 GB",
}
ARMOR_LIMIT = 16 << 20


class SharePage(Page):
    def __init__(self, store):
        super().__init__("Share", "Send encrypted files, messages and secrets without exposing them.")
        self.store = store
        self.file: Path | None = None
        self._build_file_card()
        self._build_message_card()
        self._build_secret_card()
        self._build_pubkey_card()
        self.finish()

    # ── encrypted file ──

    def _build_file_card(self):
        card = Card("Send an encrypted file",
                    "Encrypted files are safe to send over any channel. Share the password separately.")
        self.file_name = label("No file selected", "mono", wrap=False)
        self.file_meta = label("", "caption", wrap=False)
        choose = Button("Choose…", "file")
        choose.clicked.connect(self._choose_file)
        info = QVBoxLayout()
        info.setSpacing(2)
        info.addWidget(self.file_name)
        info.addWidget(self.file_meta)
        card.add(hrow(info, None, choose))
        grid = QGridLayout()
        grid.setSpacing(8)
        self.file_actions = [
            Button("Show in folder", "folder"),
            Button("Copy file", "copy"),
            Button("Email", "mail"),
            Button("Copy as text", "message"),
        ]
        for b, fn in zip(self.file_actions, (self._reveal, self._copy_file, self._email, self._copy_armor), strict=True):
            b.clicked.connect(fn)
        for i, b in enumerate(self.file_actions):
            grid.addWidget(b, i // 2, i % 2)
        card.add(grid)
        card.add(divider())
        self.part_size = Dropdown(PART_SIZES)
        self.split_btn = Button("Split", "scissors")
        self.split_btn.clicked.connect(self._split)
        join = Button("Join parts…", "link", "ghost")
        join.clicked.connect(self._join)
        card.add(Field("Split for size-limited uploads", hrow(self.part_size, self.split_btn, join)))
        self.add(card)
        self._update_file()

    def set_file(self, path: str):
        self.file = Path(path)
        self._update_file()

    def _update_file(self):
        ok = self.file is not None and self.file.exists()
        if ok:
            self.file_name.setText(self.file.name)
            self.file_meta.setText(f"{human_size(self.file.stat().st_size)}  ·  {self.file.parent}")
        else:
            self.file_name.setText("No file selected")
            self.file_meta.setText("Encrypt something first, or choose a .locksmith file.")
        for b in (*self.file_actions, self.split_btn):
            b.setEnabled(ok)

    def _choose_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose encrypted file", "",
                                              "Locksmith files (*.locked *.txt);;All files (*)")
        if path:
            self.set_file(path)

    def _reveal(self):
        reveal(self.file)

    def _copy_file(self):
        uri = QUrl.fromLocalFile(str(self.file.resolve()))
        mime = QMimeData()
        mime.setUrls([uri])
        mime.setData("x-special/gnome-copied-files", f"copy\n{uri.toString()}".encode())
        QApplication.clipboard().setMimeData(mime)
        toast("File copied. Paste it into any app or folder.", "copy")

    def _email(self):
        try:
            attached = host.compose_email(
                f"Encrypted file: {self.file.name}",
                "This file is encrypted with Locksmith. I'll send you the password separately.", self.file)
        except OSError:
            dialogs.error("No email program could be opened.")
            return
        if not attached:
            toast("Email started. Drag the highlighted file into it to attach it.", "mail", 5000)

    def _copy_armor(self):
        size = self.file.stat().st_size
        if size > ARMOR_LIMIT:
            dialogs.error(f"Files over {human_size(ARMOR_LIMIT)} are too large to paste as text. "
                          "Send the file itself, or split it into parts.")
            return
        data = self.file.read_bytes()
        text = data.decode() if data.lstrip().startswith(engine.ARMOR_BEGIN.encode()) else engine.armor(data)
        QApplication.clipboard().setText(text)
        toast(f"Copied {human_size(len(text))} of text. The recipient pastes it into Decrypt.", "message")

    def _split(self):
        size = self.part_size.value()
        if self.file.stat().st_size <= size:
            toast("The file already fits in one part", "check")
            return
        f = self.file
        run_task(lambda r, c: tools.split_file(f, size),
                 lambda parts: (toast(f"Split into {len(parts)} parts", "scissors"), reveal(parts[0])),
                 lambda m, k: dialogs.error(m), parent=self)

    def _join(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose all parts", "", "Parts (*.part*)")
        if not paths:
            return
        run_task(lambda r, c: tools.join_parts([Path(p) for p in paths]),
                 lambda out: (toast(f"Joined into {out.name}", "link"), self.set_file(str(out))),
                 lambda m, k: dialogs.error(m), parent=self)

    # ── message ──

    def _build_message_card(self):
        card = Card("Secure message",
                    "Encrypt a short message into text you can paste anywhere: chat, email, notes.")
        self.msg = mark_sensitive(QPlainTextEdit())
        self.msg.setPlaceholderText("Write a message…")
        self.msg.setFixedHeight(110)
        card.add(self.msg)
        self.msg_mode = Segmented(["Password", "Public key"])
        card.add(self.msg_mode)
        self.msg_pw = PasswordField("Password for this message", strength=True)
        card.add(self.msg_pw)
        self.msg_rcpt = Dropdown()
        self.msg_rcpt_field = Field("Recipient", self.msg_rcpt)
        self.msg_rcpt_field.setVisible(False)
        card.add(self.msg_rcpt_field)
        self.msg_mode.changed.connect(self._msg_mode)
        enc = Button("Encrypt & copy", "lock", "primary")
        enc.clicked.connect(self._encrypt_message)
        dec = Button("Open a message…", "unlock", "secondary")
        dec.clicked.connect(self._open_message)
        card.add(hrow(enc, dec, None))
        self.msg_out = mark_sensitive(QPlainTextEdit())
        self.msg_out.setReadOnly(True)
        self.msg_out.setProperty("mono", "true")
        self.msg_out.setFixedHeight(130)
        self.msg_out.setVisible(False)
        card.add(self.msg_out)
        self.add(card)

    def _msg_mode(self, i):
        self.msg_pw.setVisible(i == 0)
        self.msg_rcpt_field.setVisible(i == 1)
        if i == 1:
            fade_in(self.msg_rcpt_field, 200)
        else:
            fade_in(self.msg_pw, 200)

    def _encrypt_message(self):
        text = self.msg.toPlainText()
        if not text.strip():
            toast("Write a message first", "alert")
            return
        opts = EncryptOptions(suite=settings["suite"], kdf=settings["kdf"], preset=settings["preset"],
                              compression="zlib")
        if self.msg_mode.index() == 0:
            if not self.msg_pw.text():
                toast("Enter a password", "alert")
                return
            opts.password = self.msg_pw.text()
        else:
            if self.msg_rcpt.value() is None:
                toast("Add a contact on the Keys page first", "alert")
                return
            opts.recipients = [self.msg_rcpt.value()]

        def done(blob):
            armored = engine.armor(blob)
            self.msg_out.setPlainText(armored)
            if not self.msg_out.isVisible():
                self.msg_out.setVisible(True)
                fade_in(self.msg_out, 260)
            QApplication.clipboard().setText(armored)
            toast("Encrypted message copied", "lock")

        run_task(lambda r, c: engine.encrypt_bytes(text.encode(), opts), done,
                 lambda m, k: dialogs.error(m), parent=self)

    def _open_message(self):
        text = dialogs.text_input("Open a message", "Paste the encrypted text you received.", ok="Open")
        if not text:
            return
        try:
            blob = engine.dearmor(text)
            info = engine.inspect_bytes(blob)
        except LocksmithError as e:
            dialogs.error(str(e))
            return
        identities = self.store.unlocked_private_keys()
        password = None
        if info.password_slots and (not info.recipient_slots or not identities):
            password = dialogs.prompt("Message password", "This message is protected by a password.",
                                      "Password", secret=True, ok="Decrypt")
            if password is None:
                return
        keys = DecryptKeys(password=password, identities=identities)

        def done(res):
            if res.meta.get("kind") == "text":
                dialogs.text_view("Decrypted message", res.data.decode("utf-8", errors="replace"), mono=False,
                                  secret=True)
            else:
                dialogs.info("This is a file", "Use the Decrypt page to save files and folders.")

        def failed(msg, kind):
            if kind == "WrongKeyError":
                toast(msg, "alert")
            else:
                dialogs.error(msg)

        run_task(lambda r, c: engine.decrypt_bytes(blob, keys), done, failed, parent=self)

    # ── secrets ──

    def _build_secret_card(self):
        card = Card("Share a password",
                    "Hand a password to a phone in person, or split it so no single person can use it alone.")
        self.secret = PasswordField("Password or secret", strength=False)
        card.add(self.secret)
        qr = Button("Show QR code", "qr")
        qr.clicked.connect(self._secret_qr)
        card.add(hrow(qr, None))
        card.add(divider())
        self.k = Dropdown({i: f"{i} people" for i in range(2, 11)})
        self.n = Dropdown({i: f"{i} shares" for i in range(2, 16)})
        self.k.set_value(2)
        self.n.set_value(3)
        split = Button("Split", "scissors")
        split.clicked.connect(self._split_secret)
        combine = Button("Combine shares…", "link", "ghost")
        combine.clicked.connect(self._combine)
        card.add(Field("Shamir secret sharing: any", hrow(self.k, label("of", "caption", False), self.n, split),
                       "Each share alone reveals nothing. Any chosen number of them recovers the secret."))
        card.add(hrow(combine, None))
        self.add(card)

    def _secret_qr(self):
        if not self.secret.text():
            toast("Enter a secret first", "alert")
            return
        dialogs.qr_view("Scan to copy", self.secret.text(),
                        "Only show this to people you trust. Anyone who sees it can read the secret.")

    def _split_secret(self):
        secret, k, n = self.secret.text(), self.k.value(), self.n.value()
        if not secret:
            toast("Enter a secret first", "alert")
            return
        if k > n:
            toast("Need at least as many shares as people required", "alert")
            return
        shares = tools.shamir_split(secret.encode(), k, n)
        dialogs.text_view(f"{n} shares — any {k} recover the secret", "\n\n".join(shares),
                          "Give each person one share. Keep them separate.", secret=True)

    def _combine(self):
        text = dialogs.text_input("Combine shares", "Paste the shares, one per line.", ok="Combine")
        if not text:
            return
        try:
            secret = tools.shamir_combine(text.split())
        except LocksmithError as e:
            dialogs.error(str(e))
            return
        dialogs.text_view("Recovered secret", secret.decode("utf-8", errors="replace"), secret=True)

    # ── public key ──

    def _build_pubkey_card(self):
        card = Card("Your public key",
                    "Share this so people can encrypt files that only you can open. It is safe to publish.")
        self.pub_ident = Dropdown()
        self.pub_ident.currentIndexChanged.connect(self._show_pub)
        card.add(self.pub_ident)
        self.pub_text = label("", "mono")
        self.pub_text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        card.add(self.pub_text)
        self.pub_fp = label("", "caption")
        card.add(self.pub_fp)
        self.pub_copy = Button("Copy", "copy")
        self.pub_copy.clicked.connect(lambda: (QApplication.clipboard().setText(self.pub_text.text()),
                                               toast("Public key copied", "copy")))
        self.pub_qr = Button("QR code", "qr")
        self.pub_qr.clicked.connect(lambda: dialogs.qr_view("Your public key", self.pub_text.text()))
        self.pub_link = LinkButton("Create an identity on the Keys page")
        card.add(hrow(self.pub_copy, self.pub_qr, None))
        card.add(self.pub_link)
        self.pubkey_card = card
        self.add(card)

    def reload(self):
        self.pub_ident.set_items({i: ident.name for i, ident in enumerate(self.store.identities)})
        has = bool(self.store.identities)
        for w in (self.pub_ident, self.pub_text, self.pub_fp, self.pub_copy, self.pub_qr):
            w.setVisible(has)
        self.pub_link.setVisible(not has)
        self._show_pub()
        rc = {i.public_raw: f"{i.name} (you)" for i in self.store.identities}
        rc.update({c.public_raw: c.name for c in self.store.contacts})
        self.msg_rcpt.set_items(rc)
        self._update_file()

    def _show_pub(self):
        i = self.pub_ident.value()
        if i is None or i >= len(self.store.identities):
            return
        ident = self.store.identities[i]
        self.pub_text.setText(ident.public)
        self.pub_fp.setText(f"Fingerprint  {fingerprint(ident.public_raw)}")
