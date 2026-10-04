from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QApplication, QFileDialog, QPlainTextEdit, QVBoxLayout

from ...core import age, keys, qrdecode
from ...core.errors import LocksmithError
from ...core.keys import fingerprint, tpm_available, write_secret_file
from ...core.osutil import IS_WINDOWS
from ...core.tools import open_regular, same_secret
from .. import dialogs
from ..dialogs import Sheet
from ..widgets import (
    Button,
    Card,
    Dropdown,
    Field,
    IconButton,
    LineEdit,
    Page,
    PasswordField,
    fade_in,
    hrow,
    label,
    toast,
)
from ..workers import run_task
from .common import show_key_qr

MAX_IMAGE = 50 << 20


class _KeyRow(Card):
    def __init__(self, title, subtitle, detail):
        super().__init__(spacing=4)
        self.lay.setContentsMargins(18, 14, 12, 14)
        text = QVBoxLayout()
        text.setSpacing(3)
        t = label(title, "h2", wrap=False)
        text.addWidget(t)
        text.addWidget(label(subtitle, "mono", wrap=False))
        text.addWidget(label(detail, "caption", wrap=False))
        self.row = hrow(text, None, spacing=2)
        self.add(self.row)

    def action(self, icon, tip, fn=None):
        b = IconButton(icon, tip)
        if fn is None:
            b.setEnabled(False)   # shown greyed out, with the tooltip explaining why
        else:
            b.clicked.connect(fn)
        self.row.addWidget(b)


class KeysPage(Page):
    changed = Signal()

    def __init__(self, store):
        super().__init__("Keys", "Public-key encryption: share files with people without sharing a password.")
        self.store = store
        self.tpm = not IS_WINDOWS and tpm_available()

        how = Card()
        how.lay.setSpacing(6)
        how.add(label("How it works", "h2"))
        how.add(label(
            "1.  Create an identity. It is a key pair made on this device (X25519 + ML-KEM-768,\n"
            "     so files sent to you also resist future quantum computers).\n"
            "2.  Send your public key to friends. It only lets people encrypt files for you.\n"
            "3.  Add their public keys as contacts, then pick them under Encrypt → Public keys.\n"
            "Only the matching private key can open the file. It stays on this device unless you back it up.\n"
            "Post-quantum identities also sign files (Tools), and their public key verifies the signatures.",
            "caption"))
        self.add(how)

        head = hrow(label("Your identities", "h2", False), None)
        imp = Button("Import", "download", "ghost")
        imp.clicked.connect(self._import)
        rest = Button("Restore", "refresh", "ghost")
        rest.clicked.connect(self._restore)
        new = Button("New identity", "plus", "primary")
        new.clicked.connect(self._new_identity)
        head.addWidget(imp)
        head.addWidget(rest)
        head.addWidget(new)
        self.add(head)
        self.ident_box = QVBoxLayout()
        self.ident_box.setSpacing(8)
        self.add(self.ident_box)

        self.lay.addSpacing(10)
        head = hrow(label("Contacts", "h2", False), None)
        add = Button("Add contact", "plus", "secondary")
        add.clicked.connect(self._add_contact)
        head.addWidget(add)
        self.add(head)
        self.contact_box = QVBoxLayout()
        self.contact_box.setSpacing(8)
        self.add(self.contact_box)
        self.finish()
        self.reload()

    def reload(self, animate_last=False):
        for box in (self.ident_box, self.contact_box):
            while box.count():
                w = box.takeAt(0).widget()
                if w:
                    w.deleteLater()
        if not self.store.identities:
            self.ident_box.addWidget(label("No identities yet. Create one to receive encrypted files.",
                                           "caption"))
        for ident in self.store.identities:
            created = time.strftime("%d %b %Y", time.localtime(ident.created))
            lock = "Passphrase protected" if ident.is_locked else "Not passphrase protected"
            needs_unlock = ident.can_sign and ident.verify_raw is None
            kind = ("Post-quantum, unlock to add signing" if needs_unlock else
                    "Post-quantum, signs" if ident.can_sign else "Classical")
            sealed = "  ·  sealed to this device's TPM" if ident.is_sealed else ""
            row = _KeyRow(ident.name, fingerprint(ident.key_raw),
                          f"{kind}  ·  {lock}{sealed}  ·  created {created}")
            if IS_WINDOWS:
                row.action("chip", "TPM sealing: not available currently")
            elif self.tpm or ident.is_sealed:
                row.action("chip", "Remove TPM sealing" if ident.is_sealed else "Seal to this device's TPM",
                           lambda _=0, i=ident: self._toggle_seal(i))
            if not ident.is_post_quantum:
                row.action("shield", "Add post-quantum protection and signing (ML-KEM-768, ML-DSA-65)",
                           lambda _=0, i=ident: self._upgrade(i))
            if needs_unlock:
                row.action("fingerprint", "Unlock once to add its signing keys to the public key",
                           lambda _=0, i=ident: self._remember_verify(i))
            row.action("copy", "Copy public key", lambda _=0, i=ident: self._copy(i.key_text))
            row.action("share", "Copy as an age recipient (for age and rage)",
                       lambda _=0, i=ident: self._copy_age(i))
            row.action("qr", "Show public key as QR", lambda _=0, i=ident: show_key_qr(i.name, i.key_raw))
            row.action("download", "Export backup", lambda _=0, i=ident: self._export(i))
            row.action("message", "Show backup words", lambda _=0, i=ident: self._backup_words(i))
            row.action("file", "Save a printable paper backup (QR code and words)",
                       lambda _=0, i=ident: self._paper_backup(i))
            row.action("scissors", "Split into Shamir shares", lambda _=0, i=ident: self._split_identity(i))
            row.action("trash", "Delete", lambda _=0, i=ident: self._delete_identity(i))
            self.ident_box.addWidget(row)
        if not self.store.contacts:
            self.contact_box.addWidget(label("No contacts yet. Ask a friend for their public key: a “locksmith…” "
                                             "key, an age key (age1…) or an SSH key.", "caption"))
        for c in self.store.contacts:
            added = time.strftime("%d %b %Y", time.localtime(c.added))
            row = _KeyRow(c.name, c.fingerprint, f"{c.kind}  ·  added {added}")
            row.action("copy", "Copy public key", lambda _=0, c=c: self._copy(c.public))
            row.action("trash", "Remove", lambda _=0, c=c: self._delete_contact(c))
            self.contact_box.addWidget(row)
        if animate_last:
            for box in (self.ident_box, self.contact_box):
                for i in range(box.count()):
                    fade_in(box.itemAt(i).widget(), 260, delay=i * 40)
        self.changed.emit()

    def _copy(self, text):
        QApplication.clipboard().setText(text)
        toast("Public key copied", "copy")

    def _copy_age(self, ident):
        QApplication.clipboard().setText(age.recipient_text(ident.public_raw))
        toast("age recipient copied. Post-quantum ones (age1pq1…) need age 1.3 or later." if ident.is_post_quantum
              else "age recipient copied", "copy", 4000)

    def _new_identity(self):
        s = Sheet("New identity", "A key pair for receiving encrypted files.", icon="user")
        name = LineEdit("Name, e.g. “Work laptop”")
        s.add(name)
        s.add(label("PASSPHRASE (OPTIONAL)", "label"))
        pw = PasswordField("Protects the private key on this device", strength=True, generate=False)
        s.add(pw)
        again = PasswordField("Repeat passphrase", strength=False, generate=False)
        s.add(again)
        s.add_button("Cancel", None, "ghost")
        s.add_button("Create", True, "primary")
        if not s.exec():
            return
        if not same_secret(pw.text(), again.text()):
            dialogs.error("The passphrases don’t match. A typo here would lock you out of the key "
                          "for good, so nothing was created.", "Passphrases don’t match")
            return
        n, p = name.text(), pw.text() or None
        run_task(lambda r, c: self.store.generate(n, p),
                 lambda ident: (self.reload(True), toast(f"Created “{ident.name}”", "key")),
                 lambda m, k: dialogs.error(m), parent=self)

    def _add_contact(self):
        s = Sheet("Add contact", "Paste the public key someone shared with you: a Locksmith key, or an SSH "
                  "Ed25519 or RSA key (one line of their .pub file).", icon="user")
        name = LineEdit("Name")
        key = LineEdit("locksmith…  or  ssh-ed25519 AAAA…", mono=True)
        key.add_action("paste", "Paste", lambda: key.setText(QApplication.clipboard().text().strip()))
        s.add(name)
        s.add(key)
        s.add_button("Cancel", None, "ghost")
        s.add_button("Add", True, "primary")
        if not s.exec():
            return
        try:
            raw = keys.decode_recipient(key.text())
            same = self.store.contact_with_encryption_key(raw)
            if same is not None and not same.can_verify and keys.can_verify(raw):
                if not dialogs.confirm(
                        f"Update “{same.name}”?",
                        f"This is the key you saved as “{same.name}”, with its signing keys added, so you can "
                        f"verify their signatures. Its fingerprint changes to {fingerprint(raw)}. Check the new "
                        "fingerprint with them before trusting any signature.", ok="Update", icon="user"):
                    return
                c = self.store.update_contact_key(same, key.text())
                done = f"Updated {c.name}"
            else:
                c = self.store.add_contact(name.text(), key.text())
                done = f"Added {c.name}"
        except LocksmithError as e:
            dialogs.error(str(e))
            return
        self.reload(True)
        toast(done, "user")
        if c.ssh is not None:
            dialogs.info(f"Added {c.name}'s SSH key",
                         f"Files you encrypt to this key open with {c.name}'s SSH private key. Check its fingerprint "
                         f"with them: {c.fingerprint}. SSH keys are classical, so these files are not protected "
                         "against future quantum computers."
                         + (" Files with an SSH RSA recipient can't be opened by Locksmith 3.0 or earlier, even "
                            "with a password." if c.ssh.key_type == "ssh-rsa" else ""), icon="user")

    def _export(self, ident):
        path, _ = QFileDialog.getSaveFileName(self, "Export identity backup",
                                              f"{ident.name}.locksmith-identity.json")
        if not path:
            return
        if not ident.is_locked and not dialogs.confirm(
                "Unprotected backup", "This identity has no passphrase, so the backup file contains the "
                "raw private key. Keep it somewhere safe.", ok="Export"):
            return
        self.store.export_identity(ident, Path(path))
        toast("Backup saved", "download")

    def _import(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import identity backup", "",
                                              "Identity backups (*.json);;All files (*)")
        if not path:
            return
        try:
            ident = self.store.import_identity(Path(path))
        except LocksmithError as e:
            dialogs.error(str(e))
            return
        self.reload(True)
        toast(f"Imported “{ident.name}”", "download")

    # ── words and shares: the raw private key, for restoring on any device ──

    _RAW_WARNING = ("They are this identity's private key, without its passphrase or TPM sealing: anyone "
                    "who gets them can open every file sent to you. Keep them offline, and make sure "
                    "nobody can see your screen.")

    def _with_private_key(self, ident, then):
        """Unlock the identity (passphrase, TPM) off the UI thread and hand its raw key to ``then``."""
        passphrase = None
        if ident.is_locked:
            passphrase = dialogs.prompt("Identity passphrase", f"Unlock “{ident.name}” to back it up.",
                                        "Passphrase", secret=True, ok="Unlock")
            if not passphrase:
                return
        run_task(lambda r, c: ident.private_raw(passphrase), then, lambda m, k: dialogs.error(m), parent=self)

    def _backup_words(self, ident):
        if not dialogs.confirm("Show backup words?", "The words restore this identity on any device. "
                               + self._RAW_WARNING, ok="Show words", icon="key"):
            return

        def show(raw):
            words = keys.backup_words(raw)
            rows = "\n".join(" ".join(words[i:i + 6]) for i in range(0, len(words), 6))
            dialogs.text_view(f"Backup words for “{ident.name}”", rows,
                              f"{len(words)} words. Restore them under Keys → Restore.", secret=True)
        self._with_private_key(ident, show)

    def _paper_backup(self, ident):
        if not dialogs.confirm("Save a paper backup?", "Saves a one-page PDF with this identity's QR code and backup "
                               "words, to print and keep offline. " + self._RAW_WARNING + " Delete the PDF once it is "
                               "printed.", ok="Choose where", icon="key"):
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save paper backup", f"{ident.name} paper backup.pdf",
                                              "PDF documents (*.pdf)")
        if not path:
            return

        def save(raw):
            from .. import paper
            write_secret_file(Path(path), paper.render_pdf(ident.name, fingerprint(ident.key_raw), ident.created, raw))
            toast("Paper backup saved. Print it, then delete the PDF.", "download", 5000)
        self._with_private_key(ident, save)

    def _scan_qr(self, box):
        """Read a paper backup's QR code from a photo or scan into the restore box."""
        path, _ = QFileDialog.getOpenFileName(self, "Choose a photo or scan of the paper backup", "",
                                              "Images (*.png *.jpg *.jpeg *.bmp *.webp *.gif);;All files (*)")
        if not path:
            return
        from .. import paper
        try:
            with open_regular(Path(path)) as f:
                data = f.read(MAX_IMAGE + 1)
            if len(data) > MAX_IMAGE:
                raise LocksmithError("That image is too large.")
            w, h, gray = paper.gray_pixels(paper.load_image(data))
        except (LocksmithError, OSError, ValueError) as e:
            dialogs.error(str(e) if isinstance(e, LocksmithError) else "That image can't be read.")
            return

        def done(text):
            if not keys.is_paper_text(text):
                dialogs.error("That QR code isn't a Locksmith paper backup.", "Not a paper backup")
                return
            box.setPlainText(text)
            toast("Paper backup read. Check the name and choose Restore.", "check")
        run_task(lambda r, c: qrdecode.decode(w, h, gray), done, lambda m, k: dialogs.error(m, "No QR code found"),
                 parent=self)

    def _split_identity(self, ident):
        s = Sheet("Split into Shamir shares", "Give each share to a different person or place. Any chosen "
                  "number of them restores this identity; fewer reveal nothing.", icon="scissors")
        k = Dropdown({i: f"{i} shares" for i in range(2, 11)})
        n = Dropdown({i: f"{i} shares" for i in range(2, 16)})
        k.set_value(2)
        n.set_value(3)
        s.add(hrow(Field("Needed to restore", k), Field("Made in total", n)))
        s.add(label("Together, enough shares are the private key. " + self._RAW_WARNING, "caption"))
        s.add_button("Cancel", None, "ghost")
        s.add_button("Split", True, "primary")
        if not s.exec():
            return
        threshold, total = k.value(), n.value()
        if threshold > total:
            dialogs.error("You can't need more shares than you make.", "Not enough shares")
            return
        self._with_private_key(ident, lambda raw: dialogs.text_view(
            f"{total} shares of “{ident.name}”, any {threshold} restore it",
            "\n\n".join(keys.identity_shares(raw, threshold, total)),
            "Restore them under Keys → Restore.", secret=True))

    def _restore(self):
        s = Sheet("Restore an identity", "Type its backup words, scan its paper backup, paste enough of its Shamir "
                  "shares, or paste an age identity (AGE-SECRET-KEY-…).",
                  width=620, icon="refresh")
        name = LineEdit("Name, e.g. “Work laptop”")
        s.add(name)
        box = QPlainTextEdit()
        box.setPlaceholderText("Backup words, or one share per line")
        box.setProperty("mono", "true")
        box.setMinimumHeight(160)
        s.add(box)
        scan = Button("Scan QR code…", "qr", "ghost")
        scan.setToolTip("Read the QR code of a paper backup from a photo or scan")
        scan.clicked.connect(lambda: self._scan_qr(box))
        s.add(hrow(scan, None))
        s.add(label("PASSPHRASE (OPTIONAL)", "label"))
        pw = PasswordField("Protects the private key on this device", strength=True, generate=False)
        s.add(pw)
        again = PasswordField("Repeat passphrase", strength=False, generate=False)
        s.add(again)
        s.add_button("Cancel", None, "ghost")
        s.add_button("Restore", True, "primary")
        if not s.exec():
            return
        text, n, p = box.toPlainText(), name.text(), pw.text() or None
        if not same_secret(pw.text(), again.text()):
            dialogs.error("The passphrases don’t match, so nothing was restored.", "Passphrases don’t match")
            return

        def work(r, c):
            if keys.is_paper_text(text):
                raw = keys.private_from_paper(text)
            elif age.is_identity_text(text):
                raw = age.parse_identity(text)
            elif "locksmithshare" in text:
                raw = keys.private_from_shares(text.split())
            else:
                raw = keys.private_from_words(text)
            return self.store.restore(n, raw, p)

        run_task(work, lambda ident: (self.reload(True), toast(f"Restored “{ident.name}”", "key")),
                 lambda m, k: dialogs.error(m, "Could not restore"), parent=self)

    def _toggle_seal(self, ident):
        if ident.is_sealed:
            if not dialogs.confirm("Remove TPM sealing?",
                                   "The key will be stored without the TPM again (any passphrase is kept).",
                                   ok="Remove sealing", icon="chip"):
                return
            job, done = (lambda r, c: self.store.unseal(ident)), "TPM sealing removed"
        else:
            if not dialogs.confirm(
                    "Seal to this device's TPM?",
                    "The private key becomes unusable if keys.json is copied to another machine, for example "
                    "from a stolen disk or a leaked backup. It also becomes unusable here if the TPM is reset "
                    "or the system reinstalled, so export a backup first. The next step asks where to save it.",
                    ok="Export backup and seal", icon="chip"):
                return
            path, _ = QFileDialog.getSaveFileName(self, "Save identity backup (keep it offline)",
                                                  f"{ident.name}.locksmith-identity.json")
            if not path:
                return
            self.store.export_identity(ident, Path(path))
            job, done = (lambda r, c: self.store.seal(ident)), "Sealed to this device's TPM. Backup saved."
        run_task(job, lambda _: (self.reload(), toast(done, "chip")), lambda m, k: dialogs.error(m), parent=self)

    def _remember_verify(self, ident):
        passphrase = None
        if ident.is_locked:
            passphrase = dialogs.prompt("Identity passphrase", f"Unlock “{ident.name}” once to add its signing "
                                        "keys to its public key.", "Passphrase", secret=True, ok="Unlock")
            if not passphrase:
                return
        run_task(lambda r, c: self.store.remember_verify(ident, passphrase),
                 lambda i: (self.reload(), toast(f"“{i.name}” can sign. Share its new public key.", "fingerprint")),
                 lambda m, k: dialogs.error(m), parent=self)

    def _upgrade(self, ident):
        if not dialogs.confirm(
                "Add post-quantum protection?",
                "Adds an ML-KEM-768 key to this identity, so files sent to it resist future quantum "
                "computers, and lets it sign files. Everything already encrypted to it still opens. Your "
                "public key changes: share the new one with your contacts.", ok="Upgrade", icon="shield"):
            return
        passphrase = None
        if ident.is_locked:
            passphrase = dialogs.prompt("Identity passphrase", f"Unlock “{ident.name}” to upgrade it.",
                                        "Passphrase", secret=True, ok="Upgrade")
            if not passphrase:
                return
        run_task(lambda r, c: self.store.upgrade(ident, passphrase),
                 lambda i: (self.reload(), toast(f"“{i.name}” is now post-quantum. Share its new public key.",
                                                 "shield")),
                 lambda m, k: dialogs.error(m), parent=self)

    def _delete_identity(self, ident):
        if dialogs.confirm(f"Delete “{ident.name}”?",
                           "Files encrypted to this identity can no longer be opened unless you have a "
                           "backup.", ok="Delete"):
            self.store.remove_identity(ident)
            self.reload()
            toast("Identity deleted", "trash")

    def _delete_contact(self, c):
        if dialogs.confirm(f"Remove {c.name}?", "You can add them again later.", ok="Remove"):
            self.store.remove_contact(c)
            self.reload()
