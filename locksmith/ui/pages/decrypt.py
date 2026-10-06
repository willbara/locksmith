from __future__ import annotations

import os
import tempfile
from pathlib import Path

from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from ...core import age, engine, kdf, parity, sshkeys
from ...core.engine import AccessChange, DecryptKeys
from ...core.errors import LocksmithError
from ...core.osutil import opens_as_program
from ...core.tools import display_text, estimate_entropy, same_secret, strength_label
from .. import dialogs
from ..dialogs import Sheet
from ..lock import is_locked, withhold
from ..settings import settings
from ..widgets import (
    Button,
    Card,
    Collapsible,
    Dropdown,
    DropZone,
    Field,
    FileList,
    KeyfilePicker,
    Page,
    PasswordField,
    ProgressPanel,
    Segmented,
    ToggleRow,
    fade_in,
    hrow,
    label,
    shake,
    toast,
)
from ..workers import run_task
from .common import (
    OutputPicker,
    RecipientPicker,
    confirm_kdf_cost,
    open_url,
    own_encryption_keys,
    reveal,
    saved_signers,
    signature_text,
)
from .encrypt import THREADS


class DecryptPage(Page):
    def __init__(self, store):
        super().__init__("Decrypt", "Open .locksmith files and armored text messages.")
        self.store = store
        self.task = None
        self.pasted: dict[str, bytes] = {}
        self._paste_dir = None

        self.drop = DropZone("Drop encrypted files here", "or choose them below", folders=False,
                             file_filter="Locksmith files (*.locked *.txt);;All files (*)")
        paste = Button("Paste text", "paste")
        paste.clicked.connect(self.paste_text)
        self.drop.add_button(paste)
        self.drop.dropped.connect(lambda p: self.files.add(p))
        self.add(self.drop)
        self.files = FileList()
        self.files.changed.connect(self._files_changed)
        self.add(self.files)

        self.info_card = Card()
        self.info_card.lay.setSpacing(6)
        self.info_title = label("", "h2")
        self.info_lines = label("", "caption")
        self.info_card.add(self.info_title)
        self.info_card.add(self.info_lines)
        self.info_card.setVisible(False)
        self.add(self.info_card)

        unlock = Card("Unlock with", "Use the password, keyfile or identity the file was made for.")
        self.password = PasswordField("Password", strength=False, generate=False)
        self.password.edit.returnPressed.connect(self.start)
        self.password.changed.connect(lambda _: self._update_state())
        unlock.add(self.password)
        unlock.add(label("KEYFILE", "label"))
        self.keyfile = KeyfilePicker(allow_generate=False)
        unlock.add(self.keyfile)
        unlock.add(label("SSH KEY", "label"))
        ssh_dir = Path.home() / ".ssh"
        self.ssh_key = KeyfilePicker(allow_generate=False, button="SSH key…", empty="None",
                                     tip="For files encrypted to your SSH Ed25519 or RSA public key: choose its private "
                                         "key (for example ~/.ssh/id_ed25519). It is only read, never stored.",
                                     title="Choose your SSH private key", start=str(ssh_dir) if ssh_dir.is_dir() else "")
        unlock.add(self.ssh_key)
        self.identity = Dropdown()
        self.identity.currentIndexChanged.connect(self._identity_changed)
        self.id_field = Field("Identity", self.identity)
        unlock.add(self.id_field)
        self.passphrase = PasswordField("Identity passphrase", strength=False, generate=False)
        self.passphrase.setVisible(False)
        unlock.add(self.passphrase)
        self.add(unlock)

        opts = Collapsible("Options", "Verification, clean-up and performance", icon="layers")
        self.verify_only = ToggleRow("Verify only",
                                     "Check every chunk is authentic without writing any files.")
        self.verify_only.toggled.connect(lambda on: self.go.setText("Verify" if on else "Decrypt"))
        self.delete_after = ToggleRow("Delete encrypted file afterwards",
                                      "Remove the .locksmith file once it has been decrypted.",
                                      settings["delete_after_decrypt"])
        self.threads = Dropdown(THREADS)
        self.threads.set_value(settings["threads"])
        opts.add(self.verify_only)
        opts.add(self.delete_after)
        opts.add(Field("Worker threads", self.threads))
        self.add(opts)

        self.output = OutputPicker("Save next to the encrypted file")
        self.add(Field("Output", self.output))
        self.go = Button("Decrypt", "unlock", "primary", large=True)
        self.go.clicked.connect(self.start)
        self.add(self.go)
        self.access = Button("Change who can open it…", "key", "ghost")
        self.access.setToolTip("Change the password, keyfile or recipients of one file without encrypting it again")
        self.access.clicked.connect(self.change_access)
        self.add(hrow(self.access, None))
        self.progress = ProgressPanel()
        self.progress.cancel.connect(lambda: self.task and self.task.cancel())
        self.add(self.progress)
        self.result_box = QVBoxLayout()
        self.result_box.setSpacing(8)
        self.add(self.result_box)
        self.finish()
        self.reload_identities()
        self._update_state()

    # ── state ──

    def reload_identities(self):
        items = {"auto": "Automatic (all unlocked identities)"}
        for i, ident in enumerate(self.store.identities):
            items[i] = ident.name + ("  (passphrase)" if ident.is_locked else "")
        self.identity.set_items(items)
        self.id_field.setVisible(bool(self.store.identities))
        self._identity_changed()

    def _identity_changed(self):
        v = self.identity.value()
        locked = isinstance(v, int) and v < len(self.store.identities) and \
            self.store.identities[v].is_locked
        if locked and not self.passphrase.isVisible():
            self.passphrase.setVisible(True)
            fade_in(self.passphrase, 200)
        self.passphrase.setVisible(bool(locked))

    def _files_changed(self):
        paths = self.files.paths()
        self._update_state()
        if not paths:
            self.info_card.setVisible(False)
            return
        if self._is_age(paths[0]):
            self._show_age_info(paths)
            return
        try:
            info = engine.inspect(paths[0])
        except (LocksmithError, OSError) as e:
            self.info_title.setText(Path(paths[0]).name if paths[0] not in self.pasted else "Pasted message")
            self.info_lines.setText(str(e))
        else:
            name = "Pasted message" if paths[0] in self.pasted else Path(paths[0]).name
            self.info_title.setText(name)
            lines = [f"Cipher: {info.suite_label}"]
            for s in info.password_slots:
                lines.append("Password: " + kdf.describe(s["kdf"], s["params"]) +
                             ("  +  keyfile" if s["keyfile"] else ""))
            if info.recipient_slots:
                lines.append(f"Public-key recipients: {info.recipient_slots}")
            if len(paths) > 1:
                lines.append(f"…and {len(paths) - 1} more file{'s' if len(paths) > 2 else ''}")
            self.info_lines.setText("\n".join(lines))
            if info.needs_keyfile and not self.keyfile.path:
                toast("This file needs its keyfile", "key")
        if not self.info_card.isVisible():
            self.info_card.setVisible(True)
            fade_in(self.info_card, 260, rise=6)

    def _is_age(self, path: str) -> bool:
        blob = self.pasted.get(path)
        return blob.startswith(age.INTRO) if blob is not None else age.is_age_file(Path(path))

    def _show_age_info(self, paths):
        self.info_title.setText("Pasted age message" if paths[0] in self.pasted else Path(paths[0]).name)
        try:
            lines = ["Format: age (ChaCha20-Poly1305)", f"Opens with: {age.inspect(Path(paths[0])).summary}"]
        except (LocksmithError, OSError) as e:
            lines = [str(e)]
        if len(paths) > 1:
            lines.append(f"…and {len(paths) - 1} more file{'s' if len(paths) > 2 else ''}")
        self.info_lines.setText("\n".join(lines))
        if not self.info_card.isVisible():
            self.info_card.setVisible(True)
            fade_in(self.info_card, 260, rise=6)

    def _update_state(self):
        self.go.setEnabled(bool(self.files.paths()) and self.task is None)
        paths = self.files.paths()
        self.access.setEnabled(len(paths) == 1 and paths[0] not in self.pasted and self.task is None)

    def add_paths(self, paths):
        self.files.add(paths)

    def paste_text(self):
        text = dialogs.text_input("Paste encrypted text",
                                  "Paste a message that starts with “-----BEGIN LOCKSMITH MESSAGE-----” or "
                                  "“-----BEGIN AGE ENCRYPTED FILE-----”.", ok="Add")
        if not text:
            return
        try:
            blob = age.dearmor(text.encode()) if age.ARMOR_BEGIN in text else engine.dearmor(text)
        except LocksmithError as e:
            dialogs.error(str(e))
            return
        if self._paste_dir is None:
            self._paste_dir = tempfile.mkdtemp(prefix="locksmith-")
        path = os.path.join(self._paste_dir, f"pasted-{len(self.pasted) + 1}.locked")
        Path(path).write_bytes(blob)
        self.pasted[path] = blob
        self.files.add([path], label=f"Pasted message {len(self.pasted)}")

    # ── run ──

    def _ssh_source(self):
        """The chosen SSH private key file's contents and its passphrase, asked for here on the UI
        thread: (None, None) without one, or None when the user cancelled or it can't be read."""
        if not self.ssh_key.path:
            return None, None
        try:
            data = sshkeys.read_private(Path(self.ssh_key.path))
        except (LocksmithError, OSError) as e:
            dialogs.error(str(e), "Can't use this SSH key")
            return None
        passphrase = None
        if sshkeys.needs_passphrase(data):
            passphrase = dialogs.prompt("SSH key passphrase", f"Unlock {Path(self.ssh_key.path).name} to open "
                                        "the file.", "Passphrase", secret=True, ok="Unlock")
            if not passphrase:
                return None
        return data, passphrase

    def _key_source(self):
        """Snapshot the unlock inputs on the UI thread; returns a builder for the worker, or None
        when the user cancelled."""
        ssh = self._ssh_source()
        if ssh is None:
            return None
        ssh_data, ssh_passphrase = ssh
        v = self.identity.value()
        ident = self.store.identities[v] if isinstance(v, int) else None
        passphrase = self.passphrase.text() or None
        password, keyfile = self.password.text() or None, self.keyfile.path
        self._signers = saved_signers(self.store)   # whose signatures count, and their names
        verifiers = list(self._signers)
        own = own_encryption_keys(self.store)

        def build() -> DecryptKeys:
            # Unlocking a passphrase-protected identity runs Argon2id, so keep it off the UI thread.
            identities = [ident.private_raw(passphrase)] if ident else self.store.unlocked_private_keys()
            ssh_keys = [sshkeys.load_identity(ssh_data, ssh_passphrase)] if ssh_data else []
            return DecryptKeys(password=password, keyfile=keyfile, identities=identities, verifiers=verifiers,
                               own_keys=own, ssh=ssh_keys)
        return build

    @staticmethod
    def _kdf_cost_ok(paths, pasted) -> bool:
        infos = []
        for p in paths:
            try:
                infos.append(engine.inspect_bytes(pasted[p]) if p in pasted else engine.inspect(Path(p)))
            except (LocksmithError, OSError):
                continue   # reported when the file is opened
        return confirm_kdf_cost(infos)

    def start(self):
        paths = self.files.paths()
        if not paths or self.task is not None:
            return
        verify = self.verify_only.isChecked()
        delete = self.delete_after.isChecked() and not verify
        out_dir = self.output.directory()
        threads = self.threads.value()
        pasted = dict(self.pasted)
        ages = {p for p in paths if self._is_age(p)}
        if (self.password.text() or self.keyfile.path) and not self._kdf_cost_ok(
                [p for p in paths if p not in ages], pasted):
            return
        build_keys = self._key_source()
        if build_keys is None:
            return

        def work(report, cancel):
            keys = build_keys()
            results = []
            n = len(paths)
            for i, p in enumerate(paths):
                def sub(frac, stage, i=i):
                    report(None if frac is None else (i + frac) / n,
                           stage + (f"  ·  {i + 1} of {n}" if n > 1 else ""))
                if p in ages:
                    results.append(self._open_age(p, pasted.get(p), keys, out_dir, verify, delete, sub, cancel))
                elif verify:
                    res = engine.verify_path(Path(p), keys, threads, sub, cancel)
                    results.append(("verified", p, {**res.meta, "_signature": res.signature, "_intent": res.intent}))
                elif p in pasted:
                    results.append(self._decrypt_pasted(pasted[p], keys, out_dir, threads, sub, cancel))
                else:
                    r = engine.decrypt_path(Path(p), out_dir, keys, threads, sub, cancel)
                    meta = {**r.meta, "_skipped": r.skipped, "_signature": r.signature, "_intent": r.intent}
                    # The source may be the only copy: delete it only when the core
                    # confirms everything was restored and is on disk.
                    if delete and r.complete:
                        Path(p).unlink(missing_ok=True)
                        Path(p + parity.EXTENSION).unlink(missing_ok=True)   # its recovery data, if any
                    elif delete:
                        meta["_kept"] = True
                    results.append(("file", r.path, meta))
                if p in pasted:
                    Path(p).unlink(missing_ok=True)  # only a temporary copy of the paste
            return results

        self._clear_results()
        self.progress.start()
        self.task = run_task(work, self._done, self._failed, self.progress.update_progress,
                             self._cancelled, self)
        self._update_state()

    # ── changing who can open a file ──

    def change_access(self):
        paths = self.files.paths()
        if len(paths) != 1 or paths[0] in self.pasted or self.task is not None:
            return
        path = Path(paths[0])
        if self._is_age(paths[0]):
            dialogs.error("age files can't change who opens them without being encrypted again: decrypt it, then "
                          "encrypt it to the new recipients.", "Can't change this file")
            return
        try:
            info = engine.inspect(path)
        except (LocksmithError, OSError) as e:
            dialogs.error(str(e))
            return
        if info.format_version < 2:
            dialogs.error("This file uses format version 1, where every part of the file depends on its key "
                          "slots. Decrypt it and encrypt it again to change who can open it.", "Can't change this file")
            return
        change = self._access_sheet(path, info)
        if change is None:
            return
        build_keys = self._key_source()
        if build_keys is not None:
            self._run_access(path, change, build_keys, allow_lockout=False)

    def _access_sheet(self, path: Path, info) -> AccessChange | None:
        """Ask how to change the file's access. None when cancelled."""
        s = Sheet(f"Change who can open “{path.name}”",
                  "Only the file's key slots are rewritten; its contents are not encrypted again. Unlock it with "
                  "its current password, keyfile or identity on this page first.", width=600, icon="key")
        s.add(label("This doesn't take access away from anyone who could already open the file: they may have "
                    "kept its file key, which still opens every copy. To truly revoke access, decrypt the file and "
                    "encrypt it again.", "caption"))
        s.add(label("PASSWORD", "label"))
        has_pw = bool(info.password_slots)
        pw_mode = Segmented(["Keep", "New password", "Remove"] if has_pw else ["None", "Add a password"])
        s.add(pw_mode)
        pw_box = QWidget()
        pl = QVBoxLayout(pw_box)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(8)
        new_pw = PasswordField("New password")
        again = PasswordField("Confirm new password", strength=False, generate=False)
        keyfile = KeyfilePicker()
        pl.addWidget(new_pw)
        pl.addWidget(again)
        pl.addWidget(keyfile)
        pw_box.setVisible(False)
        s.add(pw_box)
        pw_mode.changed.connect(lambda i: (pw_box.setVisible(i == 1), s.relayout()))

        s.add(label("RECIPIENTS", "label"))
        rc_mode = Segmented(["Keep them, add more", "Replace them"])
        s.add(rc_mode)
        rc_note = label(f"The file has {info.recipient_slots} recipient slot{'s' if info.recipient_slots != 1 else ''}"
                        ". Recipients aren't named in the file, so Locksmith can't list them or take one out: to "
                        "remove someone, choose Replace and pick everyone who should still open it.", "caption")
        s.add(rc_note)
        picker = RecipientPicker(self.store, manage_link=False)
        scroll = QScrollArea()
        scroll.setWidget(picker)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setMaximumHeight(200)
        s.add(scroll)
        hide = ToggleRow("Hide the number of recipients", "Rounds the recipient slots up to 8, 16, 32 or 64 with "
                         "decoys. Classical, SSH and RSA recipients beside post-quantum ones stay countable.",
                         settings["hide_recipients"])
        s.add(hide)
        s.add_button("Cancel", None, "ghost")
        s.add_button("Save changes", True, "primary")
        if not s.exec():
            return None
        mode = pw_mode.index()   # 0 keep (or none), 1 new password, 2 remove
        if mode == 1 and not (new_pw.text() or keyfile.path):
            dialogs.error("Enter a new password or choose a keyfile.", "Nothing to set")
            return None
        if mode == 1 and new_pw.text() and not same_secret(new_pw.text(), again.text()):
            dialogs.error("The new passwords don't match, so nothing was changed.", "Passwords don't match")
            return None
        if mode == 1 and new_pw.text() and strength_label(estimate_entropy(new_pw.text()))[0] <= 1 and \
                not dialogs.confirm("Weak password", "This password could be guessed quickly. Use it anyway?",
                                    ok="Use anyway"):
            return None
        change = AccessChange(
            set_password=mode in (1, 2), password=(new_pw.text() or None) if mode == 1 else None,
            keyfile=keyfile.path if mode == 1 else None, kdf=settings["kdf"], preset=settings["preset"],
            replace_recipients=rc_mode.index() == 1, add_recipients=picker.selected(),
            hide_recipients=hide.isChecked())
        if not (change.set_password or change.replace_recipients or change.add_recipients):
            toast("Nothing to change", "check")
            return None
        return change

    def _run_access(self, path: Path, change: AccessChange, build_keys, allow_lockout: bool):
        def work(report, cancel):
            return engine.change_access(path, build_keys(), change, allow_lockout, report, cancel)

        def done(res):
            self._finish()
            self.password.clear()
            self.passphrase.clear()
            self._files_changed()
            toast(f"Updated who can open {path.name}. Its contents were not encrypted again.", "key", 4000)

        def failed(msg, kind):
            self._finish()
            if kind == "LockoutError":
                if dialogs.confirm("You won’t be able to open it",
                                   msg + " Only the people it is now encrypted to will. Continue?",
                                   ok="Change anyway"):
                    self._run_access(path, change, build_keys, allow_lockout=True)
            elif kind == "WrongKeyError":
                toast(msg + " Enter its current password, keyfile or identity above first.", "alert", 5000)
            else:
                dialogs.error(msg, "Nothing was changed")

        self.progress.start()
        self.task = run_task(work, done, failed, self.progress.update_progress, self._cancelled, self)
        self._update_state()

    @staticmethod
    def _open_age(p, blob, keys: DecryptKeys, out_dir, verify, delete, progress, cancel):
        """An age file or pasted age message: opened with the same password, identities and SSH key."""
        akeys = age.Keys(identities=keys.identities, ssh=keys.ssh, passphrase=keys.password)
        if verify and blob is None:
            res = age.verify_path(Path(p), akeys, progress, cancel)
            return ("verified", p, {**res.meta, "_signature": None})
        if blob is not None:
            res = age.decrypt_pasted(blob, DecryptPage._paste_output(out_dir), akeys, engine.MAX_ARMOR_INPUT)
            if res.path is None:
                return ("text", res.data.decode("utf-8"), {**res.meta, "_signature": None})
            return ("file", res.path, {**res.meta, "_signature": None})
        res = age.decrypt_path(Path(p), out_dir, akeys, progress, cancel)
        meta = {**res.meta, "_signature": None}
        if delete and res.complete:
            Path(p).unlink(missing_ok=True)
            Path(p + parity.EXTENSION).unlink(missing_ok=True)
        elif delete:
            meta["_kept"] = True
        return ("file", res.path, meta)

    @staticmethod
    def _paste_output(out_dir) -> Path:
        # Without a chosen folder, files from a paste go to Downloads (there is no source
        # folder to put them next to).
        if out_dir:
            return Path(out_dir)
        downloads = Path.home() / "Downloads"
        return downloads if downloads.is_dir() else Path.home()

    @staticmethod
    def _decrypt_pasted(blob: bytes, keys: DecryptKeys, out_dir, threads, progress, cancel):
        # The core writes and marks files from a paste like any decrypted file.
        res = engine.decrypt_pasted(blob, DecryptPage._paste_output(out_dir), keys, threads, progress, cancel)
        extra = {"_signature": res.signature, "_intent": res.intent}
        if res.path is None:
            return ("text", res.data.decode("utf-8", errors="replace"), {**res.meta, **extra})
        return ("file", res.path, {**res.meta, "_skipped": res.skipped, **extra})

    def _finish(self):
        self.task = None
        self.progress.finish()
        self._update_state()

    def _done(self, results):
        self._finish()
        self.files.clear()
        self.pasted.clear()
        self.password.clear()
        self.passphrase.clear()
        verified = [r for r in results if r[0] == "verified"]
        if verified:
            toast(f"All chunks authentic in {len(verified)} file{'s' if len(verified) != 1 else ''}",
                  "shield")
        else:
            kept = sum(1 for r in results if r[2].get("_kept"))
            toast(f"Decrypted {len(results)} item{'s' if len(results) != 1 else ''}"
                  + (f", kept {kept} encrypted file{'s' if kept != 1 else ''}" if kept else ""),
                  "alert" if kept else "unlock", 4000 if kept else 3200)
        for kind, value, meta in results:
            if kind == "text" and is_locked():
                withhold("Decrypted message")   # the lock already cleared the page: don't put it back
                continue
            self._add_result(kind, value, meta)

    def _failed(self, msg, kind=""):
        self._finish()
        if kind == "WrongKeyError":
            shake(self.password)
            toast(msg, "alert", 4000)
        else:
            dialogs.error(msg, "Decryption failed")

    def _cancelled(self):
        self._finish()
        toast("Cancelled", "x")

    def clear_secrets(self):
        """Called when the app locks: drop decrypted previews and pending pastes."""
        self._clear_results()

    def _clear_results(self):
        while self.result_box.count():
            w = self.result_box.takeAt(0).widget()
            if w:
                w.deleteLater()

    @staticmethod
    def _open(path: Path, sig):
        """Open a decrypted file with its default app, asking first when that would run it."""
        if opens_as_program(path.name) and not dialogs.confirm(
                "Run a program?",
                f"“{path.name}” is a program, script or shortcut: opening it runs it with your account's rights, "
                + ("and it was signed with a key you saved. " if sig is not None and sig.verified else
                   "and nothing shows who made it. ")
                + "Only open it if you trust whoever made the file.", ok="Run it", icon="alert"):
            return
        open_url(path.resolve().as_uri())

    def _add_result(self, kind, value, meta):
        card = Card()
        card.lay.setContentsMargins(18, 14, 14, 14)
        card.lay.setSpacing(8)
        if kind == "text":
            title = label("Decrypted message", "h2")
            view = Button("View", "message", "secondary")
            view.clicked.connect(lambda: dialogs.text_view("Decrypted message", value, mono=False, secret=True))
            card.add(hrow(title, None, view))
            preview = value if len(value) < 240 else value[:240] + "…"
            card.add(label(preview, "caption"))
            dialogs_needed = True
        elif kind == "verified":
            card.add(hrow(label(engine.safe_name(meta.get("name") or Path(value).name), "mono", wrap=False), None,
                          label("✓  Authentic", "caption", wrap=False)))
            dialogs_needed = False
        else:
            path = Path(value)
            show = Button("Show", "folder", "ghost")
            show.clicked.connect(lambda: reveal(path))
            open_btn = Button("Open", "arrow-right", "secondary")
            open_btn.clicked.connect(lambda: self._open(path, meta.get("_signature")))
            card.add(hrow(label(path.name, "mono", wrap=False), None, show, open_btn))
            dialogs_needed = False
        sig = meta.get("_signature")
        card.add(label(signature_text(sig, getattr(self, "_signers", {}), meta.get("_intent")), "caption"))
        if meta.get("note"):
            # The signature covers the note; without a checked one, nothing proves who wrote it.
            note = display_text(meta["note"])
            card.add(label(f"Note (signed): {note}" if sig is not None and sig.verified else
                           f"Note from the sender (not verified): {note}", "caption"))
        skipped = meta.get("_skipped") or []
        if skipped:
            shown = ", ".join(display_text(name, 120) for name in skipped[:5]) + ("…" if len(skipped) > 5 else "")
            card.add(label(f"Left out {len(skipped)} unsafe item{'s' if len(skipped) != 1 else ''} "
                           f"(links pointing outside the folder or device files): {shown}", "caption"))
        if meta.get("_kept"):
            why = ("some items were left out" if skipped else
                   "the decrypted copy could not be confirmed as complete and saved to disk")
            card.add(label(f"The encrypted file was not deleted because {why}.", "caption"))
        self.result_box.addWidget(card)
        fade_in(card, 300, rise=6)
        if dialogs_needed:
            dialogs.text_view("Decrypted message", value, mono=False, secret=True)
