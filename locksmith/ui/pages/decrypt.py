from __future__ import annotations

import os
import tempfile
from pathlib import Path

from PySide6.QtWidgets import QVBoxLayout

from ...core import engine, kdf
from ...core.engine import DecryptKeys
from ...core.errors import LocksmithError
from .. import dialogs
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
    ToggleRow,
    fade_in,
    hrow,
    label,
    shake,
    toast,
)
from ..workers import run_task
from .common import OutputPicker, open_url, reveal, saved_signers, signature_text
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

    def _update_state(self):
        self.go.setEnabled(bool(self.files.paths()) and self.task is None)

    def add_paths(self, paths):
        self.files.add(paths)

    def paste_text(self):
        text = dialogs.text_input("Paste encrypted text",
                                  "Paste a message that starts with “-----BEGIN LOCKSMITH MESSAGE-----”.",
                                  ok="Add")
        if not text:
            return
        try:
            blob = engine.dearmor(text)
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

    def _key_source(self):
        """Snapshot the unlock inputs on the UI thread; returns a builder for the worker."""
        v = self.identity.value()
        ident = self.store.identities[v] if isinstance(v, int) else None
        passphrase = self.passphrase.text() or None
        password, keyfile = self.password.text() or None, self.keyfile.path
        self._signers = saved_signers(self.store)   # whose signatures count, and their names
        verifiers = list(self._signers)

        def build() -> DecryptKeys:
            # Unlocking a passphrase-protected identity runs Argon2id, so keep it off the UI thread.
            identities = [ident.private_raw(passphrase)] if ident else self.store.unlocked_private_keys()
            return DecryptKeys(password=password, keyfile=keyfile, identities=identities, verifiers=verifiers)
        return build

    def start(self):
        paths = self.files.paths()
        if not paths or self.task is not None:
            return
        verify = self.verify_only.isChecked()
        delete = self.delete_after.isChecked() and not verify
        out_dir = self.output.directory()
        threads = self.threads.value()
        pasted = dict(self.pasted)
        build_keys = self._key_source()

        def work(report, cancel):
            keys = build_keys()
            results = []
            n = len(paths)
            for i, p in enumerate(paths):
                def sub(frac, stage, i=i):
                    report(None if frac is None else (i + frac) / n,
                           stage + (f"  ·  {i + 1} of {n}" if n > 1 else ""))
                if verify:
                    res = engine.verify_path(Path(p), keys, threads, sub, cancel)
                    results.append(("verified", p, {**res.meta, "_signature": res.signature}))
                elif p in pasted:
                    results.append(self._decrypt_pasted(pasted[p], keys, out_dir, threads, sub, cancel))
                else:
                    r = engine.decrypt_path(Path(p), out_dir, keys, threads, sub, cancel)
                    meta = {**r.meta, "_skipped": r.skipped, "_signature": r.signature}
                    # The source may be the only copy: delete it only when the core
                    # confirms everything was restored and is on disk.
                    if delete and r.complete:
                        Path(p).unlink(missing_ok=True)
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

    @staticmethod
    def _decrypt_pasted(blob: bytes, keys: DecryptKeys, out_dir, threads, progress, cancel):
        # Without a chosen folder, files from a paste go to Downloads (there is no source
        # folder to put them next to). The core writes and marks them like any decrypted file.
        if not out_dir:
            out_dir = Path.home() / "Downloads"
            if not out_dir.is_dir():
                out_dir = Path.home()
        res = engine.decrypt_pasted(blob, Path(out_dir), keys, threads, progress, cancel)
        if res.path is None:
            return ("text", res.data.decode("utf-8", errors="replace"), {**res.meta, "_signature": res.signature})
        return ("file", res.path, {**res.meta, "_skipped": res.skipped, "_signature": res.signature})

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
            card.add(hrow(label(meta.get("name", Path(value).name), "mono", wrap=False), None,
                          label("✓  Authentic", "caption", wrap=False)))
            dialogs_needed = False
        else:
            path = Path(value)
            show = Button("Show", "folder", "ghost")
            show.clicked.connect(lambda: reveal(path))
            open_btn = Button("Open", "arrow-right", "secondary")
            open_btn.clicked.connect(lambda: open_url(path.resolve().as_uri()))
            card.add(hrow(label(path.name, "mono", wrap=False), None, show, open_btn))
            dialogs_needed = False
        sig = meta.get("_signature")
        card.add(label(signature_text(sig, getattr(self, "_signers", {})), "caption"))
        if meta.get("note"):
            # The signature covers the note; without a checked one, nothing proves who wrote it.
            card.add(label(f"Note (signed): {meta['note']}" if sig is not None and sig.verified else
                           f"Note from the sender (not verified): {meta['note']}", "caption"))
        skipped = meta.get("_skipped") or []
        if skipped:
            shown = ", ".join(skipped[:5]) + ("…" if len(skipped) > 5 else "")
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
