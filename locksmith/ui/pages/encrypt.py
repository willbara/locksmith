from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QGridLayout, QVBoxLayout, QWidget

from ...core import compress, engine, kdf, tools
from ...core.ciphers import SUITES
from ...core.engine import EncryptOptions
from .. import dialogs
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
    LineEdit,
    Page,
    PasswordField,
    ProgressPanel,
    Segmented,
    ToggleRow,
    divider,
    fade_in,
    hrow,
    label,
    toast,
)
from ..workers import run_task
from .common import OutputPicker, RecipientPicker, reveal

THREADS = {0: "Automatic", 1: "1 thread", 2: "2 threads", 4: "4 threads", 8: "8 threads",
           16: "16 threads"}


class EncryptPage(Page):
    share_requested = Signal(str)
    keys_requested = Signal()

    def __init__(self, store):
        super().__init__("Encrypt", "Lock files and folders with authenticated, streaming encryption.")
        self.store = store
        self.task = None

        self.drop = DropZone()
        self.drop.dropped.connect(lambda p: self.files.add(p))
        self.add(self.drop)
        self.files = FileList()
        self.files.changed.connect(self._update_state)
        self.add(self.files)

        # ── protection ──
        prot = Card("Protect with", "Anyone who opens the file needs one of these.")
        self.mode = Segmented(["Password", "Public keys", "Both"])
        self.mode.changed.connect(self._mode_changed)
        prot.add(self.mode)

        self.pw_box = QWidget()
        pl = QVBoxLayout(self.pw_box)
        pl.setContentsMargins(0, 4, 0, 0)
        pl.setSpacing(10)
        self.password = PasswordField("Password")
        self.confirm = PasswordField("Confirm password", strength=False, generate=False)
        self.password.changed.connect(self._password_changed)
        self.confirm.changed.connect(self._update_state)
        self.match = label("", "caption")
        pl.addWidget(self.password)
        pl.addWidget(self.confirm)
        pl.addWidget(self.match)
        pl.addWidget(label("KEYFILE (OPTIONAL SECOND FACTOR)", "label"))
        self.keyfile = KeyfilePicker()
        pl.addWidget(self.keyfile)
        prot.add(self.pw_box)

        self.rcpt_box = QWidget()
        rl = QVBoxLayout(self.rcpt_box)
        rl.setContentsMargins(0, 4, 0, 0)
        rl.setSpacing(8)
        self.recipients = RecipientPicker(store)
        self.recipients.changed.connect(self._update_state)
        self.recipients.manage.connect(self.keys_requested)
        rl.addWidget(self.recipients)
        self.hide_recipients = ToggleRow(
            "Hide the number of recipients",
            "Adds decoy recipient slots, so the file shows 8, 16, 32 or 64 instead of how many people "
            "can really open it.", settings["hide_recipients"])
        rl.addWidget(self.hide_recipients)
        self.rcpt_box.setVisible(False)
        prot.add(self.rcpt_box)
        self.add(prot)

        # ── cipher ──
        cipher = Card("Encryption", "Choose the cipher and how hard the password is to brute-force.")
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        self.suite = Dropdown({k: s.label for k, s in SUITES.items()})
        self.suite.set_value(settings["suite"])
        self.suite_field = Field("Algorithm", self.suite)
        self.preset = Dropdown(kdf.PRESETS)
        self.preset.set_value(settings["preset"])
        self.preset_field = Field("Key strength", self.preset)
        grid.addWidget(self.suite_field, 0, 0)
        grid.addWidget(self.preset_field, 0, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        cipher.add(grid)
        self.suite.currentIndexChanged.connect(self._describe)
        self.preset.currentIndexChanged.connect(self._describe)
        self.add(cipher)

        # ── advanced ──
        adv = Collapsible("Advanced options", "Key derivation, compression, padding, performance",
                          icon="layers")
        g = QGridLayout()
        g.setHorizontalSpacing(14)
        g.setVerticalSpacing(14)
        self.kdf = Dropdown({k: v.label for k, v in kdf.KDFS.items()})
        self.kdf.set_value(settings["kdf"])
        self.kdf.currentIndexChanged.connect(self._describe)
        self.comp = Dropdown({"auto": "Automatic", **{k: c.label for k, c in compress.CODECS.items()},
                              "none": "None"})
        self.comp.set_value(settings["compression"])
        self.level = Dropdown(compress.LEVELS)
        self.level.set_value(settings["level"])
        self.comp.currentIndexChanged.connect(
            lambda: self.level.setEnabled(self.comp.value() != "none"))
        self.chunk = Dropdown(engine.CHUNK_SIZES)
        self.chunk.set_value(settings["chunk_size"])
        self.padding = Dropdown(engine.PADDING)
        self.padding.set_value(settings["padding"])
        self.threads = Dropdown(THREADS)
        self.threads.set_value(settings["threads"])
        fields = [
            Field("Key derivation", self.kdf),
            Field("Compression", self.comp, "Automatic skips already-compressed files."),
            Field("Compression level", self.level),
            Field("Chunk size", self.chunk),
            Field("Size padding", self.padding, "Hides the exact size of the original."),
            Field("Worker threads", self.threads),
        ]
        for i, f in enumerate(fields):
            g.addWidget(f, i // 2, i % 2, Qt.AlignmentFlag.AlignTop)
        g.setColumnStretch(0, 1)
        g.setColumnStretch(1, 1)
        adv.add(g)
        adv.add(divider())
        self.hide_name = ToggleRow("Hide file names",
                                   "Give encrypted files random names. The real name is stored inside.",
                                   settings["hide_name"])
        self.bundle = ToggleRow("Bundle into one archive",
                                "Encrypt several items together as a single file.", settings["bundle"])
        self.armor = ToggleRow("ASCII armor", "Output text you can paste into email or chat.",
                               settings["armor"])
        self.strip = ToggleRow("Remove photo metadata",
                               "Strips location, camera, date and editing details from JPEG, PNG and WebP "
                               "images, plus file times and owner names, without touching image quality. "
                               "Originals are not changed. Other formats are encrypted as they are.",
                               settings["strip_metadata"])
        self.shred = ToggleRow("Shred originals",
                               "Overwrite and delete the originals after encrypting. Best effort only: "
                               "SSDs and copy-on-write filesystems (btrfs) may keep old copies.",
                               settings["shred_after"])
        for t in (self.hide_name, self.bundle, self.armor, self.strip, self.shred):
            adv.add(t)
        self.bundle.toggled.connect(self._update_state)
        self.keyfile.changed.connect(self._update_state)
        self.note = LineEdit("Private note, stored encrypted inside the file")
        adv.add(Field("Note", self.note))
        self.add(adv)

        # ── output & action ──
        self.output = OutputPicker("Save next to the originals")
        self.add(Field("Output", self.output))
        self.go = Button("Encrypt", "lock", "primary", large=True)
        self.go.clicked.connect(self.start)
        self.add(self.go)
        self.progress = ProgressPanel()
        self.progress.cancel.connect(lambda: self.task and self.task.cancel())
        self.add(self.progress)
        self.result_box = QVBoxLayout()
        self.result_box.setSpacing(8)
        self.add(self.result_box)
        self.finish()
        self._describe()
        self._update_state()

    # ── state ──

    def _mode_changed(self, i):
        show_pw = i in (0, 2)
        show_rc = i in (1, 2)
        if show_pw and not self.pw_box.isVisible():
            self.pw_box.setVisible(True)
            fade_in(self.pw_box, 240)
        self.pw_box.setVisible(show_pw)
        if show_rc and not self.rcpt_box.isVisible():
            self.rcpt_box.setVisible(True)
            self.recipients.reload()
            fade_in(self.rcpt_box, 240)
        self.rcpt_box.setVisible(show_rc)
        self._update_state()

    def _password_changed(self, _):
        self._update_state()

    def _describe(self):
        s = SUITES[self.suite.value()]
        self.suite_field.set_caption(s.blurb)
        self.preset_field.set_caption(kdf.describe(self.kdf.value(),
                                                   kdf.params_for(self.kdf.value(), self.preset.value())))

    def _update_state(self):
        mode = self.mode.index()
        pw, cf = self.password.text(), self.confirm.text()
        match = tools.same_secret(pw, cf)
        ok = bool(self.files.paths())
        if mode in (0, 2):
            if pw and cf and not match:
                self.match.setText("Passwords don’t match")
            elif pw and match:
                self.match.setText("✓  Passwords match")
            else:
                self.match.setText("")
            ok = ok and ((pw and match) or (not pw and self.keyfile.path))
        if mode in (1, 2):
            ok = ok and bool(self.recipients.selected())
        self.go.setEnabled(bool(ok) and self.task is None)
        n = len(self.files.paths())
        self.go.setText("Encrypt" if n <= 1 else
                        (f"Encrypt {n} items" if not self.bundle.isChecked() else f"Encrypt {n} items as one"))

    def add_paths(self, paths):
        self.files.add(paths)

    def options(self) -> EncryptOptions:
        mode = self.mode.index()
        return EncryptOptions(
            suite=self.suite.value(), kdf=self.kdf.value(), preset=self.preset.value(),
            compression=self.comp.value(), level=self.level.value(),
            chunk_size=self.chunk.value(), padding=self.padding.value(), threads=self.threads.value(),
            password=self.password.text() if mode in (0, 2) else None,
            keyfile=self.keyfile.path if mode in (0, 2) else None,
            recipients=self.recipients.selected() if mode in (1, 2) else [],
            hide_name=self.hide_name.isChecked(), note=self.note.text().strip(),
            hide_recipients=mode in (1, 2) and self.hide_recipients.isChecked(),
            armor=self.armor.isChecked(), strip_metadata=self.strip.isChecked(),
        )

    # ── run ──

    def start(self):
        paths = [Path(p) for p in self.files.paths()]
        if not paths:
            return
        opts = self.options()
        if opts.password and tools.strength_label(tools.estimate_entropy(opts.password))[0] <= 1:
            if not dialogs.confirm("Weak password",
                                   "This password could be guessed quickly. Use it anyway?",
                                   ok="Use anyway"):
                return
        shred = self.shred.isChecked()
        if shred and opts.keyfile and tools.covered_by(Path(opts.keyfile), paths):
            dialogs.error("The keyfile is one of the items being shredded, or inside one of them. "
                          "Shredding would destroy it, and the encrypted files could never be opened. "
                          "Move the keyfile somewhere else or turn off shredding.", "Keyfile would be shredded")
            return
        if shred and tools.covered_by(self.store.path, paths):
            dialogs.error("Locksmith’s own keys are inside one of the items being shredded. Shredding "
                          "would destroy your private keys, and files encrypted to you could never be "
                          "opened again. Leave that folder out or turn off shredding.", "Keys would be shredded")
            return
        own = {i.public_raw for i in self.store.identities}
        if shred and not (opts.password or opts.keyfile) and not own.intersection(opts.recipients):
            if not dialogs.confirm(
                    "You won’t be able to open these",
                    "Only the selected contacts can decrypt the result, not you. Combined with shredding, "
                    "you will permanently lose access to the originals. Continue?",
                    ok="Continue anyway"):
                return
        if shred and settings["confirm_shred"] and not dialogs.confirm(
                "Shred originals?",
                "After encrypting, the original files will be overwritten and deleted. "
                "This cannot be undone.", ok="Encrypt and shred"):
            return
        out_dir = self.output.directory()
        bundle = self.bundle.isChecked() and len(paths) > 1
        groups = [paths] if bundle else [[p] for p in paths]

        def work(report, cancel):
            outputs, stats = [], {}
            n = len(groups)
            for i, group in enumerate(groups):
                def sub(frac, stage, i=i):
                    report(None if frac is None else (i + frac) / n,
                           stage + (f"  ·  {i + 1} of {n}" if n > 1 else ""))
                # Shredding requires proof the encrypted copy on disk is intact.
                outputs.append(engine.encrypt_paths(group, out_dir, opts, progress=sub, cancel=cancel,
                                                    verify=shred, stats=stats))
                if shred:
                    for p in group:
                        report(None, f"Shredding {p.name}")
                        tools.shred(p, cancel=cancel)
            return outputs, stats

        self._clear_results()
        self.progress.start()
        self.task = run_task(work, self._done, self._failed, self.progress.update_progress,
                             self._cancelled, self)
        self._update_state()

    def _finish(self):
        self.task = None
        self.progress.finish()
        self._update_state()

    def _done(self, result):
        outputs, stats = result
        self._finish()
        self.files.clear()
        self.password.clear()
        self.confirm.clear()
        toast(f"Encrypted {len(outputs)} file{'s' if len(outputs) != 1 else ''}", "lock")
        if stats:
            done, same = stats.get("stripped", 0), stats.get("unchanged", 0)
            msg = f"Metadata removed from {done} image{'s' if done != 1 else ''}"
            if same:
                msg += f". {same} other file{'s' if same != 1 else ''} kept as-is (format not supported)"
            toast(msg, "shield", 5000)
        for out in outputs:
            self._add_result(out)

    def _failed(self, msg, _kind=""):
        self._finish()
        dialogs.error(msg, "Encryption failed")

    def _cancelled(self):
        self._finish()
        toast("Cancelled", "x")

    def _clear_results(self):
        while self.result_box.count():
            w = self.result_box.takeAt(0).widget()
            if w:
                w.deleteLater()

    def _add_result(self, path: Path):
        card = Card()
        card.lay.setContentsMargins(18, 14, 14, 14)
        name = label(path.name, "mono", wrap=False)
        reveal_btn = Button("Show", "folder", "ghost")
        reveal_btn.clicked.connect(lambda: reveal(path))
        share_btn = Button("Share", "share", "secondary")
        share_btn.clicked.connect(lambda: self.share_requested.emit(str(path)))
        card.add(hrow(name, None, reveal_btn, share_btn))
        self.result_box.addWidget(card)
        fade_in(card, 300, rise=6)
