from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QSlider

from ...core import tools
from ...core.keys import write_secret_file
from .. import dialogs
from ..lock import mark_sensitive
from ..widgets import (
    Button,
    Collapsible,
    Dropdown,
    DropZone,
    Field,
    FileList,
    LineEdit,
    Page,
    PasswordField,
    ProgressPanel,
    Segmented,
    StrengthMeter,
    ToggleRow,
    copy_secret,
    hrow,
    label,
    toast,
)
from ..workers import run_task


class ToolsPage(Page):
    def __init__(self):
        super().__init__("Tools", "Generators, checksums and secure deletion.")
        self._gen_card()
        self._tester_card()
        self._hash_card()
        self._keyfile_card()
        self._shred_card()
        self.finish()

    # ── generator ──

    def _gen_card(self):
        c = Collapsible("Password generator", "Random passwords and pronounceable passphrases",
                        icon="refresh", expanded=True)
        self.gen_out = mark_sensitive(LineEdit(mono=True))
        self.gen_out.setReadOnly(True)
        self.gen_out.setFixedHeight(48)
        self.gen_out.setStyleSheet("font-size: 15px;")
        self.gen_out.add_action("refresh", "Regenerate", self._generate)
        self.gen_out.add_action("copy", "Copy", self._copy_generated)
        c.add(self.gen_out)
        self.gen_meter = StrengthMeter()
        c.add(self.gen_meter)
        self.gen_info = label("", "caption")
        c.add(self.gen_info)
        self.gen_mode = Segmented(["Random characters", "Passphrase"])
        self.gen_mode.changed.connect(self._gen_mode)
        c.add(self.gen_mode)
        self.gen_len = QSlider(Qt.Orientation.Horizontal)
        self.gen_len.setRange(8, 128)
        self.gen_len.setValue(24)
        self.gen_len_label = label("", "caption", False)
        self.gen_len.valueChanged.connect(self._generate)
        c.add(hrow(label("Length", "label", False), self.gen_len, self.gen_len_label))
        self.gen_opts = {
            "lower": ToggleRow("Lowercase", checked=True),
            "upper": ToggleRow("Uppercase", checked=True),
            "digits": ToggleRow("Digits", checked=True),
            "symbols": ToggleRow("Symbols", checked=True),
            "avoid_ambiguous": ToggleRow("Avoid look-alikes", "Skip characters like I, l, 1, O and 0"),
        }
        for t in self.gen_opts.values():
            t.toggled.connect(self._generate)
            c.add(t)
        self.add(c)
        self._generate()

    def _gen_mode(self, i):
        for t in self.gen_opts.values():
            t.setVisible(i == 0)
        if i == 0:
            self.gen_len.setRange(8, 128)
            self.gen_len.setValue(24)
        else:
            self.gen_len.setRange(3, 16)
            self.gen_len.setValue(6)
        self._generate()

    def _generate(self, *_):
        n = self.gen_len.value()
        if self.gen_mode.index() == 0:
            opts = {k: t.isChecked() for k, t in self.gen_opts.items()}
            pw = tools.generate_password(n, **opts)
            self.gen_len_label.setText(f"{n} characters")
            pool = sum(len(p) for p, on in (("a" * 26, opts["lower"]), ("A" * 26, opts["upper"]),
                                            ("0" * 10, opts["digits"]),
                                            (tools.SYMBOLS, opts["symbols"])) if on) or 26
            import math
            bits = n * math.log2(pool)
        else:
            pw = tools.generate_passphrase(n)
            self.gen_len_label.setText(f"{n} words")
            bits = tools.passphrase_entropy(n)
        self.gen_out.setText(pw)
        level, lab = tools.strength_label(bits)
        self.gen_meter.set_level(level + 1)
        self.gen_info.setText(f"{lab} · {bits:.0f} bits of entropy · offline crack: {tools.crack_time(bits)}")

    def _copy_generated(self):
        copy_secret(self.gen_out.text())
        toast("Password copied. The clipboard clears in 30 seconds.", "copy")

    # ── tester ──

    def _tester_card(self):
        c = Collapsible("Strength tester", "See how long a password would survive a brute-force attack",
                        icon="shield")
        self.tester = PasswordField("Type a password to test", generate=False)
        c.add(self.tester)
        c.add(label("Estimated locally, never sent anywhere. Assumes 10 billion guesses per second.",
                    "faint"))
        self.add(c)

    # ── checksums ──

    def _hash_card(self):
        c = Collapsible("Checksums", "Fingerprint a file to verify a download or a transfer", icon="hash")
        self.hash_file = None
        self.hash_name = label("No file selected", "caption", False)
        pick = Button("Choose file…", "file")
        pick.clicked.connect(self._pick_hash_file)
        c.add(hrow(pick, self.hash_name, None))
        self.hash_alg = Dropdown(tools.HASHES)
        self.hash_go = Button("Compute", "hash", "primary")
        self.hash_go.clicked.connect(self._compute)
        self.hash_go.setEnabled(False)
        c.add(hrow(self.hash_alg, self.hash_go))
        self.hash_progress = ProgressPanel()
        self.hash_progress.cancel_btn.setVisible(False)
        c.add(self.hash_progress)
        self.hash_out = LineEdit(mono=True)
        self.hash_out.setReadOnly(True)
        self.hash_out.setPlaceholderText("Result")
        self.hash_out.add_action("copy", "Copy", lambda: self.hash_out.text() and (
            QApplication.clipboard().setText(self.hash_out.text()), toast("Checksum copied", "copy")))
        c.add(self.hash_out)
        self.hash_expect = LineEdit("Paste the expected checksum to compare", mono=True)
        self.hash_expect.textChanged.connect(self._compare)
        c.add(self.hash_expect)
        self.hash_match = label("", "h2")
        c.add(self.hash_match)
        self.add(c)

    def _pick_hash_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file")
        if path:
            self.hash_file = Path(path)
            self.hash_name.setText(self.hash_file.name)
            self.hash_go.setEnabled(True)
            self.hash_out.clear()
            self._compare()

    def _compute(self):
        f, alg = self.hash_file, self.hash_alg.value()
        self.hash_progress.start()
        self.hash_go.setEnabled(False)

        def done(h):
            self.hash_progress.finish()
            self.hash_go.setEnabled(True)
            self.hash_out.setText(h)
            self._compare()

        def failed(m, k):
            self.hash_progress.finish()
            self.hash_go.setEnabled(True)
            dialogs.error(m)

        run_task(lambda r, c: tools.hash_file(f, alg, lambda x: r(x, "Hashing"), c), done, failed,
                 self.hash_progress.update_progress, parent=self)

    def _compare(self):
        a = self.hash_out.text().strip().lower()
        b = "".join(self.hash_expect.text().split()).lower()
        if not a or not b:
            self.hash_match.setText("")
        elif a == b:
            self.hash_match.setText("✓  Checksums match")
        else:
            self.hash_match.setText("✕  Checksums do not match")

    # ── keyfile ──

    def _keyfile_card(self):
        c = Collapsible("Keyfile generator", "Create random keyfiles to use as a second factor", icon="key")
        self.kf_size = Dropdown({64: "64 bytes (512 bits)", 1024: "1 KiB", 4096: "4 KiB",
                                 65536: "64 KiB"})
        self.kf_size.set_value(4096)
        make = Button("Create keyfile…", "plus", "primary")
        make.clicked.connect(self._make_keyfile)
        c.add(Field("Size", hrow(self.kf_size, make)))
        c.add(label("Store keyfiles on a separate device, like a USB stick. Losing the keyfile means "
                    "losing access to files that need it.", "caption"))
        self.add(c)

    def _make_keyfile(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save keyfile", "locksmith.key")
        if not path:
            return
        write_secret_file(Path(path), os.urandom(self.kf_size.value()))
        toast("Keyfile created", "key")

    # ── shred ──

    def _shred_card(self):
        c = Collapsible("Shred files", "Overwrite files with random data, then delete them", icon="trash")
        c.add(label("Best effort only. On SSDs, flash drives and copy-on-write filesystems such as btrfs, "
                    "earlier copies of the data may survive. Full-disk encryption is the reliable way to "
                    "protect deleted data.", "caption"))
        self.shred_drop = DropZone("Drop files to shred", "they will be destroyed permanently")
        self.shred_drop.setMinimumHeight(170)
        self.shred_list = FileList()
        self.shred_drop.dropped.connect(self.shred_list.add)
        c.add(self.shred_drop)
        c.add(self.shred_list)
        self.passes = Dropdown({1: "1 pass (random)", 3: "3 passes", 7: "7 passes"})
        self.shred_go = Button("Shred", "trash", "primary")
        self.shred_go.clicked.connect(self._shred)
        c.add(hrow(self.passes, self.shred_go))
        self.shred_progress = ProgressPanel()
        c.add(self.shred_progress)
        self.add(c)

    def _shred(self):
        paths = self.shred_list.paths()
        if not paths:
            toast("Add files to shred first", "alert")
            return
        if not dialogs.confirm("Shred permanently?",
                               f"{len(paths)} item{'s' if len(paths) != 1 else ''} will be overwritten and "
                               "deleted. This cannot be undone.", ok="Shred"):
            return
        passes = self.passes.value()

        def work(report, cancel):
            for i, p in enumerate(paths):
                report(i / len(paths), f"Shredding {Path(p).name}")
                tools.shred(Path(p), passes, cancel)
            return len(paths)

        self.shred_progress.start()
        self.shred_go.setEnabled(False)

        def end():
            self.shred_progress.finish()
            self.shred_go.setEnabled(True)

        task = run_task(work, lambda n: (end(), self.shred_list.clear(), toast(f"Shredded {n} items", "trash")),
                        lambda m, k: (end(), dialogs.error(m)), self.shred_progress.update_progress,
                        lambda: (end(), toast("Cancelled", "x")), self)
        self.shred_progress.cancel.connect(task.cancel)
