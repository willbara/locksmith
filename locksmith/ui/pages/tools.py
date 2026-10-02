from __future__ import annotations

import base64
import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QSlider

from ...core import minisign, tools
from ...core.errors import LocksmithError
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
    divider,
    hrow,
    label,
    toast,
)
from ..workers import run_task


def _shown(text: str) -> str:
    """Text that may hold bytes that aren't UTF-8 (kept as surrogates), made displayable.
    Qt would silently drop them, so "café" in Latin-1 would show as "caf"."""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


class ToolsPage(Page):
    def __init__(self):
        super().__init__("Tools", "Generators, checksums and secure deletion.")
        self._gen_card()
        self._tester_card()
        self._hash_card()
        self._minisign_card()
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
        c.add(divider())
        c.add(label("COMPARE AND MANIFESTS", "label"))
        compare = Button("Compare two files…", "file")
        compare.clicked.connect(self._compare_files)
        make = Button("Create folder manifest…", "folder")
        make.clicked.connect(self._make_manifest)
        check = Button("Verify folder manifest…", "check")
        check.clicked.connect(self._verify_manifest)
        c.add(hrow(compare, make, check, None))
        c.add(label("A manifest lists a checksum for every file in a folder (sha256sum --tag format), so the "
                    "whole folder can be checked later or on another computer. Uses the algorithm above; "
                    "MD5 is not offered for manifests.", "faint"))
        self.extra_progress = ProgressPanel()
        self.extra_progress.cancel.connect(lambda: self._extra_task and self._extra_task.cancel())
        c.add(self.extra_progress)
        self.extra_result = label("", "h2")
        c.add(self.extra_result)
        self._extra_task = None
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

    def _run_extra(self, work, done):
        """Run one compare or manifest job at a time, with progress and cancel."""
        if self._extra_task is not None:
            return
        self.extra_result.setText("")
        self.extra_progress.start()

        def end():
            self.extra_progress.finish()
            self._extra_task = None

        self._extra_task = run_task(
            lambda r, c: work(lambda x: r(x, "Working"), c), lambda res: (end(), done(res)),
            lambda m, k: (end(), dialogs.error(m)), self.extra_progress.update_progress,
            lambda: (end(), toast("Cancelled", "x")), parent=self)

    def _compare_files(self):
        a, _ = QFileDialog.getOpenFileName(self, "Choose the first file")
        if not a:
            return
        b, _ = QFileDialog.getOpenFileName(self, "Choose the second file", str(Path(a).parent))
        if not b:
            return
        self._run_extra(lambda p, c: tools.same_contents(Path(a), Path(b), p, c),
                        lambda same: self.extra_result.setText(
                            "✓  The files are identical" if same else "✕  The files differ"))

    def _manifest_alg(self) -> str | None:
        alg = self.hash_alg.value()
        if alg not in tools.MANIFEST_TAGS:
            dialogs.error("MD5 is broken: someone could swap a file for another with the same MD5. "
                          "Choose SHA-256 or another algorithm above.", "Choose another algorithm")
            return None
        return alg

    def _make_manifest(self):
        alg = self._manifest_alg()
        folder = alg and QFileDialog.getExistingDirectory(self, "Choose the folder to list")
        if not folder:
            return
        default = Path(folder) / f"{tools.MANIFEST_TAGS[alg]}SUMS"
        out, _ = QFileDialog.getSaveFileName(self, "Save manifest", str(default))
        if not out:
            return

        def work(p, c):
            text = tools.make_manifest(Path(folder), alg, exclude=Path(out), progress=p, cancel=c)
            write_secret_file(Path(out), text.encode("utf-8", "surrogateescape"))
            return text.count("\n")

        self._run_extra(work, lambda n: self.extra_result.setText(
            f"✓  Listed {n} file{'s' if n != 1 else ''} in {Path(out).name}"))

    def _verify_manifest(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the manifest")
        if not path:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose the folder it lists", str(Path(path).parent))
        if not folder:
            return

        def work(p, c):
            text = tools.read_text(Path(path), tools.MAX_MANIFEST, "a manifest")
            return tools.verify_manifest(text, Path(folder), exclude=Path(path), progress=p, cancel=c)

        self._run_extra(work, self._manifest_done)

    def _manifest_done(self, rep):
        if rep.ok:
            self.extra_result.setText(f"✓  All {len(rep.matched)} files match the manifest")
            return
        self.extra_result.setText(f"✕  {len(rep.matched)} match · {len(rep.changed)} changed · "
                                  f"{len(rep.missing)} missing · {len(rep.extra)} not listed · "
                                  f"{len(rep.invalid)} unusable lines")
        sections = (("Changed", rep.changed), ("Missing or not a regular file", rep.missing),
                    ("In the folder but not listed", rep.extra), ("Unusable lines", rep.invalid))
        dialogs.text_view("Manifest differences", "\n\n".join(
            f"{title}:\n" + "\n".join(f"  {_shown(n)}" for n in names) for title, names in sections if names))

    # ── minisign ──

    def _minisign_card(self):
        c = Collapsible("Verify a minisign signature", "Check a download against its .minisig file",
                        icon="fingerprint")
        self.ms_file = self.ms_sig = None
        self.ms_file_name = label("No file selected", "caption", False)
        pick = Button("Choose file…", "file")
        pick.clicked.connect(self._ms_pick_file)
        c.add(hrow(pick, self.ms_file_name, None))
        self.ms_sig_name = label("No signature selected", "caption", False)
        pick_sig = Button("Signature…", "fingerprint")
        pick_sig.clicked.connect(self._ms_pick_sig)
        c.add(hrow(pick_sig, self.ms_sig_name, None))
        self.ms_key = LineEdit("Public key, e.g. RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3", mono=True)
        self.ms_key.add_action("file", "Load a .pub file", self._ms_load_key)
        c.add(self.ms_key)
        self.ms_go = Button("Verify", "check", "primary")
        self.ms_go.clicked.connect(self._ms_verify)
        c.add(hrow(self.ms_go, None))
        self.ms_progress = ProgressPanel()
        self.ms_progress.cancel_btn.setVisible(False)
        c.add(self.ms_progress)
        self.ms_result = label("", "h2")
        c.add(self.ms_result)
        self.ms_comment = label("", "caption")
        c.add(self.ms_comment)
        c.add(label("A valid signature proves the file was signed with this key. Get the key from a source "
                    "you trust, such as the project's website, not from the same place as the download.",
                    "faint"))
        self.add(c)

    def _ms_reset(self):
        self.ms_result.setText("")
        self.ms_comment.setText("")

    def _ms_pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signed file")
        if not path:
            return
        self.ms_file = Path(path)
        self.ms_file_name.setText(self.ms_file.name)
        sig = Path(path + ".minisig")
        if sig.is_file():
            self.ms_sig = sig
            self.ms_sig_name.setText(sig.name)
        self._ms_reset()

    def _ms_pick_sig(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signature", "",
                                              "Minisign signatures (*.minisig);;All files (*)")
        if path:
            self.ms_sig = Path(path)
            self.ms_sig_name.setText(self.ms_sig.name)
            self._ms_reset()

    def _ms_load_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the public key", "",
                                              "Minisign public keys (*.pub);;All files (*)")
        if not path:
            return
        try:
            key_id, pk = minisign.parse_public_key(minisign.read_small(Path(path)))
        except (LocksmithError, OSError) as e:
            dialogs.error(str(e))
            return
        self.ms_key.setText(base64.b64encode(b"Ed" + key_id + pk).decode())
        self._ms_reset()

    def _ms_verify(self):
        if not (self.ms_file and self.ms_sig and self.ms_key.text().strip()):
            toast("Choose the file, its signature and the public key", "alert")
            return
        f, sig, key = self.ms_file, self.ms_sig, self.ms_key.text()
        self._ms_reset()
        self.ms_progress.start()
        self.ms_go.setEnabled(False)

        def end():
            self.ms_progress.finish()
            self.ms_go.setEnabled(True)

        def done(v):
            end()
            self.ms_result.setText(f"✓  Valid signature from key {v.key_id}")
            self.ms_comment.setText(f"Trusted comment: {_shown(v.trusted_comment)}")

        def failed(m, k):
            end()
            self.ms_result.setText("✕  Not verified")
            self.ms_comment.setText(m)

        run_task(lambda r, c: minisign.verify_file(f, minisign.read_small(sig), key, lambda x: r(x, "Hashing"), c),
                 done, failed, self.ms_progress.update_progress, parent=self)

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
