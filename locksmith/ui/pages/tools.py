from __future__ import annotations

import base64
import os
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QFileDialog, QSlider

from ...core import keys, minisign, openpgp, parity, signing, sshsig, tools
from ...core.errors import LocksmithError
from ...core.keys import write_secret_file
from ...core.osutil import is_link
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
    human_size,
    label,
    toast,
)
from ..workers import run_task
from .common import saved_signers, signed_with


def _shown(text: str) -> str:
    """Text that may hold bytes that aren't UTF-8 (kept as surrogates), made displayable.
    Qt would silently drop them, so "café" in Latin-1 would show as "caf"."""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


class ToolsPage(Page):
    def __init__(self, store):
        super().__init__("Tools", "Generators, checksums, signatures and secure deletion.")
        self.store = store
        self._gen_card()
        self._tester_card()
        self._hash_card()
        self._sign_card()
        self._lsig_card()
        self._minisign_card()
        self._sshsig_card()
        self._openpgp_card()
        self._recovery_card()
        self._keyfile_card()
        self._shred_card()
        self.finish()
        self.reload()

    def reload(self):
        """Called when identities or contacts change."""
        signers = {i: ident.name for i, ident in enumerate(self.store.identities) if ident.can_sign}
        self.sg_ident.set_items(signers)
        self.sg_ident.setVisible(bool(signers))
        self.sg_go.setEnabled(bool(signers))
        self.sg_none.setVisible(not signers)

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

    # ── Locksmith signatures ──

    def _sign_card(self):
        c = Collapsible("Sign a file", "Make a detached signature with one of your identities", icon="fingerprint")
        self.sg_file = None
        self.sg_ident = Dropdown()
        c.add(Field("Sign as", self.sg_ident))
        self.sg_none = label("Signing needs a post-quantum identity. Create one, or upgrade a classical one, on "
                             "the Keys page.", "caption")
        c.add(self.sg_none)
        self.sg_file_name = label("No file selected", "caption", False)
        pick = Button("Choose file…", "file")
        pick.clicked.connect(self._sg_pick_file)
        c.add(hrow(pick, self.sg_file_name, None))
        self.sg_comment = LineEdit("Comment (optional, signed with the file), e.g. “Release 1.0”")
        c.add(self.sg_comment)
        self.sg_go = Button("Sign…", "check", "primary")
        self.sg_go.clicked.connect(self._sign)
        c.add(hrow(self.sg_go, None))
        self.sg_progress = ProgressPanel()
        self.sg_progress.cancel_btn.setVisible(False)
        c.add(self.sg_progress)
        c.add(label("The signature is saved as a separate .lsig file. Anyone with your public key can check that "
                    "the file was signed with your key and hasn't changed since.", "faint"))
        self.add(c)

    def _sg_pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the file to sign")
        if path:
            self.sg_file = Path(path)
            self.sg_file_name.setText(self.sg_file.name)

    def _sign(self):
        i = self.sg_ident.value()
        if i is None or i >= len(self.store.identities) or not self.sg_file:
            toast("Choose an identity and the file to sign", "alert")
            return
        ident, f, comment = self.store.identities[i], self.sg_file, self.sg_comment.text()
        try:
            signing.check_comment(comment)
        except LocksmithError as e:
            dialogs.error(str(e))
            return
        out, _ = QFileDialog.getSaveFileName(self, "Save signature", str(f) + signing.EXTENSION,
                                             "Locksmith signatures (*.lsig);;All files (*)")
        if not out:
            return
        passphrase = None
        if ident.is_locked:
            passphrase = dialogs.prompt("Identity passphrase", f"Unlock “{ident.name}” to sign.", "Passphrase",
                                        secret=True, ok="Sign")
            if not passphrase:
                return
        out = Path(out)

        def work(r, c):
            text = signing.sign_file(f, ident.private_raw(passphrase), comment, progress=lambda x: r(x, "Hashing"),
                                     cancel=c)
            write_secret_file(out, text)
            return out

        def end():
            self.sg_progress.finish()
            self.sg_go.setEnabled(True)

        def done(path):
            end()
            toast(f"Signed. Saved {path.name}", "fingerprint")

        def failed(m, k):
            end()
            dialogs.error(m, "Not signed")

        self.sg_progress.start()
        self.sg_go.setEnabled(False)
        run_task(work, done, failed, self.sg_progress.update_progress, parent=self)

    def _lsig_card(self):
        c = Collapsible("Verify a Locksmith signature", "Check a file against its .lsig file", icon="shield")
        self.ls_file = self.ls_sig = None
        self.ls_file_name = label("No file selected", "caption", False)
        pick = Button("Choose file…", "file")
        pick.clicked.connect(self._ls_pick_file)
        c.add(hrow(pick, self.ls_file_name, None))
        self.ls_sig_name = label("No signature selected", "caption", False)
        pick_sig = Button("Signature…", "fingerprint")
        pick_sig.clicked.connect(self._ls_pick_sig)
        c.add(hrow(pick_sig, self.ls_sig_name, None))
        self.ls_key = LineEdit("Signer's public key (optional: otherwise your saved keys are tried)", mono=True)
        c.add(self.ls_key)
        self.ls_go = Button("Verify", "check", "primary")
        self.ls_go.clicked.connect(self._ls_verify)
        c.add(hrow(self.ls_go, None))
        self.ls_progress = ProgressPanel()
        self.ls_progress.cancel_btn.setVisible(False)
        c.add(self.ls_progress)
        self.ls_result = label("", "h2")
        c.add(self.ls_result)
        self.ls_detail = label("", "caption")
        c.add(self.ls_detail)
        self.ls_comment = label("", "caption")
        c.add(self.ls_comment)
        c.add(label("A valid signature proves the file was signed with that key and hasn't changed since. Whose key "
                    "it is depends on having checked its fingerprint with its owner.", "faint"))
        self.add(c)

    def _ls_reset(self):
        for w in (self.ls_result, self.ls_detail, self.ls_comment):
            w.setText("")

    def _ls_pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signed file")
        if not path:
            return
        self.ls_file = Path(path)
        self.ls_file_name.setText(self.ls_file.name)
        sig = Path(path + signing.EXTENSION)
        if sig.is_file():
            self.ls_sig = sig
            self.ls_sig_name.setText(sig.name)
        self._ls_reset()

    def _ls_pick_sig(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signature", "",
                                              "Locksmith signatures (*.lsig);;All files (*)")
        if path:
            self.ls_sig = Path(path)
            self.ls_sig_name.setText(self.ls_sig.name)
            self._ls_reset()

    def _ls_verify(self):
        if not (self.ls_file and self.ls_sig):
            toast("Choose the file and its signature", "alert")
            return
        self._ls_reset()
        saved = saved_signers(self.store)
        typed = self.ls_key.text().strip()
        if typed:
            try:
                raw = keys.decode_public(typed)
            except LocksmithError as e:
                self.ls_result.setText("✕  Not verified")
                self.ls_detail.setText(str(e))
                return
            candidates = {raw: saved.get(raw)}
        else:
            candidates = saved
        f, sig = self.ls_file, self.ls_sig
        self.ls_progress.start()
        self.ls_go.setEnabled(False)

        def end():
            self.ls_progress.finish()
            self.ls_go.setEnabled(True)

        def done(v):
            end()
            name = candidates.get(v.key)
            self.ls_result.setText(signed_with(v.key, saved) if name else "✓  Signed with the key you entered")
            try:
                when = time.strftime("%d %b %Y, %H:%M", time.localtime(v.created))
            except (OverflowError, OSError, ValueError):
                when = str(v.created)
            self.ls_detail.setText(f"Fingerprint {v.fingerprint}  ·  signed {when} (by the signer's clock)")
            self.ls_comment.setText(f"Signed comment: {v.comment}" if v.comment else "No comment")

        def failed(m, k):
            end()
            self.ls_result.setText("✕  Not verified")
            if k == "UnknownSignerError":
                m += (" A signature can claim any fingerprint. Paste the signer's public key above, or add them as a "
                      "contact after checking their fingerprint with them, and verify again.")
            self.ls_detail.setText(m)

        run_task(lambda r, c: signing.verify_file(f, signing.read_small(sig), list(candidates),
                                                  lambda x: r(x, "Hashing"), c),
                 done, failed, self.ls_progress.update_progress, parent=self)

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
            self.ms_comment.setText(f"Trusted comment: {tools.display_text(_shown(v.trusted_comment))}")

        def failed(m, k):
            end()
            self.ms_result.setText("✕  Not verified")
            self.ms_comment.setText(m)

        run_task(lambda r, c: minisign.verify_file(f, minisign.read_small(sig), key, lambda x: r(x, "Hashing"), c),
                 done, failed, self.ms_progress.update_progress, parent=self)

    # ── SSH signatures ──

    def _sshsig_card(self):
        c = Collapsible("Verify an SSH signature", "Check a file against a signature made with ssh-keygen -Y sign",
                        icon="key")
        self.ss_file = self.ss_sig = None
        self.ss_file_name = label("No file selected", "caption", False)
        pick = Button("Choose file…", "file")
        pick.clicked.connect(self._ss_pick_file)
        c.add(hrow(pick, self.ss_file_name, None))
        self.ss_sig_name = label("No signature selected", "caption", False)
        pick_sig = Button("Signature…", "fingerprint")
        pick_sig.clicked.connect(self._ss_pick_sig)
        c.add(hrow(pick_sig, self.ss_sig_name, None))
        self.ss_key = LineEdit("Public key, e.g. ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI…", mono=True)
        self.ss_key.add_action("file", "Load a .pub file", self._ss_load_key)
        c.add(self.ss_key)
        self.ss_namespace = LineEdit("file", mono=True)
        self.ss_namespace.setText("file")
        c.add(Field("Namespace", self.ss_namespace,
                    "What the signature is for: “file” for ssh-keygen -Y sign -n file, “git” for Git commits."))
        self.ss_go = Button("Verify", "check", "primary")
        self.ss_go.clicked.connect(self._ss_verify)
        c.add(hrow(self.ss_go, None))
        self.ss_progress = ProgressPanel()
        self.ss_progress.cancel_btn.setVisible(False)
        c.add(self.ss_progress)
        self.ss_result = label("", "h2")
        c.add(self.ss_result)
        self.ss_detail = label("", "caption")
        c.add(self.ss_detail)
        c.add(label("A valid signature proves the file was signed with this key. Get the key from a source "
                    "you trust, not from the same place as the file. Security-key (sk-) signatures, "
                    "certificates and RSA keys under 2048 bits are not accepted.", "faint"))
        self.add(c)

    def _ss_reset(self):
        self.ss_result.setText("")
        self.ss_detail.setText("")

    def _ss_pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signed file")
        if not path:
            return
        self.ss_file = Path(path)
        self.ss_file_name.setText(self.ss_file.name)
        sig = Path(path + ".sig")
        if sig.is_file():
            self.ss_sig = sig
            self.ss_sig_name.setText(sig.name)
        self._ss_reset()

    def _ss_pick_sig(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signature", "",
                                              "SSH signatures (*.sig);;All files (*)")
        if path:
            self.ss_sig = Path(path)
            self.ss_sig_name.setText(self.ss_sig.name)
            self._ss_reset()

    def _ss_load_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the public key", "",
                                              "SSH public keys (*.pub);;All files (*)")
        if not path:
            return
        try:
            key = sshsig.parse_public_key(sshsig.read_small(Path(path)))
        except (LocksmithError, OSError) as e:
            dialogs.error(str(e))
            return
        # The key file's comment is left out: nothing vouches for it.
        self.ss_key.setText(f"{key.key_type} {base64.b64encode(key.blob).decode()}")
        self._ss_reset()

    def _ss_verify(self):
        if not (self.ss_file and self.ss_sig and self.ss_key.text().strip()):
            toast("Choose the file, its signature and the public key", "alert")
            return
        f, sig, key, namespace = self.ss_file, self.ss_sig, self.ss_key.text(), self.ss_namespace.text()
        self._ss_reset()
        self.ss_progress.start()
        self.ss_go.setEnabled(False)

        def end():
            self.ss_progress.finish()
            self.ss_go.setEnabled(True)

        def done(v):
            end()
            self.ss_result.setText(f"✓  Valid signature from key {v.fingerprint}")
            self.ss_detail.setText(f"{v.key_label} key  ·  namespace “{v.namespace}”  ·  {v.hash_algorithm.upper()}")

        def failed(m, k):
            end()
            self.ss_result.setText("✕  Not verified")
            self.ss_detail.setText(m)

        run_task(lambda r, c: sshsig.verify_file(f, sshsig.read_small(sig), key, namespace,
                                                 lambda x: r(x, "Hashing"), c),
                 done, failed, self.ss_progress.update_progress, parent=self)

    # ── OpenPGP signatures ──

    def _openpgp_card(self):
        c = Collapsible("Verify an OpenPGP signature", "Check a download against its .sig or .asc file (GnuPG)",
                        icon="shield")
        self.pg_file = self.pg_sig = self.pg_key = None
        self.pg_file_name = label("No file selected", "caption", False)
        pick = Button("Choose file…", "file")
        pick.clicked.connect(self._pg_pick_file)
        c.add(hrow(pick, self.pg_file_name, None))
        self.pg_sig_name = label("No signature selected", "caption", False)
        pick_sig = Button("Signature…", "fingerprint")
        pick_sig.clicked.connect(self._pg_pick_sig)
        c.add(hrow(pick_sig, self.pg_sig_name, None))
        self.pg_key_name = label("No public key selected", "caption", False)
        pick_key = Button("Public key…", "key")
        pick_key.clicked.connect(self._pg_pick_key)
        c.add(hrow(pick_key, self.pg_key_name, None))
        self.pg_go = Button("Verify", "check", "primary")
        self.pg_go.clicked.connect(self._pg_verify)
        c.add(hrow(self.pg_go, None))
        self.pg_progress = ProgressPanel()
        self.pg_progress.cancel_btn.setVisible(False)
        c.add(self.pg_progress)
        self.pg_result = label("", "h2")
        c.add(self.pg_result)
        self.pg_detail = label("", "caption")
        c.add(self.pg_detail)
        c.add(label("Checks a detached signature against the one public key you choose (a .asc or .gpg file from the "
                    "project's website), with no keyring. Version 4 keys and signatures (what GnuPG makes) with "
                    "Ed25519, ECDSA or RSA of 2048 bits or more; SHA-1 and MD5 signatures are refused. The names on a "
                    "key are its owner's own claims.", "faint"))
        self.add(c)

    def _pg_reset(self):
        self.pg_result.setText("")
        self.pg_detail.setText("")

    def _pg_pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signed file")
        if not path:
            return
        self.pg_file = Path(path)
        self.pg_file_name.setText(self.pg_file.name)
        for ext in (".sig", ".asc"):
            if Path(path + ext).is_file():
                self.pg_sig = Path(path + ext)
                self.pg_sig_name.setText(self.pg_sig.name)
                break
        self._pg_reset()

    def _pg_pick_sig(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signature", "",
                                              "OpenPGP signatures (*.sig *.asc *.gpg);;All files (*)")
        if path:
            self.pg_sig = Path(path)
            self.pg_sig_name.setText(self.pg_sig.name)
            self._pg_reset()

    def _pg_pick_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the signer's public key", "",
                                              "OpenPGP keys (*.asc *.gpg *.pgp *.key);;All files (*)")
        if path:
            self.pg_key = Path(path)
            self.pg_key_name.setText(self.pg_key.name)
            self._pg_reset()

    def _pg_verify(self):
        if not (self.pg_file and self.pg_sig and self.pg_key):
            toast("Choose the file, its signature and the signer's public key", "alert")
            return
        f, sig, key = self.pg_file, self.pg_sig, self.pg_key
        self._pg_reset()
        self.pg_progress.start()
        self.pg_go.setEnabled(False)

        def end():
            self.pg_progress.finish()
            self.pg_go.setEnabled(True)

        def done(v):
            end()
            self.pg_result.setText(f"✓  Valid signature from key {v.fingerprint}")
            try:
                when = time.strftime("%d %b %Y, %H:%M", time.localtime(v.created))
            except (OverflowError, OSError, ValueError):
                when = str(v.created)
            lines = [f"{v.key_label}{' subkey ' + v.signing_key if v.signing_key != v.fingerprint else ''}  ·  "
                     f"{v.hash_name}{'  ·  text mode' if v.text_mode else ''}  ·  signed {when} (by the signer's clock)"]
            if v.user_ids:
                lines.append("The key says it belongs to: " + "; ".join(tools.display_text(uid, 200) for uid in v.user_ids) + " (not checked by anyone)")
            if v.expired:
                lines.append("The key has expired since; the signature was made while it was valid.")
            self.pg_detail.setText("\n".join(lines))

        def failed(m, k):
            end()
            self.pg_result.setText("✕  Not verified")
            self.pg_detail.setText(m)

        run_task(lambda r, c: openpgp.verify_file(f, openpgp.read_signature_file(sig), openpgp.read_key_file(key),
                                                  progress=lambda x: r(x, "Hashing"), cancel=c),
                 done, failed, self.pg_progress.update_progress, parent=self)

    # ── recovery data ──

    def _recovery_card(self):
        c = Collapsible("Recovery data", "Protect archives against bit rot and damaged storage", icon="layers")
        c.add(label("Saves a .lpar file next to a file. If the file is later damaged (a failing disk, a scratched "
                    "disc, a bad USB stick), it can be repaired from it, as long as the damage is no more than the "
                    "chosen share of the file. Keep the .lpar file with the original.", "caption"))
        self.rc_level = Dropdown(parity.LABELS)
        self.rc_level.set_value("5")
        make = Button("Create recovery data…", "plus", "primary")
        make.clicked.connect(self._rc_create)
        repair = Button("Check or repair…", "check", "secondary")
        repair.clicked.connect(self._rc_repair)
        c.add(Field("Amount", hrow(self.rc_level, make, repair)))
        self.rc_progress = ProgressPanel()
        self.rc_progress.cancel.connect(lambda: self._rc_task and self._rc_task.cancel())
        c.add(self.rc_progress)
        self.rc_result = label("", "h2")
        c.add(self.rc_result)
        self.rc_detail = label("", "caption")
        c.add(self.rc_detail)
        self._rc_task = None
        self.add(c)

    def _rc_run(self, work, done):
        if self._rc_task is not None:
            return
        self.rc_result.setText("")
        self.rc_detail.setText("")
        self.rc_progress.start()

        def end():
            self.rc_progress.finish()
            self._rc_task = None

        def failed(m, k):
            end()
            self.rc_result.setText("✕  " + ("Not repaired" if "repair" in m else "Failed"))
            self.rc_detail.setText(m)

        self._rc_task = run_task(work, lambda res: (end(), done(res)), failed, self.rc_progress.update_progress,
                                 lambda: (end(), toast("Cancelled", "x")), parent=self)

    def _rc_create(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the file to protect")
        if not path:
            return
        level = self.rc_level.value()
        self._rc_run(lambda r, c: parity.create(Path(path), level, progress=r, cancel=c),
                     lambda out: (self.rc_result.setText(f"✓  Saved {out.name}"),
                                  self.rc_detail.setText(f"{human_size(out.stat().st_size)} of recovery data.")))

    def _rc_repair(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose the file to check")
        if not path:
            return
        side = Path(path + parity.EXTENSION)
        if Path(path).suffix == parity.EXTENSION:
            side, path = Path(path), path[:-len(parity.EXTENSION)]
        if not side.is_file():
            chosen, _ = QFileDialog.getOpenFileName(self, "Choose its recovery data", str(Path(path).parent),
                                                    "Recovery data (*.lpar);;All files (*)")
            if not chosen:
                return
            side = Path(chosen)

        def repaired(rep):
            self.rc_result.setText(f"✓  Repaired {Path(path).name}")
            self.rc_detail.setText(f"{len(rep.damaged)} damaged block{'s' if len(rep.damaged) != 1 else ''} "
                                   f"rebuilt. The damaged copy was kept as {rep.kept.name}. SHA-256 {rep.sha256}.")

        def checked(rep):
            if rep.intact:
                self.rc_result.setText("✓  The file is intact")
                return
            if not rep.repairable:
                self.rc_result.setText("✕  Too damaged to repair")
                self.rc_detail.setText(f"{rep.unrepairable} part{'s' if rep.unrepairable != 1 else ''} of the file "
                                       "lost more blocks than the recovery data can rebuild. Nothing was changed.")
                return
            # Everything a repair is checked against comes from the recovery data, so a sidecar from
            # someone else decides what these blocks become: say how much, and ask.
            self.rc_result.setText(f"{len(rep.damaged)} damaged block{'s' if len(rep.damaged) != 1 else ''}")
            if not dialogs.confirm(
                    "Repair this file?",
                    f"{len(rep.damaged)} block{'s' if len(rep.damaged) != 1 else ''} "
                    f"({rep.rebuilt_fraction:.1%} of {Path(path).name}) don't match the recovery data and would be "
                    f"rebuilt from it. The repaired file's SHA-256 would be {rep.sha256}. The recovery data decides "
                    "what those blocks become, so only repair with recovery data you made or got from a source you "
                    "trust. The damaged copy is kept.", ok="Repair", icon="shield"):
                self.rc_detail.setText("Not repaired.")
                return
            self._rc_run(lambda r, c: parity.repair(Path(path), side, progress=r, cancel=c), repaired)
        self._rc_run(lambda r, c: parity.check(Path(path), side, progress=r, cancel=c), checked)

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
        links = [Path(p).name for p in paths if is_link(p)]
        if links:
            dialogs.error(f"{links[0]} is a link. Removing it would leave what it points to in place. Add the file "
                          "or folder it points to instead.", "Can't shred a link")
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
