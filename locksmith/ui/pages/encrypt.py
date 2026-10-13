from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QGridLayout, QVBoxLayout, QWidget

from ...core import age, compress, engine, kdf, parity, sshkeys, tools
from ...core.ciphers import SUITES
from ...core.engine import EncryptOptions
from ...core.osutil import is_link
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
from .common import OutputPicker, RecipientPicker, reveal, signer_choices, unlock_signer

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
            "can really open it. With several kinds of key (post-quantum, classical, SSH RSA), each kind is "
            "rounded up on its own: the file shows which kinds it has, not how many of each. SSH RSA keys over "
            "4096 bits get no decoys.",
            settings["hide_recipients"])
        rl.addWidget(self.hide_recipients)
        self.rsa_note = label("An SSH RSA recipient is selected. Locksmith 3.0 and earlier can't open such a file at "
                              "all, even with its password.", "caption")
        self.rsa_note.setVisible(False)
        rl.addWidget(self.rsa_note)
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
        self.format = Dropdown({"locked": "Locksmith (.locked)", "age": "age (.age), for age, rage and other age tools"})
        self.format_field = Field("File format", self.format)
        self.format.currentIndexChanged.connect(self._update_state)
        adv.add(self.format_field)
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
        self.recovery = ToggleRow("Add recovery data",
                                  "Also saves a .lpar file (5% of the size) that can repair the encrypted file if "
                                  "its storage is damaged later. Useful for long-term archives.",
                                  settings["recovery_data"])
        for t in (self.hide_name, self.bundle, self.armor, self.strip, self.recovery, self.shred):
            adv.add(t)
        self.bundle.toggled.connect(self._update_state)
        self.keyfile.changed.connect(self._update_state)
        self.note = LineEdit("Private note, stored encrypted inside the file")
        adv.add(Field("Note", self.note))
        self.add(adv)

        # ── signing, output & action ──
        self.sign_as = Dropdown()
        self.sign_field = Field("Sign as", self.sign_as, "Whoever opens the file can check it was signed with "
                                "your key and hasn't changed since.")
        self.add(self.sign_field)
        # On by default (audit B7): without a list, anyone who can open a signed file can re-send it to someone
        # else, and it still shows as signed, with nothing saying it was meant for someone else.
        self.address = ToggleRow("Address it to the selected people",
                                 "Lists the recipients inside the signed file, so whoever opens it can tell whether "
                                 "they were one of them, and a copy passed on to someone else says so. Everyone who "
                                 "can open it can read the list.", True)
        self._address_wanted = True   # the user's choice, kept while no recipient is selected
        self.address_note = label("", "caption")
        self.add(self.address)
        self.add(self.address_note)
        self.sign_as.currentIndexChanged.connect(self._update_state)
        self.address.toggled.connect(self._address_toggled)
        self.reload_signers()
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
        is_age = self.format.value() == "age"
        self.rsa_note.setVisible(not is_age and mode in (1, 2)
                                 and any(map(sshkeys.is_rsa_raw, self.recipients.selected())))
        self.format_field.set_caption(
            "age files use ChaCha20-Poly1305, and scrypt for a password. They have no signature, keyfile, size "
            "padding, note, decoy recipients or stored file name, and a folder becomes a .tar archive. A password "
            "and recipients can't be combined. Post-quantum keys stay post-quantum (age 1.3 or later)."
            if is_age else "")
        signing = not self.sign_field.isHidden() and isinstance(self.sign_as.value(), int)
        has_keys = mode in (1, 2) and bool(self.recipients.selected())
        self.address.setVisible(signing)
        self.address.setEnabled(has_keys)
        self.address.setChecked(has_keys and self._address_wanted)
        self.address_note.setText("" if has_keys else
                                  "Only files with public-key recipients can be addressed: a password or keyfile "
                                  "has no key to list.")
        self.address_note.setVisible(signing and not has_keys)
        n = len(self.files.paths())
        self.go.setText("Encrypt" if n <= 1 else
                        (f"Encrypt {n} items" if not self.bundle.isChecked() else f"Encrypt {n} items as one"))

    def _address_toggled(self, on: bool):
        if self.address.isEnabled():   # the user's choice, not _update_state turning it off
            self._address_wanted = on
        self._update_state()

    def add_paths(self, paths):
        self.files.add(paths)

    def reload_signers(self):
        """Called when identities change."""
        choices = signer_choices(self.store)
        self.sign_as.set_items(choices)
        self.sign_field.setVisible(len(choices) > 1)
        if hasattr(self, "go"):
            self._update_state()

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
            address_to=not self.address.isHidden() and self.address.isEnabled() and self.address.isChecked(),
        )

    # ── run ──

    def start(self):
        paths = [Path(p) for p in self.files.paths()]
        if not paths:
            return
        links = [p.name for p in paths if is_link(p)]
        if links:
            # Checked before anything runs: each item is encrypted (and shredded) in turn.
            dialogs.error(f"{links[0]} is a link. Add the file or folder it points to instead.", "Can't encrypt a link")
            return
        opts = self.options()
        is_age = self.format.value() == "age"
        if is_age and (problem := self._age_problem(opts)):
            dialogs.error(problem, "Not possible in an age file")
            return
        if opts.password and tools.strength_label(tools.estimate_entropy(opts.password))[0] <= 1:
            if not dialogs.confirm("Weak password",
                                   "This password could be guessed quickly. Use it anyway?",
                                   ok="Use anyway"):
                return
        if opts.address_to and opts.hide_recipients and not dialogs.confirm(
                "Recipients will see the list",
                "Addressing the file lists its recipients inside it, and everyone who can open it can read that "
                "list: they'll see who else it was sent to and how many people that is. Toward them, that undoes "
                "“Hide the number of recipients”, which still hides the number from everyone else. Continue?",
                ok="Sign and address it", icon="user"):
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
        signer = unlock_signer(self.store, self.sign_as.value())
        if signer is None:
            return
        out_dir = self.output.directory()
        recovery = self.recovery.isChecked()
        bundle = self.bundle.isChecked() and len(paths) > 1
        groups = [paths] if bundle else [[p] for p in paths]
        if is_age:
            ssh_blobs = {c.public_raw: c.ssh.blob for c in self.store.contacts
                         if c.ssh is not None and c.ssh.key_type == "ssh-ed25519"}
            age_recipients = [age.recipient_for(r, ssh_blobs.get(r)) for r in opts.recipients]
            if any(r.kind.startswith("ssh-") for r in age_recipients) and not dialogs.confirm(
                    "age names SSH recipients",
                    "An age file labels each SSH recipient with a short tag of their key. Anyone with a list of "
                    "public SSH keys (GitHub publishes everyone's) can tell who the file is for. Locksmith files "
                    "don't name their recipients. Continue with age?", ok="Encrypt anyway", icon="user"):
                return
            work_factor = {"fast": 16, "balanced": 18, "strong": 19, "paranoid": 20}[opts.preset]

        def work_age(report, cancel):
            outputs, stats = [], {}
            n = len(groups)
            for i, group in enumerate(groups):
                def sub(frac, stage, i=i):
                    report(None if frac is None else (i + frac) / n,
                           stage + (f"  ·  {i + 1} of {n}" if n > 1 else ""))
                outputs.append(age.encrypt_paths(group, out_dir, age_recipients, opts.password, opts.armor,
                                                 progress=sub, cancel=cancel, verify=shred, work_factor=work_factor,
                                                 strip=opts.strip_metadata, hide_name=opts.hide_name, stats=stats))
                if recovery:
                    parity.create(outputs[-1], "5", progress=sub, cancel=cancel)
                if shred:
                    for p in group:
                        report(None, f"Shredding {p.name}")
                        tools.shred(p, cancel=cancel)
            return outputs, stats

        def work(report, cancel):
            if is_age:
                return work_age(report, cancel)
            ident, passphrase = signer
            # Unlocking may run Argon2id, so it happens here, off the UI thread.
            opts.signer = ident.private_raw(passphrase) if ident else None
            outputs, stats = [], {}
            n = len(groups)
            for i, group in enumerate(groups):
                def sub(frac, stage, i=i):
                    report(None if frac is None else (i + frac) / n,
                           stage + (f"  ·  {i + 1} of {n}" if n > 1 else ""))
                # Shredding requires proof the encrypted copy on disk is intact.
                outputs.append(engine.encrypt_paths(group, out_dir, opts, progress=sub, cancel=cancel,
                                                    verify=shred, stats=stats))
                if recovery:
                    parity.create(outputs[-1], "5", progress=sub, cancel=cancel)
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

    def _age_problem(self, opts: EncryptOptions) -> str | None:
        """Why these settings can't make an age file, if they can't. Options that protect
        privacy or authenticity are refused rather than silently left out."""
        if opts.keyfile:
            return "age files can't use a keyfile. Remove it, or choose the Locksmith format."
        if opts.password and opts.recipients:
            return ("An age file opens either with a password or with public keys, not both. Choose one, or the "
                    "Locksmith format.")
        if isinstance(self.sign_as.value(), int) and not self.sign_field.isHidden():
            return "age files can't be signed. Choose “Don't sign”, or the Locksmith format."
        if opts.padding != "none":
            return "age files have no size padding. Set Size padding to None, or choose the Locksmith format."
        if opts.note:
            return "age files can't hold a note. Clear it, or choose the Locksmith format."
        if opts.hide_recipients:
            return ("age files can't hide the number of recipients. Turn that off, or choose the Locksmith "
                    "format.")
        if len({len(r) == 1216 for r in opts.recipients}) > 1:
            return ("age doesn't mix post-quantum and classical recipients in one file: it would be only as strong "
                    "as the classical ones. Choose one kind, or the Locksmith format.")
        return None

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
