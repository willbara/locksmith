from __future__ import annotations

from PySide6.QtWidgets import QGridLayout

from ... import __version__
from ...core import compress, desktop, engine, kdf
from ...core.ciphers import SUITES
from ...core.errors import LocksmithError
from ...core.keys import config_dir
from ...core.osutil import IS_WINDOWS
from .. import dialogs, host
from ..settings import settings
from ..theme import theme
from ..widgets import Button, Card, Dropdown, Field, Page, ToggleRow, hrow, label, toast
from .common import open_url
from .encrypt import THREADS


def protection_summary(h, display: str = "") -> list[str]:
    """One honest line per protection, for this platform. ``display``: Qt's platform plugin name."""
    if IS_WINDOWS:
        return [
            "DLL-injection protection: " + ("active (extension points disabled, no remote or low-integrity "
                                            "libraries)" if h.injection_blocked else "not accepted by this Windows"),
            "Crash-dump and memory-reading protection: not available on Windows.",
            "Network block: not available on Windows.",
            "TPM sealing: not available currently.",
        ]
    return [
        "Memory protection: on (core dumps disabled, other programs running as you refused access to this "
        "process's memory)" if h.ok else "Memory protection: unavailable. " + " ".join(h.problems),
        "Network block: on (a seccomp filter refuses internet sockets)"
        if h.network_blocked else "Network block: unavailable on this system.",
    ] + (["Display: X11. Any program on this display can read what you type, passwords included, and what "
          "Locksmith shows. A Wayland session keeps each app's input and window to itself."]
         if display == "xcb" else [])


class SettingsPage(Page):
    def __init__(self, on_defaults_changed):
        super().__init__("Settings", "Appearance and the defaults used for new encryptions.")
        self.on_defaults_changed = on_defaults_changed

        look = Card("Appearance")
        self.theme = Dropdown({"dark": "Dark", "light": "Light", "system": "Match system"})
        self.theme.set_value(settings["theme"])
        self.theme.currentIndexChanged.connect(self._theme)
        look.add(Field("Theme", self.theme))
        self.anim = ToggleRow("Animations", "Smooth transitions throughout the app.", settings["animations"])
        self.anim.toggled.connect(self._anim)
        look.add(self.anim)
        self.add(look)

        from ..lock import LOCK_SHORTCUT, PANIC_SHORTCUT
        security = Card("Security")
        self.lock_changed = lambda minutes: None   # set by the main window
        self.auto_lock = Dropdown({0: "Never", 1: "After 1 minute", 5: "After 5 minutes",
                                   10: "After 10 minutes", 15: "After 15 minutes", 30: "After 30 minutes",
                                   60: "After 1 hour"})
        self.auto_lock.set_value(settings["auto_lock"])
        self.auto_lock.currentIndexChanged.connect(self._auto_lock)
        security.add(Field("Auto-lock when idle", self.auto_lock,
                           "Locking clears passwords and decrypted content from the window."))
        security.add(label(f"{LOCK_SHORTCUT}  locks now.   {PANIC_SHORTCUT}  (panic) locks, clears everything "
                           "and minimizes the window. Shortcuts work while Locksmith is focused.", "caption"))
        security.add(label("Copied passwords and decrypted text are hidden from clipboard managers and "
                           "cleared from the clipboard after 30 seconds.", "caption"))
        self.add(security)

        defaults = Card("Encryption defaults", "Used when the app starts. You can still change them per file.")
        g = QGridLayout()
        g.setSpacing(14)
        self.fields = {
            "suite": Dropdown({k: s.label for k, s in SUITES.items()}),
            "preset": Dropdown(kdf.PRESETS),
            "kdf": Dropdown({k: v.label for k, v in kdf.KDFS.items()}),
            "compression": Dropdown({"auto": "Automatic", **{k: c.label for k, c in compress.CODECS.items()},
                                     "none": "None"}),
            "padding": Dropdown(engine.PADDING),
            "threads": Dropdown(THREADS),
        }
        names = {"suite": "Algorithm", "preset": "Key strength", "kdf": "Key derivation",
                 "compression": "Compression", "padding": "Size padding", "threads": "Worker threads"}
        for i, (key, dd) in enumerate(self.fields.items()):
            dd.set_value(settings[key])
            dd.currentIndexChanged.connect(lambda _=0, k=key, d=dd: self._set(k, d.value()))
            g.addWidget(Field(names[key], dd), i // 2, i % 2)
        g.setColumnStretch(0, 1)
        g.setColumnStretch(1, 1)
        defaults.add(g)
        for key, title, caption in (
            ("hide_name", "Hide file names", "Random names for encrypted files."),
            ("hide_recipients", "Hide the number of recipients", "Add decoy recipient slots."),
            ("bundle", "Bundle multiple items", "Encrypt several items into one file."),
            ("armor", "ASCII armor", "Produce text output instead of binary."),
            ("strip_metadata", "Remove photo metadata", "Strip location and camera details from images."),
            ("recovery_data", "Add recovery data", "Save a .lpar file that can repair encrypted files later."),
            ("delete_after_decrypt", "Delete encrypted file after decrypting", ""),
            ("confirm_shred", "Confirm before shredding", ""),
        ):
            t = ToggleRow(title, caption, settings[key])
            t.toggled.connect(lambda on, k=key: self._set(k, on))
            defaults.add(t)
        self.add(defaults)

        integration = Card("Desktop integration", "Open .locked files with Locksmith, and add “Encrypt with "
                           "Locksmith” to the file manager's right-click menu, for your account only.")
        integration.add(label("Linux: GNOME Files (under Scripts), KDE Dolphin and Nemo, plus the application menu "
                              "entry. Windows: Explorer (under “Show more options” on Windows 11). Each entry starts "
                              "Locksmith from where it is now: add it again if you move it.", "caption"))
        self.integration_state = label("", "caption")
        integration.add(self.integration_state)
        self.integrate = Button("Add to the desktop", "plus", "secondary")
        self.integrate.clicked.connect(self._integrate)
        self.unintegrate = Button("Remove", "trash", "ghost")
        self.unintegrate.clicked.connect(self._unintegrate)
        integration.add(hrow(self.integrate, self.unintegrate, None))
        self.add(integration)
        self._integration_status()

        about = Card("About")
        about.add(label(f"Locksmith {__version__}", "h2"))
        about.add(label(
            "Streaming authenticated encryption with a random 256-bit file key, wrapped per password or "
            "recipient. Frames are bound to their position and to the file header, so reordering, "
            "truncation and tampering are detected. Keys are derived with HKDF-SHA512 and include a key "
            "commitment. Public-key sharing uses X25519 + ML-KEM-768 (post-quantum).", "caption"))
        from PySide6.QtGui import QGuiApplication

        from ...hardening import status as hardening
        for line in protection_summary(hardening, QGuiApplication.platformName()):
            about.add(label(line, "caption"))
        self.key_protection = label("", "caption")
        self.key_protection.setVisible(False)
        about.add(self.key_protection)
        about.add(label(f"Settings and keys live in {config_dir()}", "faint"))
        folder = Button("Open settings folder", "folder", "ghost")
        folder.clicked.connect(lambda: open_url(config_dir().as_uri()))
        about.add(hrow(folder, None))
        self.add(about)
        self.finish()

    def show_key_protection(self, store):
        """Say how many identities are stored without a passphrase or TPM seal (audit A5)."""
        n = len(store.unprotected)
        self.key_protection.setText(
            f"{n} identit{'ies are' if n != 1 else 'y is'} stored without a passphrase or TPM seal: any program "
            "running as you, or a copy of the settings folder, can use "
            f"{'them' if n != 1 else 'it'}. Add a passphrase on the Keys page." if n else "")
        self.key_protection.setVisible(bool(n))

    def _integration_status(self):
        on = desktop.installed()
        self.integration_state.setText("Added: Locksmith opens .locked files and is in the right-click menu." if on else
                                       "Not added.")
        self.integrate.setText("Add again" if on else "Add to the desktop")
        self.unintegrate.setEnabled(on)

    def _integrate(self):
        try:
            if IS_WINDOWS:
                desktop.install_windows()
            else:
                desktop.install_linux()
                for args in desktop.refresh_commands():
                    host.launch(args)   # refresh the desktop's caches; best effort
        except (LocksmithError, OSError) as e:
            dialogs.error(str(e), "Not added")
            return
        self._integration_status()
        toast("Added to the desktop. Some file managers show it after they restart.", "check", 4500)

    def _unintegrate(self):
        try:
            if IS_WINDOWS:
                desktop.uninstall_windows()
            else:
                desktop.uninstall_linux()
                for args in desktop.refresh_commands()[:2]:
                    host.launch(args)
        except OSError as e:
            dialogs.error(str(e), "Not removed")
            return
        self._integration_status()
        toast("Removed from the desktop", "trash")

    def _set(self, key, value):
        settings[key] = value
        self.on_defaults_changed()

    def _auto_lock(self):
        settings["auto_lock"] = self.auto_lock.value()
        self.lock_changed(self.auto_lock.value())

    def _theme(self):
        settings["theme"] = self.theme.value()
        theme.apply(self.theme.value())

    def _anim(self, on):
        settings["animations"] = on
        theme.animations = on
