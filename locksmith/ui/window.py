from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QHBoxLayout, QMainWindow, QWidget

from .. import __version__
from ..core import scratch
from ..core.engine import is_encrypted_name, looks_encrypted
from ..core.keys import KeyStore
from . import dialogs
from .lock import Locker
from .pages.decrypt import DecryptPage
from .pages.encrypt import EncryptPage
from .pages.keys import KeysPage
from .pages.settings_page import SettingsPage
from .pages.share import SharePage
from .pages.tools import ToolsPage
from .settings import settings
from .theme import app_icon
from .widgets import AnimatedStack, Sidebar, Toaster, clear_clipboard_secret
from .workers import run_task

NAV = [("Encrypt", "lock"), ("Decrypt", "unlock"), ("Share", "share"), ("Keys", "key"),
       ("Tools", "tool"), ("-", ""), ("Settings", "settings")]


class MainWindow(QMainWindow):
    def __init__(self, open_paths: list[str] | None = None):
        super().__init__()
        self.setWindowTitle("Locksmith")
        self.setWindowIcon(app_icon())
        self.resize(1120, 800)
        self.setMinimumSize(820, 600)
        self.store = KeyStore()
        # Plaintext temporary files a killed run left behind are shredded in the background.
        scratch.enable(self.store.dir / "scratch.json")
        run_task(lambda r, c: scratch.clean_leftovers())

        root = QWidget()
        root.setObjectName("root")
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.sidebar = Sidebar(NAV)
        self.sidebar.footer.setText(f"v{__version__}")
        lay.addWidget(self.sidebar)
        self.stack = AnimatedStack()
        self.stack.setObjectName("content")
        lay.addWidget(self.stack, 1)
        self.setCentralWidget(root)

        self.encrypt = EncryptPage(self.store)
        self.decrypt = DecryptPage(self.store)
        self.share = SharePage(self.store)
        self.keys = KeysPage(self.store)
        self.tools = ToolsPage(self.store)
        self.settings_page = SettingsPage(self._defaults_changed)
        for page in (self.encrypt, self.decrypt, self.share, self.keys, self.tools, self.settings_page):
            self.stack.addWidget(page)

        self.sidebar.changed.connect(self._navigate)
        self.encrypt.share_requested.connect(self._share_file)
        self.encrypt.keys_requested.connect(lambda: self.sidebar.select(3))
        self.keys.changed.connect(self._keys_changed)
        self._keys_changed()

        self.toaster = Toaster(root)
        dialogs.set_host(root)
        self.locker = Locker(self, root, settings["auto_lock"])
        self.settings_page.lock_changed = self.locker.set_minutes
        self.setAcceptDrops(True)
        QTimer.singleShot(0, lambda: self.sidebar.select(0, animate=False))
        if open_paths:
            QTimer.singleShot(50, lambda: self.open_paths(open_paths))
        if self.store.problem:
            QTimer.singleShot(400, lambda: dialogs.error(self.store.problem, "Problem loading your keys"))

    def _navigate(self, i):
        self.stack.switch_to(i)
        if self.stack.currentWidget() is self.share:
            self.share.reload()

    def _keys_changed(self):
        self.encrypt.recipients.reload()
        self.decrypt.reload_identities()
        self.share.reload()
        self.tools.reload()
        self.encrypt.reload_signers()

    def _share_file(self, path):
        self.share.set_file(path)
        self.sidebar.select(2)

    def _defaults_changed(self):
        e = self.encrypt
        for key, dd in (("suite", e.suite), ("preset", e.preset), ("kdf", e.kdf), ("compression", e.comp),
                        ("padding", e.padding), ("threads", e.threads)):
            dd.set_value(settings[key])
        for key, t in (("hide_name", e.hide_name), ("hide_recipients", e.hide_recipients), ("bundle", e.bundle),
                       ("armor", e.armor), ("strip_metadata", e.strip)):
            t.setChecked(settings[key])
        self.decrypt.delete_after.setChecked(settings["delete_after_decrypt"])

    def open_paths(self, paths: list[str]):
        """Route dropped or command-line paths to Encrypt or Decrypt."""
        enc = [p for p in paths if not self._is_encrypted(p)]
        dec = [p for p in paths if self._is_encrypted(p)]
        if dec:
            self.decrypt.add_paths(dec)
        if enc:
            self.encrypt.add_paths(enc)
        self.sidebar.select(1 if dec and not enc else 0)

    @staticmethod
    def _is_encrypted(p: str) -> bool:
        path = Path(p)
        if not path.is_file():
            return False
        if is_encrypted_name(path.name):
            return True
        try:
            with open(path, "rb") as f:
                return looks_encrypted(f.read(8))
        except OSError:
            return False

    def closeEvent(self, e):
        clear_clipboard_secret()
        super().closeEvent(e)

    # Dropping anywhere outside a drop zone routes files automatically.
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.open_paths(paths)
