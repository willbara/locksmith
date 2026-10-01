"""End-to-end flows through the real window, offscreen."""

import hashlib
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


def wait(pred, timeout=60.0):
    end = time.monotonic() + timeout
    while not pred():
        QApplication.processEvents()
        if time.monotonic() > end:
            raise TimeoutError
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "config"))
    app = QApplication.instance() or QApplication([])
    from locksmith.ui import dialogs, settings
    monkeypatch.setattr(settings, "settings", settings.Settings())
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, *a, **k: (asked.append(title), True)[1])
    monkeypatch.setattr(dialogs, "error", lambda msg, *a, **k: asked.append("ERROR: " + msg))
    from locksmith.ui.theme import load_fonts, theme
    from locksmith.ui.window import MainWindow
    load_fonts()
    theme.animations = False
    theme.apply("dark")
    w = MainWindow()
    w.asked = asked
    w.show()
    yield w
    w.close()
    app.processEvents()


def _set_password(page, pw="V3ry-Str0ng-Passphrase!"):
    page.password.setText(pw)
    if hasattr(page, "confirm"):
        page.confirm.setText(pw)


def test_encrypt_shred_decrypt_folder(tmp_path, window):
    e, d = window.encrypt, window.decrypt
    src = tmp_path / "src"
    (src / "Folder").mkdir(parents=True)
    (src / "a.txt").write_text("hello\n")
    (src / "Folder" / "b.bin").write_bytes(os.urandom(300_000))
    try:
        (src / "Folder" / "abs-link").symlink_to("/usr/bin")
    except OSError:
        pass  # Windows without Developer Mode
    digest = hashlib.sha256((src / "Folder" / "b.bin").read_bytes()).hexdigest()

    # Output inside the folder being encrypted is refused and the originals survive.
    e.add_paths([str(src / "Folder")])
    _set_password(e)
    e.shred.setChecked(True)
    e.output._dir = str(src / "Folder" / "out")
    e.output._rebuild()
    e.go.click()
    wait(lambda: e.task is None)
    assert any("inside" in a for a in window.asked)
    assert (src / "Folder" / "b.bin").exists()

    # Encrypt both items with shredding: verified first, then the originals go.
    e.files.clear()
    e.add_paths([str(src / "Folder"), str(src / "a.txt")])
    _set_password(e)
    e.output._dir = str(tmp_path / "out")
    e.output._rebuild()
    e.go.click()
    wait(lambda: e.task is None)
    assert not (src / "Folder").exists() and not (src / "a.txt").exists()
    outs = sorted((tmp_path / "out").glob("*.locked"))
    assert len(outs) == 2

    d.add_paths([str(o) for o in outs])
    _set_password(d)
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.go.click()
    wait(lambda: d.task is None)
    assert hashlib.sha256((tmp_path / "dec" / "Folder" / "b.bin").read_bytes()).hexdigest() == digest
    assert (tmp_path / "dec" / "a.txt").read_text() == "hello\n"


def test_recipients_only_shred_warns(tmp_path, window):
    from locksmith.core.keys import KeyStore
    e = window.encrypt
    window.store.add_contact("Friend", KeyStore(tmp_path / "friend").generate("f").public)
    window._keys_changed()
    (tmp_path / "x.txt").write_text("x")
    e.add_paths([str(tmp_path / "x.txt")])
    e.mode.setIndex(1)
    for row, _ in e.recipients.rows:
        row.setChecked(True)
    e.shred.setChecked(True)
    e.go.click()
    wait(lambda: e.task is None)
    assert window.asked[0] == "You won’t be able to open these"


def test_lock_and_panic_clear_secrets(window):
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import PasswordField, copy_secret
    window.encrypt.password.setText("secret-1")
    window.share.msg.setPlainText("meet at the docks")
    window.share.secret.setText("vault-pass")
    copy_secret("clipboard-secret")
    sheet = dialogs.Sheet("Decrypted message")
    sheet.open()
    window.locker.lock()
    wait(lambda: not sheet.isVisible())
    assert not any(f.text() for f in window.findChildren(PasswordField))
    assert window.share.msg.toPlainText() == "" and window.tools.gen_out.text() == ""
    assert QApplication.clipboard().text() != "clipboard-secret"
    assert window.locker.overlay.isVisible()
    QTest.keyClick(window.locker.overlay, Qt.Key.Key_Space)
    assert not window.locker.overlay.isVisible()
    window.share.secret.setText("again")
    window.locker.panic()
    assert window.share.secret.text() == "" and window.locker.overlay.isVisible()


def test_sender_text_is_never_rendered_as_html(tmp_path, window, monkeypatch):
    """File names and notes come from whoever made the file: show them literally."""
    from PySide6.QtWidgets import QLabel

    from locksmith.ui import dialogs
    monkeypatch.setattr(dialogs, "text_view", lambda *a, **k: None)

    page = window.decrypt
    evil = "<h1>Verified by your bank<img src='x.png'>"
    page._add_result("file", str(tmp_path / f"{evil}.pdf"), {"note": evil})
    page._add_result("text", evil, {})
    texts = [lab for lab in page.findChildren(QLabel) if "<h1>" in lab.text()]
    assert len(texts) >= 3
    assert all(lab.textFormat() == Qt.TextFormat.PlainText for lab in texts)
    for lab in window.findChildren(QLabel):
        assert lab.textFormat() == Qt.TextFormat.PlainText, lab.text()


def test_output_is_durable_before_shred_or_delete(tmp_path, window, monkeypatch):
    """The output folder is fsynced before any original is shredded or source deleted."""
    from pathlib import Path

    from locksmith.core import engine, tools
    events = []
    monkeypatch.setattr(engine, "fsync_dir", lambda p: events.append(("sync", Path(p))) or True)
    real_shred, real_unlink = tools.shred, Path.unlink
    monkeypatch.setattr(tools, "shred", lambda p, **k: (events.append(("shred", p)), real_shred(p, **k))[1])

    def unlink(self, *a, **k):
        if self.suffix == ".locked":
            events.append(("delete", self))
        return real_unlink(self, *a, **k)
    monkeypatch.setattr(Path, "unlink", unlink)

    e, d = window.encrypt, window.decrypt
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    e.add_paths([str(tmp_path / "a.txt")])
    _set_password(e)
    e.shred.setChecked(True)
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    e.go.click()
    wait(lambda: e.task is None)
    assert events == [("sync", tmp_path / "enc"), ("shred", tmp_path / "a.txt")]

    events.clear()
    d.add_paths([str(p) for p in (tmp_path / "enc").glob("*.locked")])
    _set_password(d)
    d.delete_after.setChecked(True)
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.go.click()
    wait(lambda: d.task is None)
    assert [ev[0] for ev in events] == ["sync", "delete"] and events[0][1] == tmp_path / "dec"
    assert (tmp_path / "dec" / "a.txt").read_text(encoding="utf-8") == "a"


def test_delete_after_keeps_source_when_items_were_left_out(tmp_path, window, needs_symlinks):
    """A folder with a link outside it can't be fully restored, so its only copy must survive."""
    from locksmith.ui.widgets import Label
    e, d = window.encrypt, window.decrypt
    src = tmp_path / "proj"
    src.mkdir()
    (src / "data.txt").write_text("keep me", encoding="utf-8")
    (src / "abs-link").symlink_to("/usr/bin")
    e.add_paths([str(src)])
    _set_password(e)
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    e.go.click()
    wait(lambda: e.task is None)
    (locked,) = (tmp_path / "enc").glob("*.locked")

    d.add_paths([str(locked)])
    _set_password(d)
    d.delete_after.setChecked(True)
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.go.click()
    wait(lambda: d.task is None)
    assert locked.exists()
    assert (tmp_path / "dec" / "proj" / "data.txt").read_text(encoding="utf-8") == "keep me"
    texts = [lab.text() for lab in d.findChildren(Label)]
    assert any("proj/abs-link" in t for t in texts)
    assert any("was not deleted" in t for t in texts)
