"""End-to-end flows through the real window, offscreen."""

import hashlib
import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent, Qt  # noqa: E402
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
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "config"))
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
    # Destroy the window: closed ones stay alive, and theme.apply restyles every live widget,
    # so each later test's setup would get slower.
    w.deleteLater()
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
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


def test_shred_refuses_keyfile_inside_inputs(tmp_path, window):
    e = window.encrypt
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "a.txt").write_text("hello\n", encoding="utf-8")
    (vault / "key.bin").write_bytes(os.urandom(64))
    key = (vault / "key.bin").read_bytes()
    e.add_paths([str(vault)])
    e.keyfile.set_path(str(vault / "key.bin"))
    e.shred.setChecked(True)
    e.output._dir = str(tmp_path / "out")
    e.output._rebuild()
    assert e.go.isEnabled()
    e.go.click()
    wait(lambda: e.task is None)
    assert any(a.startswith("ERROR: The keyfile") for a in window.asked)
    assert (vault / "key.bin").read_bytes() == key
    assert (vault / "a.txt").read_text(encoding="utf-8") == "hello\n"
    assert not list(tmp_path.glob("out/*.locked"))


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


def test_secret_qr_code_cannot_be_copied_as_an_image(window, monkeypatch):
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import Button
    sheets = []
    monkeypatch.setattr(dialogs.Sheet, "exec", lambda self: (self.open(), sheets.append(self))[1])
    window.share.secret.setText("vault-pass")
    window.share._secret_qr()
    dialogs.qr_view("Your public key", "locksmith1abc")
    secret_qr, public_qr = ([b.text() for b in s.findChildren(Button)] for s in sheets)
    assert "Copy image" not in secret_qr
    assert "Copy image" in public_qr


def test_shred_refuses_inputs_holding_the_key_store(tmp_path, window):
    e = window.encrypt
    window.store.generate("me", post_quantum=False)
    window._keys_changed()
    keys = window.store.path.read_bytes()
    e.add_paths([str(tmp_path / "config")])
    _set_password(e)
    e.shred.setChecked(True)
    e.output._dir = str(tmp_path / "out")
    e.output._rebuild()
    e.go.click()
    wait(lambda: e.task is None)
    assert any(a.startswith("ERROR: Locksmith’s own keys") for a in window.asked)
    assert window.store.path.read_bytes() == keys
    assert not list(tmp_path.glob("out/*.locked"))


def test_pasted_folder_reports_left_out_items_and_unverified_note(tmp_path, window, monkeypatch,
                                                                   needs_symlinks):
    from locksmith.core import engine
    from locksmith.core.engine import EncryptOptions
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import Label
    src = tmp_path / "proj"
    src.mkdir()
    (src / "data.txt").write_text("keep me", encoding="utf-8")
    (src / "abs-link").symlink_to("/usr/bin")
    opts = EncryptOptions(password="pw", kdf="pbkdf2-sha512", preset="fast", armor=True, note="From: Alice")
    armored = engine.encrypt_paths([src], tmp_path / "enc", opts).read_text(encoding="utf-8")
    monkeypatch.setattr(dialogs, "text_input", lambda *a, **k: armored)

    d = window.decrypt
    d.paste_text()
    d.password.setText("pw")
    d.output._dir = str(tmp_path / "dec")   # doesn't exist yet: it is created, as for files (N7)
    d.output._rebuild()
    d.go.click()
    wait(lambda: d.task is None)
    data = tmp_path / "dec" / "proj" / "data.txt"   # unwrapped one level, not proj/proj/ (N7)
    assert data.read_text(encoding="utf-8") == "keep me"
    texts = [lab.text() for lab in d.findChildren(Label)]
    assert any("Left out 1" in t and "abs-link" in t for t in texts)
    assert any(t == "Note from the sender (not verified): From: Alice" for t in texts)


def _capture_text_views(monkeypatch):
    from locksmith.ui import dialogs
    shown = []
    monkeypatch.setattr(dialogs, "text_view", lambda title, text, *a, **k: shown.append((title, text, k)))
    return shown


def test_backup_words_and_shares_restore_the_identity(tmp_path, window, monkeypatch):
    from PySide6.QtWidgets import QPlainTextEdit

    from locksmith.core import keys
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import Dropdown, LineEdit
    shown = _capture_text_views(monkeypatch)
    page, store = window.keys, window.store
    ident = store.generate("me", passphrase="pass phrase")
    page.reload()
    monkeypatch.setattr(dialogs, "prompt", lambda *a, **k: "pass phrase")
    page._backup_words(ident)
    wait(lambda: shown)
    title, words, opts = shown.pop()
    assert opts["secret"] and len(words.split()) == 50

    def split_sheet(self):
        self.open()
        k, n = self.findChildren(Dropdown)
        k.set_value(3)
        n.set_value(5)
        return True
    monkeypatch.setattr(dialogs.Sheet, "exec", split_sheet)
    page._split_identity(ident)
    wait(lambda: shown)
    shares = shown.pop()[1].split()
    assert len(shares) == 5

    raw = ident.private_raw("pass phrase")
    for source in (words, "\n".join(shares[1:4])):
        store.identities.clear()   # as if on a new device
        store.save()

        def restore_sheet(self, source=source):
            self.open()
            self.findChild(QPlainTextEdit).setPlainText(source)
            self.findChild(LineEdit).setText("restored")
            return True
        monkeypatch.setattr(dialogs.Sheet, "exec", restore_sheet)
        page._restore()
        wait(lambda: len(store.identities) == 1)
        assert store.identities[0].private_raw() == raw and store.identities[0].name == "restored"
    assert keys.KeyStore(store.dir).identities[-1].public == ident.public   # saved to disk


def test_identity_shares_are_not_shown_as_a_password(window, monkeypatch):
    import os

    from locksmith.core import keys
    from locksmith.ui import dialogs
    shown = _capture_text_views(monkeypatch)
    infos = []
    monkeypatch.setattr(dialogs, "info", lambda title, *a, **k: infos.append(title))
    shares = keys.identity_shares(os.urandom(32), 2, 2)
    monkeypatch.setattr(dialogs, "text_input", lambda *a, **k: "\n".join(shares))
    window.share._combine()
    assert infos == ["These shares hold an identity"] and not shown


def test_hide_recipients_option_reaches_the_engine(window):
    e = window.encrypt
    e.mode.setIndex(1)
    e.hide_recipients.setChecked(True)
    assert e.options().hide_recipients
    e.mode.setIndex(0)
    assert not e.options().hide_recipients   # password only: no recipients to hide


def test_minisign_and_manifest_tools(tmp_path, window, monkeypatch):
    import base64
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from PySide6.QtWidgets import QFileDialog
    t = window.tools
    f = tmp_path / "release.tar"
    f.write_bytes(b"release")
    sk = Ed25519PrivateKey.generate()
    sig = sk.sign(hashlib.blake2b(b"release", digest_size=64).digest())
    comment = "<b>timestamp</b>"
    (tmp_path / "release.tar.minisig").write_text(
        f"untrusted comment: x\n{base64.b64encode(b'ED' + bytes(8) + sig).decode()}\ntrusted comment: {comment}\n"
        f"{base64.b64encode(sk.sign(sig + comment.encode())).decode()}\n", encoding="utf-8")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(f), "")))
    t._ms_pick_file()   # finds release.tar.minisig next to it
    t.ms_key.setText(base64.b64encode(b"Ed" + bytes(8) + sk.public_key().public_bytes_raw()).decode())
    t._ms_verify()
    wait(lambda: t.ms_go.isEnabled() and t.ms_result.text())
    assert t.ms_result.text().startswith("✓") and t.ms_comment.text() == f"Trusted comment: {comment}"

    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "a.txt").write_text("a", encoding="utf-8")
    manifest = folder / "SHA256SUMS"
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(folder)))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(manifest), "")))
    t._make_manifest()
    wait(lambda: t._extra_task is None and t.extra_result.text())
    assert manifest.read_text(encoding="utf-8").startswith("SHA256 (a.txt) = ")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(manifest), "")))
    t._verify_manifest()
    wait(lambda: t._extra_task is None and "match" in t.extra_result.text())
    assert t.extra_result.text() == "✓  All 1 files match the manifest"


def test_ssh_signature_tool(tmp_path, window, monkeypatch):
    import shutil
    from pathlib import Path

    from PySide6.QtWidgets import QFileDialog
    t = window.tools
    vectors = Path(__file__).resolve().parent / "interop" / "sshsig"
    f = tmp_path / "message.bin"
    shutil.copy(vectors / "message.bin", f)
    shutil.copy(vectors / "ed25519.sig", tmp_path / "message.bin.sig")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(f), "")))
    t._ss_pick_file()   # finds message.bin.sig next to it
    monkeypatch.setattr(QFileDialog, "getOpenFileName",
                        staticmethod(lambda *a, **k: (str(vectors / "ed25519.pub"), "")))
    t._ss_load_key()
    assert t.ss_key.text().startswith("ssh-ed25519 ") and "locksmith-interop" not in t.ss_key.text()
    t._ss_verify()
    wait(lambda: t.ss_go.isEnabled() and t.ss_result.text())
    assert t.ss_result.text() == "✓  Valid signature from key SHA256:xauNrprfcp4IDDUtjL6QVgiksKosYcaX2xHnrsnB1WU"
    assert t.ss_detail.text() == "ED25519 key  ·  namespace “file”  ·  SHA512"

    t.ss_namespace.setText("git")
    t._ss_verify()
    wait(lambda: t.ss_go.isEnabled() and t.ss_result.text())
    assert t.ss_result.text() == "✕  Not verified" and "made for “file”, not “git”" in t.ss_detail.text()


def test_sign_and_verify_through_the_tools_page(tmp_path, window, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    from locksmith.ui import dialogs
    store, t = window.store, window.tools
    assert not t.sg_go.isEnabled() and not t.sg_none.isHidden()   # no identity can sign yet
    store.generate("old", post_quantum=False)
    ident = store.generate("Alice", passphrase="pass phrase")
    window.keys.reload()   # emits changed: the Tools page lists the identities that can sign
    assert [t.sg_ident.itemText(i) for i in range(t.sg_ident.count())] == ["Alice"]
    assert t.sg_go.isEnabled() and t.sg_none.isHidden()
    f = tmp_path / "release.tar"
    f.write_bytes(b"release\n" * 1000)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(f), "")))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(f) + ".lsig", "")))
    monkeypatch.setattr(dialogs, "prompt", lambda *a, **k: "pass phrase")
    t._sg_pick_file()
    t.sg_comment.setText("<b>Release</b> 1.0")
    t._sign()
    wait(lambda: t.sg_go.isEnabled() and (tmp_path / "release.tar.lsig").exists())

    store.add_contact("Alice (contact)", ident.key_text)
    t._ls_pick_file()   # finds release.tar.lsig next to it
    t._ls_verify()
    wait(lambda: t.ls_go.isEnabled() and t.ls_result.text())
    assert t.ls_result.text() == "✓  Signed with the key you saved as Alice (you)"
    assert t.ls_comment.text() == "Signed comment: <b>Release</b> 1.0"
    assert t.ls_detail.text().startswith(f"Fingerprint {keys_fingerprint(ident.key_raw)}")

    f.write_bytes(b"changed")
    t._ls_verify()
    wait(lambda: t.ls_go.isEnabled() and t.ls_result.text())
    assert t.ls_result.text() == "✕  Not verified" and "does not match" in t.ls_detail.text()

    f.write_bytes(b"release\n" * 1000)
    other = store.generate("Bob")
    t.ls_key.setText(other.key_text)   # only the pasted key is tried
    t._ls_verify()
    wait(lambda: t.ls_go.isEnabled() and t.ls_result.text())
    assert "None of the keys" in t.ls_detail.text() and "Paste the signer's public key" in t.ls_detail.text()


def keys_fingerprint(raw):
    from locksmith.core.keys import fingerprint
    return fingerprint(raw)


def test_contact_upgrade_asks_and_shows_the_new_fingerprint(window, monkeypatch):
    from PySide6.QtWidgets import QWidget

    from locksmith.core import keys
    from locksmith.ui import dialogs
    from locksmith.ui.dialogs import Sheet
    store, page = window.store, window.keys
    source = keys.KeyStore(store.dir / "elsewhere")
    alice = source.generate("Alice")
    store.add_contact("Alice", alice.public)   # saved before signing existed
    confirms = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, msg, **k: (confirms.append((title, msg)), True)[1])

    def fill(sheet):
        edits = [w for w in sheet.findChildren(QWidget) if w.__class__.__name__ == "LineEdit"]
        edits[0].setText("ignored")
        edits[1].setText(alice.key_text)
        return True

    monkeypatch.setattr(Sheet, "exec", fill)
    store.mark_checked(store.contacts[0])
    page._add_contact()
    assert len(store.contacts) == 1 and store.contacts[0].can_verify
    title, msg = confirms[0]
    assert title == "Add signing keys to “Alice”?" and keys.fingerprint(alice.key_raw) in msg
    assert "proves nothing yet" in msg and "This is the key you saved" not in msg   # audit A1
    # Audit B9: the update resets the check, and it isn't asked again on the spot: a one-click "It matches"
    # right after pasting a key would invite a reflexive yes.
    assert len(confirms) == 1 and not store.contacts[0].checked


def test_share_page_shows_the_full_key_and_a_fingerprint_qr(window, monkeypatch):
    from locksmith.core import keys
    from locksmith.ui import dialogs
    store, s = window.store, window.share
    ident = store.generate("Me")
    window.keys.reload()
    s.reload()
    assert s._pub_key == ident.key_text and s.pub_text.text().startswith("locksmith3") and "…" in s.pub_text.text()
    s.pub_copy.click()
    assert QApplication.clipboard().text() == ident.key_text
    assert s.pub_fp.text() == f"Fingerprint  {keys.fingerprint(ident.key_raw)}"
    shown = []
    monkeypatch.setattr(dialogs, "qr_view", lambda title, data, caption="", **k: shown.append((data, caption)))
    s._pub_qr()
    assert shown[0][0] == keys.qr_text(ident.key_raw) and "fingerprint" in shown[0][1]


def _visible_sheets(window):
    from locksmith.ui.dialogs import Sheet
    return [s for s in window.findChildren(Sheet) if s.isVisible() and not getattr(s, "_closing", False)]


def test_results_that_arrive_after_a_lock_are_not_shown(tmp_path, window, monkeypatch):
    """N3: a task that finishes after Ctrl+L must not put decrypted text back on screen."""
    from locksmith.ui import lock
    from locksmith.ui.widgets import Label
    toasts = []
    monkeypatch.setattr(lock, "toast", lambda text, *a, **k: toasts.append(text), raising=False)
    d = window.decrypt
    written = tmp_path / "report.pdf"
    written.write_bytes(b"%PDF")
    window.locker.lock()
    d._done([("text", "top secret message", {}), ("file", written, {})])
    QApplication.processEvents()
    assert not _visible_sheets(window)
    texts = [lab.text() for lab in d.findChildren(Label)]
    assert not any("top secret" in t for t in texts)
    assert any(t == "report.pdf" for t in texts)   # files already on disk are fine to list
    window.locker.overlay.unlock()
    assert toasts and "Decrypted message" in toasts[0] and "Open it again" in toasts[0]
    assert not window.locker.locked


def test_share_message_opened_while_locked_is_withheld(window, monkeypatch):
    from locksmith.core import engine
    from locksmith.core.engine import EncryptOptions
    from locksmith.ui import dialogs, lock
    toasts = []
    monkeypatch.setattr(lock, "toast", lambda text, *a, **k: toasts.append(text), raising=False)
    blob = engine.encrypt_bytes(b"meet at noon", EncryptOptions(password="pw", kdf="pbkdf2-sha512", preset="fast"),
                                kind="text")
    monkeypatch.setattr(dialogs, "text_input", lambda *a, **k: engine.armor(blob))
    monkeypatch.setattr(dialogs, "prompt", lambda *a, **k: "pw")
    window.share._open_message()   # the result arrives through the event loop, after this lock
    window.locker.lock()
    wait(lambda: window.locker.withheld)
    assert not _visible_sheets(window)
    window.locker.overlay.unlock()
    assert "Decrypted message" in toasts[0]


def test_sheets_opened_while_locked_stay_under_the_lock_screen(window):
    from locksmith.ui import dialogs
    from locksmith.ui.dialogs import Sheet
    root = window.locker.root
    window.locker.lock()
    s = Sheet("Decryption failed")
    s.open()
    QApplication.processEvents()
    order = [c for c in root.children() if c in (s, window.locker.overlay)]
    assert order == [s, window.locker.overlay] and window.locker.overlay.hasFocus()
    dialogs.text_view("Backup words for “me”", "secret words", secret=True)   # returns at once
    assert window.locker.withheld == ["Backup words for “me”"]
    s.done(None)


def test_signed_file_through_encrypt_and_decrypt(tmp_path, window, monkeypatch):
    from locksmith.core import keys
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import Label
    store, e, d = window.store, window.encrypt, window.decrypt
    me = store.generate("Alice", passphrase="pass phrase")
    store.generate("old", post_quantum=False)   # classical: not offered for signing
    window.keys.reload()
    choices = [e.sign_as.itemText(i) for i in range(e.sign_as.count())]
    assert choices == ["Don't sign", "Alice"] and not e.sign_field.isHidden()
    monkeypatch.setattr(dialogs, "prompt", lambda *a, **k: "pass phrase")
    src = tmp_path / "invoice.txt"
    src.write_text("pay 10", encoding="utf-8")
    e.files.add([str(src)])
    _set_password(e, "pw-Strong-enough-123")
    e.note.setText("<b>from Alice</b>")
    e.sign_as.set_value(store.identities.index(me))
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    e.start()
    wait(lambda: e.task is None)
    (enc,) = (tmp_path / "enc").glob("*.locked")

    def decrypt_and_read():
        d.files.add([str(enc)])
        d.password.setText("pw-Strong-enough-123")
        d.output._dir = str(tmp_path / "dec")
        d.output._rebuild()
        d.start()
        wait(lambda: d.task is None)
        return [lab.text() for lab in d.findChildren(Label)]

    texts = decrypt_and_read()
    assert "✓  Signed with the key you saved as Alice (you)" in texts
    assert "Note (signed): <b>from Alice</b>" in texts

    # The same file, read by someone who hasn't saved Alice's key.
    store.remove_identity(me)
    for f in (tmp_path / "dec").iterdir():
        f.unlink()
    texts = decrypt_and_read()
    assert any(t.startswith("Has a signature that claims a key you haven't saved (claimed fingerprint "
                            f"{keys.fingerprint(me.key_raw)}). Nothing was checked") for t in texts)
    assert "Note from the sender (not verified): <b>from Alice</b>" in texts


def test_signed_message_through_the_share_page(window, monkeypatch):
    from locksmith.core import engine
    from locksmith.ui import dialogs
    store, s = window.store, window.share
    me = store.generate("Alice")
    window.keys.reload()
    assert s.msg_sign.value() == "none"   # signing a message is opt-in
    s.msg.setPlainText("meet at noon")
    s.msg_pw.setText("message password 123")
    s.msg_sign.set_value(store.identities.index(me))
    s._encrypt_message()
    wait(lambda: s.msg_out.toPlainText())
    armored = s.msg_out.toPlainText()
    assert engine.decrypt_bytes(engine.dearmor(armored), engine.DecryptKeys(
        password="message password 123", verifiers=[me.key_raw])).signature.verified
    shown = []
    monkeypatch.setattr(dialogs, "text_input", lambda *a, **k: armored)
    monkeypatch.setattr(dialogs, "prompt", lambda *a, **k: "message password 123")
    monkeypatch.setattr(dialogs, "text_view", lambda title, text, caption="", **k: shown.append((text, caption)))
    s._open_message()
    wait(lambda: shown)
    assert shown[0] == ("meet at noon", "✓  Signed with the key you saved as Alice (you)")


@pytest.mark.parametrize("target", ["file", "folder"])
def test_shred_refuses_symlinked_inputs(tmp_path, window, needs_symlinks, target):
    """N2: with shredding on, a link given as input is refused on Encrypt and on Tools → Shred;
    the data it points to and the link itself are untouched, and nothing is encrypted."""
    real = tmp_path / "real"
    if target == "file":
        real.write_text("plaintext\n", encoding="utf-8")
    else:
        real.mkdir()
        (real / "inside.txt").write_text("plaintext\n", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(real)
    e = window.encrypt
    e.add_paths([str(tmp_path / "plain.txt"), str(link)])
    (tmp_path / "plain.txt").write_text("other\n", encoding="utf-8")
    _set_password(e)
    e.shred.setChecked(True)
    e.output._dir = str(tmp_path / "out")
    e.output._rebuild()
    e.go.click()
    wait(lambda: e.task is None)
    assert any("is a link" in a for a in window.asked)
    assert link.is_symlink() and (tmp_path / "plain.txt").exists()
    assert (real.read_text(encoding="utf-8") if target == "file" else
            (real / "inside.txt").read_text(encoding="utf-8")) == "plaintext\n"
    assert not list(tmp_path.glob("out/*.locked"))

    t = window.tools
    window.asked.clear()
    t.shred_list.add([str(link)])
    t._shred()
    assert any("is a link" in a for a in window.asked)
    assert link.is_symlink() and real.exists()


def test_change_who_can_open_a_file(tmp_path, window, monkeypatch):
    """Decrypt → Change who can open it: unlock with the page's inputs, rewrite the slots, and ask
    before leaving the user unable to open it."""
    from locksmith.core import engine
    from locksmith.core.engine import AccessChange, DecryptKeys, EncryptOptions
    src = tmp_path / "doc.txt"
    src.write_bytes(b"contents\n")
    enc = engine.encrypt_paths([src], tmp_path / "enc", EncryptOptions(password="old-pw", kdf="pbkdf2-sha512",
                                                                       preset="fast"))
    before = engine.inspect(enc)
    d = window.decrypt
    d.add_paths([str(enc)])
    assert d.access.isEnabled()
    d.password.setText("old-pw")
    friend = window.store.generate("Friend")
    monkeypatch.setattr(d, "_access_sheet", lambda path, info: AccessChange(
        set_password=True, password="new-pw", kdf="pbkdf2-sha512", preset="fast", add_recipients=[friend.public_raw]))
    d.access.click()
    wait(lambda: d.task is None)
    assert not [a for a in window.asked if a.startswith("ERROR")]
    after = engine.inspect(enc)
    assert after.recipient_slots == before.recipient_slots + 1
    assert engine.decrypt_bytes(enc.read_bytes(), DecryptKeys(password="new-pw")).data == b"contents\n"
    assert engine.decrypt_bytes(enc.read_bytes(), DecryptKeys(identities=[friend.private_raw()])).data == b"contents\n"
    assert d.password.text() == ""

    # Removing the password the user opened it with, leaving only the friend: asked first.
    window.asked.clear()
    d.password.setText("new-pw")
    monkeypatch.setattr(d, "_access_sheet", lambda path, info: AccessChange(set_password=True))
    monkeypatch.setattr(window.store, "identities", [])   # the friend's identity isn't one of the user's
    d.access.click()
    wait(lambda: d.task is None and window.asked)
    wait(lambda: d.task is None)
    assert window.asked[0] == "You won’t be able to open it"
    assert engine.inspect(enc).password_slots == []


def test_addressed_file_through_encrypt_and_decrypt(tmp_path, window, monkeypatch):
    """The "addressed to" toggle: only with recipients, a warning when decoys are on too, and
    neutral wording on Decrypt for a reader who isn't on the list."""
    from locksmith.core.keys import KeyStore
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import Label
    store, e, d = window.store, window.encrypt, window.decrypt
    me = store.generate("Alice")
    bob_store = KeyStore(tmp_path / "bob")
    bob = bob_store.generate("Bob")
    store.add_contact("Bob", bob.key_text)
    window._keys_changed()
    src = tmp_path / "plan.txt"
    src.write_text("the plan", encoding="utf-8")
    e.files.add([str(src)])
    e.sign_as.set_value(store.identities.index(me))
    assert not e.address.isHidden() and not e.address.isEnabled()   # password only: nothing to list
    assert "no key to list" in e.address_note.text()
    e.mode.setIndex(1)
    for row, raw in e.recipients.rows:
        row.setChecked(raw == bob.public_raw)
    assert e.address.isEnabled()
    e.address.setChecked(True)
    e.hide_recipients.setChecked(True)
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, *a, **k: (asked.append(title), True)[1])
    e.start()
    wait(lambda: e.task is None)
    assert asked == ["Recipients will see the list"]
    (enc,) = (tmp_path / "enc").glob("*.locked")

    # Bob forwards it to Carol by adding her slot; Carol has saved Alice's key.
    from locksmith.core import engine
    carol = KeyStore(tmp_path / "carol").generate("Carol")
    engine.change_access(enc, engine.DecryptKeys(identities=[bob.private_raw()]),
                         engine.AccessChange(add_recipients=[carol.public_raw]))
    store.remove_identity(me)
    store.contacts.clear()
    store.mark_checked(store.add_contact("Alice", me.key_text))
    store.identities.append(carol)
    window._keys_changed()
    d.files.add([str(enc)])
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.start()
    wait(lambda: d.task is None)
    texts = [lab.text() for lab in d.findChildren(Label)]
    assert ("✓  Signed with the key you saved as Alice, but you weren't on its original recipient list"
            in texts)


def test_ssh_key_recipient_through_encrypt_and_decrypt(tmp_path, window, monkeypatch):
    """Encrypt to an SSH contact, then open the file on Decrypt with the protected SSH private key."""
    from pathlib import Path

    from locksmith.ui import dialogs
    keys_dir = Path(__file__).parent / "interop" / "sshkeys"
    store, e, d = window.store, window.encrypt, window.decrypt
    store.add_contact("Server", (keys_dir / "id_rsa3072.pub").read_text(encoding="utf-8"))
    window._keys_changed()
    src = tmp_path / "notes.txt"
    src.write_text("for the server", encoding="utf-8")
    e.files.add([str(src)])
    e.mode.setIndex(1)
    for row, _ in e.recipients.rows:
        row.setChecked(True)
    assert not e.rsa_note.isHidden()   # older versions can't open it: said before encrypting
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    e.start()
    wait(lambda: e.task is None)
    (enc,) = (tmp_path / "enc").glob("*.locked")

    passphrase = (keys_dir / "passphrase.txt").read_text(encoding="utf-8").strip()
    asked = []
    monkeypatch.setattr(dialogs, "prompt", lambda title, *a, **k: (asked.append(title), passphrase)[1])
    d.files.add([str(enc)])
    d.ssh_key.set_path(str(keys_dir / "id_rsa3072_protected"))
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.start()
    wait(lambda: d.task is None)
    assert asked == ["SSH key passphrase"]
    assert (tmp_path / "dec" / "notes.txt").read_text(encoding="utf-8") == "for the server"


def test_age_files_through_encrypt_and_decrypt(tmp_path, window, monkeypatch):
    """Encrypt → File format → age: to a post-quantum identity (an mlkem768x25519 stanza), then
    opened on Decrypt; options age can't honour are refused, and a pasted age message opens."""
    from locksmith.core import age
    from locksmith.ui import dialogs
    from locksmith.ui.widgets import Label
    store, e, d = window.store, window.encrypt, window.decrypt
    store.generate("Me")
    window._keys_changed()
    src = tmp_path / "photo.txt"
    src.write_text("age content", encoding="utf-8")
    e.files.add([str(src)])
    e.format.set_value("age")
    assert "ChaCha20-Poly1305" in e.format_field.caption.text()
    e.mode.setIndex(2)
    _set_password(e)
    for row, _ in e.recipients.rows:
        row.setChecked(True)
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    e.start()
    assert any("not both" in a for a in window.asked)   # password and recipients: refused before anything runs
    e.mode.setIndex(1)
    e.start()
    wait(lambda: e.task is None)
    (enc,) = (tmp_path / "enc").glob("*.age")
    assert [s.type for s in age.read_header(open(enc, "rb")).stanzas] == [b"mlkem768x25519"]

    d.files.add([str(enc)])
    assert "post-quantum age key" in d.info_lines.text()
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.start()
    wait(lambda: d.task is None)
    assert (tmp_path / "dec" / "photo.txt").read_text(encoding="utf-8") == "age content"

    # A pasted armored age message with a password, shown as text.
    out = __import__("io").BytesIO()
    age.encrypt_stream(__import__("io").BytesIO(b"pasted secret"), out, [], "pw-for-age", work_factor=10)
    monkeypatch.setattr(dialogs, "text_input", lambda *a, **k: age.armor(out.getvalue()))
    shown = []
    monkeypatch.setattr(dialogs, "text_view", lambda title, text, *a, **k: shown.append(text))
    d.paste_text()
    d.password.setText("pw-for-age")
    d.start()
    wait(lambda: d.task is None)
    assert shown == ["pasted secret"]
    assert any(lab.text() == "Decrypted message" for lab in d.findChildren(Label))


def test_openpgp_signature_tool(window):
    from pathlib import Path

    from locksmith.ui.widgets import Label
    here = Path(__file__).parent / "interop" / "openpgp"
    t = window.tools
    t.pg_file, t.pg_sig, t.pg_key = here / "message.bin", here / "rsa-subkey.sig", here / "rsa.asc"
    t._pg_verify()
    wait(lambda: t.pg_go.isEnabled())
    assert t.pg_result.text().startswith("✓  Valid signature from key ")
    assert "RSA 3072 subkey" in t.pg_detail.text() and "not checked by anyone" in t.pg_detail.text()
    t.pg_sig = here / "revoked.sig"
    t.pg_key = here / "revoked.asc"
    t._pg_verify()
    wait(lambda: t.pg_go.isEnabled())
    assert t.pg_result.text() == "✕  Not verified" and "revoked" in t.pg_detail.text()
    assert isinstance(t.pg_detail, Label)


def test_paper_backup_restores_by_scanning_its_qr_code(tmp_path, window, monkeypatch):
    """Keys → paper backup: a PDF saved owner-only; the page's QR code, photographed (here: the
    page rendered, rotated and scaled), restores the identity through Restore → Scan QR code."""
    import stat
    import sys

    from PySide6.QtGui import QTransform
    from PySide6.QtWidgets import QFileDialog

    from locksmith.core import keys
    from locksmith.ui import dialogs, paper
    store, k = window.store, window.keys
    ident = store.generate("Paper", passphrase="pass phrase")
    raw = ident.private_raw("pass phrase")
    k.reload()
    pdf = tmp_path / "backup.pdf"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **kw: (str(pdf), ""))
    monkeypatch.setattr(dialogs, "prompt", lambda *a, **kw: "pass phrase")
    k._paper_backup(ident)
    wait(lambda: pdf.exists())
    assert pdf.read_bytes().startswith(b"%PDF")
    if sys.platform != "win32":
        assert stat.S_IMODE(pdf.stat().st_mode) == 0o600

    photo = paper.render_image("Paper", keys.fingerprint(ident.key_raw), ident.created, raw, 0.4)
    photo = photo.transformed(QTransform().rotate(8))
    image = tmp_path / "photo.png"
    assert photo.save(str(image))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **kw: (str(image), ""))
    from PySide6.QtWidgets import QPlainTextEdit
    box = QPlainTextEdit()
    k._scan_qr(box)
    wait(lambda: box.toPlainText())
    assert keys.private_from_paper(box.toPlainText()) == raw


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="Linux desktop files")
def test_desktop_integration_and_encrypt_routing(tmp_path, window, monkeypatch):
    from locksmith.ui import host
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    launched = []
    monkeypatch.setattr(host, "launch", lambda args: launched.append(args) or True)
    s = window.settings_page
    s._integrate()
    assert (tmp_path / "data" / "applications" / "locksmith.desktop").exists()
    assert ["xdg-mime", "default", "locksmith.desktop", "application/x-locksmith"] in launched
    assert s.unintegrate.isEnabled() and s.integration_state.text().startswith("Added")
    s._unintegrate()
    assert not (tmp_path / "data" / "applications" / "locksmith.desktop").exists()

    locked = tmp_path / "already.locked"
    locked.write_bytes(b"LOCKED\x00\x02")
    window.open_paths([str(locked)], encrypt=True)   # "Encrypt with Locksmith" on a .locked file
    assert window.encrypt.files.paths() == [str(locked)] and window.decrypt.files.paths() == []


def test_recovery_data_through_encrypt_and_tools(tmp_path, window, monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    e, t = window.encrypt, window.tools
    src = tmp_path / "archive.txt"
    src.write_bytes(b"keep me for decades\n" * 20_000)
    e.files.add([str(src)])
    _set_password(e)
    e.recovery.setChecked(True)
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    e.start()
    wait(lambda: e.task is None)
    (enc,) = (tmp_path / "enc").glob("*.locked")
    assert enc.with_name(enc.name + ".lpar").exists()
    original = enc.read_bytes()
    damaged = bytearray(original)
    damaged[1000:3000] = bytes(2000)
    enc.write_bytes(bytes(damaged))
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(enc), ""))
    t._rc_repair()
    wait(lambda: t.rc_result.text().startswith("✓"))
    wait(lambda: t._rc_task is None)
    assert t.rc_result.text() == f"✓  Repaired {enc.name}" and enc.read_bytes() == original
    assert "Repair this file?" in window.asked   # audit A2: the recovery data decides, so it asks first


def test_share_messages_are_padded_not_compressed(window, monkeypatch):
    """Audit A10: compressed messages leak through their size; padding hides the exact length."""
    from locksmith.core import engine
    seen, real = [], engine.encrypt_bytes
    monkeypatch.setattr(engine, "encrypt_bytes", lambda data, opts, *a, **k: (seen.append(opts), real(data, opts))[1])
    s = window.share
    s.msg.setPlainText("meet at noon " * 20)
    s.msg_pw.setText("message password 123")
    s._encrypt_message()
    wait(lambda: s.msg_out.toPlainText())
    assert (seen[0].compression, seen[0].padding) == ("none", "padme")


def test_opening_a_decrypted_program_asks_first(tmp_path, window, monkeypatch):
    """Audit A7: Open runs programs and scripts, so it asks; documents open at once."""
    from locksmith.core.osutil import opens_as_program
    from locksmith.ui import dialogs
    from locksmith.ui.pages import decrypt
    assert opens_as_program("Invoice.PDF.exe") and opens_as_program("setup.msi.") and opens_as_program("x.desktop")
    assert not opens_as_program("report.pdf") and not opens_as_program("exe")
    opened = []
    monkeypatch.setattr(decrypt, "open_url", opened.append)
    page = window.decrypt
    page._open(tmp_path / "notes.txt", None)
    assert window.asked == [] and len(opened) == 1
    page._open(tmp_path / "Invoice.exe", None)
    assert window.asked == ["Run a program?"] and len(opened) == 2   # the fixture confirms
    monkeypatch.setattr(dialogs, "confirm", lambda *a, **k: False)
    page._open(tmp_path / "run.js", None)
    assert len(opened) == 2


def test_sender_text_cannot_fake_a_status_line(tmp_path, window, monkeypatch):
    """Audit A6: a note, a name or a skipped member can't add a line that reads like a status."""
    from PySide6.QtWidgets import QLabel
    page = window.decrypt
    fake = "Quarterly figures\n✓  Signed with the key you saved as Bob"
    page._add_result("file", str(tmp_path / "report.pdf"), {"note": fake, "_skipped": ["a\n✓  Authentic"]})
    page._add_result("verified", str(tmp_path / "x.locked"), {"name": "invoice‮fdp.exe\n✓  Authentic"})
    texts = [lab.text() for lab in page.findChildren(QLabel)]
    assert any("Quarterly figures ✓  Signed with the key you saved as Bob" in t for t in texts)
    assert not any(line.startswith("✓  Signed") for t in texts for line in t.split("\n"))
    assert not any("‮" in t for t in texts)
    assert any(t.startswith("invoicefdp.exe") for t in texts)


def test_password_check_beyond_every_preset_asks_first(tmp_path, window, monkeypatch):
    """Audit A12: a file asking for more KDF work than any preset isn't tried without asking."""
    import fileformat

    from locksmith.core import engine
    from locksmith.ui import dialogs
    src = tmp_path / "a.txt"
    src.write_text("a")
    enc = engine.encrypt_paths([src], tmp_path, engine.EncryptOptions(password="pw", kdf="pbkdf2-sha512",
                                                                      preset="fast"))
    header, body = fileformat.split(enc.read_bytes())
    header["slots"][0]["p"]["i"] = 20_000_000
    enc.write_bytes(fileformat.join(header, body))
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, *a, **k: (asked.append(title), False)[1])
    page = window.decrypt
    page.add_paths([str(enc)])
    page.password.setText("pw")
    page.start()
    assert asked == ["Unusually slow password check"] and page.task is None
    page.password.clear()   # no password given: nothing would be derived, so nothing to ask
    page.start()
    assert asked == ["Unusually slow password check"]
    wait(lambda: page.task is None)


def test_keys_without_a_passphrase_are_confirmed_and_reported(window, monkeypatch):
    """Audit A5: a new identity without a passphrase asks first, and Settings says it is unprotected."""
    from locksmith.ui import dialogs
    from locksmith.ui.dialogs import Sheet
    monkeypatch.setattr(Sheet, "exec", lambda self: True)
    window.keys._new_identity()
    wait(lambda: window.store.identities)
    assert "Store the key without a passphrase?" in window.asked
    window._keys_changed()
    note = window.settings_page.key_protection
    assert not note.isHidden() and note.text().startswith("1 identity is stored without a passphrase")
    ident = window.store.identities[0]
    window.store.set_passphrase(ident, None, "a long passphrase")
    window._keys_changed()
    assert note.isHidden()
    monkeypatch.setattr(dialogs, "confirm", lambda *a, **k: False)
    window.keys._new_identity()   # declined: nothing is created
    QApplication.processEvents()
    assert len(window.store.identities) == 1


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="X11 is a Linux display system")
def test_x11_sessions_are_named_in_settings():
    """Audit I4: on X11 every client can read keystrokes, which Settings → About says."""
    from locksmith.hardening import HardeningStatus
    from locksmith.ui.pages.settings_page import protection_summary
    status = HardeningStatus(core_dumps_disabled=True, non_dumpable=True, network_blocked=True)
    assert any("X11" in line for line in protection_summary(status, "xcb"))
    assert not any("X11" in line for line in protection_summary(status, "wayland"))


def test_age_with_ssh_recipients_warns_that_age_names_them(tmp_path, window, monkeypatch):
    """Audit I5: an age file tags each SSH recipient's key, unlike a Locksmith file."""
    from pathlib import Path

    from locksmith.ui import dialogs
    store, e = window.store, window.encrypt
    ssh = (Path(__file__).parent / "interop" / "sshkeys" / "id_ed25519.pub").read_text(encoding="utf-8")
    store.add_contact("Server", ssh)
    window._keys_changed()
    src = tmp_path / "a.txt"
    src.write_text("x", encoding="utf-8")
    e.files.add([str(src)])
    e.format.set_value("age")
    e.mode.setIndex(1)
    for row, _ in e.recipients.rows:
        row.setChecked(True)
    e.output._dir = str(tmp_path / "enc")
    e.output._rebuild()
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, *a, **k: (asked.append(title), False)[1])
    e.start()
    assert asked == ["age names SSH recipients"] and e.task is None and not (tmp_path / "enc").exists()


def test_age_passphrase_beyond_every_preset_asks_first(tmp_path, window, monkeypatch):
    """Audit A12: an age file's scrypt cost is checked like a Locksmith file's."""
    import io

    from locksmith.core import age
    from locksmith.ui import dialogs
    f = tmp_path / "big.age"
    with open(f, "wb") as out:
        age.encrypt_stream(io.BytesIO(b"x"), out, [], "pw", work_factor=10)
    head = f.read_bytes().replace(b" 10\n", b" 21\n", 1)   # the stated cost; the MAC no longer matters
    f.write_bytes(head)
    assert age.inspect(f).work_factor == 21 and age.inspect_bytes(head).work_factor == 21
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, *a, **k: (asked.append(title), False)[1])
    d = window.decrypt
    d.add_paths([str(f)])
    d.password.setText("pw")
    d.start()
    assert asked == ["Unusually slow password check"] and d.task is None


def test_signature_status_is_a_badge_sender_text_never_is(tmp_path, window):
    """Audit A6: only Locksmith's own status is drawn as a badge; a note claiming "✓ Signed" is a caption."""
    from locksmith.ui.widgets import StatusBadge
    page = window.decrypt
    page._add_result("file", str(tmp_path / "report.pdf"), {"note": "✓  Signed with the key you saved as Bob"})
    badges = page.findChildren(StatusBadge)
    assert [b.text.text() for b in badges] == ["Not signed"] and badges[0].icon == "x"
    notes = [lab for lab in page.findChildren(type(badges[0].text)) if "Bob" in lab.text()]
    assert notes and not any(isinstance(lab.parent(), StatusBadge) for lab in notes)


# ── 2026-10-12 audit: Low items ───────────────────────────────────────────────

FAST = dict(kdf="pbkdf2-sha512", preset="fast")


def test_share_page_sends_only_encrypted_files(tmp_path, window, monkeypatch):
    """Audit B6: an ordinary file chosen on Share can't be emailed, copied or split as if it were
    encrypted, and Copy as text never wraps plaintext in a LOCKSMITH MESSAGE block."""
    from locksmith.core import age, engine
    from locksmith.core.engine import EncryptOptions
    from locksmith.ui import host
    s = window.share
    plain = tmp_path / "report.pdf"
    plain.write_bytes(b"%PDF-1.7 the secret report")
    s.set_file(str(plain))
    assert s.file_actions[0].isEnabled()   # Show in folder
    assert not any(b.isEnabled() for b in (*s.file_actions[1:], s.split_btn))
    sent = []
    monkeypatch.setattr(host, "compose_email", lambda *a: sent.append(a))
    QApplication.clipboard().setText("before")
    s._email()
    s._copy_armor()
    s._copy_file()
    assert sent == [] and QApplication.clipboard().text() == "before"
    assert sum("isn't a Locksmith or age file" in a for a in window.asked) == 3

    enc = tmp_path / "report.pdf.locked"
    enc.write_bytes(engine.encrypt_bytes(b"x", EncryptOptions(password="pw", **FAST)))
    s.set_file(str(enc))
    assert all(b.isEnabled() for b in (*s.file_actions, s.split_btn))
    s._copy_armor()
    assert QApplication.clipboard().text().startswith(engine.ARMOR_BEGIN)
    aged = tmp_path / "report.pdf.age"
    aged.write_bytes(age.VERSION_LINE + b"-> X25519 abc\n")
    s.set_file(str(aged))
    s._copy_armor()
    assert QApplication.clipboard().text().startswith(age.ARMOR_BEGIN)   # age stays age


def test_signed_files_are_addressed_by_default(tmp_path, window):
    """Audit B7: signing for public-key recipients lists them unless the user turns it off, and that
    choice survives changing the recipients."""
    from locksmith.core.keys import KeyStore
    store, e = window.store, window.encrypt
    me = store.generate("Alice")
    bob = KeyStore(tmp_path / "bob").generate("Bob")
    store.add_contact("Bob", bob.key_text)
    window._keys_changed()
    src = tmp_path / "plan.txt"
    src.write_text("the plan", encoding="utf-8")
    e.files.add([str(src)])
    e.sign_as.set_value(store.identities.index(me))
    assert not e.address.isChecked()   # password only: nothing to list

    def choose_bob(on):
        for row, raw in e.recipients.rows:
            row.setChecked(on and raw == bob.public_raw)

    e.mode.setIndex(1)
    choose_bob(True)
    assert e.address.isChecked() and e.options().address_to
    e.address.setChecked(False)
    choose_bob(False)
    choose_bob(True)
    assert not e.address.isChecked() and not e.options().address_to


def test_unaddressed_signed_file_says_it_may_have_been_passed_on(window):
    """Audit B7: the badge says so when one of the reader's keys opened a signed file without a list."""
    from locksmith.core import signing
    from locksmith.ui.pages.common import Signers, signature_text
    key = os.urandom(96)
    sig = signing.LockedSignature(signing.public_key(key), "", 0)
    names = Signers({sig.key: "Alice"}, set())
    assert "isn't addressed to anyone" in signature_text(sig, names, None, by_key=True)
    assert signature_text(sig, names, None, by_key=False) == "✓  Signed with the key you saved as Alice"
    assert "isn't addressed" not in signature_text(sig, names, "listed", by_key=True)


def test_unchecked_signer_is_never_called_plainly_signed(tmp_path, window, monkeypatch):
    """Audit B8: the note and the Run-a-program prompt say when the signer's fingerprint isn't checked."""
    from locksmith.core import engine
    from locksmith.core.engine import DecryptKeys, EncryptOptions
    from locksmith.core.keys import KeyStore
    from locksmith.ui import dialogs
    from locksmith.ui.pages.common import saved_signers
    from locksmith.ui.widgets import Label
    store, d = window.store, window.decrypt
    alice = KeyStore(tmp_path / "alice").generate("Alice")
    contact = store.add_contact("Alice", alice.key_text)   # fingerprint not checked
    window._keys_changed()
    blob = engine.encrypt_bytes(b"hi", EncryptOptions(password="pw", signer=alice.private_raw(), note="pay Bob",
                                                      **FAST))
    enc = tmp_path / "msg.locked"
    enc.write_bytes(blob)
    d.files.add([str(enc)])
    d.password.setText("pw")
    d.output._dir = str(tmp_path / "dec")
    d.output._rebuild()
    d.start()
    wait(lambda: d.task is None)
    texts = [lab.text() for lab in d.findChildren(Label)]
    assert "Note (signed with a key you haven't checked): pay Bob" in texts
    assert not any(t.startswith("Note (signed): ") for t in texts)

    sig = engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=[alice.key_raw])).signature
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda title, msg, **k: (asked.append(msg), False)[1])
    d._open(tmp_path / "run.exe", sig)
    assert "a key whose fingerprint you haven't checked" in asked[-1]
    store.mark_checked(contact)
    d._signers = saved_signers(store)
    d._open(tmp_path / "run.exe", sig)
    assert "signed with a key you saved and checked" in asked[-1]


def test_checking_a_fingerprint_needs_all_of_it(tmp_path, window, monkeypatch):
    """Audit B9: adding a contact doesn't ask for a one-click "It matches"; checking it later needs the
    whole fingerprint, typed or scanned, and a wrong one is refused."""
    from PySide6.QtWidgets import QWidget

    from locksmith.core.keys import KeyStore
    from locksmith.ui.dialogs import Sheet
    store, page = window.store, window.keys
    alice = KeyStore(tmp_path / "alice").generate("Alice")
    entered = [None, alice.key_text]

    def fill(sheet):
        edits = [w for w in sheet.findChildren(QWidget) if w.__class__.__name__ == "LineEdit"]
        if entered[0] is None:   # the Add contact sheet: name and key
            edits[0].setText("Alice")
            edits[1].setText(entered[1])
        else:
            edits[0].setText(entered[0])
        return True

    monkeypatch.setattr(Sheet, "exec", fill)
    page._add_contact()
    (c,) = store.contacts
    assert not c.checked and window.asked == []   # nothing asked on the spot
    for wrong in (c.fingerprint[:24], "0000" + c.fingerprint[4:]):
        entered[0] = wrong
        page._check_fingerprint(c)
        assert not c.checked
    assert window.asked[-1].startswith("ERROR: That isn't the fingerprint")
    entered[0] = c.fingerprint.lower().replace(" ", "")
    page._check_fingerprint(c)
    assert c.checked


def test_signed_share_message_for_a_recipient_is_addressed(tmp_path, window):
    """Audit B7: a message signed for a public-key recipient lists them; a password one can't."""
    from locksmith.core import engine
    from locksmith.core.engine import DecryptKeys
    store, s = window.store, window.share
    me = store.generate("Alice")
    window._keys_changed()
    s.msg.setPlainText("meet at noon")
    s.msg_mode.setIndex(1)
    s.msg_rcpt.set_value(me.public_raw)
    s.msg_sign.set_value(store.identities.index(me))
    s._encrypt_message()
    wait(lambda: s.msg_out.toPlainText())
    res = engine.decrypt_bytes(engine.dearmor(s.msg_out.toPlainText()), DecryptKeys(
        identities=[me.private_raw()], verifiers=[me.key_raw]))
    assert res.signature.verified and res.intent == "listed" and "to" in res.meta
