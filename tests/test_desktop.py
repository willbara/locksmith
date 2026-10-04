"""Desktop integration (locksmith/core/desktop.py) and the --encrypt command line."""

import os
import shutil
import subprocess
import sys

import pytest

from locksmith.app import command_line
from locksmith.core import desktop
from locksmith.core.errors import LocksmithError


def test_exec_quoting():
    assert desktop.desktop_quote("/opt/Locksmith.AppImage") == '"/opt/Locksmith.AppImage"'
    assert desktop.desktop_quote('/home/a b/"x"$y`z\\w%') == r'"/home/a b/\\"x\\"\\$y\\`z\\\\w%%"'
    with pytest.raises(LocksmithError):
        desktop.desktop_quote("/a\nb")


@pytest.mark.skipif(sys.platform == "win32", reason="Linux desktop files")
def test_install_and_remove_on_linux(tmp_path):
    cmd = ["/home/me/Apps/Lock smith.AppImage"]
    written = desktop.install_linux(tmp_path, cmd)
    assert len(written) == 6 and desktop.installed_linux(tmp_path)
    entry = (tmp_path / "applications" / "locksmith.desktop").read_text(encoding="utf-8")
    assert 'Exec="/home/me/Apps/Lock smith.AppImage" %F' in entry and "MimeType=application/x-locksmith;" in entry
    script = tmp_path / "nautilus" / "scripts" / "Encrypt with Locksmith"
    assert os.access(script, os.X_OK)
    assert "exec '/home/me/Apps/Lock smith.AppImage' --encrypt \"$@\"" in script.read_text(encoding="utf-8")
    service = (tmp_path / "kio" / "servicemenus" / "locksmith-encrypt.desktop").read_text(encoding="utf-8")
    assert 'Exec="/home/me/Apps/Lock smith.AppImage" "--encrypt" %F' in service
    if shutil.which("desktop-file-validate"):
        for name in ("applications/locksmith.desktop",):
            out = subprocess.run(["desktop-file-validate", str(tmp_path / name)], capture_output=True, text=True)
            assert out.returncode == 0, out.stdout + out.stderr
    desktop.install_linux(tmp_path, cmd)   # again: replaces its own files
    assert sorted(desktop.uninstall_linux(tmp_path)) == sorted(written)
    assert not desktop.installed_linux(tmp_path) and not any(p.exists() for p in written)


@pytest.mark.skipif(sys.platform == "win32", reason="Linux desktop files")
def test_never_overwrites_or_removes_someone_elses_files(tmp_path):
    other = tmp_path / "applications" / "locksmith.desktop"
    other.parent.mkdir(parents=True)
    other.write_text("[Desktop Entry]\nName=Someone else's\n", encoding="utf-8")
    with pytest.raises(LocksmithError, match="left alone"):
        desktop.install_linux(tmp_path, ["/x"])
    assert desktop.uninstall_linux(tmp_path) == [] and other.exists()
    assert not (tmp_path / "nautilus").exists()


class FakeRegistry:
    def __init__(self):
        self.keys: dict[str, dict[str, str]] = {}

    def get(self, key, name):
        return self.keys.get(key, {}).get(name)

    def set(self, key, values):
        self.keys.setdefault(key, {}).update(values)

    def delete_tree(self, key):
        for k in [k for k in self.keys if k == key or k.startswith(key + "\\")]:
            del self.keys[k]


def test_windows_registry_entries():
    reg = FakeRegistry()
    desktop.install_windows(reg, exe=r"C:\Apps\Locksmith.exe")
    assert reg.get(".locked", "") == desktop.PROG_ID
    assert reg.get(desktop.PROG_ID + r"\shell\open\command", "") == r'"C:\Apps\Locksmith.exe" "%1"'
    assert reg.get(r"*\shell\Locksmith.Encrypt\command", "") == r'"C:\Apps\Locksmith.exe" --encrypt "%1"'
    assert desktop.installed_windows(reg)
    reg.set(r"*\shell\SomethingElse", {"": "x"})
    desktop.uninstall_windows(reg)
    assert set(reg.keys) == {r"*\shell\SomethingElse"}


def test_windows_leaves_another_programs_association():
    reg = FakeRegistry()
    reg.set(".locked", {"": "OtherApp.File"})
    with pytest.raises(LocksmithError, match="another program"):
        desktop.install_windows(reg, exe="C:\\L.exe")
    assert reg.keys == {".locked": {"": "OtherApp.File"}}


def test_command_line():
    assert command_line(["a.txt", "--encrypt", "b.locked"]) == (["a.txt", "b.locked"], True)
    assert command_line(["--self-test"]) == ([], False)
    assert command_line(["--encrypt", "--", "-odd name", "--encrypt"]) == (["-odd name", "--encrypt"], True)
