"""Desktop integration (locksmith/core/desktop.py) and the --encrypt command line."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

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
    assert "exec '/home/me/Apps/Lock smith.AppImage' --encrypt -- \"$@\"" in script.read_text(encoding="utf-8")
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


@pytest.mark.skipif(sys.platform == "win32", reason="a POSIX shell script")
def test_files_script_passes_absolute_paths_after_dashes(tmp_path):
    """Audit B3: GNOME Files passes names relative to the folder; the script makes them absolute and puts
    them after "--", so a file named "-platformpluginpath" can't arrive as an option."""
    show = tmp_path / "show-args"   # stands in for Locksmith: prints each argument on a line
    show.write_text('#!/bin/sh\nfor a; do printf "%s\\n" "$a"; done\n', encoding="utf-8")
    show.chmod(0o755)
    desktop.install_linux(tmp_path / "share", [str(show)])
    script = tmp_path / "share" / "nautilus" / "scripts" / "Encrypt with Locksmith"
    folder = tmp_path / "Downloads"
    folder.mkdir()
    out = subprocess.run([str(script), "-platformpluginpath", "plugins", "a b.txt", "/abs/c"], cwd=folder,
                         capture_output=True, text=True, check=True).stdout.splitlines()
    here = os.path.realpath(folder)
    assert [line.replace(here, str(folder)) if line.startswith(here) else line for line in out] == [
        "--encrypt", "--", f"{folder}/-platformpluginpath", f"{folder}/plugins", f"{folder}/a b.txt", "/abs/c"]


@pytest.mark.skipif(sys.platform == "win32", reason="Windows integration needs the built .exe (install_windows)")
def test_source_command_runs_python_isolated(tmp_path, monkeypatch):
    """Audit B4: from source, the integration starts Python with -I, so modules in the folder being
    browsed (its working directory) are never imported in place of the real ones."""
    monkeypatch.delenv("APPIMAGE", raising=False)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    cmd = desktop.command()
    assert cmd[:2] == [sys.executable, "-I"] and cmd[-2:] == ["-m", "locksmith"]
    (tmp_path / "json.py").write_text("raise SystemExit('planted json ran')\n", encoding="utf-8")
    (tmp_path / "locksmith").mkdir()
    (tmp_path / "locksmith" / "__init__.py").write_text("raise SystemExit('planted package ran')\n",
                                                          encoding="utf-8")
    probe = cmd[:cmd.index("-m")] + ["-c", "import json, locksmith.core.desktop; print(locksmith.__file__)"]
    out = subprocess.run(probe, cwd=tmp_path, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert not out.stdout.strip().startswith(str(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="Linux desktop files")
def test_refresh_updates_only_this_programs_integration(tmp_path):
    """Audit B3/B4: an integration this program installed is brought up to date on start, so the fixed
    script reaches existing installs; one that points at another program, or a file Locksmith didn't
    write, is left alone."""
    cmd = ["/home/me/Apps/Locksmith.AppImage"]
    desktop.install_linux(tmp_path, cmd)
    script = tmp_path / "nautilus" / "scripts" / "Encrypt with Locksmith"
    old = f"#!/bin/sh\n# {desktop.MARKER}\nexec '/home/me/Apps/Locksmith.AppImage' --encrypt \"$@\"\n"
    script.write_text(old, encoding="utf-8")
    nemo = tmp_path / "nemo" / "actions" / "locksmith-encrypt.nemo_action"
    nemo.write_text("someone else's action\n", encoding="utf-8")
    assert desktop.refresh_linux(tmp_path, ["/elsewhere/Other.AppImage"]) == []   # not ours to update
    assert script.read_text(encoding="utf-8") == old
    assert desktop.refresh_linux(tmp_path, cmd) == [script]
    assert '--encrypt -- "$@"' in script.read_text(encoding="utf-8") and os.access(script, os.X_OK)
    assert nemo.read_text(encoding="utf-8") == "someone else's action\n"
    assert desktop.refresh_linux(tmp_path, cmd) == []   # up to date: nothing written
    assert desktop.refresh_linux(tmp_path / "none", cmd) == []   # not installed


def test_qt_never_sees_the_file_names(tmp_path):
    """Audit B3: Qt is given only the program name, so "-platformpluginpath dir" among the paths
    doesn't make it look for plugins there."""
    from locksmith.app import qt_arguments
    argv = ["locksmith", "--encrypt", "-platformpluginpath", "plugdir", "-style=x"]
    assert qt_arguments(argv) == ["locksmith"]
    code = ("import sys\nfrom PySide6.QtWidgets import QApplication\nfrom locksmith.app import qt_arguments\n"
            "QApplication(qt_arguments(sys.argv))\n")
    root = str(Path(desktop.__file__).resolve().parents[2])   # where locksmith is, installed or not
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "QT_DEBUG_PLUGINS": "1", "PYTHONPATH": root}
    (tmp_path / "plugdir").mkdir()
    out = subprocess.run([sys.executable, "-c", code, *argv[1:]], cwd=tmp_path, env=env, capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert "plugdir" not in out.stderr
