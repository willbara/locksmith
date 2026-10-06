"""Talking to the host desktop from a hardened process.

Locksmith marks itself non-dumpable (see locksmith/hardening.py). The desktop
portal identifies callers through /proc/<pid>/root, which that hides, so the
portal rejects every request made directly by this process. Anything that needs
the host desktop therefore goes through a short-lived child process instead:
children start dumpable again, and they never hold any secrets.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import urllib.parse
from pathlib import Path

from ..core.osutil import IS_WINDOWS
from ..core.sysenv import clean_env

# Desktop session variables a launched program needs.
_SESSION_VARS = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE",
                 "DBUS_SESSION_BUS_ADDRESS")


def launch(args: list[str]) -> bool:
    """Start a host program (file manager, mail client...). Locksmith runs without
    network access and that restriction is inherited by its children, so programs
    are started by the user's systemd instead: outside Locksmith's process tree and
    sandbox, like any app started from the desktop."""
    env = clean_env()
    runner = shutil.which("systemd-run", path=env.get("PATH"))
    if runner:
        args = [runner, "--user", "--quiet", "--collect", "--no-block",
                "--property=KillMode=process",  # keep the app running after its launcher exits
                *(f"--setenv={v}={env[v]}" for v in _SESSION_VARS if v in env), "--", *args]
    try:
        subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except OSError:
        return False


def reveal(path: Path):
    """Show a file selected in the system file manager."""
    path = Path(path).resolve()
    if IS_WINDOWS:
        subprocess.Popen(f'explorer /select,"{path}"')
        return
    ok = launch(["dbus-send", "--session", "--dest=org.freedesktop.FileManager1", "--type=method_call",
                 "/org/freedesktop/FileManager1", "org.freedesktop.FileManager1.ShowItems",
                 f"array:string:{path.as_uri()}", "string:"])
    if not ok:
        open_path(path.parent)


def open_path(path: Path):
    """Open a file or folder with its default application."""
    path = Path(path).resolve()
    if IS_WINDOWS:
        os.startfile(str(path))
        return
    if not launch(["xdg-open", path.as_uri()]):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        QDesktopServices.openUrl(QUrl(path.as_uri()))


def mail_safe(text: str) -> str:
    """Text for a mail subject or body without the characters mail launchers parse. Some
    xdg-email versions paste the decoded subject into Thunderbird's ``subject='…'`` unescaped
    (the CVE-2022-4055 class), so a file name like ``x',cc='someone@example.com`` would add
    a recipient. File names come from whoever made the file."""
    return "".join(" " if c in "'\",&%\\;" or not c.isprintable() else c for c in text)


def compose_email(subject: str, body: str, attachment: Path) -> bool:
    """Start a new email. Returns True if the file was attached automatically; on
    Windows there is no standard way to attach, so the file is shown in Explorer."""
    subject, body = mail_safe(subject), mail_safe(body)
    if IS_WINDOWS:
        query = urllib.parse.urlencode({"subject": subject, "body": body}, quote_via=urllib.parse.quote)
        os.startfile(f"mailto:?{query}")
        reveal(attachment)
        return False
    if not launch(["xdg-email", "--subject", subject, "--body", body, "--attach", str(Path(attachment).resolve())]):
        raise OSError("xdg-email is not available")
    return True


def system_color_scheme() -> str | None:
    """"dark", "light", or None if the desktop has no preference or cannot be asked."""
    if IS_WINDOWS:
        return None  # Qt reads the Windows setting itself
    try:
        out = subprocess.run(
            ["gdbus", "call", "--session", "--dest", "org.freedesktop.portal.Desktop",
             "--object-path", "/org/freedesktop/portal/desktop",
             "--method", "org.freedesktop.portal.Settings.ReadOne",
             "org.freedesktop.appearance", "color-scheme"],
            env=clean_env(), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=2,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"uint32 (\d)", out)
    return {"1": "dark", "2": "light"}.get(m[1]) if m else None
