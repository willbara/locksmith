from __future__ import annotations

import os
import sys
import time


def _attach_windows_console():
    """The Windows build is a GUI program with no console; for --self-test, print
    into the console it was started from (the exit code reports the result too)."""
    import ctypes
    if ctypes.windll.kernel32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
        sys.stdout = sys.stderr = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115


def command_line(args: list[str]) -> tuple[list[str], bool]:
    """The paths to open, and whether --encrypt asked for them all to go to Encrypt (as the file
    manager's "Encrypt with Locksmith" does). Everything after "--" is a path."""
    paths, encrypt, options = [], False, True
    for a in args:
        if options and a == "--":
            options = False
        elif options and a.startswith("-"):
            encrypt = encrypt or a == "--encrypt"
        else:
            paths.append(a)
    return paths, encrypt


def qt_arguments(argv: list[str]) -> list[str]:
    """What Qt is given of the command line: the program name only. Qt reads every argument for options
    of its own (-platformpluginpath, -plugin, -style…) and doesn't stop at "--", so a file name passed
    on the command line could otherwise make it load a library from a folder (audit B3)."""
    return argv[:1]


def instance_address() -> tuple[str, bytes] | None:
    """Where this user's running Locksmith listens for later launches, and the key both sides prove they
    hold, or None when that can't be set up. Two running copies would each save their own key list over
    the other's and shred each other's temporary files. The key is a random token in the private config
    folder: another user can't stand in for either side, so the paths a launch hands over stay private.
    Linux: a socket file in a folder only this user can enter, so no other user can connect to it, or
    take the address first and leave every launch waiting for an answer. Windows: a named pipe."""
    import hashlib
    import re
    import secrets

    from .core.keys import config_dir
    from .core.osutil import open_new
    folder = config_dir()
    path = folder / "instance"
    try:
        fd = open_new(path)
    except FileExistsError:
        try:
            token = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError):
            return None
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return None
    except OSError:
        return None
    else:
        token = secrets.token_hex(16)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(token)
    # Other users can list pipe names, so the name is a hash: the token stays secret. The hash also keeps
    # the sockets of two config folders apart in the one runtime folder.
    name = "locksmith-" + hashlib.sha256(token.encode()).hexdigest()[:32]
    if sys.platform == "win32":
        return rf"\\.\pipe\{name}", bytes.fromhex(token)
    return str(_socket_folder(folder) / f"{name[:26]}.sock"), bytes.fromhex(token)   # a socket path is short


def _socket_folder(fallback):
    """Where the socket file goes: the session's runtime folder (a short path, in memory, emptied at logout)
    when it is this user's alone, else the config folder."""
    import stat
    from pathlib import Path
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    try:
        st = os.stat(runtime) if runtime else None
    except OSError:
        st = None
    if st and stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o077:
        return Path(runtime)
    return fallback


MAX_HANDOVER = 4 << 20   # above any command line (Linux allows about 2 MiB, Windows 32K characters)


def hand_over(where: tuple[str, bytes], paths: list[str], encrypt: bool) -> bool:
    """Give the paths to the Locksmith already running there. False when none answers."""
    import json
    from multiprocessing import AuthenticationError
    from multiprocessing.connection import Client
    address, key = where
    try:
        with Client(address, authkey=key) as conn:   # bytes only: never pickle
            conn.send_bytes(json.dumps({"paths": [os.path.abspath(p) for p in paths], "encrypt": encrypt}).encode())
    except (OSError, EOFError, AuthenticationError):   # nobody listening, a stale socket, or a failed handshake
        return False
    return True


def listen(where: tuple[str, bytes], on_paths) -> bool | None:
    """Accept later launches in a background thread and call ``on_paths(paths, encrypt)`` from it. Only
    one copy can: the first to ask. False: another copy has the address (it is running, or starting), so
    hand over to it. None: listening isn't possible here, and Locksmith runs as it would without it."""
    import json
    import threading
    from multiprocessing import AuthenticationError
    from multiprocessing.connection import Listener
    address, key = where
    lock = None
    if sys.platform != "win32":
        # A socket file outlives a copy that was killed, so who listens is decided by a lock, which
        # doesn't: its holder removes the old socket file and makes its own. (A named pipe goes away
        # with its process, and Windows lets only one process create it.)
        import fcntl
        try:
            lock = os.open(address + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return None
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(lock)
            return False
        try:
            os.unlink(address)
        except OSError:
            pass
    try:
        listener = Listener(address, authkey=key)
    except OSError as e:
        if lock is not None:
            os.close(lock)
        return False if isinstance(e, PermissionError) and sys.platform == "win32" else None

    def run(lock=lock):   # the lock is held for as long as this copy runs
        while True:
            try:
                conn = listener.accept()
            except (AuthenticationError, EOFError):   # not one of this user's launches, or it gave up
                continue
            except OSError:
                listener.close()   # so later launches find nobody, rather than hang in the handshake
                return
            try:
                with conn:
                    msg = json.loads(conn.recv_bytes(MAX_HANDOVER))
                paths, encrypt = msg["paths"], msg["encrypt"]
            except (OSError, EOFError, ValueError, KeyError, TypeError, RecursionError):
                continue
            if isinstance(paths, list) and all(isinstance(p, str) for p in paths) and isinstance(encrypt, bool):
                on_paths(paths, encrypt)
    threading.Thread(target=run, daemon=True).start()
    return True


def _options(args: list[str]) -> list[str]:
    return args[:args.index("--")] if "--" in args else args


def main() -> int:
    if "--self-test" in _options(sys.argv[1:]):
        if sys.platform == "win32" and getattr(sys, "frozen", False):
            _attach_windows_console()
        from .selftest import run
        return run()

    # Before anything touches a secret: keep process memory from leaving the process.
    from .hardening import harden
    harden()

    linux = sys.platform.startswith("linux")
    if linux:
        # Prefer native Wayland, fall back to X11.
        os.environ.setdefault("QT_QPA_PLATFORM", "wayland;xcb")
        # The portal rejects this hardened process (see ui/host.py), so do not load the
        # portal theme, and silence Qt's harmless failed attempt to register with it.
        os.environ["QT_QPA_PLATFORMTHEME"] = "generic"
        os.environ["QT_LOGGING_RULES"] = ";".join(
            filter(None, [os.environ.get("QT_LOGGING_RULES"), "qt.qpa.services=false"]))
    elif sys.platform == "win32":
        # Own taskbar identity, so Windows shows Locksmith's icon rather than Python's.
        import ctypes
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Locksmith.Locksmith")
        except (AttributeError, OSError):
            pass
    from PySide6.QtCore import QObject, Qt, Signal
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    if linux:
        # Qt's own file dialogs: native ones go through the portal, which is unavailable.
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs, True)
    app = QApplication(qt_arguments(sys.argv))
    app.setApplicationName("Locksmith")
    app.setApplicationDisplayName("Locksmith")
    app.setDesktopFileName("locksmith")
    app.setStyle("Fusion")
    # Qt is connected to the display now (over TCP too, for X11 via SSH), so the
    # rest of the session can run without any network access.
    from .hardening import block_network
    block_network()

    from .ui.settings import settings
    from .ui.theme import app_icon, load_fonts, theme
    from .ui.window import MainWindow

    load_fonts()
    theme.animations = bool(settings["animations"])
    theme.apply(settings["theme"])
    app.setWindowIcon(app_icon())
    app.styleHints().colorSchemeChanged.connect(
        lambda _: theme.mode == "system" and theme.apply("system"))
    # Without the portal theme there is no change signal: re-check the system
    # scheme whenever the app is focused.
    app.applicationStateChanged.connect(
        lambda state: state == Qt.ApplicationState.ApplicationActive and theme.mode == "system"
        and theme.refresh_system())

    paths, encrypt = command_line(sys.argv[1:])
    where = instance_address()
    if where and hand_over(where, paths, encrypt):
        return 0   # the running Locksmith opens them: one copy at a time keeps keys.json whole

    class Handover(QObject):
        received = Signal(list, bool)   # emitted from the listening thread, delivered on this one

    handover, windows, early = Handover(), [], []

    def opened(more: list[str], enc: bool):
        if not windows:
            early.append((more, enc))   # the window is still being built
            return
        win = windows[0]
        if more:
            win.open_paths(more, enc)
        win.showNormal()
        win.raise_()
        win.activateWindow()
    handover.received.connect(opened)
    # Listen before the window is built. Building it takes a moment, and copies started together (several
    # files opened at once) would otherwise all find nobody listening and all stay open.
    if where and listen(where, handover.received.emit) is False:
        # Another copy got there first and is still starting: it takes the paths as soon as it answers.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if hand_over(where, paths, encrypt):
                return 0
            time.sleep(0.1)
    win = MainWindow(paths, encrypt)
    windows.append(win)
    for more, enc in early:
        opened(more, enc)
    win.show()
    if linux:
        _refresh_integration()
    return app.exec()


def _refresh_integration():
    """Update file-manager integration this program installed earlier (best effort)."""
    from .core import desktop
    from .core.errors import LocksmithError
    from .ui import host
    try:
        if desktop.refresh_linux():
            for args in desktop.refresh_commands()[:2]:   # not the default-app setting: that was the user's
                host.launch(args)
    except (OSError, LocksmithError):
        pass


if __name__ == "__main__":
    sys.exit(main())
