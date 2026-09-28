from __future__ import annotations

import os
import sys


def _attach_windows_console():
    """The Windows build is a GUI program with no console; for --self-test, print
    into the console it was started from (the exit code reports the result too)."""
    import ctypes
    if ctypes.windll.kernel32.AttachConsole(-1):  # ATTACH_PARENT_PROCESS
        sys.stdout = sys.stderr = open("CONOUT$", "w", encoding="utf-8")  # noqa: SIM115


def main() -> int:
    if "--self-test" in sys.argv[1:]:
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
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QGuiApplication
    from PySide6.QtWidgets import QApplication

    QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    if linux:
        # Qt's own file dialogs: native ones go through the portal, which is unavailable.
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_DontUseNativeDialogs, True)
    app = QApplication(sys.argv)
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

    paths = [a for a in sys.argv[1:] if not a.startswith("-")]
    win = MainWindow(paths)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
