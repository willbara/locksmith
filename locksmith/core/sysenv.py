"""Environment for running host programs from inside the AppImage bundle."""

from __future__ import annotations

import os


def clean_env() -> dict:
    """Restore the variables the AppImage/PyInstaller bootloader changed, so host
    programs load the host's libraries rather than ours."""
    env = dict(os.environ)
    for var in ("LD_LIBRARY_PATH", "QT_PLUGIN_PATH", "QML2_IMPORT_PATH", "PYTHONHOME", "PYTHONPATH"):
        orig = env.pop(var + "_ORIG", None)
        if orig is not None:
            env[var] = orig
        elif var in env and os.environ.get("APPIMAGE"):
            env.pop(var)
    return env
