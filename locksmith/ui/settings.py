"""Persisted user preferences."""

from __future__ import annotations

import json

from ..core import compress, engine, kdf
from ..core.ciphers import SUITES
from ..core.keys import config_dir, write_secret_file

DEFAULTS = {
    "theme": "dark",
    "animations": True,
    "suite": "aes-256-gcm",
    "preset": "balanced",
    "kdf": "argon2id",
    "compression": "auto",
    "level": "balanced",
    "chunk_size": 1 << 20,
    "padding": "none",
    "threads": 0,
    "hide_name": False,
    "hide_recipients": False,
    "bundle": False,
    "armor": False,
    "shred_after": False,
    "delete_after_decrypt": False,
    "confirm_shred": True,
    "auto_lock": 10,        # minutes of inactivity; 0 = never
    "strip_metadata": False,
}


# Every value a setting may take. Anything else in settings.json (a typo, a value
# from another version) falls back to the default instead of reaching the engine.
ALLOWED = {
    "theme": {"dark", "light", "system"},
    "suite": set(SUITES),
    "preset": set(kdf.PRESETS),
    "kdf": set(kdf.KDFS),
    "compression": {"auto", "none", *compress.CODECS},
    "level": set(compress.LEVELS),
    "chunk_size": set(engine.CHUNK_SIZES),
    "padding": set(engine.PADDING),
    "threads": {0, 1, 2, 4, 8, 16},
    "auto_lock": {0, 1, 5, 10, 15, 30, 60},
}


def _valid(key, value) -> bool:
    default = DEFAULTS[key]
    if isinstance(default, bool):
        return isinstance(value, bool)
    if key in ALLOWED:
        try:
            return not isinstance(value, bool) and value in ALLOWED[key]
        except TypeError:  # unhashable value such as a list
            return False
    return isinstance(value, type(default))


class Settings:
    def __init__(self):
        self.path = config_dir() / "settings.json"
        self.data = dict(DEFAULTS)
        try:
            stored = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError):
            stored = {}
        if isinstance(stored, dict):
            for key, value in stored.items():
                if key in DEFAULTS and _valid(key, value):
                    self.data[key] = value

    def __getitem__(self, key):
        return self.data.get(key, DEFAULTS.get(key))

    def __setitem__(self, key, value):
        if key in DEFAULTS and not _valid(key, value):
            raise ValueError(f"Invalid value for setting {key!r}: {value!r}")
        self.data[key] = value
        self.save()

    def save(self):
        try:
            write_secret_file(self.path, json.dumps(self.data, indent=2))
        except OSError:
            pass


settings = Settings()
