"""Password-based key derivation with tunable strength presets."""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import CorruptedError

KEY_LEN = 32
SALT_LEN = 16

MiB_IN_KiB = 1024


@dataclass(frozen=True)
class KdfInfo:
    id: str
    label: str
    blurb: str


KDFS: dict[str, KdfInfo] = {
    k.id: k
    for k in (
        KdfInfo("argon2id", "Argon2id",
                "Memory-hard winner of the Password Hashing Competition."),
        KdfInfo("scrypt", "scrypt", "Memory-hard, widely deployed."),
        KdfInfo("pbkdf2-sha512", "PBKDF2-SHA512",
                "Classic and compatible, but not memory-hard."),
    )
}

PRESETS = {
    "fast": "Fast",
    "balanced": "Balanced",
    "strong": "Strong",
    "paranoid": "Paranoid",
}

_PARAMS = {
    "argon2id": {
        "fast": {"m": 64 * MiB_IN_KiB, "t": 2, "p": 4},
        "balanced": {"m": 256 * MiB_IN_KiB, "t": 3, "p": 4},
        "strong": {"m": 512 * MiB_IN_KiB, "t": 4, "p": 4},
        "paranoid": {"m": 1024 * MiB_IN_KiB, "t": 6, "p": 4},
    },
    "scrypt": {
        "fast": {"n": 2**16, "r": 8, "p": 1},
        "balanced": {"n": 2**18, "r": 8, "p": 1},
        "strong": {"n": 2**19, "r": 8, "p": 1},
        "paranoid": {"n": 2**20, "r": 8, "p": 1},
    },
    "pbkdf2-sha512": {
        "fast": {"i": 300_000},
        "balanced": {"i": 1_000_000},
        "strong": {"i": 2_000_000},
        "paranoid": {"i": 5_000_000},
    },
}

# Upper bounds accepted when reading a file, so a crafted header cannot make
# decryption allocate absurd memory or spin for minutes. They leave headroom
# above the Paranoid preset.
MAX_MEMORY_BYTES = 2 << 30
_LIMITS = {
    "argon2id": {"m": MAX_MEMORY_BYTES // 1024, "t": 16, "p": 16},
    "scrypt": {"n": 2**21, "r": 16, "p": 4},
    "pbkdf2-sha512": {"i": 20_000_000},
}


def params_for(kdf: str, preset: str) -> dict:
    return dict(_PARAMS[kdf][preset])


def beyond_presets(kdf: str, params: dict) -> bool:
    """Whether a file's KDF settings ask for more memory or work than any preset Locksmith
    writes. The sender chooses them, up to _LIMITS: a crafted file can make every password
    attempt take GiBs of memory and minutes, so the reader is asked first."""
    presets = _PARAMS.get(kdf)
    if presets is None or not isinstance(params, dict):
        return False
    return any(isinstance(params.get(k), int) and params[k] > max(p[k] for p in presets.values())
               for k in presets["paranoid"])


def describe(kdf: str, params: dict) -> str:
    if kdf == "argon2id":
        return f"Argon2id · {params['m'] // MiB_IN_KiB} MiB · {params['t']} passes · {params['p']} lanes"
    if kdf == "scrypt":
        mem = 128 * params["r"] * params["n"] // (1 << 20)
        return f"scrypt · N=2^{params['n'].bit_length() - 1} · {mem} MiB"
    return f"PBKDF2-SHA512 · {params['i']:,} iterations"


def validate(kdf: str, params: dict) -> None:
    if not isinstance(params, dict):
        raise CorruptedError("Key derivation parameters are malformed.")
    limits = _LIMITS.get(kdf)
    if limits is None:
        raise CorruptedError(f"Unknown key derivation function: {kdf}")
    for key, limit in limits.items():
        value = params.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > limit:
            raise CorruptedError("Key derivation parameters are out of range.")
    if set(params) != set(limits):
        raise CorruptedError("Key derivation parameters are malformed.")
    if kdf == "argon2id" and params["m"] < 8 * params["p"]:
        raise CorruptedError("Invalid Argon2id parameters.")
    if kdf == "scrypt":
        n, r = params["n"], params["r"]
        if n < 2 or n & (n - 1) or 128 * r * n > MAX_MEMORY_BYTES:
            raise CorruptedError("Invalid scrypt parameters.")


def derive(secret: bytes, salt: bytes, kdf: str, params: dict) -> bytes:
    validate(kdf, params)
    if kdf == "argon2id":
        return Argon2id(
            salt=salt, length=KEY_LEN, iterations=params["t"],
            lanes=params["p"], memory_cost=params["m"],
        ).derive(secret)
    if kdf == "scrypt":
        return Scrypt(salt=salt, length=KEY_LEN, n=params["n"], r=params["r"],
                      p=params["p"]).derive(secret)
    return PBKDF2HMAC(algorithm=hashes.SHA512(), length=KEY_LEN, salt=salt,
                      iterations=params["i"]).derive(secret)


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)
