"""AEAD cipher suites, including multi-layer cascades.

Every suite exposes the same shape: it is built from one 32-byte (or 64-byte
for SIV) key per layer and seals/opens a chunk given a 12-byte nonce and
associated data. Cascades apply each layer in order with independent keys, so
the data stays protected as long as any one layer's primitive holds.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)

TAG_SIZE = 16
NONCE_SIZE = 12


class _Layer:
    key_size = 32

    def __init__(self, key: bytes):
        raise NotImplementedError

    def seal(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        raise NotImplementedError

    def open(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        raise NotImplementedError


class _NonceAEAD(_Layer):
    impl: type

    def __init__(self, key: bytes):
        self._aead = self.impl(key)

    def seal(self, nonce, data, aad):
        return self._aead.encrypt(nonce, data, aad)

    def open(self, nonce, data, aad):
        return self._aead.decrypt(nonce, data, aad)


class _AESGCM(_NonceAEAD):
    impl = AESGCM


class _ChaCha(_NonceAEAD):
    impl = ChaCha20Poly1305


class _GCMSIV(_NonceAEAD):
    impl = AESGCMSIV


class _OCB3(_NonceAEAD):
    impl = AESOCB3


class _SIV(_Layer):
    # AES-SIV takes a 512-bit key (two AES-256 keys) and is nonce-misuse
    # resistant; the nonce is fed in as an extra associated-data component.
    key_size = 64

    def __init__(self, key: bytes):
        self._aead = AESSIV(key)

    def seal(self, nonce, data, aad):
        return self._aead.encrypt(data, [aad, nonce])

    def open(self, nonce, data, aad):
        return self._aead.decrypt(data, [aad, nonce])


LAYERS: dict[str, type[_Layer]] = {
    "aes-gcm": _AESGCM,
    "chacha20": _ChaCha,
    "aes-gcm-siv": _GCMSIV,
    "aes-ocb3": _OCB3,
    "aes-siv": _SIV,
}


@dataclass(frozen=True)
class Suite:
    id: str
    label: str
    layers: tuple[str, ...]
    blurb: str

    @property
    def overhead(self) -> int:
        return TAG_SIZE * len(self.layers)


SUITES: dict[str, Suite] = {
    s.id: s
    for s in (
        Suite("aes-256-gcm", "AES-256-GCM", ("aes-gcm",),
              "Industry standard. Hardware accelerated on modern CPUs."),
        Suite("chacha20-poly1305", "ChaCha20-Poly1305", ("chacha20",),
              "Fast everywhere, constant-time in software."),
        Suite("aes-256-gcm-siv", "AES-256-GCM-SIV", ("aes-gcm-siv",),
              "Nonce-misuse resistant variant of AES-GCM."),
        Suite("aes-256-ocb3", "AES-256-OCB3", ("aes-ocb3",),
              "Single-pass authenticated AES. Very fast."),
        Suite("aes-256-siv", "AES-256-SIV", ("aes-siv",),
              "Deterministic, misuse resistant, 512-bit key."),
        Suite("cascade-2", "Cascade: AES + ChaCha20", ("aes-gcm", "chacha20"),
              "Two independent keys and ciphers layered together."),
        Suite("cascade-3", "Cascade: AES + ChaCha20 + OCB3",
              ("aes-gcm", "chacha20", "aes-ocb3"),
              "Three layers. Maximum paranoia, slower."),
    )
}

DEFAULT_SUITE = "aes-256-gcm"


class SuiteCipher:
    """Seals and opens chunks with every layer of a suite."""

    def __init__(self, suite: Suite, keys: list[bytes]):
        self.suite = suite
        self._layers = [LAYERS[name](key) for name, key in zip(suite.layers, keys, strict=True)]

    def seal(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        for layer in self._layers:
            data = layer.seal(nonce, data, aad)
        return data

    def open(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
        for layer in reversed(self._layers):
            data = layer.open(nonce, data, aad)
        return data


def layer_key_sizes(suite: Suite) -> list[int]:
    return [LAYERS[name].key_size for name in suite.layers]


__all__ = ["InvalidTag", "SUITES", "DEFAULT_SUITE", "Suite", "SuiteCipher",
           "layer_key_sizes", "NONCE_SIZE", "TAG_SIZE"]
