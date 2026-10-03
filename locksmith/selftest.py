"""`locksmith --self-test`: prove a build works on this machine.

Round-trips every cipher suite, codec and key-derivation function, checks
public-key encryption, signatures and memory hardening, then builds the full window
offscreen. Uses a throwaway config directory, so real keys and settings are
never touched. Exit code 0 means everything passed.
"""

from __future__ import annotations

import os
import sys
import tempfile
import traceback
from pathlib import Path


def run() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="locksmith-selftest-"))
    os.environ["XDG_CONFIG_HOME"] = str(tmp / "config")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    failures = []

    class Skip(Exception):
        """A protection this platform does not offer: reported, not a failure."""

    def check(name, fn):
        try:
            fn()
            print(f"  ok    {name}")
        except Skip as e:
            print(f"  skip  {name}: {e}")
        except Exception as e:  # noqa: BLE001
            failures.append(name)
            print(f"  FAIL  {name}: {e}")
            traceback.print_exc(limit=3)

    from .hardening import block_network, harden
    status = harden()
    block_network()

    from .core import compress, engine, kdf
    from .core.ciphers import SUITES
    from .core.engine import DecryptKeys, EncryptOptions
    from .core.keys import KeyStore

    data = os.urandom(70_000) + b"compressible " * 20_000
    src = tmp / "sample.bin"
    src.write_bytes(data)

    def roundtrip(**kw):
        def go():
            opts = EncryptOptions(password="pw", chunk_size=64 << 10, **{"kdf": "pbkdf2-sha512",
                                                                       "preset": "fast", **kw})
            out = tmp / "out" / os.urandom(4).hex()
            enc = engine.encrypt_paths([src], out, opts, verify=True)
            res = engine.decrypt_path(enc, out / "dec", DecryptKeys(password="pw"))
            assert res.path.read_bytes() == data, "decrypted data differs"
        return go

    windows = sys.platform == "win32"

    def hardening():
        if windows and not status.ok:
            # Older Windows versions and Wine may not support the mitigation policies.
            raise Skip("this system did not accept the DLL-injection protections")
        if not status.ok:
            raise RuntimeError("; ".join(status.problems))

    def no_network():
        import socket
        if windows:
            raise Skip("not available on Windows")
        if not status.network_blocked:
            raise RuntimeError("; ".join(status.problems) or "not installed")
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
        except OSError:
            return
        raise RuntimeError("an internet socket could still be created")

    print("Locksmith self-test")
    check("DLL-injection protection" if windows else "memory hardening", hardening)
    check("network blocked", no_network)
    for suite in SUITES:
        check(f"cipher {suite}", roundtrip(suite=suite, compression="none"))
    for codec in compress.CODECS:
        check(f"compression {codec}", roundtrip(compression=codec))
    for k in kdf.KDFS:
        check(f"key derivation {k}", roundtrip(kdf=k, preset="fast"))

    def pubkey():
        store = KeyStore(tmp / "keys")
        ident = store.generate("self-test", passphrase="pass")
        enc = engine.encrypt_paths([src], tmp / "pk", EncryptOptions(recipients=[ident.public_raw]))
        res = engine.decrypt_path(enc, tmp / "pk" / "dec", DecryptKeys(identities=[ident.private_raw("pass")]))
        assert res.path.read_bytes() == data

    check("public-key encryption", pubkey)

    def signatures():
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

        from .core import signing
        from .core.errors import LocksmithError

        # ML-DSA needs cryptography built with OpenSSL 3.5+, AWS-LC or BoringSSL; a distro
        # package linked to an older system OpenSSL lacks it.
        try:
            MLDSA65PrivateKey.generate()
        except UnsupportedAlgorithm:
            raise RuntimeError(f"ML-DSA is not available with {backend.openssl_version_text()}") from None
        ident = KeyStore(tmp / "signing").generate("self-test")
        text = signing.sign_file(src, ident.private_raw(), "self-test")
        assert signing.verify_file(src, text, [ident.key_raw]).comment == "self-test"
        blob = engine.encrypt_bytes(data, EncryptOptions(password="pw", kdf="pbkdf2-sha512", preset="fast",
                                                         signer=ident.private_raw()))
        res = engine.decrypt_bytes(blob, DecryptKeys(password="pw", verifiers=[ident.key_raw]))
        assert res.data == data and res.signature.verified, "a signed file did not verify"
        changed = tmp / "changed.bin"
        changed.write_bytes(data + b"!")
        try:
            signing.verify_file(changed, text, [ident.key_raw])
        except LocksmithError:
            return
        raise RuntimeError("a signature verified for a different file")

    check("signatures (Ed25519, ML-DSA-65)", signatures)

    def window():
        from PySide6.QtWidgets import QApplication

        from .ui.theme import load_fonts, theme
        from .ui.window import MainWindow
        app = QApplication.instance() or QApplication([])
        load_fonts()
        theme.apply("dark")
        w = MainWindow()
        w.show()
        for i in range(len(w.sidebar.items)):
            w.sidebar.select(i)
            app.processEvents()
        w.close()

    check("user interface", window)

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print("SELF-TEST " + ("PASSED" if not failures else f"FAILED ({len(failures)}): " + ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
