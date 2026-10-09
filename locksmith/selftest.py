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
    # Every place a config folder can come from, so the self-test never sees (or moves) real keys.
    for var in ("XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"):
        os.environ[var] = str(tmp / "config")
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

    def age_files():
        import io

        from .core import age
        from .core.keys import public_from_private
        hybrid, classical = os.urandom(96), os.urandom(32)
        for raw in (hybrid, classical):
            out, back = io.BytesIO(), io.BytesIO()
            age.encrypt_stream(io.BytesIO(data), out, [age.recipient_for(public_from_private(raw))])
            age.decrypt_stream(io.BytesIO(out.getvalue()), back, age.Keys(identities=[raw]))
            assert back.getvalue() == data, "an age file did not round-trip"

    check("age files (X25519, ML-KEM-768 + X25519)", age_files)

    def ssh_keys():
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from .core import sshkeys
        key = Ed25519PrivateKey.generate()
        # A passphrase-protected OpenSSH key needs the bcrypt module.
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.BestAvailableEncryption(b"self-test"))
        ident = sshkeys.load_identity(pem, "self-test")
        line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        blob = engine.encrypt_bytes(b"ssh", EncryptOptions(recipients=[sshkeys.parse_recipient(line.decode()).raw]))
        assert engine.decrypt_bytes(blob, DecryptKeys(ssh=[ident])).data == b"ssh"

    check("SSH keys (bcrypt)", ssh_keys)

    def recovery():
        from .core import parity
        lpar = parity.create(src, "10")
        damaged = bytearray(data)
        damaged[100:5000] = bytes(4900)
        src.write_bytes(bytes(damaged))
        parity.repair(src)
        assert src.read_bytes() == data, "recovery data did not repair the file"
        lpar.unlink()
        for leftover in tmp.glob("sample.bin.damaged*"):
            leftover.unlink()

    check("recovery data", recovery)

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

    def paper_backup():
        from PySide6.QtCore import QBuffer, QIODevice
        from PySide6.QtWidgets import QApplication

        from .core import keys, qrdecode
        from .ui import paper
        QApplication.instance() or QApplication([])
        raw = os.urandom(96)
        page = paper.render_image("self-test", "-", 0, raw, 0.4)
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        assert page.save(buf, "JPG", 85), "JPEG images can't be written (image plugin missing)"
        photo = paper.load_image(bytes(buf.data()))
        assert not photo.isNull(), "JPEG images can't be read (image plugin missing)"
        assert keys.private_from_paper(qrdecode.decode(*paper.gray_pixels(photo))) == raw
        assert paper.render_pdf("self-test", "-", 0, raw).startswith(b"%PDF")

    check("paper backup (PDF, JPEG photo, QR reader)", paper_backup)

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print("SELF-TEST " + ("PASSED" if not failures else f"FAILED ({len(failures)}): " + ", ".join(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
