"""Signature verification against files made by the real tools (tests/interop), plus
crafted signatures for every way a signature must be refused."""

import base64
import hashlib
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from locksmith.core import minisign, sshsig
from locksmith.core.errors import LocksmithError

INTEROP = Path(__file__).resolve().parent / "interop"
SSH = INTEROP / "sshsig"
MINISIGN = INTEROP / "minisign"


def _ssh(name: str) -> str:
    return sshsig.read_small(SSH / name)


def _ms(name: str) -> str:
    return minisign.read_small(MINISIGN / name)


# ── minisign signatures made by minisign 0.12 ────────────────────────────────

@pytest.mark.parametrize("sig,file,comment,prehashed", [
    ("default.minisig", "message.bin", "timestamp:1791003224\tfile:message.bin\thashed", True),
    ("comment.minisig", "message.bin", "release 1.0\tfile:message.bin ✓", True),
    ("not-utf8.minisig", "message.bin", "latin-1 caf\udce9", True),   # the byte 0xE9, kept as signed
    ("legacy.minisig", "message.bin", "legacy", False),
    ("empty.minisig", "empty.bin", "empty", True),
])
def test_minisign_signatures_verify(sig, file, comment, prehashed):
    v = minisign.verify_file(MINISIGN / file, _ms(sig), _ms("key.pub"))
    # The key ID as minisign printed it in key.pub's comment
    assert (v.key_id, v.trusted_comment, v.prehashed) == ("64D42CAF725AA265", comment, prehashed)


def test_minisign_signature_is_bound_to_file_key_and_comment(tmp_path):
    sig, pub = _ms("comment.minisig"), _ms("key.pub")
    assert "untrusted" not in minisign.verify_file(MINISIGN / "message.bin", sig, pub).trusted_comment
    with pytest.raises(LocksmithError, match="different key"):
        minisign.verify_file(MINISIGN / "message.bin", sig, _ms("other.pub"))
    with pytest.raises(LocksmithError, match="does not match"):
        minisign.verify_file(MINISIGN / "empty.bin", sig, pub)
    data = bytearray((MINISIGN / "message.bin").read_bytes())
    data[-1] ^= 1
    (tmp_path / "changed").write_bytes(bytes(data))
    with pytest.raises(LocksmithError, match="does not match"):
        minisign.verify_file(tmp_path / "changed", sig, pub)
    # Same file signature, another signature's trusted comment
    lines = sig.splitlines()
    lines[2] = _ms("default.minisig").splitlines()[2]
    with pytest.raises(LocksmithError, match="trusted comment was altered"):
        minisign.verify_file(MINISIGN / "message.bin", "\n".join(lines), pub)
    # An untrusted comment can be changed freely: it is never shown
    lines = sig.splitlines()
    lines[0] = "untrusted comment: anything"
    minisign.verify_file(MINISIGN / "message.bin", "\n".join(lines), pub)


# ── SSH signatures made by ssh-keygen ────────────────────────────────────────

@pytest.mark.parametrize("sig,key,file,namespace,hash_alg,label", [
    ("ed25519.sig", "ed25519.pub", "message.bin", "file", "sha512", "ED25519"),
    ("ed25519-sha256.sig", "ed25519.pub", "message.bin", "file", "sha256", "ED25519"),
    ("ed25519-git.sig", "ed25519.pub", "message.bin", "git", "sha512", "ED25519"),
    ("ed25519-empty.sig", "ed25519.pub", "empty.bin", "file", "sha512", "ED25519"),
    ("rsa3072.sig", "rsa3072.pub", "message.bin", "file", "sha512", "RSA 3072"),
    ("ecdsa256.sig", "ecdsa256.pub", "message.bin", "file", "sha512", "ECDSA P-256"),
    ("ecdsa384.sig", "ecdsa384.pub", "message.bin", "file", "sha512", "ECDSA P-384"),
    ("ecdsa521.sig", "ecdsa521.pub", "message.bin", "file", "sha512", "ECDSA P-521"),
])
def test_ssh_keygen_signatures_verify(sig, key, file, namespace, hash_alg, label):
    v = sshsig.verify_file(SSH / file, _ssh(sig), _ssh(key), namespace)
    assert (v.namespace, v.hash_algorithm, v.key_label) == (namespace, hash_alg, label)


def test_ssh_fingerprint_matches_ssh_keygen():
    # `ssh-keygen -lf tests/interop/sshsig/ed25519.pub` when the vectors were made
    assert sshsig.parse_public_key(_ssh("ed25519.pub")).fingerprint == \
        "SHA256:xauNrprfcp4IDDUtjL6QVgiksKosYcaX2xHnrsnB1WU"


def test_ssh_signature_is_bound_to_file_key_and_namespace(tmp_path):
    sig, pub = _ssh("ed25519.sig"), _ssh("ed25519.pub")
    with pytest.raises(LocksmithError, match="made for “git”, not “file”"):
        sshsig.verify_file(SSH / "message.bin", _ssh("ed25519-git.sig"), pub, "file")
    with pytest.raises(LocksmithError, match="made for “file”, not “git”"):
        sshsig.verify_file(SSH / "message.bin", sig, pub, "git")
    with pytest.raises(LocksmithError, match="different key"):
        sshsig.verify_file(SSH / "message.bin", sig, _ssh("ecdsa256.pub"))
    with pytest.raises(LocksmithError, match="does not match"):
        sshsig.verify_file(SSH / "empty.bin", sig, pub)
    data = bytearray((SSH / "message.bin").read_bytes())
    data[3] ^= 1
    (tmp_path / "changed").write_bytes(bytes(data))
    with pytest.raises(LocksmithError, match="does not match"):
        sshsig.verify_file(tmp_path / "changed", sig, pub)
    with pytest.raises(LocksmithError, match="namespace"):
        sshsig.verify_file(SSH / "message.bin", sig, pub, "  ")


def test_small_rsa_keys_are_refused():
    with pytest.raises(LocksmithError, match="1024 bits"):
        sshsig.verify_file(SSH / "message.bin", _ssh("rsa1024.sig"), _ssh("rsa1024.pub"))


@pytest.mark.skipif(not shutil.which("ssh-keygen"), reason="ssh-keygen is not installed")
def test_fresh_signature_from_installed_ssh_keygen(tmp_path):
    subprocess.run(["ssh-keygen", "-q", "-N", "", "-t", "ed25519", "-f", str(tmp_path / "k")], check=True)
    f = tmp_path / "f"
    f.write_bytes(b"fresh\n")
    subprocess.run(["ssh-keygen", "-q", "-Y", "sign", "-f", str(tmp_path / "k"), "-n", "file", str(f)],
                   check=True, capture_output=True)
    v = sshsig.verify_file(f, (tmp_path / "f.sig").read_text(), (tmp_path / "k.pub").read_text())
    assert v.key_label == "ED25519"


# ── crafted SSH signatures ───────────────────────────────────────────────────

def _s(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _mpint(n: int) -> bytes:
    return _s(n.to_bytes((n.bit_length() + 8) // 8, "big"))   # a leading zero only when the top bit is set


def _pub(key) -> tuple[str, bytes]:
    line = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return line.decode() + " comment <b>shown?</b>", base64.b64decode(line.split()[1])


def _sign(key, signed: bytes, sig_type: str | None) -> tuple[str, bytes]:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return sig_type or "ssh-ed25519", key.sign(signed)
    if isinstance(key, rsa.RSAPrivateKey):
        sig_type = sig_type or "rsa-sha2-512"
        h = {"ssh-rsa": hashes.SHA1, "rsa-sha2-256": hashes.SHA256, "rsa-sha2-512": hashes.SHA512}[sig_type]
        return sig_type, key.sign(signed, padding.PKCS1v15(), h())
    r, s = decode_dss_signature(key.sign(signed, ec.ECDSA(hashes.SHA256())))
    return sig_type or "ecdsa-sha2-nistp256", _mpint(r) + _mpint(s)


def _sshsig(key, data: bytes, namespace=b"file", hash_alg=b"sha512", reserved=b"", sig_type=None,
            version=1, key_blob=None, trailing=b"", sig_bytes=None) -> str:
    digest = hashlib.new(hash_alg.decode() if hash_alg in (b"sha256", b"sha512") else "sha512", data).digest()
    signed = b"SSHSIG" + _s(namespace) + _s(reserved) + _s(hash_alg) + _s(digest)
    sig_type, sig = _sign(key, signed, sig_type)
    blob = (b"SSHSIG" + struct.pack(">I", version) + _s(key_blob or _pub(key)[1]) + _s(namespace) + _s(reserved)
            + _s(hash_alg) + _s(_s(sig_type.encode()) + _s(sig_bytes if sig_bytes is not None else sig)) + trailing)
    body = base64.b64encode(blob).decode()
    return "\n".join([sshsig.ARMOR_BEGIN, *(body[i:i + 70] for i in range(0, len(body), 70)), sshsig.ARMOR_END])


@pytest.fixture
def signed(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"crafted\n")
    return f


def test_crafted_signatures_verify(signed):
    for key in (ed25519.Ed25519PrivateKey.generate(), rsa.generate_private_key(65537, 2048),
                ec.generate_private_key(ec.SECP256R1())):
        pub = _pub(key)[0]
        v = sshsig.verify_file(signed, _sshsig(key, b"crafted\n"), pub)
        assert "shown" not in repr(v)   # the key's comment is not covered by anything
        sshsig.verify_file(signed, _sshsig(key, b"crafted\n", hash_alg=b"sha256").replace("\n", "\r\n"), pub)
    rsa_key = rsa.generate_private_key(65537, 2048)
    sshsig.verify_file(signed, _sshsig(rsa_key, b"crafted\n", sig_type="rsa-sha2-256"), _pub(rsa_key)[0])


def test_reserved_field_is_signed(signed):
    key = ed25519.Ed25519PrivateKey.generate()
    pub = _pub(key)[0]
    sshsig.verify_file(signed, _sshsig(key, b"crafted\n", reserved=b"future"), pub)
    good = _sshsig(key, b"crafted\n", reserved=b"future")
    blob = base64.b64decode("".join(good.splitlines()[1:-1])).replace(b"future", b"futurf")
    altered = f"{sshsig.ARMOR_BEGIN}\n{base64.b64encode(blob).decode()}\n{sshsig.ARMOR_END}"
    with pytest.raises(LocksmithError, match="does not match"):
        sshsig.verify_file(signed, altered, pub)


def test_rsa_signature_without_leading_zero_is_accepted(signed):
    # OpenSSH drops leading zero bytes from RSA signatures; about 1 in 256 has one.
    key = rsa.generate_private_key(65537, 2048)
    for i in range(5000):
        ns = f"file{i}".encode()
        text = _sshsig(key, b"crafted\n", namespace=ns)
        blob = base64.b64decode("".join(text.splitlines()[1:-1]))
        if blob[-256] == 0:
            break
    else:
        pytest.fail("no signature with a leading zero byte")
    short = _sshsig(key, b"crafted\n", namespace=ns, sig_bytes=blob[-255:])
    sshsig.verify_file(signed, short, _pub(key)[0], ns.decode())


@pytest.mark.parametrize("case,match", [
    ("sha1-rsa", "SHA-1"),
    ("wrong-sig-type", "doesn't match the key"),
    ("version-2", "version 2"),
    ("hash-sha1", "hash Locksmith doesn't accept"),
    ("empty-namespace", "not a valid SSH signature"),
    ("trailing-data", "not a valid SSH signature"),
    ("security-key", "Security-key"),
    ("non-minimal-mpint", "not a valid SSH signature"),
    ("short-ed25519", "does not match"),
    ("no-armor", "not an SSH signature file"),
])
def test_crafted_signatures_are_refused(signed, case, match):
    ed, rs, ecd = ed25519.Ed25519PrivateKey.generate(), rsa.generate_private_key(65537, 2048), \
        ec.generate_private_key(ec.SECP256R1())
    key, sig = ed, None
    if case == "sha1-rsa":
        key, sig = rs, _sshsig(rs, b"crafted\n", sig_type="ssh-rsa")
    elif case == "wrong-sig-type":
        sig = _sshsig(ed, b"crafted\n", sig_type="ecdsa-sha2-nistp256")
    elif case == "version-2":
        sig = _sshsig(ed, b"crafted\n", version=2)
    elif case == "hash-sha1":
        sig = _sshsig(ed, b"crafted\n", hash_alg=b"sha1")
    elif case == "empty-namespace":
        sig = _sshsig(ed, b"crafted\n", namespace=b"")
    elif case == "trailing-data":
        sig = _sshsig(ed, b"crafted\n", trailing=b"\0")
    elif case == "security-key":
        raw = ed.public_key().public_bytes_raw()
        sig = _sshsig(ed, b"crafted\n", key_blob=_s(b"sk-ssh-ed25519@openssh.com") + _s(raw) + _s(b"ssh:"),
                      sig_type="sk-ssh-ed25519@openssh.com")
    elif case == "non-minimal-mpint":
        key = ecd
        r, s = decode_dss_signature(ecd.sign(b"x", ec.ECDSA(hashes.SHA256())))
        sig = _sshsig(ecd, b"crafted\n", sig_bytes=_s(b"\0\0" + r.to_bytes(32, "big")) + _mpint(s))
    elif case == "short-ed25519":
        sig = _sshsig(ed, b"crafted\n", sig_bytes=b"\1" * 63)
    elif case == "no-armor":
        sig = "".join(_sshsig(ed, b"crafted\n").splitlines()[1:-1])
    with pytest.raises(LocksmithError, match=match):
        sshsig.verify_file(signed, sig, _pub(key)[0])


@pytest.mark.parametrize("text,match", [
    ("locksmith ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA", "without the names or options"),
    ('namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA', "without the names or options"),
    ("ssh-ed25519-cert-v01@openssh.com AAAA", "certificates"),
    ("sk-ssh-ed25519@openssh.com AAAA", "Security-key"),
    ("ssh-dss AAAAB3NzaC1kc3M=", "not a supported SSH public key"),
    ("ssh-ed25519", "incomplete"),
    ("ssh-ed25519 AAAAB3NzaC1yc2E=", "damaged"),   # the blob says ssh-rsa
    ("ssh-ed25519 !!!!", "damaged"),
    ("ssh-ed25519 A\nssh-ed25519 B", "one SSH public key"),
    ("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3", "not a supported SSH public key"),
])
def test_public_key_input_is_strict(text, match):
    with pytest.raises(LocksmithError, match=match):
        sshsig.parse_public_key(text)


def test_compressed_ecdsa_point_is_refused_cleanly():
    point = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    blob = _s(b"ecdsa-sha2-nistp256") + _s(b"nistp256") + _s(point)
    with pytest.raises(LocksmithError, match="damaged"):   # cryptography raises NotImplementedError
        sshsig.parse_public_key(f"ecdsa-sha2-nistp256 {base64.b64encode(blob).decode()}")


def test_public_key_file_with_comments_and_blank_lines():
    text = "# my key\n\n" + _ssh("ed25519.pub") + "\n\n"
    assert sshsig.parse_public_key(text).key_type == "ssh-ed25519"


def test_ssh_signature_files_are_read_small(tmp_path):
    (tmp_path / "big.sig").write_bytes(b"a" * (sshsig.MAX_SIGNATURE_FILE + 1))
    with pytest.raises(LocksmithError, match="too large"):
        sshsig.read_small(tmp_path / "big.sig")
