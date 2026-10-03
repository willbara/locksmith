"""Take Locksmith files apart and put them back together, for tests that craft files.

``split`` returns the header as the engine sees it: for version 2, the fixed header's
fields plus "kc" (base64) and "slots". ``join`` writes it back in the file's own layout.
A version 2 commitment covers the fixed header's exact bytes, so when only the slots (or
nothing) changed, ``join`` reuses those bytes and the file still opens.
"""

import base64
import binascii
import json
import struct

V1, V2 = b"LOCKED\x00\x01", b"LOCKED\x00\x02"
_RAW = "_fixed_raw"   # the original fixed header bytes, carried in the dict


def _u32(blob: bytes, pos: int) -> int:
    return struct.unpack(">I", blob[pos:pos + 4])[0]


def split(blob: bytes) -> tuple[dict, bytes]:
    if blob[:8] == V1:
        hlen = _u32(blob, 8)
        return json.loads(blob[12:12 + hlen]), blob[12 + hlen:]
    assert blob[:8] == V2, "not a Locksmith file"
    kc = blob[8:40]
    flen = _u32(blob, 40)
    fixed_raw = blob[44:44 + flen]
    slen = _u32(blob, 44 + flen)
    slots = json.loads(blob[48 + flen:48 + flen + slen])
    header = {**json.loads(fixed_raw), "kc": base64.b64encode(kc).decode(), "slots": slots, _RAW: fixed_raw}
    return header, blob[48 + flen + slen:]


def join(header: dict, body: bytes) -> bytes:
    if header.get("v") == 1 and _RAW not in header:
        raw = json.dumps(header).encode()
        return V1 + struct.pack(">I", len(raw)) + raw + body
    fixed = {k: v for k, v in header.items() if k not in ("kc", "slots") and not k.startswith("_")}
    try:
        kc = base64.b64decode(header.get("kc"), validate=True)
        if len(kc) != 32:
            raise ValueError
    except (TypeError, ValueError, binascii.Error):
        # A commitment that can't be one goes into the fixed header, where readers refuse it.
        kc, fixed = bytes(32), {**fixed, "kc": header.get("kc")}
    original = header.get(_RAW)
    raw = original if original is not None and json.loads(original) == fixed else \
        json.dumps(fixed, separators=(",", ":")).encode()
    slots = json.dumps(header["slots"]).encode() if "slots" in header else b"null"
    return V2 + kc + struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(slots)) + slots + body


def fixed_bytes(blob: bytes) -> bytes:
    """The bytes a file's frames authenticate: v2's fixed header, v1's whole header."""
    header, _ = split(blob)
    return header.get(_RAW) or blob[12:12 + _u32(blob, 8)]


def forge(opts, meta: dict, frames: list[bytes], meta_raw: bytes | None = None, fmt=None) -> bytes:
    """A correctly encrypted version 2 file whose frame plaintexts we choose, as a sender
    holding the file key could make. ``meta_raw`` replaces the encrypted metadata with any
    bytes; the commitment is recomputed to match, as such a sender could."""
    import hashlib
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from locksmith.core import engine
    head = engine._build_header(opts, meta, engine._Checker(None, None), fmt or engine.WRITE_FORMAT)
    header, _ = split(head.preamble)
    k = head.keys
    if meta_raw is not None:
        n = os.urandom(12)
        c = AESGCM(k.meta_key).encrypt(n, meta_raw, k.fmt.label + b"meta")
        header["meta"] = {"n": base64.b64encode(n).decode(), "c": base64.b64encode(c).decode()}
        del header[_RAW]
        fixed = {key: v for key, v in header.items() if key not in ("kc", "slots")}
        raw = json.dumps(fixed, separators=(",", ":")).encode()
        kc = engine._commitment(head.dek, base64.b64decode(header["salt"]), k.fmt, raw)
        header["kc"] = base64.b64encode(kc).decode()
    out = bytearray(join(header, b""))
    prefix, aad = base64.b64decode(header["np"]), hashlib.sha256(fixed_bytes(bytes(out))).digest()
    for i, fr in enumerate(frames):
        ct = k.cipher.seal(engine._nonce(prefix, i, i == len(frames) - 1), fr, aad)
        out += struct.pack(">I", len(ct)) + ct
    return bytes(out)
