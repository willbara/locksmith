"""Generate a stand-in icuuc.dll for building and testing under Wine only.

Real Windows (10 1903 and later) ships icuuc.dll as part of the OS, and Qt loads
it for legacy character-set conversion (ucnv_*), which Locksmith never uses.
Wine has no ICU, so Qt cannot even load there. This writes a minimal x64 DLL
exporting the functions Qt imports; each reports failure (ucnv_open sets
U_FILE_ACCESS_ERROR and returns NULL), which Qt handles by skipping those codecs.

It is installed into the Wine prefix's system32 only. It is never shipped: the
Windows spec excludes icuuc.dll, and PyInstaller treats system32 as the OS.

    python icu_stub.py OUTPUT.dll FUNCTION [FUNCTION ...]
"""

import struct
import sys

FILE_ALIGN, SECT_ALIGN, BASE_RVA = 0x200, 0x1000, 0x1000

RET_ZERO = bytes.fromhex("31c0c3")                                   # xor eax,eax ; ret
# test rdx,rdx ; jz +6 ; mov dword [rdx], 4 (U_FILE_ACCESS_ERROR) ; xor eax,eax ; ret
OPEN_FAILS = bytes.fromhex("4885d27406c7020400000031c0c3")


def align(n, a):
    return (n + a - 1) // a * a


def build(dll_name: str, functions: list[str]) -> bytes:
    names = sorted(set(functions), key=lambda s: s.encode())   # the loader binary-searches names
    code = bytearray()
    code_rva = {}
    for name in names:
        code_rva[name] = BASE_RVA + len(code)
        stub = OPEN_FAILS if name == "ucnv_open" else RET_ZERO
        code += stub + b"\xcc" * (16 - len(stub))

    exp_rva = BASE_RVA + len(code)
    n = len(names)
    eat_rva = exp_rva + 40
    names_rva = eat_rva + 4 * n
    ords_rva = names_rva + 4 * n
    strings_rva = ords_rva + 2 * n
    strings = bytearray()
    name_rvas = []
    dll_name_rva = strings_rva + len(strings)
    strings += dll_name.encode() + b"\0"
    for name in names:
        name_rvas.append(strings_rva + len(strings))
        strings += name.encode() + b"\0"
    export = struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, dll_name_rva, 1, n, n, eat_rva, names_rva, ords_rva)
    export += b"".join(struct.pack("<I", code_rva[name]) for name in names)
    export += b"".join(struct.pack("<I", r) for r in name_rvas)
    export += b"".join(struct.pack("<H", i) for i in range(n))
    export += strings
    section = bytes(code) + export
    raw_size = align(len(section), FILE_ALIGN)
    image_size = align(BASE_RVA + len(section), SECT_ALIGN)

    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x2022)   # AMD64, 1 section, DLL
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, raw_size, 0, 0, 0, BASE_RVA)
    opt += struct.pack("<QII", 0x180000000, SECT_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
    opt += struct.pack("<IIIHH", image_size, FILE_ALIGN, 0, 3, 0x0100)   # NX compatible
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = [(exp_rva, len(export))] + [(0, 0)] * 15
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    sect = struct.pack("<8sIIIIIIHHI", b".text", len(section), BASE_RVA, raw_size, FILE_ALIGN, 0, 0, 0, 0,
                       0x60000060)
    headers = dos + b"PE\0\0" + coff + opt + sect
    return headers.ljust(FILE_ALIGN, b"\0") + section.ljust(raw_size, b"\0")


if __name__ == "__main__":
    out, *funcs = sys.argv[1:]
    with open(out, "wb") as f:
        f.write(build("icuuc.dll", funcs))
