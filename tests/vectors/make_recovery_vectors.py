"""Make the recovery data test vector (run from the repository root):

    .venv/bin/python tests/vectors/make_recovery_vectors.py

A deterministic 50,000-byte file and its recovery data at 20% (k = 20, m = 4: 13 blocks of
4096 bytes, one stripe). The second reader (spec_reader.read_recovery) recomputes every parity
byte from FORMAT.md §17. Every other vector is left untouched. Only do this deliberately.
"""

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent.parent), str(HERE.parent)]

import spec_reader  # noqa: E402

from locksmith.core import parity  # noqa: E402


def main():
    folder = HERE / "recovery"
    folder.mkdir(exist_ok=True)
    data = b"".join(hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(1563))[:50_000]
    sample = folder / "sample.bin"
    sample.write_bytes(data)
    lpar = parity.create(sample, "20")
    spec_reader.read_recovery(data, lpar.read_bytes())


if __name__ == "__main__":
    main()
