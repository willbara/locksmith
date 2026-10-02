# Locksmith file format, version 1

This document specifies everything needed to read and write Locksmith files and the related text
formats (armor, public keys, Shamir shares, identity backups, checksum manifests) without Locksmith's
code. The test vectors in [`tests/vectors`](../tests/vectors) are files made to this specification;
[`tests/spec_reader.py`](../tests/spec_reader.py) is an independent reader written from it, and
`tests/test_vectors.py` checks the two against each other.

Conventions: integers are unsigned big-endian. `||` is concatenation. Base64 is the standard alphabet
with padding (RFC 4648 §4), and readers reject anything else. Strings in labels are ASCII. `LABEL` is
`locksmith/v1/`. `HKDF(ikm, length, salt, info)` is HKDF with SHA-512 (RFC 5869).

## 1. Container

```
magic      8 bytes   "LOCKED" 0x00 0x01
hdr_len    u32       at most 1 MiB
header     hdr_len bytes of UTF-8 JSON
frames     one or more of: u32 ct_len || ct
```

A reader that sees `LOCKED` with a different version byte must say the file comes from a newer
version. Files use the extension `.locked`, or `.locked.txt` when armored (section 8).

## 2. Header

The header is a JSON object. Readers check every field's type and size before using any of them and
reject the file if any check fails.

| Field   | Value |
|---------|-------|
| `v`     | `1` |
| `suite` | cipher suite id (section 5) |
| `chunk` | plaintext bytes per frame, an integer from 1024 to 67,108,864 (64 MiB) |
| `np`    | base64 of the 7-byte nonce prefix |
| `salt`  | base64 of the 32-byte file salt |
| `kc`    | base64 of the 32-byte key commitment |
| `slots` | 1 to 64 key slots (section 3) |
| `meta`  | `{"n": base64 of a 12-byte nonce, "c": base64 of the encrypted metadata}` |

The writer serialises the header with no whitespace (`separators=(",", ":")`); readers must use the
exact bytes they read, never a re-serialisation, because their hash is authenticated (section 6).

## 3. Key slots

A random 32-byte data key (DEK) encrypts the file. Each slot wraps it under a key-encryption key (KEK):
`w = AES-256-GCM(KEK, nonce = n, plaintext = DEK, aad = LABEL || "slot/" || t)`, so `w` is 48 bytes.
Every slot has `t` (its type), `n` (base64, 12 bytes) and `w` (base64, 48 bytes). The writer shuffles
the slots, so their order says nothing.

### Password slot, `t = "pw"`

| Field  | Value |
|--------|-------|
| `kdf`  | `argon2id`, `scrypt` or `pbkdf2-sha512` |
| `p`    | parameters: Argon2id `{"m": KiB, "t": passes, "p": lanes}`; scrypt `{"n", "r", "p"}`; PBKDF2 `{"i": iterations}` |
| `salt` | base64, 16 bytes |
| `kf`   | `true` if a keyfile is also needed |

```
secret = UTF-8(NFC(password))            (empty when only a keyfile is used)
base   = KDF(secret, salt, p)            32 bytes
ikm    = base || SHA-512(keyfile bytes)  when kf, else base
KEK    = HKDF(ikm, 32, salt, LABEL || "pw" || ("+keyfile" if kf else ""))
```

Limits a reader enforces before deriving anything: Argon2id `m` ≤ 2,097,152 (2 GiB), `t` ≤ 16,
`p` ≤ 16 and `m` ≥ 8·`p`; scrypt `n` a power of two up to 2^21, `r` ≤ 16, `p` ≤ 4 and 128·`r`·`n` ≤ 2 GiB;
PBKDF2 `i` ≤ 20,000,000. A reader tries at most 4 password slots per file. A writer that uses only a
keyfile must use one of at least 32 bytes.

### Classical recipient slot, `t = "x25519"`

`epk` is base64 of a fresh ephemeral X25519 public key (32 bytes). With the recipient's X25519 public
key `rpk`:

```
shared = X25519(ephemeral private, rpk)
KEK    = HKDF(shared, 32, salt = epk || rpk, LABEL || "x25519")
```

### Hybrid post-quantum recipient slot, `t = "x25519-mlkem768"`

The recipient's public key is `rpk = x25519_pk (32) || mlkem768_pk (1184)`. `epk` is as above and `kct`
is base64 of the ML-KEM-768 ciphertext (1088 bytes).

```
ss_x       = X25519(ephemeral private, x25519_pk)
ss_m, kct  = ML-KEM-768.Encaps(mlkem768_pk)
transcript = SHA-256(epk || kct || rpk)
KEK        = HKDF(ss_m || ss_x, 32, salt = transcript, "locksmith/v1/x25519-mlkem768")
```

The KEK stays secret unless both X25519 and ML-KEM-768 are broken.

### Decoy slots

A writer may add recipient slots for keys that are generated and immediately discarded, wrapping a
random value, to hide how many recipients there are (Locksmith rounds up to 8, 16, 32 or 64 in total,
within the 64-slot limit). Decoys are hybrid if any real recipient is, otherwise classical, so a file
with both kinds still shows that it has at least one classical recipient. They are ordinary slots that
no key opens, so readers need nothing special.

## 4. Unlocking and key schedule

A reader tries the slots its keys can open. A slot "opens" only if the AES-GCM unwrap succeeds **and**
the result matches the key commitment:

```
kc == HKDF(DEK, 32, salt, LABEL || "commit")
```

Otherwise it moves on to the next slot. A failed commitment is reported exactly like a wrong key.
The commitment stops a file from opening to different contents under different keys.

From the DEK and the file salt:

```
layer key i = HKDF(DEK, size, salt, LABEL || "layer/" || i || "/" || layer name)   (i in decimal from 0)
meta key    = HKDF(DEK, 32, salt, LABEL || "meta")
```

`size` is 64 for `aes-siv` and 32 for every other layer.

## 5. Cipher suites

| Suite id            | Layers, innermost first |
|---------------------|-------------------------|
| `aes-256-gcm`       | `aes-gcm` |
| `chacha20-poly1305` | `chacha20` |
| `aes-256-gcm-siv`   | `aes-gcm-siv` |
| `aes-256-ocb3`      | `aes-ocb3` |
| `aes-256-siv`       | `aes-siv` |
| `cascade-2`         | `aes-gcm`, `chacha20` |
| `cascade-3`         | `aes-gcm`, `chacha20`, `aes-ocb3` |

Each layer is an AEAD with a 16-byte tag, its own key, and the frame's nonce and associated data
(section 6). Sealing applies the layers in order; opening applies them in reverse. `aes-siv` (RFC 5297,
512-bit key) takes no nonce: it is given two associated-data components, `[aad, nonce]`.

## 6. Frames

```
frame plaintext = kind (u8) || len (u32) || block (len bytes) || zero bytes
nonce           = np (7) || index (u32) || final (u8: 1 for the last frame, else 0)
aad             = SHA-256(header bytes exactly as stored)
```

Frame `index` counts from 0 and must stay below 2^32. A frame's ciphertext is at most
`chunk + 5 + 16 × layers` bytes. The final flag and the authenticated header mean frames can't be
reordered, dropped, truncated, appended or moved to another file.

| kind | Meaning |
|------|---------|
| 0 | raw: `block` is content, at most `chunk` bytes |
| 1 | compressed: `block` is one complete stream of the codec named in the metadata, decoding to at most `chunk` bytes |
| 2 | padding: `len` is 0 |

Rules a reader enforces: everything after `block` is zero bytes; padding frames come only after the
last content frame; a compressed frame needs a codec. Writers compress a block only when that makes it
smaller, emit at least one frame (empty content is one raw frame with an empty block), and add padding
(zero bytes in the last frame, then padding frames) to reach the chosen padded size.

Codecs: `zstd` (Zstandard frame), `zlib` (RFC 1950), `lzma` (`.xz` container, dictionary within
128 MiB of decoder memory), `bz2`.

## 7. Metadata

`AES-256-GCM(meta key, nonce = meta.n, plaintext = JSON, aad = LABEL || "meta")`. The JSON object may
hold:

| Field     | Meaning |
|-----------|---------|
| `name`    | original name. Readers must sanitise it: no path separators, no control or formatting characters, no leading dots |
| `kind`    | `file`, `text`, `dir` (one folder) or `bundle` (several items) |
| `comp`    | codec id, or `none` |
| `size`    | content size in bytes, when known in advance (informational only: never a limit) |
| `mtime`   | the file's modification time (Unix seconds), omitted when metadata is stripped |
| `created` | when the file was encrypted (Unix seconds) |
| `items`   | number of items in a bundle |
| `note`    | the sender's free text, which nothing verifies |

Readers ignore unknown fields and fields of the wrong type. For `dir` and `bundle`, the content is a
POSIX (PAX) tar stream. A `dir` archive holds one top-level folder. Readers must extract only regular
files, folders and links that stay inside the destination, and must refuse metadata headers over
1 MiB and sparse members, which Locksmith never writes.

## 8. ASCII armor

```
-----BEGIN LOCKSMITH MESSAGE-----
base64 of the whole file, in lines of 64 characters
-----END LOCKSMITH MESSAGE-----
```

Readers ignore whitespace inside the body and accept at most 128 MiB of text. Locksmith writes
armor only for content up to 64 MiB, and opens pasted messages in memory only up to 64 MiB of
content.

## 9. Public keys

`prefix || base64url(raw || SHA-256(raw)[0..4])` without padding, where the prefix is `locksmith1`
for a 32-byte X25519 key and `locksmith2` for a 1216-byte hybrid key. Readers reject low-order X25519
points and malformed ML-KEM keys. A fingerprint is the first 20 hex digits of SHA-256(raw), in groups
of four.

## 10. Identity backups

**Backup file** (JSON): `{"locksmith-identity": 1, "name", "public", "created", "private" | "locked"}`.
`private` is base64 of the raw private key: 32 bytes (X25519) or 96 bytes (X25519 key || 64-byte
ML-KEM-768 seed). `locked` is `{"kdf": "argon2id", "p", "salt", "n", "c"}` with
`c = AES-256-GCM(Argon2id(NFC(passphrase), salt, p), n, raw, aad = "locksmith/v1/identity")`.

**Backup words**: the raw private key followed by `SHA-256("locksmith/v1/backup-words" || raw)[0..4]`,
written as proquints: each 16 bits, big-endian, becomes consonant-vowel-consonant-vowel-consonant from
`bdfghjklmnprstvz` (4 bits) and `aiou` (2 bits). That is 18 words for a classical key and 50 for a
hybrid one. The words are the private key, with no passphrase.

**Identity shares**: Shamir shares (section 11) of `"LSI1" || raw private key`.

## 11. Shamir shares

Secrets are split byte-wise over GF(2^8) with the AES polynomial (0x11B), at x = 1…n, with fresh
random coefficients. Text form (version 2, written):

```
locksmithshare2-<k>-<x>-<split id: 8 hex>-<data: hex>-<check: 6 hex>
data  = the share's bytes of (secret || SHA-256("locksmith/share/v2" || split id || secret)[0..8])
check = hex(SHA-256(byte k || byte x || split id || data))[0..6]
```

Every share of one split has the same random 4-byte split ID. Combining rejects mixed IDs, shares
beyond the threshold that disagree, and a recovered secret whose tag doesn't match. Version 1
(`locksmithshare-<k>-<x>-<data>-<check>`, no split ID or tag, check over `k || x || data`) is still
read.

## 12. Checksum manifests

One line per file, in the BSD tag format of `sha256sum --tag`: `ALG (path) = hex`, with `ALG` one of
`SHA256`, `SHA512`, `SHA3-256`, `SHA3-512`, `BLAKE2b`, `BLAKE2s`. Paths are relative, `/`-separated
and never contain `.` or `..` components. A name holding a backslash, line feed or carriage return is
escaped as `\\`, `\n` and `\r`, and its line starts with a backslash. MD5 is not accepted. Links are
not listed.
