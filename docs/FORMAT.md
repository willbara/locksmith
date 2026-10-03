# Locksmith file format, version 2

This document specifies everything needed to read and write Locksmith files and the related text
formats (armor, public keys, Shamir shares, identity backups, checksum manifests, signing keys and
detached signatures) without Locksmith's code. The test vectors in [`tests/vectors`](../tests/vectors) are files made to this specification;
[`tests/spec_reader.py`](../tests/spec_reader.py) is an independent reader written from it, and
`tests/test_vectors.py` checks the two against each other.

Locksmith writes version 2 and still reads version 1 (section 16).

Conventions: integers are unsigned big-endian. `||` is concatenation. Base64 is the standard alphabet
with padding (RFC 4648 §4), and readers reject anything else. Strings in labels are ASCII. In sections
1–8 and 15, `LABEL` is `locksmith/v2/`; the other sections spell out their labels in full.
`HKDF(ikm, length, salt, info)` is HKDF with SHA-512 (RFC 5869).

## 1. Container

```
magic      8 bytes   "LOCKED" 0x00 0x02
kc         32 bytes  key commitment (section 4)
fixed_len  u32       at most 1 MiB
fixed      fixed_len bytes of UTF-8 JSON: the fixed header (section 2)
slots_len  u32       at most 1 MiB
slots      slots_len bytes of UTF-8 JSON: an array of 1 to 64 key slots (section 3)
frames     one or more of: u32 ct_len || ct
```

Everything except the slots is fixed when the file is written: the commitment and every frame are
bound to the fixed header, not to the slots. Changing who can open a file (a password, a keyfile, a
recipient) rewrites only the slots section, so the data is not re-encrypted.

A reader that sees `LOCKED` with a version byte other than 1 or 2 must say the file comes from a
newer version. Files use the extension `.locked`, or `.locked.txt` when armored (section 8).

## 2. Fixed header

The fixed header is a JSON object with exactly these fields. Readers check every field's type and size
before using any of them and reject the file if any check fails or any other field is present.

| Field   | Value |
|---------|-------|
| `v`     | `2` |
| `suite` | cipher suite id (section 5) |
| `chunk` | plaintext bytes per frame, an integer from 1024 to 67,108,864 (64 MiB) |
| `np`    | base64 of the 7-byte nonce prefix |
| `salt`  | base64 of the 32-byte file salt |
| `meta`  | `{"n": base64 of a 12-byte nonce, "c": base64 of the encrypted metadata}` |

The writer serialises it with no whitespace (`separators=(",", ":")`); readers must use the exact
bytes they read, never a re-serialisation, because their hash is authenticated (sections 4 and 6).

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
KEK        = HKDF(ss_m || ss_x, 32, salt = transcript, LABEL || "x25519-mlkem768")
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
kc == HKDF(DEK, 32, salt, LABEL || "commit" || SHA-256(fixed header bytes))
```

Otherwise it moves on to the next slot. A failed commitment is reported exactly like a wrong key.
The commitment stops a file from opening to different contents under different keys, and because it
covers the fixed header, any change to the suite, chunk size, nonce prefix, salt or metadata makes the
file refuse to open at all, before a single frame is read. It does not cover the slots, so slots can be
added, removed or replaced without touching it.

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
aad             = SHA-256(fixed header bytes exactly as stored)
```

Frame `index` counts from 0 and must stay below 2^32. A frame's ciphertext is at most
`chunk + 5 + 16 × layers` bytes. The final flag and the authenticated fixed header mean frames can't be
reordered, dropped, truncated, appended or moved to another file.

| kind | Meaning |
|------|---------|
| 0 | raw: `block` is content, at most `chunk` bytes |
| 1 | compressed: `block` is one complete stream of the codec named in the metadata, decoding to at most `chunk` bytes |
| 2 | padding: `len` is 0 |
| 3 | signature: `block` is the next part of the file's signature (section 15), at most `chunk` bytes |

Frames come in this order: one or more content frames (kinds 0 and 1), then any padding frames, then
any signature frames. Rules a reader enforces: everything after `block` is zero bytes; the order above;
a compressed frame needs a codec. Writers compress a block only when that makes it smaller, emit at
least one content frame (empty content is one raw frame with an empty block), and add padding (zero
bytes in the last content frame, then padding frames) to reach the chosen padded size. Padding is
computed over the content only, so a signature adds its own fixed size on top.

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
| `note`    | the sender's free text. Only a valid signature (section 15) vouches for it |
| `to`      | reserved: the signer's intended recipients (see below) |

Readers ignore unknown fields and fields of the wrong type.

`to`, reserved for a later version of Locksmith, lists the recipients the signer addressed a signed
file to: an array of base64 32-byte entries, each `SHA-256("locksmith/v2/recipient" || 0x00 || key)`
where `key` is a recipient's raw encryption key exactly as in section 9 (the 32-byte X25519 key, or the
1216-byte X25519 || ML-KEM-768 key, with no prefix or checksum). A reader tests every one of its own
identities' encryption keys against it. It means something only in a signed file, because anyone who
can open a file can rewrite its metadata; readers ignore it in unsigned files. For `dir` and `bundle`, the content is a
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

`prefix || base64url(raw || SHA-256(raw)[0..4])` without padding. The prefix says what `raw` holds:

| Prefix       | `raw` | Bytes |
|--------------|-------|-------|
| `locksmith1` | X25519 public key | 32 |
| `locksmith2` | X25519 key (32) \|\| ML-KEM-768 key (1184) | 1216 |
| `locksmith3` | X25519 key (32) \|\| ML-KEM-768 key (1184) \|\| Ed25519 key (32) \|\| ML-DSA-65 key (1952) | 3200 |

A `locksmith3` key also verifies signatures (sections 13 and 14). Encrypting to it uses its first 1216
bytes exactly as a `locksmith2` key: in a hybrid slot, `rpk` is those 1216 bytes. Readers reject
low-order X25519 points and malformed ML-KEM keys. The fingerprint is the first 20 hex digits of
SHA-256(raw), in groups of four, so it covers every key in `raw`. Adding signing keys to an identity
therefore gives it a new fingerprint, which contacts check once.

A `locksmith3` key is too large for a QR code. Its QR code holds only its hash, as
`LOCKSMITH3:FP:` followed by the 64 uppercase hex digits of SHA-256(raw). The key itself travels as
text; whoever receives it compares its SHA-256 with the scanned hash (the first 20 digits are the
fingerprint). `locksmith1` and `locksmith2` QR codes hold the whole key text.

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

Signing keys are derived from the raw private key (section 13), so backups, words and shares hold
nothing extra and restore them too.

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

## 13. Signing keys

Only hybrid identities sign. Their two signing keys are derived from the 96-byte raw private key
(section 10):

```
ed25519 seed   = HKDF(raw, 32, salt = empty, "locksmith/v1/sig/ed25519")
ml-dsa-65 seed = HKDF(raw, 32, salt = empty, "locksmith/v1/sig/ml-dsa-65")
```

The Ed25519 seed is an RFC 8032 private key. The ML-DSA-65 seed is the 32-byte FIPS 204 key
generation seed ξ (`ML-DSA.KeyGen_internal`). The identity's `locksmith3` public key (section 9) is its
`locksmith2` key followed by the two public keys. The labels carry the version: a different derivation
would use new labels and a new key prefix.

A classical identity (32-byte raw key) has no signing keys. Its raw key is only an X25519 key, which a
quantum computer could recover from the public key, together with every key derived from it: an
ML-DSA key made that way would be no stronger than X25519. Writers refuse to sign with one: it must be upgraded to a
hybrid identity first.

## 14. Detached signatures

A signature is a separate file, by convention the signed file's name plus `.lsig`. It holds:

```
magic     8 bytes   "LOCKSIG" 0x01
alg       u8        1 = Ed25519 + ML-DSA-65
created   u64       when it was signed (Unix seconds), as the signer's clock said
key_id    32 bytes  SHA-256 of the signer's locksmith3 raw key (section 9)
clen      u16       comment length, at most 1024
comment   clen bytes of UTF-8
sig_ed    64 bytes  Ed25519 signature
sig_ml    3309 bytes ML-DSA-65 signature
```

Its text form, which is what Locksmith writes and reads:

```
-----BEGIN LOCKSMITH SIGNATURE-----
base64 of the signature, in lines of 64 characters
-----END LOCKSMITH SIGNATURE-----
```

`head` is every byte before `sig_ed` (magic through comment). Both parts sign the same message:

```
M      = "locksmith/v1/sig/file" || 0x00 || head || SHA-512(signed file)
sig_ed = Ed25519.Sign(ed25519 key, M)                                   (RFC 8032, pure)
sig_ml = ML-DSA-65.Sign(ml-dsa-65 key, M, ctx = "locksmith/v1/sig")     (FIPS 204, hedged or deterministic)
```

Because `head` contains `key_id`, each part is bound to the whole `locksmith3` key, so neither can be
moved to a key that shares only one of its halves.

The comment is one line chosen by the signer (it may be empty): valid UTF-8 with no characters in
the Unicode categories Cc, Cf, Zl or Zp.

A reader:

1. Accepts at most 16 KiB of text, ignores whitespace inside the body, and decodes the base64.
2. Rejects the signature unless the magic matches, `alg` is 1, `clen` is at most 1024, the comment
   follows the rule above, and the length is exactly `3424 + clen` bytes.
3. Finds the `locksmith3` key whose SHA-256 equals `key_id`. Without it, the signature can't be
   checked, and the reader says so (it may show `key_id`'s first 20 hex digits as the signer's
   fingerprint). A key of any other kind never verifies a signature, whatever `alg` says.
4. Accepts the signature only if both `sig_ed` and `sig_ml` verify over `M`.

A valid signature shows that the file was signed with that key. `created` is only the signer's claim.
`key_id` is in the clear, so a detached signature always says which key made it.

## 15. Signed files

A file may carry its signer's signature inside the encryption, so only those who can open it see who
signed it. The signature is the structure of section 14 with `clen = 0`, exactly 3424 bytes, split in
order across the signature frames (kind 3, section 6), each block at most `chunk` bytes. It signs:

```
M      = LABEL || "sig/locked" || 0x00 || head || SHA-256(fixed header bytes) || SHA-512(content)
sig_ed = Ed25519.Sign(ed25519 key, M)
sig_ml = ML-DSA-65.Sign(ml-dsa-65 key, M, ctx = LABEL || "sig")
```

`head` is the signature's first 51 bytes (magic through `clen`) and `content` is the plaintext the
content frames decrypt to: the file, the text, or the tar stream of a folder. The signature therefore
covers the cipher suite, chunk size, nonce prefix, salt and metadata (name, kind, note, `to`) as well as
the content, but **not the key slots**: recipients, passwords and keyfiles can change without a new
signature. The other side of that is that anyone who can open a signed file can let someone else open
it too, and it still verifies; a signature says who signed the content, not whom it was sent to.

A reader, after every frame has authenticated:

1. Joins the signature blocks; anything but exactly 3424 bytes that parse as section 14 with `alg` 1
   and `clen` 0 makes the file invalid.
2. Looks for the `locksmith3` key whose SHA-256 equals `key_id` among the keys it trusts (its contacts
   and its own identities). Without one, the file still opens and the reader says it was signed by an
   unknown key, showing the fingerprint from `key_id`.
3. With the key, requires both `sig_ed` and `sig_ml` to verify over `M`. If either fails, the file is
   invalid: the reader reports it and writes or shows none of its content.

An unsigned file has no signature frames.

## 16. Reading version 1

Version 1 files are still read, never written. They differ from version 2 as follows:

- `magic` ends in 0x01, and the container is `magic || hdr_len (u32) || header || frames`. The header is
  one JSON object holding the fields of section 2 with `v = 1`, plus `kc` (base64 of the 32-byte key
  commitment) and `slots` (the array of section 3).
- `LABEL` is `locksmith/v1/` in every derivation and AEAD label of sections 3–7, including the hybrid
  slot's (`locksmith/v1/x25519-mlkem768`).
- `kc == HKDF(DEK, 32, salt, LABEL || "commit")`: the commitment covers only the DEK.
- Frames use `aad = SHA-256(header bytes exactly as stored)`, so they are bound to the slots too.
- Frame kinds are 0–2 only: version 1 files are never signed.
