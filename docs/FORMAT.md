# Locksmith file format, version 2

This document specifies everything needed to read and write Locksmith files and the related text
formats (armor, public keys, Shamir shares, identity backups and paper backups, checksum manifests,
signing keys, detached signatures and recovery data) without Locksmith's code, and how Locksmith's
keys map onto age files (section 18). The test vectors in [`tests/vectors`](../tests/vectors) are files made to this specification;
[`tests/spec_reader.py`](../tests/spec_reader.py) is a second reader written from it, and
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
Every slot has `t` (its type), `n` (base64, 12 bytes) and `w` (base64, 48 bytes). A reader rejects a
slot type it doesn't know. The writer shuffles
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

### SSH Ed25519 recipients

An SSH Ed25519 public key (`ssh-ed25519`, RFC 8709) is converted to the X25519 key of the same secret
and gets an ordinary `x25519` slot, so the file doesn't show that an SSH key is involved. With `y` the
Ed25519 key read as a little-endian integer with its top bit cleared, and `p = 2^255 - 19`:

```
rpk = u = (1 + y) / (1 - y) mod p        (32 bytes, little-endian)
```

Writers reject keys with `y ≥ p`, `y = 1`, no valid `x` coordinate, or a low-order result. The SSH
private key opens the slot with the X25519 private key `SHA-512(seed)[0..32]`, where `seed` is the
32-byte Ed25519 private key; X25519 clamps it exactly as Ed25519 does. Such a slot is classical.

### SSH RSA recipient slot, `t = "ssh-rsa"`

An SSH RSA public key of 2048 to 16384 bits. `rpk` is its SSH wire encoding (RFC 4253 §6.6: the string
`ssh-rsa`, then `e` and `n` as mpints). `c` is base64 of the RSA-OAEP ciphertext, exactly as long as
the modulus:

```
secret = 32 random bytes
c      = RSA-OAEP(rpk, secret, hash = SHA-256, MGF1 with SHA-256, label = LABEL || "ssh-rsa")
KEK    = HKDF(secret, 32, salt = SHA-256(c || rpk), LABEL || "ssh-rsa")
```

The slot holds `t`, `c`, `n` and `w`, with `w` wrapped as for every slot (aad `LABEL || "slot/ssh-rsa"`).
A slot names no key: a reader tries its RSA keys of the matching size on it. RSA is classical, and the
length of `c` shows the key's size. RSA keys whose wire encoding is exactly 32 or 1216 bytes are not
used, so a raw recipient key's length alone tells the kinds apart. Locksmith 3.0 and earlier don't know
this slot type and refuse the whole file, whatever else could open it.

### Decoy slots

A writer may add recipient slots for keys that are generated and immediately discarded, wrapping a
random value, to hide how many recipients there are. Since Locksmith 5, each kind of recipient slot
(`x25519`, hybrid, and `ssh-rsa` of one ciphertext size) is rounded up on its own to 8, 16, 32 or
64, the largest kind first, and a kind that no longer fits within the 64-slot limit gets as many
decoys as there is room for. The file then shows which kinds of recipient it has, but not how many
of each. (Locksmith 4 rounded the total and made every decoy one kind, which showed exactly how many
recipients of the other kinds there were.) `ssh-rsa` decoys are RSA-OAEP encryptions of a random
value to a recipient key of the same size, or to a throwaway key of that size up to 4096 bits, so
they look like real ones even to someone who knows the recipients' keys. (A ciphertext for a
throwaway key can be larger than a real recipient's modulus, which shows it is a decoy, so a writer
uses a recipient key whenever it knows one of that size; larger RSA keys get no decoys.) Decoys are
ordinary slots that no key opens, so readers need nothing special.

### Changing the slots

A writer that changes who can open a file (a new password or keyfile, recipients added or replaced)
unlocks it, keeps `magic`, `kc`, the fixed header bytes and every frame exactly as they are, and writes
a new slots array of 1 to 64 slots wrapping the same DEK, shuffled again. Nothing else is re-encrypted.
Without a recipient's private key, its slot can't be told apart from other recipients' slots or from
decoys, so a writer either keeps every recipient slot or replaces them all with a new list; it can't
take out one. When it hides the number of recipients, it rounds the recipient slots up as above,
counting the kept ones. For `ssh-rsa` decoys it uses the keys it knows of that may be among the kept
recipients (Locksmith: saved contacts), so they look like the kept slots.

A change revokes nothing. Anyone who could open the file before may have kept its DEK, which opens
every copy, old or new, whatever its slots say. Taking access away means encrypting the content again
under a new DEK.

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
| `created` | when the file was encrypted (Unix seconds), omitted when metadata is stripped |
| `items`   | number of items in a bundle |
| `note`    | the sender's free text. Only a valid signature (section 15) vouches for it |
| `to`      | the signer's intended recipients, in signed files only (see below) |

Readers ignore unknown fields and fields of the wrong type.

`to` lists the recipients the signer addressed a signed file to: an array of 1 to 64 base64 32-byte
entries, each `SHA-256("locksmith/v2/recipient" || 0x00 || key)` where `key` is a recipient's raw
encryption key exactly as in section 9 (the 32-byte X25519 key, or the 1216-byte X25519 || ML-KEM-768
key, with no prefix or checksum), the bytes its slot was made for: for an SSH Ed25519 recipient, its
converted X25519 key, and for an SSH RSA recipient, its wire encoding (section 3). A writer lists only real recipients
(never decoys), writes `to` only in a signed file, and refuses it for a file with no recipient slots: a
password or keyfile has no key to list. The list keeps the signer's original intent: changing the slots
later (section 3) leaves it as it was.

`to` means something only when the file's signature verifies with a key the reader trusts (section 15),
because anyone who can open a file can rewrite its metadata; readers ignore it in unsigned files, in
files signed by an unknown key, and when it isn't an array of 1 to 64 such entries. A reader tests the
encryption keys of every one of its own identities against it, not only the one that opened the file:

- one of them is listed: the reader was addressed, and says nothing more;
- none is listed and an identity's slot opened the file: the reader says it wasn't on the original
  recipient list;
- none is listed and a password or keyfile opened it: the reader says the file was addressed to
  specific people and opened with its password, never that the reader was left off.

Without `to`, a reader says nothing about whom a file was meant for. Everyone who can open a file can
read its list, and so learn how many recipients were addressed, even when decoy slots hide that number
from everyone else.

For `dir` and `bundle`, the content is a
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
low-order X25519 points and malformed ML-KEM keys. The fingerprint is the first 32 hex digits (128
bits) of SHA-256(raw), in eight groups of four, so it covers every key in `raw`. Locksmith 4 and
earlier showed only the first 20 digits (80 bits), which are the first five groups of the same
fingerprint. Adding signing keys to an identity
therefore gives it a new fingerprint, which contacts check once.

A `locksmith3` key is too large for a QR code. Its QR code holds only its hash, as
`LOCKSMITH3:FP:` followed by the 64 uppercase hex digits of SHA-256(raw). The key itself travels as
text; whoever receives it compares its SHA-256 with the scanned hash (the first 32 digits are the
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

**Paper backup**: a printed page with the backup words and a QR code holding
`LOCKSMITH-ID1:` followed by the base32 (RFC 4648, upper case, no padding) of the same bytes the
words encode: the raw private key and its 4-byte checksum. QR codes store this text in their compact
alphanumeric mode. Readers accept it in either case and check the checksum.

**Identity shares**: Shamir shares (section 11) of `"LSI1" || raw private key`.

Signing keys are derived from the raw private key (section 13), so backups, words and shares hold
nothing extra and restore them too.

## 11. Shamir shares

Secrets are split byte-wise over GF(2^8) with the AES polynomial (0x11B), at x = 1…n, with fresh
random coefficients. Text form (version 3, written since Locksmith 5):

```
locksmithshare3-<k>-<x>-<split id: 8 hex>-<data: hex>-<check: 6 hex>
padded = u16 len(secret) || secret || zero bytes up to a multiple of 32 bytes
data   = the share's bytes of (padded || SHA-256("locksmith/share/v3" || split id || padded)[0..8])
check  = hex(SHA-256(byte k || byte x || split id || data))[0..6]
```

Secrets are 1 to 4096 bytes. The padding means a share shows its holder only the secret's length
rounded up to 32 bytes, not the exact length of a password. Every share of one split has the same
random 4-byte split ID. Combining rejects mixed IDs, shares beyond the threshold that disagree, a
recovered secret whose tag doesn't match, and padding that isn't all zeros or a length that doesn't
fit.

Older forms are still read. Version 2 (`locksmithshare2-…`, the same fields) shares
`secret || SHA-256("locksmith/share/v2" || split id || secret)[0..8]`, without length or padding.
Version 1 (`locksmithshare-<k>-<x>-<data>-<check>`, no split ID or tag, check over `k || x || data`)
shares the secret alone.

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
created   u64       when it was signed (Unix seconds), as the signer's clock said; 0: not said
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
   checked, and the reader says so (it may show `key_id`'s first 32 hex digits as the fingerprint the
   signature claims, never as the signer's). A key of any other kind never verifies a signature, whatever `alg` says.
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

A writer that strips metadata writes `created` = 0, as it leaves out the metadata's `created`.
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
   and its own identities). Without one, the file still opens, but nothing about the signature has been
   checked: `key_id` is only a claim that anyone can write. A reader may show the fingerprint it names,
   but only as a claim, never as the signer.
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
- Frames use `aad = SHA-256(header bytes exactly as stored)`, so they are bound to the slots too:
  changing who can open a version 1 file means encrypting it again.
- Frame kinds are 0–2 only: version 1 files are never signed.

## 17. Recovery data

Recovery data is a separate file, by convention the protected file's name plus `.lpar`, that can
repair storage damage to any file (Locksmith writes it for its own files on request). It doesn't
change the protected file, and it protects against decay, not against tampering: the block hashes and
the whole-file hash a repair is checked against come from the sidecar itself, so whoever can change
the sidecar alone decides what a repair rebuilds (up to `m/k` of the file). Locksmith files are
authenticated anyway when opened; a reader repairing any other file should show how much it would
rebuild and the expected SHA-256, and ask first.

Parity is not encryption. It is made of the file's own bytes: a file of at most `m` blocks can be
rebuilt from the sidecar alone, a larger one partly, and the block hashes confirm guesses. A writer
makes the sidecar no more readable than the file (Locksmith: owner read and write, plus group and
others' read only where the file has it), shreds it with the file, and warns before making one for a
file that isn't encrypted.

**Layout.** The protected file of `size` bytes is cut into `n = ceil(size / B)` data blocks of `B`
bytes, the last one padded with zeros (blocks past the end are all zeros). With `k` data and `m`
parity blocks per stripe, there are `S = max(1, ceil(n / k))` stripes, and data block `b` is at
position `t = b div S` of stripe `j = b mod S`, so each stripe's blocks are spread evenly over the
file. `(k, m)` is (200, 2), (80, 4), (40, 4) or (20, 4) (1, 5, 10 or 20% of the file), and `B` is
`ceil(size / 65536)` rounded up to a multiple of 4096, at least 4096 and at most 1 MiB. Readers refuse
any other layout: with `k = m = 1`, for example, a crafted sidecar would have every block rebuilt from
its parity, which is the whole file.

**Parity.** Over GF(2^8) with the polynomial `x^8 + x^4 + x^3 + x^2 + 1` (0x11D), parity block `i`
of stripe `j` is, byte by byte,

```
P[j][i] = XOR over t of  C(i, t) · D[t·S + j]        C(i, t) = 1 / (i XOR (m + t))
```

for `i` from 0 to `m - 1` and `t` from 0 to `k - 1`. `C` is a Cauchy matrix, so any `m` lost blocks
of a stripe (data or parity) can be rebuilt from the others by solving a small linear system.

**File.**

```
"LOCKPAR" 0x01 || u32 len(meta) || meta || SHA-256(meta)
parity blocks P[0][0], P[0][1], …, P[0][m-1], P[1][0], …   (S·m blocks of B bytes)
meta || SHA-256(meta) || u32 len(meta) || "LOCKPAR" 0x02

meta  = u32 len(header) || header || data hashes (n × 16 bytes) || parity hashes (S·m × 16 bytes)
```

`header` is UTF-8 JSON: `{"v": 1, "size", "block": B, "k", "m", "sha256": hex SHA-256 of the whole
protected file, "name": its name when made}`. A block's hash is the first 16 bytes of SHA-256 of
its bytes (a data block without its padding). The description is stored twice; a reader uses
whichever copy matches its checksum and whose sizes add up to the file's length.

**Repair.** A reader marks the data blocks whose hash differs (or that are missing) and the parity
blocks whose hash differs, rebuilds each stripe with at most as many damaged data blocks as it
has intact parity blocks, and accepts the result only if its SHA-256 equals `sha256`. A
contiguous run of damage up to `m·S - 1` blocks long touches no stripe more than `m` times.

## 18. age files

Locksmith also reads and writes files in the age format (age-encryption.org/v1, specified at
c2sp.org/age), for exchanging files with age and rage. Those files follow that specification, not
this one; this section only says how Locksmith's keys take part.

- A classical identity's 32-byte raw private key is an age X25519 identity (`AGE-SECRET-KEY-1…`),
  and its public key is the `age1…` recipient.
- An age post-quantum identity (`AGE-SECRET-KEY-PQ-1…`) is a 32-byte seed that X-Wing expands as
  `SHAKE256(seed, 96) = d || z || sk_X`. Locksmith keeps it as the hybrid raw private key
  `sk_X || d || z` (section 10): the X25519 key, then the ML-KEM-768 seed. The `age1pq1…` recipient
  holds `pk_M || pk_X`; Locksmith's `locksmith2` key holds the same keys as `pk_X || pk_M`. So every
  Locksmith hybrid identity opens `mlkem768x25519` stanzas and can be written as an `age1pq1…`
  recipient, but not as a seed.
- `ssh-ed25519` and `ssh-rsa` stanzas follow age's own rules for SSH keys, which differ from the
  slots of section 3 (age tweaks the Ed25519 shared secret and names the key with a 4-byte tag).
- Locksmith writes ChaCha20-Poly1305 payloads as age requires, with a passphrase (scrypt, work
  factor 16 to 20) or with recipients, never both, and never post-quantum and classical recipients
  in one file. It reads scrypt work factors up to 21. age files have no name, signature, padding or
  note: Locksmith names the output after the file without `.age`, and stores a folder as a tar
  archive (`name.tar.age`), which comes back as that archive.
