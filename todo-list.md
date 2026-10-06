# Locksmith security audit

- **Code reviewed:** commit `61e83d6` (Locksmith 4.0.0), everything under `locksmith/`, plus the packaging scripts
  as far as they affect what ships.
- **Date:** 2026-10-05
- **Method:** I read every module by hand. Suspected issues were checked with small proof-of-concept scripts run
  against the real code from a scratch folder. The only change to the repository is this file. Windows-only behaviour
  (Mark of the Web, `os.startfile`, roaming profiles) is reasoned from the code and was not run on Windows.
- **Previous findings:** the earlier audit's items (N1–N15) are fixed in this commit, and I didn't re-raise them. The
  findings below are new.

## Severity scale

| Level | Meaning |
|---|---|
| **High** | Defeats a guarantee the app makes (confidentiality, or "signed by X") under conditions an attacker can realistically arrange |
| **Medium** | An attacker can cause real harm (data replaced, a protection bypassed, a misleading security claim), but needs extra conditions or user steps |
| **Low** | Narrow, needs unusual conditions, or leaks only a little information |
| **Info** | Not a bug: a limit of the design that users or the docs should state clearly |

## Summary

| ID | Severity | Finding | Area | Status |
|---|---|---|---|---|
| A1 | **High** | A contact's signing keys can be replaced with anyone's ("update contact"), so an attacker's signatures show as "✓ Signed with the key you saved as Alice" | Keys, signing | Open |
| A2 | **Medium** | A crafted `.lpar` makes "Repair" replace an intact file with arbitrary content | Recovery data | Open |
| A3 | **Medium** | "Signed by a key you haven't saved (fingerprint …)" shows a fingerprint the attacker chose, without verifying anything | Signing | Open |
| A4 | **Medium** | Share → Join strips the Mark of the Web (Windows): a way to deliver programs past SmartScreen | Share | Open |
| A5 | **Medium** | Identity private keys are stored unencrypted by default, and on Windows in the *roaming* profile | Key storage | Open |
| A6 | Low | Sender-controlled text (notes, names, OpenPGP user IDs) can fake status lines such as "✓ Signed with…" | UI | ✅ Patched (partly: no status badge yet) |
| A7 | Low | "Open" on a decrypted file runs programs and scripts directly, without a warning | Decrypt | ✅ Patched |
| A8 | Low | 80-bit fingerprints are the only thing most users compare | Keys | Skipped (needs format revision) |
| A9 | Low | "Hide the number of recipients" still shows how many classical, SSH and RSA recipients a file has | Format privacy | Partly: help text only |
| A10 | Low | Default settings leak usernames, file times and content sizes to recipients and observers | Privacy defaults | ✅ Patched |
| A11 | Low | Plaintext from a failed decryption is deleted, not shredded | Decrypt | ✅ Patched |
| A12 | Low | A crafted file can make each open use 2 GiB of RAM and minutes of CPU | Decrypt | ✅ Patched (partly: not cancellable mid-run, age not covered) |
| A13 | Low | Folder extraction safety depends on the Python patch level when run from source | Extraction | ✅ Patched |
| A14 | Low | The email subject passes a file name through `xdg-email`, which some mail clients parse unsafely | Share | ✅ Patched |
| A15 | Low | A password split with Shamir shows its exact length in every share | Share | Skipped (needs share format change) |
| I1–I8 | Info | Lock screen, network block, TPM sealing, X11, age SSH tags, OpenPGP key freshness, ICC profiles, Windows ACLs | Design limits | Info (no fix planned) |

The core cryptography holds up well; see "Checked and found sound" at the end. The serious issues are
about **trust and display**: who the app says signed something, and what it lets a file or sidecar from someone
else overwrite.

## Progress on the Low items (2026-10-05)

Done in order of simplicity. Each fix has a regression test (in the "2026-10-05 audit" section at the end of
`tests/test_security.py`, or in `tests/test_ui_flows.py`) that fails without the fix. The full suite passes
(930 passed, 5 skipped) and `ruff check` is clean. Nothing is committed yet.

| ID | Status | What changed |
|---|---|---|
| A14 | **Fixed** | `host.mail_safe` removes `' " , & % \ ;` and control characters from the subject and body before `xdg-email`; the body no longer contains "I'll" |
| A10 | **Fixed** | Folder archives never store user or group names or ids (times are still kept unless stripping is on); Share messages are padded (Padmé) and no longer compressed |
| A11 | **Fixed** | New `scratch.discard`: plaintext left by a failed, cancelled or signature-rejected decryption (Locksmith and age, including partly extracted folders) is shredded when it holds at most 1 GiB, then deleted. Larger leftovers are only deleted, so cancelling a huge file doesn't take minutes. The crash journal still shreds everything |
| A13 | **Fixed** | `engine._check_tarfile` refuses to decrypt folders (checked before anything is decrypted) on Python older than 3.12.11, or on 3.13.0–3.13.3. README updated |
| A7 | **Fixed** | Decrypt → Open asks before opening a program, script, shortcut or installer (`osutil.opens_as_program`, Windows and Linux types). The prompt says whether the file was signed with a saved key |
| A6 | **Fixed (partly)** | `tools.display_text` turns line breaks into spaces, drops control characters and bidi overrides, and limits the length. Used for notes, skipped member names, minisign trusted comments and OpenPGP user IDs; verify-only mode now shows names through `safe_name`. **Not done:** showing the signature status as a separate badge with an icon (a UI design change) |
| A12 | **Fixed (partly)** | `kdf.beyond_presets` flags KDF settings above every preset Locksmith writes. Decrypt and Share → Open a message then show the cost and ask before trying the password. **Not done:** running the KDF in a child process so it can be cancelled mid-run (a bigger change), and the same check for age `scrypt` work factors (`age.inspect` doesn't report them yet) |
| A9 | **Partly: wording only** | The "Hide the number of recipients" help texts (Encrypt page, Change who can open it) now say that classical, SSH and RSA recipients beside post-quantum ones stay countable. **Skipped:** changing the decoys. Any decoy mix that follows the real recipients still leaks which kinds are present, and RSA would need decoy `ssh-rsa` slots (random ciphertexts of common modulus sizes). That is a design decision: pick a fixed policy (for example, refuse mixed kinds when hiding, or always add every kind), then test how files look with each mix |
| A15 | **Skipped** | Needs a share format change: Shamir shares are specified in `docs/FORMAT.md` §11 (`locksmithshare2`). Padding the secret means a new `locksmithshare3` (length prefix and padding inside the shared data, with a block size to choose, for example 32 or 64 bytes), a spec update and new vectors, while still reading v1 and v2. Identity shares are fixed-size, so they don't leak and could stay on v2 |
| A8 | **Skipped** | The fingerprint ("first 20 hex digits of SHA-256") is defined in `docs/FORMAT.md` §9, checked by committed vectors (`tests/vectors/signatures.json`, `tests/spec_reader.py`), printed on paper backups, and already compared by users. Lengthening it means a spec revision, new vectors (the old ones must stay), a decision on how old 20-digit fingerprints are shown during the transition, and UI layout checks. A lighter interim step would be to show the full 64-digit hash on a contact's details sheet |

---

## A1 (High): a contact's signing keys can be swapped for an attacker's

**Where:** [keys.py:718](locksmith/core/keys.py#L718) (`KeyStore.update_contact_key`), the dialog in
[ui/pages/keys.py:205-214](locksmith/ui/pages/keys.py#L205-L214), and `add_contact`, which steers users to that dialog.

**What happens.** A `locksmith3` public key is three keys put side by side: an encryption key (X25519 + ML-KEM) and
two verify keys (Ed25519 + ML-DSA). Nothing in the key shows that the verify keys belong to the same person as the
encryption key. They are derived from the private key, but only its holder can check that.
`update_contact_key` accepts any `locksmith3` key whose *encryption* part matches a saved contact, and saves the
verify keys that came with it.

The dialog then says: *"This is the key you saved as "Alice", with its signing keys added, so you can verify their
signatures."* The first half of that sentence can't be known. It also suggests that the fingerprint you already
checked still applies. After one click, the contact looks the same as before. There is no "unverified" state.

**How it could be abused.** The user has had Alice's `locksmith2` key for months and checked its fingerprint long
ago. Mallory sends a message: "I upgraded Locksmith, here's my new key so you can verify my signatures." It contains
Alice's encryption key with Mallory's verify keys. The user pastes it, Locksmith says it is Alice's key, and the user
clicks Update. From then on, every file and `.lsig` Mallory signs shows **"✓ Signed with the key you saved as
Alice"**, including the "Note (signed)" line. Files the user encrypts still go to the real Alice, so nothing looks
wrong.

**Evidence (run):** Alice's `locksmith2` key was saved as a contact, then updated with
`alice.public_raw + mallory_verify_keys`, which was accepted. Mallory signed with a client that writes the spliced
key's ID. Result: `signature_text(...)` returned `✓  Signed with the key you saved as Alice`. Changing the client
means one line of code. No secret of Alice's is needed.

**The reverse case.** An attacker can also publish their own encryption key with *Alice's* verify keys. Alice's
genuine signatures then verify under the attacker's key. That gives the false impression that "this key must be
Alice's, her files verify", while files encrypted to it go to the attacker. A fingerprint check catches this, but
signature success should never count as evidence that an encryption key is right.

**Fix:**
1. Treat an update as a new key. Don't say "this is the key you saved as X". Say "This key claims to belong to X. Its
   new fingerprint is …; it is not verified until you compare it with them." Add a "fingerprint checked" flag to
   contacts that is set only by an explicit confirmation. Until it is set, show signatures as "signed with a key
   claimed to be Alice's (fingerprint not checked)", not ✓.
2. Bind the parts of a `locksmith3` key in the format: add a self-signature by the verify keys over the encryption
   key, plus a proof that the holder has the encryption key (for example, a signature made with a key derived from
   the X25519/ML-KEM secret, or a challenge made at the first exchange). The self-signature alone stops the
   reverse case. Stopping the main case needs proof that the holder has the decryption key, or the fingerprint flag
   from item 1.
3. In `update_contact_key`, refuse the update if the contact already verified any signature, or require the old
   fingerprint to be checked again.

---

## A2 (Medium): a crafted recovery file replaces an intact file with arbitrary content

**Where:** [parity.py:248](locksmith/core/parity.py#L248) (`_parse_meta`) and
[parity.py:368](locksmith/core/parity.py#L368) (`repair`). UI: Tools → Recovery data
([ui/pages/tools.py:854](locksmith/ui/pages/tools.py#L854)).

**What happens.** Everything `repair` checks against comes from the `.lpar` itself: the size, the per-block hashes
and the final SHA-256. `_parse_meta` accepts any layout with `k + m ≤ 256`, including `k = 1, m = 1`. There, every
block is its own stripe and the parity block alone rebuilds it. A sidecar that marks every block "damaged" and
supplies parity for other content makes `repair` write that content. It passes the SHA-256 check (the attacker chose
that hash too), renames the real file to `name.damaged`, and reports "✓ Repaired". The module docstring says
recovery data doesn't protect "against someone who can change both files". In fact, changing **only the sidecar** is
enough.

**How it could be abused.**
- Someone who can place or edit a `.lpar` next to a file (a shared drive, a synced folder, a download offered with
  "recovery data") can turn `contract.pdf` into any content the next time the user checks it. The result can even be
  a different size or type.
- On Windows, the "repaired" file is new (`create_private`) and has **no Mark of the Web**, even if the original
  did. The UI says the file is now repaired, so the user trusts it more than before.
- For `.locked` files, swapped content fails authentication unless the attacker can make a valid file for the user
  (anyone with the user's public key can), so a file signed by someone else can be replaced by an unsigned one.

**Evidence (run):** a 7.6 KB "PDF" plus a hand-built `contract.pdf.lpar` (`k=1, m=1`, all data hashes wrong, parity
= attacker content ÷ the Cauchy coefficient). `parity.repair()` returned `intact=False`, and afterwards the file
matched the attacker's content byte for byte, with the original moved to `contract.pdf.damaged`.

**Fix:**
- Accept only the layouts Locksmith writes (`LEVELS`), and refuse a repair that rebuilds more than the level's share
  of the file (m/k). Real bit rot never "damages" 100% of the blocks while the size changes.
- Refuse a repair when the file's size differs from the recorded size by more than one block, or when it would change
  the file type.
- Show the expected SHA-256 before repairing, and say plainly that the result is only as trustworthy as the `.lpar`.
- For `.locked` files, authenticate the repaired copy (`verify_path`) before moving it into place.
- Copy the original's Zone.Identifier to the repaired file (`osutil.copy_zone_identifier`).
- Optional: store the `.lpar`'s own hash inside the encrypted metadata of the `.locked` file it protects, so a swapped
  sidecar is detected.

---

## A3 (Medium): an unverified signer fingerprint is shown as if it meant something

**Where:** [signing.py:259](locksmith/core/signing.py#L259) (`check_locked` returns `sig.fingerprint` for an unknown
signer), [ui/pages/common.py:68](locksmith/ui/pages/common.py#L68), and
[signing.py:211](locksmith/core/signing.py#L211) (`verify_file`: *"It was made with the key whose fingerprint is …"*).

**What happens.** When no saved key matches a signature's `key_id`, nothing is verified. Still, the UI shows "Signed
by a key you haven't saved (fingerprint XXXX …)". That `key_id` is just 32 bytes the sender wrote. The detached
signature message goes further and states it "was made with" that key.

**How it could be abused.** The attacker puts the `key_id` of a well-known key (Alice's published fingerprint) into a
file with a random signature. A reader who knows Alice's fingerprint but hasn't saved her key sees *"Signed by a key
you haven't saved (fingerprint 2797 6841 22F1 97C0 8DA7)"*, matches it with Alice's website, and believes Alice
signed it. The note is shown as "not verified", but the fingerprint line works against that.

**Evidence (run):** a file whose signature frame held Alice's `key_id` and 3,373 random bytes decrypted fine. The UI
text showed exactly Alice's real fingerprint.

**Fix:** never show a claimed fingerprint as a fact. Use wording like "Has a signature that claims to be from a key you
haven't saved (claimed fingerprint …). Nothing has been checked; save that key and open the file again to check it."
Or show no fingerprint until a key is saved. Use the same wording for `UnknownSignerError` in `verify_file`.

---

## A4 (Medium, Windows): Join removes the Mark of the Web

**Where:** [tools.py:597](locksmith/core/tools.py#L597) (`join_parts`), [tools.py:582](locksmith/core/tools.py#L582)
(`split_file`), UI [ui/pages/share.py:164](locksmith/ui/pages/share.py#L164).

**What happens.** `join_parts` joins *any* files named `X.partNNN` into `X`, whatever the type. The new file is
created with `open_new` and never gets the parts' Zone.Identifier. The N7 fix covered decrypted output, but this path
writes the same kind of content (received from someone else) without the mark.

**How it could be abused.** An attacker sends `Invoice.exe.part001` and `Invoice.exe.part002` (or `.js`, `.hta`, a
macro document). Each is marked by the browser or mail client. They tell the victim "the file was too large, join it
with Locksmith (Share → Join)". The result `Invoice.exe` has no mark, so SmartScreen, Smart App Control and Office
Protected View don't apply. Locksmith becomes a tool for getting around the Mark of the Web, which is a common
technique in malware delivery.

**Fix:** copy the Zone.Identifier of the first marked part to the output (or call `mark_untrusted` whenever any part
has a mark). Consider limiting Join to outputs that are `.locked`/`.age` files, which is all the feature is for. Mark
split parts the same way as their source.

---

## A5 (Medium): private keys are stored unencrypted by default; on Windows they roam

**Where:** [keys.py:610](locksmith/core/keys.py#L610) (`generate`), [keys.py:688](locksmith/core/keys.py#L688),
[ui/pages/keys.py:174](locksmith/ui/pages/keys.py#L174) ("PASSPHRASE (OPTIONAL)"),
[osutil.py:113](locksmith/core/osutil.py#L113) (`%APPDATA%`, the roaming profile).

**What happens.** A new identity is saved as plain base64 in `keys.json` unless the user types a passphrase. The file
is `0600`, which stops other users, but not:
- backup tools, dotfile sync, cloud sync of `~/.config`;
- any program running as the user (the in-process hardening protects memory, not this file);
- on Windows, **roaming profiles**: `%APPDATA%\Roaming` is copied to the domain's profile server at logoff in managed
  environments, so the private keys leave the machine.

**How it could be abused.** Information-stealing malware already collects files from known paths;
`~/.config/locksmith/keys.json` and `%APPDATA%\locksmith\keys.json` with unencrypted keys are an easy target. One copy
opens every file ever sent to the user.

**Fix:** make the passphrase (or TPM sealing) the default and require a confirmation to skip it. On Windows, keep
`keys.json` under `%LOCALAPPDATA%` (Local, which doesn't roam) and migrate existing files. Settings → About could
show "N identities are stored without a passphrase".

---

## A6 (Low): sender-controlled text can fake status lines

**Status (2026-10-05):** fixed, except the status badge. See Progress above.

**Where:** [ui/pages/decrypt.py:559](locksmith/ui/pages/decrypt.py#L559) (notes),
[ui/pages/decrypt.py:544](locksmith/ui/pages/decrypt.py#L544) (verify-only mode shows `meta["name"]` without
`safe_name`), [ui/pages/tools.py:788](locksmith/ui/pages/tools.py#L788) (OpenPGP user IDs), and minisign trusted
comments.

**What happens.** `Label` correctly refuses HTML, but plain text can still contain line breaks and Unicode bidi
controls (U+202E etc.). An unsigned file's note can be
`"Quarterly report\n✓  Signed with the key you saved as Bob"`. It then shows a second caption line that looks
exactly like the real status line, a few pixels below "Not signed". OpenPGP user IDs are chosen by whoever made the
key and can add a fake line in the same way. In verify-only mode, a file name with U+202E shows reversed
(`invoice‮fdp.exe` → "invoiceexe.pdf").

**Fix:** for every string from a file or a signer (notes, names, user IDs, comments), remove `Cc`/`Cf`/`Zl`/`Zp`
characters (or show them as visible escapes) and limit the length. Run the verify-mode name through
`engine.safe_name`. Show the signature status as a separate badge with an icon, not as a caption in the same style as
sender text.

---

## A7 (Low): "Open" runs decrypted programs directly

**Status (2026-10-05):** fixed.

**Where:** [ui/pages/decrypt.py:552](locksmith/ui/pages/decrypt.py#L552) → [host.py:59](locksmith/ui/host.py#L59)
(`os.startfile` on Windows, `xdg-open` on Linux).

**What happens.** The Open button hands the decrypted file to the shell. On Windows that runs `.exe`, `.scr`, `.bat`,
`.js`, `.hta`, `.lnk`, `.msi` and so on. The Mark of the Web is copied only when the `.locked` file had one, which
isn't the case for files from USB drives, many chat apps, or archives extracted by tools that don't copy the mark.
Encrypted delivery is a known way to get malware past mail scanners ("password is in the next email"), and the Open
button saves the attacker one step.

**Fix:** before opening an executable or script type (a list like the one browsers use), ask for confirmation that
names the type, especially when the file isn't validly signed. Consider showing "Show in folder" instead of "Open"
for those types.

---

## A8 (Low): 80-bit fingerprints

**Status (2026-10-05):** skipped: needs a format revision. See Progress above.

**Where:** [keys.py:354](locksmith/core/keys.py#L354) (`fingerprint`: the first 20 hex digits of SHA-256),
[signing.py:90](locksmith/core/signing.py#L90).

**What happens.** Users check contacts by comparing 80 bits. A second preimage (a key of the attacker's with your
contact's fingerprint) costs about 2^80 hash operations. The attacker controls the 1952-byte ML-DSA part, so each
try needs only one SHA-256 compression. That is out of reach for most attackers, but below the 112–128-bit level
the rest of Locksmith aims for (hybrid post-quantum encryption, ML-DSA-65). A match would give full impersonation,
for both encryption and signatures. The QR code already uses the full hash.

**Fix:** show at least 128 bits (32 hex digits, or words) for `locksmith3` keys. Keep the short form only as a quick
visual hint, labelled as such.

---

## A9 (Low): hiding the number of recipients doesn't hide their kinds

**Status (2026-10-05):** help text only; the decoy policy is a design decision. See Progress above.

**Where:** [engine.py:613](locksmith/core/engine.py#L613) (`_dummy_recipients`) and
[engine.py:621](locksmith/core/engine.py#L621) (`_decoy_keys`).

**What happens.** Decoys are all hybrid when any real recipient is hybrid, otherwise all X25519. With mixed
recipients, the `x25519` slots are exactly the classical and SSH Ed25519 recipients. `ssh-rsa` slots never get decoys,
and their ciphertext length shows the RSA key size. A file "hidden" at 16 slots with one RSA slot of 512 bytes tells
an observer "one recipient has a 4096-bit SSH RSA key", which, together with public GitHub SSH keys, narrows down who
it is.

**Fix:** make decoys match the real slots' types in proportion. Or, when hiding is on, refuse mixed kinds or warn that
the kinds stay visible. For RSA, add decoy `ssh-rsa` slots of common sizes, or document the leak in the toggle's help
text.

---

## A10 (Low): defaults that leak to recipients and observers

**Status (2026-10-05):** fixed (owner names, message padding and compression).

- **Folder archives** (non-strip path, [engine.py:1165](locksmith/core/engine.py#L1165)): `tar.add` stores the local
  username, group, uid/gid, permissions and exact modification times of every file. `strip_metadata` is off by
  default, so every folder sent to someone carries the sender's login name.
- **Sizes:** padding defaults to "none", and messages are compressed with zlib
  ([ui/pages/share.py:221](locksmith/ui/pages/share.py#L221)). The per-frame ciphertext lengths show the compressed
  size of every 1 MiB chunk. That is enough to recognise a known file (a leaked document, a specific photo) from the
  ciphertext alone, and for messages with attacker-influenced text it opens a CRIME-style compression side channel.
- **Fix:** always replace owner names and ids in archives (they are useless to recipients), even when stripping is
  off. Default padding to Padmé for messages and turn compression off for short text messages. Mention per-chunk size
  leakage in the padding help text.

---

## A11 (Low): plaintext from a failed decryption is only unlinked

**Status (2026-10-05):** fixed (shredded up to 1 GiB, then deleted).

**Where:** [engine.py:1493](locksmith/core/engine.py#L1493) and
[engine.py:1529](locksmith/core/engine.py#L1529).

Decryption writes plaintext to `.locksmith-….part` before the signature is checked. When the signature is invalid
(or decryption fails or is cancelled), the file is removed with `unlink`. The plaintext stays in free disk blocks,
on the same disk as the output folder, which may be a USB stick. The crash journal shreds leftovers, but the normal
error path doesn't.
**Fix:** use `tools.shred` (best effort) for `.part` files on the error path. For signed files, consider checking the
signature in a first pass that writes nothing (as `verify_path` does), then decrypting to disk.

---

## A12 (Low): a crafted file can use a lot of memory and CPU

**Status (2026-10-05):** confirmation added; cancelling a KDF mid-run and age scrypt are not done.

**Where:** [kdf.py:70](locksmith/core/kdf.py#L70) (limits: Argon2id 2 GiB × 16 passes × 16 lanes; PBKDF2 20 M
iterations), [engine.py:118](locksmith/core/engine.py#L118) (up to 4 KDF runs per file).

Opening a file with a password runs up to four KDFs with parameters the sender chose: 8 GiB allocated in total, one
after another, plus minutes of CPU. Cancel is only checked between runs. On a machine with little memory this can
trigger the OOM killer against *other* programs. **Fix:** when a slot's cost is above the Paranoid preset, show the
cost (the info card already shows `kdf.describe`) and ask before running it. Run the KDF in a way that can be
cancelled, for example in a child process.

---

## A13 (Low): extraction safety depends on the Python version when run from source

**Status (2026-10-05):** fixed.

**Where:** `pyproject.toml` allows Python ≥ 3.12; [engine.py:1656](locksmith/core/engine.py#L1656) relies on
`tarfile.data_filter`.

The shipped builds use Python 3.14.7, which is fine. Running from source on an older 3.12.x or 3.13.x without the 2025
tarfile fixes (CVE-2025-4517, CVE-2025-4330, CVE-2025-4138, CVE-2024-12718: filter bypasses that allow writing outside
the destination) would let a crafted folder archive write outside the output folder. **Fix:** at start-up, refuse to
extract folders (or refuse to run) on Python versions older than 3.12.11 / 3.13.4, and say why.

---

## A14 (Low): file names in the email subject

**Status (2026-10-05):** fixed.

**Where:** [ui/pages/share.py:134](locksmith/ui/pages/share.py#L134) → [host.py:79](locksmith/ui/host.py#L79).

The subject is `Encrypted file: <name>`. With Thunderbird, older `xdg-email` versions decode the subject and paste it
into `subject='…'` without escaping. That is the class of bug behind CVE-2022-4055, where crafted text adds fields
such as `cc=` or `attachment=`. A file name such as `x',cc='attacker@example.com.locked` (no slash needed) could add
a recipient to the message. This needs a malicious file name and a vulnerable `xdg-email`. **Fix:** leave the file
name out of the subject, or remove `'`, `,`, `&`, `%`, `\` and control characters from it.

---

## A15 (Low): Shamir shares reveal the secret's length

**Status (2026-10-05):** skipped: needs a share format change. See Progress above.

**Where:** [tools.py:403](locksmith/core/tools.py#L403). Each share's data is `len(secret) + 8` bytes, so every share
holder knows the exact length of the password. **Fix:** pad the secret to a fixed block (for example 32 or 64 bytes,
with a length prefix inside the shared data) before splitting.

---

## Design limits worth stating (Info)

- **I1 – The lock screen is a privacy screen, not access control.** Any click or key unlocks it
  ([lock.py:104-112](locksmith/ui/lock.py#L104-L112)). Afterwards, anyone at the keyboard can decrypt with
  unprotected identities, show backup words and export keys. That is consistent with A5, but the docs should say
  "covers the window", not suggest that it locks anything. If real locking is wanted, require a passphrase to unlock
  and drop unlocked identity keys on lock.
- **I2 – The network block only protects against mistakes, not against a compromised process.** The seccomp filter
  allows `AF_UNIX`, so code running inside Locksmith (for example after a parser memory bug in Qt's image plugins)
  can ask the user's systemd or D-Bus to start a program that has network access, which is exactly what `host.launch`
  does. The README wording ("configured to refuse creating any internet socket") is accurate. Don't present it as a
  sandbox.
- **I3 – TPM sealing protects a copied disk, not a live session.** `--user --tpm2-pcrs=` (no PCRs,
  [keys.py:96](locksmith/core/keys.py#L96)) means any process running as the user on this machine can unseal it
  through `systemd-creds`. Without a passphrase, a sealed identity protects against stolen disks and backups only.
- **I4 – On X11, every X client can read keystrokes**, including passwords typed into Locksmith. Wayland doesn't allow
  this. Consider a note in Settings → About when the session is X11.
- **I5 – age files with SSH recipients name them.** age's `ssh-ed25519`/`ssh-rsa` stanzas carry a 4-byte tag of the
  key ([age.py:339](locksmith/core/age.py#L339)), so anyone with a list of public SSH keys (GitHub) can tell who a file
  is for. "Recipients aren't named in the file" is true of `.locked` files but not of these age files; say so where
  age plus SSH is chosen.
- **I6 – OpenPGP revocation and expiry are only as current as the key file given.** Anyone handing over the key can
  leave out a revocation or a newer binding. Also, for subkeys the *last* valid binding in packet order wins
  ([openpgp.py:460](locksmith/core/openpgp.py#L460)), not the newest one as for the primary key. Choose by creation
  time for consistency.
- **I7 – Metadata stripping keeps ICC colour profiles** ([metadata.py:169](locksmith/core/metadata.py#L169),
  `iCCP` in `PNG_KEEP`). Phone and camera profiles often contain the device model, the maker and a creation date.
  Consider replacing known profiles with a standard sRGB/Display P3 profile, or removing their description and date
  tags. Formats that aren't supported (HEIC, TIFF, PDF, Office, video) pass through untouched; the UI reports them as
  "unchanged", which is correct.
- **I8 – Windows file permissions come from the folder.** `open_new`'s `0600` is ignored on Windows: decrypted files
  get the output folder's access list. Decrypting into `C:\Users\Public` or a shared folder makes the plaintext
  readable to others. Consider setting an owner-only access list on decrypted output, or warning about shared folders.

---

## Checked and found sound

These areas were reviewed specifically and I found no problems:

- **Format v2 crypto:** a random 256-bit DEK per file; HKDF-SHA512 with domain-separated labels per format version;
  a key commitment over the DEK and the SHA-256 of the fixed header, checked with `hmac.compare_digest`, so tampering
  with the header reads as a wrong key; frame nonces `prefix ‖ counter ‖ final` with the header hash as AAD, which
  stops reordering, truncation and appending; zero padding checked; frame order checked (content → padding →
  signature). No nonce reuse: `change_access` never re-encrypts frames.
- **Key slots:** X25519 low-order points refused when writing and skipped when reading. The hybrid KEK combines both
  shared secrets with a transcript hash (ephemeral key, KEM ciphertext, full recipient key). RSA-OAEP-SHA256 with a
  label, at least 2048 bits. The password and keyfile KEK mixes in SHA-512(keyfile) through HKDF with its own label.
  Slots are shuffled, and decoys are real slots for keys thrown away at once.
- **Signed files:** the signature covers the fixed header (so the note, name and recipient list) and SHA-512 of the
  content. Both Ed25519 and ML-DSA-65 must verify, with separate contexts and labels for detached and embedded
  signatures. An invalid signature from a saved key refuses the whole file before anything is moved into place.
- **Header parsing:** sizes and types checked before use, deep JSON nesting caught, KDF parameters capped, metadata
  fields type-checked, armor and frame sizes capped, decompression output capped per chunk, LZMA memory limited.
- **Extraction:** `data` filter, refusal of sparse and oversized headers, NUL/long-name/Windows-reserved-name
  handling, collision detection that knows about case-insensitive drives, owner-only modes, a disk-space guard, and
  `complete` reported honestly so "delete after decrypt" never removes the only copy.
- **File writing:** `O_EXCL|O_NOFOLLOW` everywhere, temporary file then `rename`, `fsync` of files and folders, a
  crash journal that only removes Locksmith-named temp paths.
- **Shredding:** links refused at the top level, `O_NOFOLLOW`, refusal for hard-linked files, keys and keyfiles
  protected from being shredded.
- **age:** strict base64 and armor, `scrypt` must be the only stanza, stanza bodies checked for exact length
  (partitioning oracles), header MAC checked before the payload, final-chunk rules followed. It passes the CCTV kit.
- **SSH, minisign and OpenPGP verification:** the key's type decides the algorithm, sk/cert keys and SHA-1/MD5 are
  refused, SSH namespaces are enforced, minisign trusted comments are verified, OpenPGP signing subkeys need a
  back-signature, critical subpackets are honoured.
- **Desktop integration:** arguments are quoted correctly for desktop files and the registry; only files and keys
  that Locksmith wrote are touched; the file manager passes absolute paths, so Qt's own `argv` options can't be
  injected.
- **UI:** every label is plain text (`widgets.Label`), tooltips are escaped, secret results are held back while
  locked, clipboard secrets carry the "don't record" hints and are cleared after 30 s.
- **Builds:** pinned and hash-checked tools, a hash-locked `requirements.lock`, Python 3.14.7 in both builds.

## Suggested order of work

1. **A1:** remove the assertion from the update dialog now (a one-line change), then add the "fingerprint checked"
   state.
2. **A3** and **A6:** wording and sanitising, both small.
3. **A2:** limit layouts and the share of the file a repair may rebuild, copy the Mark of the Web, authenticate
   `.locked` files after repair.
4. **A4:** copy the Mark of the Web on Join.
5. **A5:** passphrase by default; move `keys.json` to `%LOCALAPPDATA%`.
6. The rest as convenient. A1, A2, A3 and A4 each need a regression test that fails before the fix; the
   proof-of-concepts described above translate directly into tests.
