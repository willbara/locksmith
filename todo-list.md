# Locksmith To-Do List

Two parts: **features** (Part 1) and **security fixes** (Part 2). Within each category, tasks are ordered
from easiest to hardest. Categories are ordered by priority. **Signature verification is the top priority.**

Complexity tags: **[Easy]** about a day or less · **[Medium]** a few days · **[Hard]** a week or more, or needs a format change.

## Start here: critical path for signature verification

1. ~~Part 2, "Signing prerequisites" (N7, N3).~~ Done.
2. ~~Part 1, "Signature verification".~~ Done, including signed `.locked` files and the Decrypt signer status.
3. Format v2 (Part 1, "Format v2"). **Done:** the v2 container (fixed header and key slots kept apart, frames
   and the key commitment bound to the fixed header only), signed files, and the reserved `to` field
   (`intended_recipients`) in `docs/FORMAT.md` §7. Every file is now written as v2; v1 is still read. This is
   version 3.0.0. **Still to build:** editing passwords,
   keyfiles and recipients in place, the recipient-list UI, and the authenticated-encryption re-evaluation.

---

# Part 1: Features

## 1.1 Signature verification (top priority)

Effort ranges come from the scope check and are rough.

- [x] **[Easy]** Raise the `cryptography` floor in `pyproject.toml` (currently `>=44`; the code needs ML-KEM and
  signing needs ML-DSA). Add an ML-DSA check to `--self-test`, since ML-DSA needs OpenSSL 3.5+, AWS-LC or BoringSSL
- [x] **[Easy]** Verify SSH signatures (`ssh-keygen -Y sign`) on the Tools page next to minisign (2–4 days).
  Check the namespace, refuse or handle `sk-` (FIDO) keys, and show only what the signature covers
- [x] **[Easy]** Add interop vectors made by real `minisign` (current tests use signatures from Locksmith's own helper)
- [x] **[Medium]** Write the signature decisions into `docs/FORMAT.md` before any code, then make vectors from that
  text: key derivation, key string and fingerprint, hybrid combiner, exactly what is signed, domain-separation labels
- [x] **[Medium]** Hybrid signing keys (Ed25519 + ML-DSA-65), derived from the existing hybrid identity key so
  `keys.json`, backups, backup words and Shamir shares stay unchanged. Classical identities must upgrade to hybrid
  first. A signature needs both parts to verify, and the stored key type decides the algorithm
- [x] **[Medium]** New public key string for keys that can verify (new prefix, own fingerprint). It is too big for
  a QR code, so decide: drop the QR or use multi-part. Store the verify key inside the contact's `public` field,
  not a side field, because old builds drop unknown fields on save
- [x] **[Medium]** Sign and Verify files with detached signatures (a Tools card pair): prehashed, labeled
  `locksmith/v1/sig/…`, with vectors, a fuzz target and negative tests (stripped ML-DSA part, swapped Ed25519 part,
  wrong key type, altered comment, one-bit file change, truncated signature)
- [x] **[Hard]** Signed `.locked` files (embedded signature, format v2): sign every header field except the key
  slots, plus the metadata (including the optional `intended_recipients` list) and the plaintext hash, inside the
  encryption (see the decision in 1.2)
- [x] **[Hard]** Show the signer and status on Decrypt results ("Signed by the key you saved as Alice ✓" / unknown
  key / invalid / not signed). It must come from core, never from file metadata. Needs the item above and N3 + N7

Wording rule for all of the above: a valid signature means "signed with the key you saved as X", not "from X".

## 1.2 Format v2 (decide as one bundle, with signed files)

These interact. Editing recipients without re-encrypting conflicts with signatures that bind the key slots, so
decide the bundle before building any of them.

- [x] **[Medium]** Decide the v2 bundle: do signatures re-sign on recipient edits, or exclude the slots?
  Keep all v1 test vectors untouched
  - **Decided (2026-10-03):** signatures **exclude the key slots**. This *allows* forwarding with the signature
    intact: anyone who can open a signed file can add a slot for someone else, and it still shows as signed by
    the original signer ("surreptitious forwarding"). Reasons for accepting that:
    - Every key slot edit would break a signature that binds the slots, and v2 needs slot edits: changing the
      password or keyfile is a slot edit, and so is adding or removing a recipient. Excluding the slots keeps
      all of them working without a re-sign.
    - It is a trade-off. Binding the slots protects the signer's intent (a forwarded copy would no longer verify
      as signed for its new reader), but blocks those recipient, password and keyfile edits. Neither choice stops
      plaintext forwarding: anyone who can decrypt can pass the content on unsigned. The optional list below
      recovers most of the intent protection without blocking edits.
    - Most files are recipient-independent (documents, releases), so the signature only needs to attest who
      wrote the content.
  - **Mitigation, reserved in the v2 format now (UI may follow later):** an optional `intended_recipients` field
    inside the signed, encrypted metadata. Each entry is a domain-separated hash of a recipient's *encryption*
    key (the 32- or 1216-byte part slots are made for), so it matches whether the contact was saved as
    `locksmith2` or `locksmith3`; the UI shows fingerprints. What Decrypt says depends on how the file was
    opened, and is always neutral, never accusatory:
    - Opened with a key that is on the list: no warning.
    - Opened with a key that isn't on the list: "Signed by <name>, but you weren't on the original recipient
      list".
    - Opened with a password or keyfile (any non-key slot): "Addressed to specific people; opened with its
      password". It must not say the reader was left off.
    - Field absent: Decrypt says nothing about intent. Keep "signed with the key you saved as X" and never imply
      the signer sent the file to the reader.
    - Signer UI: an "addressed to specific people" toggle, off by default.
    - Caveats: anyone who can decrypt can read the list, so recipients learn who else was addressed. That also
      cancels "hide recipients" (decoy slots) toward recipients: when both are on, the signer UI shows this
      privacy trade-off before signing. Files with only password or keyfile slots can't use the list (those
      slots have no key to list), and the UI must say so rather than silently leave it out. The list records
      the signer's original intent and doesn't change when someone later adds a legitimate recipient, who will
      then see the neutral "not on the original list" wording.
  - **Spec first:** the list-entry definition goes into `docs/FORMAT.md` before any code: the hash input (the
    exact encryption public-key bytes, as in §9: the 32-byte X25519 key, or the X25519 key followed by the
    ML-KEM-768 key, 1216 bytes, with no prefix or checksum), a domain-separation label in the `locksmith/v2/…`
    style, and that the reader tests every one of its saved identities' encryption keys against the list.
  - **Required tests when it is built:** a file with a list opened by a reader who is on it (no warning), one
    who isn't, and by password; a signed file with no list (no intent wording); the list stripped from the
    metadata (the signature must fail); one entry altered (the signature must fail); and the signer-side
    warning when the list and decoy slots are both enabled.
- [x] **[Hard]** Extend the key commitment to cover the fixed header fields, so tampering fails at unlock.
  It must also exclude the key slots, so recipient, password and keyfile edits don't break it
- [ ] **[Hard]** Change the password or keyfile without re-encrypting the data
- [ ] **[Hard]** Add or remove recipients without re-encrypting the data. Removing a recipient does **not**
  revoke access for anyone who already has the file key and a copy of the data; the UI and docs must say so
  plainly. Real revocation means re-encrypting with a new file key
- [ ] **[Hard]** Optional authenticated public-key encryption ("from Alice ✓"). Signed files in 1.1 plus the
  `intended_recipients` list may cover most of its use case, so re-evaluate it after signed files ship

## 1.3 Interop

- [ ] **[Medium]** Accept SSH Ed25519 public keys as recipients (3–6 days). Convert to X25519 and reuse the
  `x25519` slot. Classical only. Decrypting with a passphrase-protected SSH key also needs the `bcrypt` module
  (3–5 days more, a new hash-locked dependency)
- [ ] **[Hard]** Accept SSH RSA public keys as recipients
- [ ] **[Hard]** Read and write age-compatible files
- [ ] **[Hard]** OpenPGP signature verify-only (15–25 days hand-written, or 3–6 with `gpgv` on Linux only).
  Do this only if you have a concrete need to check OpenPGP-signed downloads. A narrow option is a v4 detached-signature
  verifier with a pinned key and no keyring
- [ ] **[Deferred]** OpenPGP encrypt, decrypt and sign. Months of work, plus the RFC 9580 vs LibrePGP split

## 1.4 Identity backup

- [ ] **[Medium]** Printable paper backup (QR + words)
- [ ] **[Hard]** Restore an identity by scanning the paper backup's QR code

## 1.5 Smaller features

- [ ] **[Medium]** File manager integration: a right-click "Encrypt with Locksmith" and a `.locked` file association
- [ ] **[Hard]** Recovery data (parity records) for long-term archives

## 1.6 Trust and hardening

- [ ] **[Easy]** Add a status note near the top of the README: not independently audited, built with AI-assisted
  review, tests and fuzzing, not the only copy of irreplaceable data
- [ ] **[Easy]** Soften absolute claims in the README and FORMAT.md: "independent reader" → "second reader",
  runtime protections → "configured to", "Recipients stay anonymous" → "recipients aren't named in the file", and
  any implication that secrets are cleared from Python memory
- [ ] **[Medium]** Reproducible builds
- [ ] **[Hard]** Independent audit (long term)

---

# Part 2: Security fixes

All open items below are Medium severity. They come from the 2026-10-01 re-audit (commit `7be605e`) and keep their
IDs from `todo-list-checked.md`, which holds the original write-ups. Every other finding from the original review
(including N1 and N9–N15) is already fixed. Line numbers are from that commit and may have shifted since, so
search by function name if they don't match. Each fix needs a regression test that fails before the fix and
passes after.

## 2.1 Signing prerequisites (do before any signer UI)

- [x] **[Medium]** **N7: Files decrypted from pasted text have no Mark of the Web on Windows**
  - **Problem:** `decrypt_path` copies the source's Zone.Identifier onto the output, but the Decrypt page's paste
    path writes files and folders with no mark at all. Pasted text comes from someone else, through chat or email.
    A sender can paste-deliver an `.exe`, script or macro document that, after one click on the result's Open
    button, runs without SmartScreen or Office Protected View.
  - **Where:** `locksmith/ui/pages/decrypt.py:245-266`, `locksmith/core/osutil.py:68-90` (originally
    `todo-list-checked.md`, N7; the scope check also lists the paste path as `decrypt.py:244-266`, the file path
    as `engine.py:1167-1230` and the in-memory path as `engine.py:1233-1241`)
  - **Fix:** add `osutil.mark_untrusted(target)`, which writes `[ZoneTransfer]\r\nZoneId=3\r\n` to every file of
    the target (no-op off Windows), and call it from `_decrypt_pasted` for files and folders. Better: move the
    paste-to-disk logic into core so the rule lives in one place and signature checks can hook in there too. Moving
    it also fixes two quirks of that path: when the chosen output folder doesn't exist yet, output silently goes to
    the home folder (`decrypt_path` creates the folder), and a pasted folder isn't unwrapped, so it lands one level
    deeper (`proj/proj/…`) than the same folder decrypted from a file.
  - **Test (Windows suite):** decrypt a pasted file message and a pasted folder message. Every output file has a
    `Zone.Identifier` stream with `ZoneId=3`.

- [x] **[Medium]** **N3: Results that arrive after a lock are shown on top of the lock screen**
  - **Problem:** the lock overlay and every sheet share the parent `root`, and `Sheet.open()` calls `raise_()`. A
    task that finishes after Ctrl+L, Ctrl+Shift+L or auto-lock opens its sheet *above* the overlay (confirmed
    offscreen). For example, a pasted message under a slow Argon2 preset, or Share → Open message, then shows the
    decrypted text in a "Decrypted message" sheet. The Decrypt page also adds the text preview to its result list
    after the lock already cleared it. This defeats the panic key in exactly the case it exists for.
  - **Where:** `locksmith/ui/lock.py:137-139`, `locksmith/ui/dialogs.py:136-139`,
    `locksmith/ui/pages/share.py:252-257`, `locksmith/ui/pages/decrypt.py:313-352`
  - **Fix:** give `Locker` a `locked` flag (set in `lock()`, cleared in `unlock()`). While it is set, secret
    results are not shown: `text_view(..., secret=True)` and the Decrypt page's text results are dropped, with a
    toast after unlock saying the message was opened while locked and needs opening again. Files already written to
    disk are fine to list. As a backstop, have `Sheet.open()` re-raise the overlay when locked.
  - **Test:** lock the window, then deliver a text result to the Decrypt and Share pages' done handlers. No sheet is
    visible above the overlay and the result list holds no decrypted text.

## 2.2 Shredding

- [ ] **[Easy]** **N2: Encrypt-and-shred on a symlink leaves the original in place**
  - **Problem:** the file list keeps paths as given (`abspath`, not resolved). For a symlink to a file,
    `encrypt_paths` encrypts the target's contents, but `tools.shred` only unlinks the link: the plaintext target
    survives while the app reports it shredded. For a symlink to a folder, `tarfile.add` stores only the link, so
    the `.locked` file holds no data. It passes verification, decrypts to nothing (the absolute link is skipped),
    and the link is "shredded" while the folder stays in plaintext. Both confirmed. Tools → Shred has the same gap
    for dropped links. A user who deletes the folder afterwards, believing it is encrypted, loses it.
  - **Where:** `locksmith/core/engine.py:957-1013`, `locksmith/core/tools.py:286-301`,
    `locksmith/ui/widgets.py:909`, `locksmith/ui/pages/tools.py:239-253`
  - **Fix:** in `encrypt_paths`, refuse a top-level input that is a symlink: "<name> is a link. Add the file or
    folder it points to instead." In the Tools shredder, refuse links the same way, rather than reporting a link
    removal as a shred. Links *inside* a folder are fine: they are stored as links, and unlinking them is correct.
  - **Test:** `encrypt_paths([link_to_file])` and `encrypt_paths([link_to_folder])` raise `LocksmithError` and
    write nothing. A UI flow with shred on and a symlinked input is refused, and the target is untouched.

## 2.3 Decrypt and extraction safety

- [ ] **[Easy]** **N5: Decrypting a crafted file can fill the disk**
  - **Problem:** the earlier 4.4 fix capped only in-memory output. `decrypt_path` still writes everything a file
    expands to, so a few MB at ~22,000:1 becomes tens of GiB in the output folder (twice that for a folder: the
    `.part` archive plus the extracted copy). The `.part` file is deleted on ENOSPC, but until then the disk is
    full and other programs' writes fail, which can corrupt their data. (Sparse archive members are already
    refused by the N1 fix.)
  - **Where:** `locksmith/core/engine.py:770-840`, `engine.py:1129-1192`, `engine.py:1259-1310`
  - **Fix:** in `decrypt_path`, check `shutil.disk_usage(out_dir).free` every batch. Stop with a clear
    `LocksmithError` when continuing would leave less than a reserve (for example, the larger of 1 GiB and 2% of
    the disk). A legitimate file that doesn't fit fails the same way, only earlier and without filling the disk.
    Apply the same check while extracting a folder.
  - **Test:** monkeypatch `shutil.disk_usage` to report little free space and assert `decrypt_path` stops with
    `LocksmithError` and leaves no `.part` file.

- [ ] **[Medium]** **N6: One member that can't be created makes the whole folder fail to extract**
  - **Problem:** `extractall` treats an `OSError` on any member as fatal, and `extract_archive` then deletes
    everything already extracted. Confirmed: a folder holding `good.txt` and one file named with 90 CJK characters
    (270 bytes in UTF-8: valid on Windows, over Linux's 255-byte limit) fails with "File name too long", and
    `good.txt` is gone too. A folder made on Windows can therefore never be opened on Linux, and a sender can make
    any folder unopenable. The `.locked` file is kept, so nothing is lost, but this contradicts the function's
    promise that one odd entry can't make a folder unrecoverable.
  - **Where:** `locksmith/core/engine.py:1259-1310` (`extract_archive`, `keep_safe`)
  - **Fix:** in `keep_safe`, skip and report any member with a path component over 255 bytes (`os.fsencode`), or
    over 255 UTF-16 units on Windows. Also extract members one at a time
    (`tar.extract(member, dest, filter=keep_safe)`) and turn an `OSError` on a single member into a `skipped`
    entry. Keep aborting on `TarError` (a damaged archive). `complete` stays false whenever anything is skipped, so
    delete-after still keeps the source.
  - **Test:** extract the two-member archive above. `good.txt` exists, the long name is in `skipped`, and
    `decrypt_path` reports `complete=False`.

- [ ] **[Medium]** **N8: Case collisions still overwrite on case-insensitive drives under Linux (UNSURE)**
  - **Problem:** the earlier 5.2 fix compares names without case only when `IS_WINDOWS`. On Linux, FAT32 and exFAT
    USB drives (and casefolded ext4 folders) are case-insensitive too. Decrypting a folder holding `Notes.txt` and
    `notes.txt` onto one should let the second overwrite the first, report `complete=True`, and let delete-after
    remove the only copy. Reasoned from the code, not reproduced: confirming it needs a FAT or exFAT mount.
  - **Where:** `locksmith/core/engine.py:1221-1227`
  - **Fix:** decide case-sensitivity from the destination, not the platform. Probe once per extraction: create a
    file in `dest` and check whether its case-swapped name exists. Casefold the key when it does.
  - **Test:** monkeypatch the probe to report a case-insensitive destination on Linux. The second name is skipped
    and `complete` is false. Then reproduce on a real exFAT image (loop mount) and record the result in this entry.

## 2.4 Metadata privacy

- [ ] **[Medium]** **N4: JPEG metadata stripping keeps any APP0 and APP14 segment verbatim**
  - **Problem:** APP0 (`0xE0`) and Adobe APP14 (`0xEE`) are kept by marker alone, whatever they contain. Confirmed
    kept: a JFIF thumbnail, a JFXX thumbnail (a full embedded JPEG, which after a crop can still show the
    uncropped original), an unknown APP0 carrying `serial=… owner=…`, and extra bytes after the Adobe fields. This
    breaks the module's rule that unknown data is dropped, not kept. Smaller gaps of the same kind: PNG `sPLT`
    carries a free-text palette name, and WebP `ANMF` frames may hold unknown sub-chunks.
  - **Where:** `locksmith/core/metadata.py:158-160`, `metadata.py:216`, `metadata.py:238`
  - **Fix:** keep APP0 only when it starts with `JFIF\x00`, and rewrite it as the 16-byte form with a 0×0
    thumbnail (copy the version, units and density; set Xthumbnail = Ythumbnail = 0). Drop JFXX and every other
    APP0. Keep APP14 only when it starts with `Adobe`, rewritten to its fixed 12-byte payload. Drop `sPLT` from
    `PNG_KEEP`.
  - **Test:** strip a JPEG containing a JFIF thumbnail, a JFXX segment, an unknown APP0 and an oversized APP14.
    None of their payload bytes remain, and the JFIF and Adobe fields a decoder needs are intact.

## Done when

- Every box above is ticked, apart from items marked Deferred.
- Each security fix has a regression test in `tests/` that failed before the fix and passes now.
- `.venv/bin/pytest` and `.venv/bin/ruff check` pass on Linux, and the suite passes under Windows Python (see
  .md).
- The security verification checklist has been re-run against the fixed code with no FAIL results.