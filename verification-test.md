# Locksmith Security Fix List

- **Date:** 2026-09-28
- **Commit:** `a08aa3a` (main)
- **Python:** 3.14.7
- **Scope:** `locksmith/core` and the UI flows that drive it (encrypt, decrypt, share, keys, tools).

Each task below is a FAIL or UNSURE item from a security verification review. IDs match the review
checklist so each fix can be traced back to its finding.

## 1. Secret exposure and data loss

- [x] **[High] 7.3: A failed TPM re-seal during upgrade can leave the private key unsealed**
  - **Problem:** `upgrade()` changes the stored identity in memory (new public key, sealed field cleared,
    private key set) before `_seal()` runs. If the TPM refuses, the change isn't rolled back. The next save
    of anything, such as adding a contact, writes the private key to `keys.json` unsealed.
  - **Where:** [keys.py:366-373](locksmith/core/keys.py#L366-L373)
  - **Fix:** build the upgraded identity on a copy (`dataclasses.replace(ident)`). Run `_store_private` and,
    if the original was sealed, `_seal` on the copy. Copy the fields back onto `ident` only after every step
    has succeeded. A failure then leaves the stored identity exactly as it was.
  - **Test:** monkeypatch `keys.tpm_seal` to raise during `upgrade` of a sealed identity. Assert the upgrade
    raises and the identity's `public`, `sealed` and `private` fields are unchanged. Then call
    `store.add_contact(...)`, reload `KeyStore` from disk, and assert the identity still has `sealed` set
    and `private is None`.

- [ ] **[High] 6.2: Delete-after-decrypt removes the only copy when extraction was incomplete**
  - **Problem:** the encrypted file is deleted even when extraction skipped members. The extracted folder
    contents are also never fsynced before the delete. Trigger: encrypt a folder containing
    `link -> /etc/hosts` on Linux, or a file named `notes: v2.txt` that Windows can't create, and decrypt it
    with "Delete encrypted file afterwards" on. The skipped entry is lost for good. A power cut soon after
    decrypting a folder can also lose data that was never written to disk.
  - **Where:** [decrypt.py:227-228](locksmith/ui/pages/decrypt.py#L227-L228),
    [engine.py:1100-1110](locksmith/core/engine.py#L1100-L1110)
  - **Fix:** make the core decide whether the output is complete, instead of leaving it to the page.
    - Have `extract_archive` fsync every extracted file and folder.
    - Have `decrypt_path` report a `complete` flag on `DecryptResult`. It is true only when nothing was
      skipped or renamed and everything was flushed, including the folder entry.
    - In the decrypt page, delete the source only when `complete` is true. Otherwise keep it and tell the
      user why.
  - **Test:** in `tests/test_ui_flows.py`, encrypt a folder containing an absolute symlink, then decrypt it
    with delete-after on. Assert the `.locked` file still exists and the result lists the skipped member.
    Add a core test asserting `complete` is false whenever `skipped` is non-empty.
  - **Depends on:** 5.2 (name collisions must appear in `skipped`, so they also block the delete) and 6.3
    (`fsync_dir` must be called after the final rename).

- [ ] **[High] 6.1: "Shred originals" can destroy the keyfile**
  - **Problem:** nothing checks whether the keyfile is one of the files being shredded. Verification uses
    the in-memory data key, so it passes anyway. Trigger: encrypt `~/vault/` with keyfile
    `~/vault/key.bin` and shred on. The keyfile is shredded with the originals, and the new file can never
    be opened.
  - **Where:** [encrypt.py:261-292](locksmith/ui/pages/encrypt.py#L261-L292)
  - **Fix:** add a core helper that reports whether a path is one of, or inside, a set of input paths.
    Compare resolved paths and also `(st_dev, st_ino)`, so symlinks and hard links are caught. When shred is
    on and the keyfile is covered by an input, refuse to start with a clear message. Run the check before
    any work begins, next to the existing recipients-only check.
  - **Test:** a unit test for the helper covering the same file, a file inside an input folder, a symlink
    and a hard link. A UI flow asserting that encrypt-and-shred with the keyfile inside the input folder is
    refused and that both the keyfile and the originals are untouched.

## 2. Crashes and denial of service

- [ ] **[High] 4.4: In-memory decompression bomb**
  - **Problem:** decompressed output is capped per chunk, but there is no total cap. `decrypt_bytes` builds
    the whole plaintext in memory. Confirmed: 12 KB of armored text expanded to 256 MiB, about 22,000:1.
    Anyone with your public key can send a message that is opened through Share → Open message or
    Decrypt → Paste text. About 1 MB of text expands to over 20 GiB and kills the app.
  - **Where:** [compress.py:33-45](locksmith/core/compress.py#L33-L45),
    [engine.py:1128-1136](locksmith/core/engine.py#L1128-L1136),
    [share.py:265](locksmith/ui/pages/share.py#L265)
  - **Fix:** add a `max_output` limit to `_decrypt_stream` that raises CorruptedError as soon as the running
    total goes over it. `decrypt_bytes` passes `MAX_ARMOR_INPUT`, the limit already used for armored
    output. Make `encrypt_bytes` refuse input above the same limit, so every message the app writes can still
    be read. Don't use the metadata `size` as the cap: a file that grew while it was being encrypted records
    a smaller size than its real content, so existing files would stop opening.
  - **Test:** `encrypt_bytes(bytes(256 << 20), ...)` with `chunk_size=64 << 20` and `compression="zstd"`,
    then assert `decrypt_bytes` raises CorruptedError before building the full output. Also assert that a
    message just under the limit still round-trips.

- [x] **[Low] 4.2: Deeply nested header JSON escapes as `RecursionError`**
  - **Problem:** a header made of 200,000 `[` characters raises `RecursionError` (confirmed). It isn't turned
    into a LocksmithError, so it escapes `_files_changed` on the UI thread, which catches only LocksmithError
    and OSError.
  - **Where:** [engine.py:444-450](locksmith/core/engine.py#L444-L450),
    [decrypt.py:138-140](locksmith/ui/pages/decrypt.py#L138-L140)
  - **Fix:** in `_read_header`, add `RecursionError` to the exceptions that become CorruptedError. Do the
    same in `_read_meta`, which parses JSON chosen by the file's creator. With the cause handled in the core,
    no UI change is needed.
  - **Test:** `inspect_bytes` on a deeply nested header raises CorruptedError. A forged file whose encrypted
    metadata is deeply nested also raises CorruptedError when decrypted.

- [x] **[Medium] 4.6: Encrypting can produce a file that no one can open**
  - **Problem:** the reader caps slots at 64 and the header at 1 MiB, but the writer checks neither.
    Confirmed: 64 recipients plus a password writes a file that fails with "The file header is damaged."
    Shred is protected, because verification catches it. Without shred, the user gets an unopenable file
    and no warning.
  - **Where:** [engine.py:297](locksmith/core/engine.py#L297), [engine.py:479](locksmith/core/engine.py#L479)
  - **Fix:** make the writer enforce the reader's limits.
    - In `validate_options`, drop duplicate recipients and reject more than `MAX_SLOTS` slots in total,
      counting the password slot.
    - At the end of `_build_header`, run the new header through `_check_header` and the `MAX_HEADER` size
      check before returning. Any future mismatch between writer and reader then fails before anything is
      written.
  - **Test:** 64 recipients plus a password raises LocksmithError before any output file exists, and 63
    recipients plus a password round-trips. A note large enough to push the header over `MAX_HEADER` is
    refused up front.

## 3. Everything else

- [ ] **[Medium] 7.4: Shamir combine accepts shares from different secrets**
  - **Problem:** combining share 1 of secret A with share 2 of secret B, where both secrets have the same
    length and threshold, returns garbage without an error (confirmed). The existing test only covers
    secrets of different lengths. Shares carry nothing that ties them to one split, and the recovered
    secret isn't checked.
  - **Where:** [tools.py:222-233](locksmith/core/tools.py#L222-L233)
  - **Fix:** add a new share format that carries a random split ID in every share, and split the secret
    together with a short hash of it.
    - When combining, reject shares with different IDs, and check the recovered secret against its hash.
    - When more than `threshold` shares are given, also check that the extra shares agree.
    - Keep reading the current format, so existing shares still combine.
  - **Test:** `shamir_combine([a[0], b[1]])` for two same-length secrets raises LocksmithError. A share
    whose data was changed but whose checksum was recomputed is rejected. Old-format shares still combine
    to the right secret.

- [x] **[Medium] 5.2: Names that differ only in case overwrite each other on Windows**
  - **Problem:** escaping the output folder is blocked, but colliding names silently overwrite each other.
    Trigger: a folder made on Linux containing `Notes.txt` and `notes.txt`, decrypted on Windows. One file
    replaces the other.
  - **Where:** [engine.py:1154-1179](locksmith/core/engine.py#L1154-L1179)
  - **Fix:** in `extract_archive`'s filter, keep a record of every path already extracted. Normalise the key
    with `casefold()` on Windows and exactly on other systems. Skip any later member whose path collides
    with an earlier one, and add it to `skipped`, so the first file is never overwritten and the collision
    is reported.
  - **Test:** build a tar containing both names and call `extract_archive` under the Windows test suite.
    Assert the first file's content is intact and the second name is in `skipped`. On Linux, assert that a
    tar with an exact duplicate name reports the duplicate.

- [x] **[Low] 3.4: Padding is authenticated but not validated**
  - **Problem:** bytes after a frame's declared length are ignored without checking they are zero. A
    `KIND_PAD` frame with `n > 0` is output as data, and pad frames are accepted anywhere in the stream.
    Only the file's creator can make such a file, since the frames are authenticated.
  - **Where:** [engine.py:757-768](locksmith/core/engine.py#L757-L768)
  - **Fix:** in `open_frame`, reject any frame whose bytes after the block aren't all zero, and any
    `KIND_PAD` frame with `n != 0`. In the loop that writes frames, reject a data frame that follows a pad
    frame. This only tightens the reader: every file this version writes already follows these rules, so
    no format version bump is needed.
  - **Test:** forge files with a `KIND_PAD` frame carrying data, a data frame with non-zero trailing bytes,
    and a data frame after a pad frame. Assert each is rejected. Assert that files made with every padding
    mode still decrypt.

- [x] **[Low] 6.3: Renames aren't made durable before shred or delete (UNSURE)**
  - **Problem:** there is no directory fsync after `os.replace` before originals are shredded or the source
    is deleted. `osutil.fsync_dir` exists, but the engine never calls it. This is probably safe on ext4 but
    can't be confirmed for XFS or btrfs. Separately, a failed join leaves a truncated output file with the
    real name.
  - **Where:** [engine.py:991](locksmith/core/engine.py#L991), [engine.py:1113](locksmith/core/engine.py#L1113),
    [tools.py:329-333](locksmith/core/tools.py#L329-L333)
  - **Fix:**
    - Call `fsync_dir` on the output folder after each final `os.replace` in `encrypt_paths` and
      `decrypt_path`, and after moving an extracted folder into place.
    - In `join_parts`, write to a temporary file, fsync it, and rename it to the final name only on success.
      Delete the temporary file on any failure.
  - **Test:** mock `osutil.fsync_dir` and record the order of calls. Assert it runs on the output folder
    before any shred or source delete. Make reading one part fail during `join_parts` and assert no output
    file is left behind.

- [x] **[Low] 5.1: `CONIN$` and `CONOUT$` aren't treated as reserved on Windows**
  - **Problem:** file-name sanitising passed the review, with one gap. The Windows reserved-name pattern
    misses the console device names `CONIN$` and `CONOUT$`.
  - **Where:** [osutil.py:77-92](locksmith/core/osutil.py#L77-L92)
  - **Fix:** add `conin$` and `conout$` to `_WINDOWS_RESERVED`, so `windows_unsafe` and `portable_name` handle
    them like `CON` and `NUL`.
  - **Test:** `windows_unsafe("CONIN$")` and `windows_unsafe("conout$.txt")` are true. On Windows,
    `safe_name("CONIN$")` returns a renamed, safe name.

## Done when

- Every box above is ticked.
- Each task's regression test is in `tests/`, failed before its fix, and passes now. `.venv/bin/pytest` and
  `.venv/bin/ruff check` pass on Linux, and the suite passes under Windows Python (see CLAUDE.md).
- The security verification checklist has been re-run against the fixed code with no FAIL results.
