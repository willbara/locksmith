# Security model

This document tells how Locksmith protects a file, what it does not protect, and which limits you
must know. [FORMAT.md](FORMAT.md) gives the full specification.

## How a file is protected

```
"LOCKED\x00\x02" | key commitment | u32 len | fixed header JSON | u32 len | key slots JSON | { u32 len | AEAD frame }*
```

This is format version 2. Locksmith still reads version 1 files (Locksmith 2.x). Locksmith 2.0 replaced
the format of Cryptor 1.x, the former name of the app. Locksmith does not read Cryptor files or keys.

- **Key slots:** a random 256-bit data key (DEK) encrypts the file. Each slot wraps the DEK with
  AES-256-GCM.
  - A password slot uses the KDF output. When a keyfile is set, HKDF mixes in SHA-512 of the keyfile.
  - A classical recipient slot uses an ephemeral X25519 exchange and HKDF.
  - A hybrid slot also encapsulates to the ML-KEM-768 key of the recipient. Its key comes from the two
    shared secrets and the transcript. Thus an attacker must break both X25519 and ML-KEM-768.
- **Key commitment:** HKDF-SHA512 derives the layer keys, the metadata key and a key commitment from
  the DEK. The commitment also covers the fixed header (cipher, chunk size, nonce prefix, salt and
  metadata). If a person changes one of these, the file does not open. A slot opens only when its key
  agrees with the commitment. If it does not agree, Locksmith reports a wrong key.
- **Frames:** frame `i` uses the nonce `prefix(7) ‖ i(u32) ‖ final(u8)`. Its associated data is the
  SHA-256 of the fixed header. Thus authentication fails if a person reorders, truncates, appends or
  changes frames, or changes the header. The key slots are bound only to the DEK. Thus they can change
  without encryption of the data again.
- **Metadata:** the file name, size, type, compression method and note are in an encrypted metadata
  blob. Locksmith pads this blob, so its length shows little about the name and the note.
- **Signatures:** you can sign a file (Encrypt → Sign as). The Ed25519 + ML-DSA-65 signature is inside
  the encryption, after the content. It covers the fixed header and the content, but not the key slots.
  If the signature of a file is not valid, Locksmith refuses the file and writes none of it.
- **Output:** Locksmith writes the output to a temporary file. It moves the file to its location only
  after all the frames are authenticated.

## What a file shows without a key

Some data about a file is not encrypted. Without a key, anyone can see:

- the cipher suite and the chunk size,
- the number and the types of key slots,
- the key-derivation settings, and if a keyfile is necessary,
- if the file is signed (but not who signed it),
- a range for the length of the metadata,
- the size after padding.

[FORMAT.md](FORMAT.md) section 19 gives the full list.

## Runtime protection

The process applies these settings to itself when it starts. Settings → About shows which ones this
system accepted. They make it harder for other programs to get to Locksmith's data. They do not give
protection against root, the kernel, or malware that already controls your account.

- **Memory:** Locksmith turns off core dumps and makes the process non-dumpable. Thus a crash does not
  write keys to the disk. Other programs that run as you cannot read the memory of the process. Python
  cannot reliably erase secrets from memory after use. Thus this protection keeps that memory inside
  the process. It does not erase it.
- **No network:** a seccomp filter on each thread refuses to make internet sockets and other non-local
  sockets. systemd starts the programs that Locksmith opens (the file manager and the mail program)
  outside this filter. The filter prevents accidental network access by Locksmith. It is not a sandbox
  against a compromised Locksmith. Local (Unix) sockets stay open, so code inside Locksmith can tell
  systemd to start a program that has network access.
- **Auto-lock and panic:** Locksmith removes secrets from the window and covers the window after a
  period of inactivity (10 minutes by default), or when you push Ctrl+L. Ctrl+Shift+L also minimizes
  the window. If a task finishes while the window is locked, Locksmith does not show its secret result.
  After you unlock, Locksmith tells you to open it again. The lock is a privacy screen, not a password
  lock. A click or a key brings the window back, and identities without a passphrase stay usable. If
  other persons can use your computer, give your identities a passphrase.
- **Clipboard:** Locksmith marks copied passwords and decrypted text, so that clipboard managers do not
  keep them. It clears them after 30 seconds, when the window locks and when Locksmith closes.

The desktop portal refuses requests from a non-dumpable process. Thus Locksmith uses its own file
dialogs. It reads the dark or light setting of the system through a short-lived helper process.
Settings → About shows the status.

## Your data

Settings and keys are in `~/.config/locksmith/`. The mode of `keys.json` is 0600. You can protect an
identity with a passphrase (Argon2id + AES-GCM).

Only one copy of Locksmith runs at a time. When you start it again, for example from the file manager,
the new copy gives its files to the open window and stops. This prevents two copies from writing
`keys.json` at the same time. The file `instance` holds a random token. The two copies use it to
identify each other, so another user cannot receive the names of your files. On Linux, the two copies
connect through a socket file in a folder that only you can open (the runtime folder of your session,
or the config folder). Thus another user cannot connect to it or prevent the start of Locksmith.

## Limits

- **Lost keys:** if you lose the password, the keyfile or the private key, you lose the data.
  Recovery is not possible.
- **Access changes:** a new password or new recipients do not remove access. A person who opened the
  file before can keep its file key. To remove access, decrypt the file and encrypt it again.
- **Unencrypted data:** some data about a file is not encrypted (see above).
- **Unprotected private keys:** backup words, identity shares, paper backups, the QR code of a paper
  backup, and the backup file of an identity without a passphrase all contain the private key with no
  protection. If a person has one of them, or a photo of it, that person can use the identity. Keep
  them as safe as the identity itself.
- **Unsigned files:** an unsigned file is not authenticated. Decryption shows that nobody changed the
  file after someone made it. It does not show who made it. Anyone with your public key can send you a
  file, and its name and note can claim anything.
- **Signed files:** a signature shows who made the file (Encrypt → Sign as, or a detached `.lsig` from
  Tools). A valid signature means "signed with the key that you saved as X". This is only as good as
  your fingerprint check. A contact is checked only after you enter the fingerprint that the person gave
  you through a different channel (Keys → the fingerprint button). A signature shows who signed the
  content, not to whom it was sent. Anyone who can open a signed file can send it to a different person,
  and the signature stays valid. A signed file with a recipient list tells a reader who is not on the
  list about this. A signed file with no list tells the reader that it does not say for whom it is.
- **Recipient list:** when a signed file has a recipient list, each recipient can find out if a person
  whose public key they have was a recipient. The list is off by default.
- **Shredding:** shredding is not reliable on SSDs and on copy-on-write file systems such as btrfs.
  These can keep old copies.
- **Recovery data:** recovery data (`.lpar`) is made from the contents of the file. Locksmith can
  rebuild a small file from it alone. For an unencrypted file, keep the recovery data as safe as the
  file, or encrypt the file first. When you shred a file, Locksmith also shreds its `.lpar`. When you
  change who can open a file, Locksmith makes its `.lpar` again, so that a repair cannot bring back the
  old key slots.
- **TPM sealing:** TPM sealing prevents use of an identity from a copied disk or backup. On the same
  computer, any program that runs as you can tell the TPM to unseal it. Give the identity a passphrase
  to prevent this.
- **X11:** on X11, all programs on the display can read what you type, also passwords. Wayland does
  not allow this. Settings → About shows which one is in use.
- **Classical keys:** SSH keys and classical age keys are not post-quantum. Locksmith 3.0 and earlier
  cannot open a file that has an SSH RSA recipient.
- **Older versions:** Locksmith 4 and earlier cannot combine the Shamir shares of Locksmith 5, because
  these hide the length of the secret. On Windows, Locksmith 5 moves keys and settings from `%APPDATA%`
  to `%LOCALAPPDATA%` when it starts for the first time. After this, Locksmith 4 cannot find them.
  Files and public keys do not change.
- **Mark of the Web (Windows):** a decrypted file gets the Mark of the Web of the encrypted file. If the
  encrypted file has no mark, Locksmith marks programs, scripts and macro documents inside it as
  downloaded from the internet. It does not do this if you, or a contact whose fingerprint you checked,
  signed the file.
