# Features

## Encryption

- **Ciphers:** AES-256-GCM, ChaCha20-Poly1305, AES-256-GCM-SIV, AES-256-OCB3 and AES-256-SIV. Two
  cascades are also available: AES + ChaCha20, and AES + ChaCha20 + OCB3. Each layer of a cascade has
  its own key.
- **Key derivation:** Argon2id, scrypt or PBKDF2-SHA512, with four strength presets (Fast to
  Paranoid).
- **Access:** a password, a keyfile (a second factor), public keys for one or more recipients, or a
  combination. Each of these wraps the same random file key. Thus you can change the password, the
  keyfile and the recipients later without encrypting the data again (Decrypt → Change who can open
  it). This change does not remove access from a person who could open the file before. To remove
  access, encrypt the file again.
- **Streaming:** Locksmith encrypts in chunks and compresses the chunks in parallel, with Zstandard,
  zlib, LZMA, bzip2 or an automatic choice.
- **Content:** files, folders, bundles of more than one item, and text messages. Each file can have an
  encrypted note. ASCII armor and a verify-only mode are also available.
- **Shredding:** Locksmith can shred the originals after encryption.

## Privacy

- **Defaults:** Padmé size padding, decoy recipient slots and padded metadata are on by default.
- **Size padding:** Padmé, a block size, or the next power of two. Padding hides the size fully only
  when compression is off ([SECURITY_MODEL.md](SECURITY_MODEL.md)).
- **Decoy slots:** decoy recipient slots hide the approximate number of recipients
  ([FORMAT.md](FORMAT.md) section 3).
- **Hidden file names:** the encrypted file gets a random name. The real name stays in the encrypted
  metadata.
- **Photo metadata:** Locksmith can remove location, camera data and dates from JPEG, PNG and WebP
  files without loss of image quality. It can also remove the file times. It also removes data that is
  after the image, for example the video of a motion photo or an HDR layer. Locksmith tells you when it
  removes such data, and it does not shred that original.
- **Folders:** folder archives never record user names or group names.
- **Text messages:** Locksmith pads text messages and does not compress them.

## Keys

- **Identities and contacts:** identities are your key pairs. Contacts are the public keys of other
  people.
- **Post-quantum:** new identities are hybrid post-quantum keys (X25519 + ML-KEM-768). They can sign
  files (Ed25519 + ML-DSA-65). You can upgrade an older classical identity.
- **Protection:** you can protect an identity with a passphrase, or seal it to the TPM of the
  computer.
- **Backups:** you can export an identity as a backup file, as backup words, as Shamir shares, or as a
  printable paper backup. A paper backup has a QR code and the backup words. To restore it, take a photo
  of the page or scan it.
- **Sharing:** you can share a public key as text or as a QR code.
- **Recipients:** a file does not name its recipients. A signed file can include a list of its
  recipients inside the encryption ("Address it to the selected people" on the Encrypt page). This list
  is off by default. When it is on, each recipient can see if they were addressed. Each recipient can
  also find out if a person whose public key they have was a recipient.

## SSH and age

- **SSH keys:** SSH Ed25519 and RSA public keys can be recipients. The SSH private key opens the file,
  also when the key has a passphrase.
- **age keys:** you can add age keys (`age1…`, `age1pq1…`, `AGE-SECRET-KEY-…`) as contacts or restore
  them as identities.
- **age files:** Locksmith encrypts and decrypts `.age` files (age-encryption.org/v1), with the
  post-quantum recipients of age. Thus you can exchange files with age and rage. The test kit of the age
  authors checks this. age files have no size padding and no decoy recipients. Turn these off before you
  make an age file.

## Share

- Copy a file to the clipboard, send it by email, or copy it as text that you can paste.
- Split a file into parts of a maximum size, and join the parts again.
- Send encrypted text messages.
- Show a password as a QR code.
- Split a password among people with Shamir secret sharing.
- Publish your public key.

## Tools

- A password and passphrase generator, and a strength test.
- Checksums, file comparison, and folder manifests (compatible with `sha256sum --tag`).
- Detached signatures (`.lsig`): sign and verify.
- Verification of minisign, SSH (`ssh-keygen -Y sign`) and OpenPGP signatures. OpenPGP verification
  uses GnuPG `.sig` or `.asc` files and one public key, with no keyring.
- Recovery data (`.lpar`) that repairs files that failing storage has damaged.
- A keyfile generator and a shredder.

## Desktop

- **Integration:** Settings → Desktop integration opens `.locked` files with Locksmith. It also adds
  "Encrypt with Locksmith" to the right-click menu of GNOME Files, Dolphin, Nemo and Windows Explorer.
- **Interface:** dark, light or system theme, in monochrome.
