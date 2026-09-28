# Locksmith To-Do List

## 1. Signatures and sender authentication
- [ ] **[Easy]** Show the signer's identity and verification status on Decrypt results (after signing exists)
- [ ] **[Medium]** Add hybrid signing keys (Ed25519 + ML-DSA) to identities
- [ ] **[Medium]** **Sign** and **Verify** for files, including detached signatures
- [ ] **[Hard]** Optional authenticated public-key encryption, so the recipient sees "from Alice ✓" (format v2)

## 2. Edit access on existing `.locked` files
- [ ] **[Hard]** Add or remove recipients without re-encrypting the data (format v2)
- [ ] **[Hard]** Change the password or keyfile without re-encrypting the data (format v2)
- [ ] **[Hard]** Extend the key commitment to cover the fixed header fields, so tampering fails at unlock (format v2)

## 3. Better identity backup
- [ ] **[Easy]** Shamir-split identity backups
- [ ] **[Easy]** Restore an identity by combining Shamir shares or typing the backup words
- [ ] **[Medium]** Printable paper backup (QR + words)
- [ ] **[Hard]** Restore an identity by scanning the paper backup's QR code

## 4. Interop
- [ ] **[Easy]** Minisign signature verification, alongside the Checksums tool
- [ ] **[Medium]** Accept SSH Ed25519 public keys as recipients
- [ ] **[Hard]** Accept SSH RSA public keys as recipients
- [ ] **[Hard]** Read and write age-compatible files

## 5. Smaller features
- [ ] **[Easy]** Checksum extras: compare two files, and generate or verify manifests for folders
- [ ] **[Easy]** (Optional) Pad with dummy recipient slots to hide the recipient count
- [ ] **[Medium]** File manager integration: a right-click "Encrypt with Locksmith" and a `.locked` file association
- [ ] **[Hard]** Recovery data (parity records) for long-term archives

## 6. Trust and hardening
- [ ] **[Easy]** Publish a file-format specification
- [ ] **[Easy]** Publish a threat model
- [ ] **[Easy]** Publish test vectors
- [ ] **[Easy]** Fuzz the file and header parsers
- [ ] **[Easy]** Cap total key-derivation work per file (other header bounds are already enforced)
- [ ] **[Easy]** (Optional, low priority) Unify "wrong password" and "key commitment failed" errors
- [ ] **[Medium]** Reproducible builds
- [ ] Independent audit (long term)
