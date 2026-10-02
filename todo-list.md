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
- [ ] **[Medium]** Printable paper backup (QR + words)
- [ ] **[Hard]** Restore an identity by scanning the paper backup's QR code

## 4. Interop
- [ ] **[Medium]** Accept SSH Ed25519 public keys as recipients
- [ ] **[Hard]** Accept SSH RSA public keys as recipients
- [ ] **[Hard]** Read and write age-compatible files

## 5. Smaller features
- [ ] **[Medium]** File manager integration: a right-click "Encrypt with Locksmith" and a `.locked` file association
- [ ] **[Hard]** Recovery data (parity records) for long-term archives

## 6. Trust and hardening
- [ ] **[Medium]** Reproducible builds
- [ ] Independent audit (long term)
