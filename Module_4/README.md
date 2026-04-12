# Module 4 — Integrity + Symmetric Encryption

This module contains a small Python script that:

- Accepts user input (a message or a file)
- Hashes the input with SHA-256
- Encrypts the input using symmetric encryption (AES-GCM)
- Decrypts the content and verifies integrity by comparing hashes

## How to run

From the workspace root:

```powershell
pip install -r .\Module_4\requirements.txt
```

### Option A: Interactive demo (encrypt → decrypt → verify)

```powershell
python .\Module_4\secure_vault.py demo
```

### Option B: Encrypt to a portable bundle, then decrypt later

Encrypt a message to a JSON bundle:

```powershell
python .\Module_4\secure_vault.py encrypt --message "hello" --out-file .\Module_4\bundle.json
```

Decrypt + verify integrity:

```powershell
python .\Module_4\secure_vault.py decrypt .\Module_4\bundle.json
```

Encrypt a file:

```powershell
python .\Module_4\secure_vault.py encrypt --in-file .\Module_4\somefile.txt --out-file .\Module_4\somefile.bundle.json
```

Decrypt a file bundle back to bytes:

```powershell
python .\Module_4\secure_vault.py decrypt .\Module_4\somefile.bundle.json --out-file .\Module_4\somefile.decrypted
```

## Short explanation (CIA + entropy)

### Confidentiality

- The script uses **AES-GCM** (a symmetric encryption mode) to encrypt the plaintext.
- Without the correct key (derived from the password), the ciphertext cannot be feasibly recovered.
- A fresh random **nonce** is generated for each encryption. Reusing a nonce with AES-GCM is dangerous, so randomness here supports confidentiality and safety.

### Integrity

This solution provides integrity in two ways:

1. **AES-GCM authentication tag**: AES-GCM is an “AEAD” mode (Authenticated Encryption with Associated Data). If ciphertext is modified, decryption fails.
2. **SHA-256 hash comparison** (assignment requirement): the script stores `SHA-256(plaintext)` at encryption time and recomputes SHA-256 after decryption. If the hashes differ, the decrypted data has changed or is not the original.

### Availability

- The script is a small offline tool with minimal dependencies and clear error messages.
- It supports both messages and files, and stores encrypted output in a portable JSON bundle, making it practical to run repeatedly and recover data when needed.

## Entropy and key generation

- **Entropy** is “unpredictability.” Cryptographic security depends on secrets being hard to guess.
- The script derives a 256-bit AES key from a user password using **PBKDF2-HMAC-SHA256** with:
  - A **random salt** (16 bytes) so the same password yields different keys per bundle and to defeat precomputed/rainbow-table attacks.
  - A high **iteration count** (200,000) to slow down brute-force guessing.
- The salt and nonce are stored in the bundle (they are not secrets). Security still depends on the password being strong.

If you want maximum security, use a long passphrase (high-entropy) rather than a short/guessable password.
