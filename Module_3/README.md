# Module 3 — Hashing, Substitution Cipher, and Digital Signatures (Python)

This folder contains three small CLI apps written in Python:

1) **SHA-256 hashing** for input strings or files
2) **Caesar (substitution) cipher** encryption/decryption for text
3) **Digital signature simulation** using **OpenSSL** (sign/verify a file)

## 1) SHA-256 hash generator

File: `sha256_hasher.py`

Hash a string:

```bash
python sha256_hasher.py --text "hello"
```

Hash a file:

```bash
python sha256_hasher.py --file .\users.json
```

If you run it with no args, it prompts for text.

## 2) Caesar cipher (encrypt/decrypt)

File: `caesar_cipher.py`

Encrypt text (default shift is 3):

```bash
python caesar_cipher.py encrypt --text "Attack at dawn" --shift 3
```

Decrypt text:

```bash
python caesar_cipher.py decrypt --text "Dwwdfn dw gdzq" --shift 3
```

You can also read from a file and write output to a file:

```bash
python caesar_cipher.py encrypt --in-file .\plain.txt --out-file .\cipher.txt --shift 5
```

## 3) Digital signature (OpenSSL sign/verify)

File: `openssl_signature_demo.py`

This uses the external `openssl` command to:

- generate an RSA keypair
- sign a file (SHA-256 digest)
- verify the signature

Generate keys:

```bash
python openssl_signature_demo.py gen-keys
```

Sign a file:

```bash
python openssl_signature_demo.py sign --in .\users.json
```

Verify the signature:

```bash
python openssl_signature_demo.py verify --in .\users.json
```
