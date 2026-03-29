# Module 2 — Symmetric vs Asymmetric Encryption (Demo)

This module contains:

- `rbac_login_encrypt_app.py`: a **login + role-based access control (RBAC)** demo that restricts encryption actions by role and demonstrates:
    - **Symmetric encryption**: `Fernet` (from the `cryptography` package)
    - **Asymmetric encryption**: **RSA** public-key encryption with **OAEP** padding (SHA-256)

When you run it, it:

1. Ensures a small demo user database exists (`users.json`)
2. Prompts for **username/password** (authentication)
3. Asks whether you want to **Read** or **Write**:
  - **Read**: prints only the last saved **message** and **decrypted result** (no keys)
  - **Write**: encrypts/decrypts a new message and saves the full details to a file
4. For **Write**, shows encryption methods based on **role** (RBAC):
  - `user`: can use **symmetric encryption only**
  - `admin`: can use **symmetric** or **asymmetric (RSA)**
5. Generates the keys needed for the selected method (Fernet key, or RSA key pair)
6. Encrypts and then decrypts the message to prove it round-trips
7. Writes `rbac_encryption_output.txt` with **keys used**, **inputs**, and **outputs** (this is the file to screenshot/submit)

## Requirements

Install the dependency:

```bash
pip install cryptography
```

On first run, it creates a small `users.json` in the same folder with demo credentials:

- `admin / admin123!` (can run symmetric + asymmetric and view RSA key material)
- `user / user123!` (can run symmetric only; the RSA option is not shown)

It writes a submission-friendly text file here:

- `Module_2/rbac_encryption_output.txt`

## Reading the output file (admin vs user)

Run the app and choose **Read**.

- The app prints only the **message** and **decrypted output** (no keys shown on screen).
- RBAC still applies when reading:
  - If the last saved output was **symmetric**, both roles can read it.
  - If the last saved output was **asymmetric (RSA)**, only `admin` can read it (users are denied).
- To capture **keys used / inputs / outputs** for the assignment, open and screenshot `rbac_encryption_output.txt`.

Optional non-interactive view (skips prompts):

```bash
python rbac_login_encrypt_app.py --username user --password "user123!" --view-output
python rbac_login_encrypt_app.py --username admin --password "admin123!" --view-output
```

## Strengths vs weaknesses (high level)

- **Symmetric encryption (one shared secret key)**
  - Strengths: fast; efficient for large data; simple for bulk encryption
  - Weaknesses: key distribution problem (both sides must securely share the same secret key)

- **Asymmetric encryption (public/private keys)**
  - Strengths: solves key distribution for confidentiality (share public key freely); enables identity features like signatures
  - Weaknesses: slower than symmetric; encryption payload size is limited; typically used to exchange a symmetric key rather than encrypt large data directly
