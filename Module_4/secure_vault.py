from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS: Final[int] = 200_000
SALT_LEN: Final[int] = 16
NONCE_LEN: Final[int] = 12
KEY_LEN: Final[int] = 32


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key_from_password(password: str, salt: bytes) -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


@dataclass(frozen=True)
class Bundle:
    version: int
    kdf: Literal["pbkdf2-hmac-sha256"]
    iterations: int
    salt_b64: str
    nonce_b64: str
    ciphertext_b64: str
    sha256_hex: str

    def to_json(self) -> str:
        return json.dumps(
            {
                "version": self.version,
                "kdf": self.kdf,
                "iterations": self.iterations,
                "salt_b64": self.salt_b64,
                "nonce_b64": self.nonce_b64,
                "ciphertext_b64": self.ciphertext_b64,
                "sha256_hex": self.sha256_hex,
            },
            indent=2,
            sort_keys=True,
        )

    @staticmethod
    def from_json(text: str) -> "Bundle":
        obj = json.loads(text)
        kdf_value = str(obj["kdf"])
        if kdf_value != "pbkdf2-hmac-sha256":
            raise ValueError(f"Unsupported kdf: {kdf_value}")
        return Bundle(
            version=int(obj["version"]),
            kdf=cast(Literal["pbkdf2-hmac-sha256"], kdf_value),
            iterations=int(obj["iterations"]),
            salt_b64=str(obj["salt_b64"]),
            nonce_b64=str(obj["nonce_b64"]),
            ciphertext_b64=str(obj["ciphertext_b64"]),
            sha256_hex=str(obj["sha256_hex"]),
        )


def encrypt_bytes(plaintext: bytes, password: str) -> Bundle:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key_from_password(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return Bundle(
        version=1,
        kdf="pbkdf2-hmac-sha256",
        iterations=PBKDF2_ITERATIONS,
        salt_b64=_b64e(salt),
        nonce_b64=_b64e(nonce),
        ciphertext_b64=_b64e(ciphertext),
        sha256_hex=sha256_hex(plaintext),
    )


def decrypt_bytes(bundle: Bundle, password: str) -> tuple[bytes, bool]:
    if bundle.kdf != "pbkdf2-hmac-sha256":
        raise ValueError(f"Unsupported kdf: {bundle.kdf}")

    salt = _b64d(bundle.salt_b64)
    nonce = _b64d(bundle.nonce_b64)
    ciphertext = _b64d(bundle.ciphertext_b64)

    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    # Assignment requirement: verify integrity via hash comparison.
    ok = sha256_hex(plaintext) == bundle.sha256_hex
    return plaintext, ok 

def _read_input_bytes(message: str | None, in_file: Path | None) -> bytes:
    if (message is None) == (in_file is None):
        raise ValueError("Provide exactly one of --message or --in-file")

    if message is not None:
        return message.encode("utf-8")

    assert in_file is not None
    return in_file.read_bytes()


def cmd_encrypt(args: argparse.Namespace) -> int:
    plaintext = _read_input_bytes(args.message, args.in_file)
    password = args.password or getpass.getpass("Password to derive encryption key: ")

    bundle = encrypt_bytes(plaintext, password)

    if args.out_file:
        args.out_file.write_text(bundle.to_json(), encoding="utf-8")
        print(f"Wrote bundle: {args.out_file}")
    else:
        print(bundle.to_json())

    print(f"Plaintext SHA-256: {bundle.sha256_hex}")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    bundle_text = args.bundle.read_text(encoding="utf-8")
    bundle = Bundle.from_json(bundle_text)

    password = args.password or getpass.getpass("Password to derive decryption key: ")
    plaintext, ok = decrypt_bytes(bundle, password)

    if args.out_file:
        args.out_file.write_bytes(plaintext)
        print(f"Wrote plaintext: {args.out_file}")
    else:
        # Avoid printing arbitrary binary as text.
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print("(Decrypted bytes are not UTF-8; use --out-file to write them.)")

    print(f"Integrity (SHA-256 match): {ok}")
    return 0 if ok else 2


def cmd_demo(_: argparse.Namespace) -> int:
    print("Demo: encrypt -> decrypt -> verify (in-memory)")
    message = input("Enter a message to protect: ").encode("utf-8")
    password = getpass.getpass("Password to derive encryption key: ")

    bundle = encrypt_bytes(message, password)
    decrypted, ok = decrypt_bytes(bundle, password)

    print("---")
    print(f"Ciphertext bundle fields: salt/nonce/ciphertext + sha256")
    print(f"Plaintext SHA-256: {bundle.sha256_hex}")
    print(f"Decrypted text: {decrypted.decode('utf-8', errors='replace')}")
    print(f"Integrity (SHA-256 match): {ok}")
    return 0 if ok else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 4: SHA-256 integrity + AES-GCM symmetric encryption demo",
    )
    sub = p.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Hash + encrypt a message or file")
    enc.add_argument("--message", type=str, help="Message to encrypt")
    enc.add_argument("--in-file", type=Path, help="Path to file to encrypt")
    enc.add_argument("--out-file", type=Path, help="Where to write JSON bundle")
    enc.add_argument(
        "--password",
        type=str,
        help="Password (if omitted, you will be prompted)",
    )
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="Decrypt a JSON bundle and verify integrity")
    dec.add_argument("bundle", type=Path, help="Path to JSON bundle")
    dec.add_argument("--out-file", type=Path, help="Where to write decrypted bytes")
    dec.add_argument(
        "--password",
        type=str,
        help="Password (if omitted, you will be prompted)",
    )
    dec.set_defaults(func=cmd_decrypt)

    demo = sub.add_parser("demo", help="Interactive encrypt/decrypt/verify demo")
    demo.set_defaults(func=cmd_demo)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Validate file args early with friendlier errors.
    if getattr(args, "in_file", None) is not None and not args.in_file.exists():
        raise SystemExit(f"Input file not found: {args.in_file}")

    if getattr(args, "bundle", None) is not None and not args.bundle.exists():
        raise SystemExit(f"Bundle file not found: {args.bundle}")

    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
