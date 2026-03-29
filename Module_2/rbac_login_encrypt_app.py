from __future__ import annotations

import argparse
import base64
import getpass
import hmac
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


USER_FILE = Path(__file__).resolve().parent / "users.json"
OUTPUT_FILE = Path(__file__).resolve().parent / "rbac_encryption_output.txt"

VALID_ROLES = {"admin", "user"}


@dataclass(frozen=True)
class AuthUser:
	username: str
	role: str


def _b64e(raw: bytes) -> str:
	return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
	return base64.b64decode(text.encode("ascii"))


def _pbkdf2_hash(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
	return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def _load_users() -> dict[str, dict[str, Any]]:
	if not USER_FILE.exists():
		return {}
	try:
		return json.loads(USER_FILE.read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError):
		return {}


def _save_users(users: dict[str, dict[str, Any]]) -> None:
	USER_FILE.write_text(json.dumps(users, indent=2), encoding="utf-8")


def _ensure_default_users() -> None:
	users = _load_users()
	if users:
		return

	def add_user(username: str, password: str, role: str) -> None:
		salt = os.urandom(16)
		iterations = 200_000
		dk = _pbkdf2_hash(password, salt, iterations)
		users[username] = {
			"role": role,
			"salt_b64": _b64e(salt),
			"iterations": iterations,
			"dk_b64": _b64e(dk),
		}

	add_user("admin", "admin123!", "admin")
	add_user("user", "user123!", "user")
	_save_users(users)
	print("Created demo users in users.json (demo-only):")
	print("- admin / admin123!")
	print("- user  / user123!")


def login() -> AuthUser | None:
	users = _load_users()
	if not users:
		print("No users found. Creating demo users...")
		_ensure_default_users()
		users = _load_users()

	username = input("Username: ").strip()
	password = getpass.getpass("Password: ")

	entry = users.get(username)
	if not entry:
		print("Invalid credentials.")
		return None

	role = str(entry.get("role", "user")).lower()
	if role not in VALID_ROLES:
		role = "user"

	salt = _b64d(entry["salt_b64"])
	iterations = int(entry.get("iterations", 200_000))
	stored_dk = _b64d(entry["dk_b64"])
	candidate_dk = _pbkdf2_hash(password, salt, iterations)

	if not hmac.compare_digest(stored_dk, candidate_dk):
		print("Invalid credentials.")
		return None

	print(f"Logged in as {username} (role={role})")
	return AuthUser(username=username, role=role)


def login_with_credentials(username: str, password: str) -> AuthUser | None:
	users = _load_users()
	if not users:
		_ensure_default_users()
		users = _load_users()

	entry = users.get(username)
	if not entry:
		return None

	role = str(entry.get("role", "user")).lower()
	if role not in VALID_ROLES:
		role = "user"

	salt = _b64d(entry["salt_b64"])
	iterations = int(entry.get("iterations", 200_000))
	stored_dk = _b64d(entry["dk_b64"])
	candidate_dk = _pbkdf2_hash(password, salt, iterations)

	if not hmac.compare_digest(stored_dk, candidate_dk):
		return None

	return AuthUser(username=username, role=role)


def require_role(user: AuthUser, required: str) -> None:
	if user.role != required:
		raise PermissionError(f"Action requires role={required}")


def _import_crypto() -> tuple[Any, Any, Any, Any, Any, Any]:
	try:
		from cryptography.fernet import Fernet
		from cryptography.hazmat.primitives import hashes, serialization
		from cryptography.hazmat.primitives.asymmetric import padding, rsa
		from cryptography.hazmat.backends import default_backend

		return Fernet, hashes, serialization, padding, rsa, default_backend
	except ModuleNotFoundError:
		print("Missing dependency: cryptography")
		print("Install with: pip install cryptography")
		raise SystemExit(1)


def symmetric_demo(message: str) -> dict[str, str]:
	Fernet, _hashes, _serialization, _padding, _rsa, _backend = _import_crypto()
	key = Fernet.generate_key()
	f = Fernet(key)
	cipher = f.encrypt(message.encode("utf-8"))
	plain = f.decrypt(cipher).decode("utf-8")
	return {
		"symmetric_key_base64": key.decode("ascii"),
		"symmetric_ciphertext_token_base64": cipher.decode("ascii"),
		"symmetric_decrypted": plain,
	}


def asymmetric_demo(message: str) -> dict[str, str]:
	Fernet, hashes, serialization, padding, rsa, default_backend = _import_crypto()
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
	public_key = private_key.public_key()
	cipher = public_key.encrypt(
		message.encode("utf-8"),
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None,
		),
	)
	plain = private_key.decrypt(
		cipher,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None,
		),
	).decode("utf-8")

	public_pem = public_key.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo,
	).decode("utf-8")
	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption(),
	).decode("utf-8")

	return {
		"rsa_public_key_pem": public_pem.rstrip(),
		"rsa_private_key_pem": private_pem.rstrip(),
		"rsa_ciphertext_base64": _b64e(cipher),
		"rsa_decrypted": plain,
	}


def write_output(user: AuthUser, message: str, results: dict[str, str]) -> None:
	lines: list[str] = []
	lines.append("RBAC + Encryption Demo Output")
	lines.append(f"user: {user.username}")
	lines.append(f"role: {user.role}")
	method = "asymmetric" if any(k.startswith("rsa_") for k in results.keys()) else "symmetric"
	lines.append(f"method: {method}")
	lines.append("")
	lines.append("INPUT")
	lines.append(f"message: {message}")
	lines.append("")
	lines.append("OUTPUT")
	for k, v in results.items():
		lines.append(f"{k}: {v}")
	lines.append("")
	OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")
	print(f"Saved results to: {OUTPUT_FILE}")



def _extract_message_only(text: str) -> tuple[str | None, str | None]:
	message: str | None = None
	decrypted: str | None = None
	for line in text.splitlines():
		stripped = line.strip()
		if stripped.startswith("message:") and message is None:
			message = stripped.split(":", 1)[1].lstrip()
		elif stripped.startswith("symmetric_decrypted:"):
			decrypted = stripped.split(":", 1)[1].lstrip()
		elif stripped.startswith("rsa_decrypted:"):
			decrypted = stripped.split(":", 1)[1].lstrip()
	return message, decrypted


def _output_contains_rsa(text: str) -> bool:
	for line in text.splitlines():
		if line.strip().startswith("rsa_"):
			return True
	return False


def view_output_message_only(user: AuthUser) -> None:
	if not OUTPUT_FILE.exists():
		print(f"No output file found yet at: {OUTPUT_FILE}")
		print("Run an encryption action first to generate it.")
		return

	text = OUTPUT_FILE.read_text(encoding="utf-8")
	if _output_contains_rsa(text) and user.role != "admin":
		print("DENIED: Last saved output was generated using admin-only asymmetric (RSA) encryption.")
		return
	message, decrypted = _extract_message_only(text)
	print(f"\n=== Last Saved Message ({OUTPUT_FILE.name}) ===\n")
	if message is not None:
		print(f"Input message: {message!r}")
	if decrypted is not None:
		print(f"Decrypted: {decrypted!r}")
	if message is None and decrypted is None:
		print("Could not parse message from the output file.")


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Login + RBAC + encryption demo")
	parser.add_argument("--username", help="Optional: username for non-interactive run")
	parser.add_argument("--password", help="Optional: password for non-interactive run")
	parser.add_argument("--mode", choices=["read", "write"], help="read=show last saved message, write=encrypt/decrypt")
	parser.add_argument("--action", choices=["1", "2", "3"], help="1=symmetric, 2=asymmetric, 3=view output")
	parser.add_argument("--view-output", action="store_true", help="Shortcut for action 3")
	parser.add_argument("--message", help="Message to encrypt")
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	_ensure_default_users()
	if args.username and args.password:
		user = login_with_credentials(args.username, args.password)
		if not user:
			print("Invalid credentials.")
			return
		print(f"Logged in as {user.username} (role={user.role})")
	else:
		user = login()
	if not user:
		return

	if args.view_output or args.action == "3" or args.mode == "read":
		mode = "read"
	elif args.mode == "write":
		mode = "write"
	else:
		print("\nDo you want to read or write?")
		print("1) Read last saved message")
		print("2) Write (encrypt/decrypt) a new message")
		mode_choice = input("Enter choice (1/2): ").strip()
		mode = "read" if mode_choice == "1" else "write"

	if mode == "read":
		view_output_message_only(user)
		return

	if args.message is not None:
		message = args.message
	else:
		message = input("Message to encrypt: ").strip() or "Confidential message for RBAC demo."

	print("\nChoose an encryption method:")
	print("1) Symmetric (Fernet)")
	is_admin = user.role == "admin"
	if is_admin:
		print("2) Asymmetric (RSA-OAEP) [admin only]")

	if args.action in {"1", "2"}:
		choice = args.action
	else:
		choice_prompt = "Enter choice (1/2): " if is_admin else "Enter choice (1): "
		choice = input(choice_prompt).strip()

	try:
		if choice == "1":
			results = symmetric_demo(message)
			print("\n[OK] Symmetric completed.")
			print(f"Decrypted: {results['symmetric_decrypted']!r}")
			write_output(user, message, results)
			return
		if choice == "2":
			require_role(user, "admin")
			results = asymmetric_demo(message)
			print("\n[OK] Asymmetric completed.")
			print(f"Decrypted: {results['rsa_decrypted']!r}")
			write_output(user, message, results)
			return

		print("Invalid choice.")
	except PermissionError as exc:
		print(f"DENIED: {exc}")


if __name__ == "__main__":
	main()
