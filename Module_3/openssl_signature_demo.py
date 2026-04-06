from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from pathlib import Path


DEFAULT_PRIVATE_KEY = Path(__file__).resolve().parent / "private_key.pem"
DEFAULT_PUBLIC_KEY = Path(__file__).resolve().parent / "public_key.pem"
DEFAULT_SIGNATURE = Path(__file__).resolve().parent / "signature.bin"



def _resolve_openssl(explicit: Path | None) -> str:
	if explicit is not None:
		if explicit.exists() and explicit.is_file():
			return str(explicit)
		raise SystemExit(f"OpenSSL executable not found at: {explicit}")

	env_exe = os.environ.get("OPENSSL_EXE")
	if env_exe:
		env_path = Path(env_exe)
		if env_path.exists() and env_path.is_file():
			return str(env_path)
		raise SystemExit(f"OPENSSL_EXE is set but invalid: {env_exe}")

	which = shutil.which("openssl")
	if which:
		return which

	program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
	program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

	candidates = [
		Path(program_files) / "OpenSSL-Win64" / "bin" / "openssl.exe",
		Path(program_files_x86) / "OpenSSL-Win32" / "bin" / "openssl.exe",
		Path(program_files) / "Git" / "usr" / "bin" / "openssl.exe",
		Path(program_files) / "Git" / "mingw64" / "bin" / "openssl.exe",
		Path(program_files_x86) / "Git" / "usr" / "bin" / "openssl.exe",
		Path(program_files_x86) / "Git" / "mingw64" / "bin" / "openssl.exe",
	]
	for p in candidates:
		if p.exists() and p.is_file():
			return str(p)

	raise SystemExit(
		"OpenSSL was not found.\n\n"
		"Fix options:\n"
		"- Ensure 'openssl' works in this terminal: run `where.exe openssl`\n"
		"- Restart VS Code after editing PATH (VS Code must re-launch to pick up environment changes)\n"
		"- Or pass an explicit path: `python openssl_signature_demo.py --openssl C:\\path\\to\\openssl.exe gen-keys`\n"
		"- Or set OPENSSL_EXE to the full path of openssl.exe"
	)


def _run_openssl(args: list[str], openssl_exe: str) -> subprocess.CompletedProcess[str]:
	try:
		return subprocess.run(
			[openssl_exe, *args],
			text=True,
			capture_output=True,
			check=False,
		)
	except FileNotFoundError:
		raise SystemExit("OpenSSL executable could not be executed. Re-check --openssl / OPENSSL_EXE.")


def gen_keys(private_key: Path, public_key: Path, openssl_exe: str) -> None:
	private_key.parent.mkdir(parents=True, exist_ok=True)
	public_key.parent.mkdir(parents=True, exist_ok=True)

	# Generate a 2048-bit RSA private key.
	p1 = _run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)], openssl_exe)
	if p1.returncode != 0:
		raise SystemExit(p1.stderr.strip() or "OpenSSL key generation failed")

	# Extract public key from the private key.
	p2 = _run_openssl(["pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], openssl_exe)
	if p2.returncode != 0:
		raise SystemExit(p2.stderr.strip() or "OpenSSL public key extraction failed")

	print(f"Generated private key: {private_key}")
	print(f"Generated public key:  {public_key}")


def sign_file(input_file: Path, private_key: Path, signature_file: Path, openssl_exe: str) -> None:
	if not input_file.exists() or not input_file.is_file():
		raise SystemExit(f"Input file not found: {input_file}")
	if not private_key.exists() or not private_key.is_file():
		raise SystemExit(f"Private key not found: {private_key} (run 'gen-keys' first)")

	signature_file.parent.mkdir(parents=True, exist_ok=True)
	p = _run_openssl([
		"dgst",
		"-sha256",
		"-sign",
		str(private_key),
		"-out",
		str(signature_file),
		str(input_file),
	], openssl_exe)
	if p.returncode != 0:
		raise SystemExit(p.stderr.strip() or "OpenSSL signing failed")
	print(f"Signed: {input_file}")
	print(f"Signature: {signature_file}")


def verify_file(input_file: Path, public_key: Path, signature_file: Path, openssl_exe: str) -> None:
	if not input_file.exists() or not input_file.is_file():
		raise SystemExit(f"Input file not found: {input_file}")
	if not public_key.exists() or not public_key.is_file():
		raise SystemExit(f"Public key not found: {public_key} (run 'gen-keys' first)")
	if not signature_file.exists() or not signature_file.is_file():
		raise SystemExit(f"Signature not found: {signature_file} (run 'sign' first)")

	p = _run_openssl([
		"dgst",
		"-sha256",
		"-verify",
		str(public_key),
		"-signature",
		str(signature_file),
		str(input_file),
	], openssl_exe)
	# OpenSSL prints "Verified OK" on success.
	if p.returncode == 0:
		print("Signature verification: OK")
		if p.stdout.strip():
			print(p.stdout.strip())
		return

	err = (p.stderr.strip() or p.stdout.strip() or "Signature verification failed")
	raise SystemExit(f"Signature verification: FAILED\n{err}")


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Digital signature demo using OpenSSL (sign/verify)")
	parser.add_argument(
		"--openssl",
		type=Path,
		help="Optional path to openssl executable (or set OPENSSL_EXE)",
	)
	sub = parser.add_subparsers(dest="cmd", required=True)

	p_gen = sub.add_parser("gen-keys", help="Generate RSA keypair")
	p_gen.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
	p_gen.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)

	p_sign = sub.add_parser("sign", help="Sign a file")
	p_sign.add_argument("--in", dest="input_file", type=Path, required=True)
	p_sign.add_argument("--private-key", type=Path, default=DEFAULT_PRIVATE_KEY)
	p_sign.add_argument("--signature", type=Path, default=DEFAULT_SIGNATURE)

	p_verify = sub.add_parser("verify", help="Verify a signature for a file")
	p_verify.add_argument("--in", dest="input_file", type=Path, required=True)
	p_verify.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
	p_verify.add_argument("--signature", type=Path, default=DEFAULT_SIGNATURE)

	return parser.parse_args()


def main() -> None:
	args = parse_args()
	openssl_exe = _resolve_openssl(args.openssl)
	if args.cmd == "gen-keys":
		gen_keys(args.private_key, args.public_key, openssl_exe)
		return
	if args.cmd == "sign":
		sign_file(args.input_file, args.private_key, args.signature, openssl_exe)
		return
	if args.cmd == "verify":
		verify_file(args.input_file, args.public_key, args.signature, openssl_exe)
		return

	raise SystemExit("Unknown command")


if __name__ == "__main__":
	main()
