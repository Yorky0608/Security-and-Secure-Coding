from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def sha256_text(text: str) -> str:
	data = text.encode("utf-8")
	return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
	h = hashlib.sha256()
	with path.open("rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			h.update(chunk)
	return h.hexdigest()


def parse_args() -> argparse.Namespace:
	p = argparse.ArgumentParser(description="Generate SHA-256 hashes for input strings or files")
	g = p.add_mutually_exclusive_group(required=False)
	g.add_argument("--text", help="Text to hash (UTF-8)")
	g.add_argument("--file", type=Path, help="File path to hash")
	return p.parse_args()


def main() -> None:
	args = parse_args()
	if args.text is None and args.file is None:
		text = input("Enter text to hash (SHA-256): ")
		digest = sha256_text(text)
		print(digest)
		return

	if args.text is not None:
		print(sha256_text(args.text))
		return

	path: Path = args.file
	if not path.exists() or not path.is_file():
		raise SystemExit(f"File not found: {path}")
	print(sha256_file(path))


if __name__ == "__main__":
	main()
