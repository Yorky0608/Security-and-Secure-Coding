from __future__ import annotations

import argparse
from pathlib import Path


def _shift_char(ch: str, shift: int) -> str:
	if "a" <= ch <= "z":
		base = ord("a")
		return chr(base + ((ord(ch) - base + shift) % 26))
	if "A" <= ch <= "Z":
		base = ord("A")
		return chr(base + ((ord(ch) - base + shift) % 26))
	return ch


def caesar(text: str, shift: int) -> str:
	shift = shift % 26
	return "".join(_shift_char(ch, shift) for ch in text)


def parse_args() -> argparse.Namespace:
	p = argparse.ArgumentParser(description="Encrypt/decrypt text using a Caesar (substitution) cipher")
	p.add_argument("mode", choices=["encrypt", "decrypt"], help="encrypt or decrypt")
	p.add_argument("--shift", type=int, default=3, help="Shift amount (default: 3)")
	p.add_argument("--text", help="Text to encrypt/decrypt")
	p.add_argument("--in-file", type=Path, help="Read input text from a file")
	p.add_argument("--out-file", type=Path, help="Write output text to a file")
	return p.parse_args()


def main() -> None:
	args = parse_args()
	if (args.text is None) == (args.in_file is None):
		raise SystemExit("Provide exactly one of --text or --in-file")

	if args.in_file is not None:
		if not args.in_file.exists() or not args.in_file.is_file():
			raise SystemExit(f"File not found: {args.in_file}")
		input_text = args.in_file.read_text(encoding="utf-8")
	else:
		input_text = args.text

	shift = args.shift
	if args.mode == "decrypt":
		shift = -shift

	output_text = caesar(input_text, shift)

	if args.out_file is not None:
		args.out_file.write_text(output_text, encoding="utf-8")
		print(f"Wrote output to: {args.out_file}")
		return

	print(output_text)


if __name__ == "__main__":
	main()
