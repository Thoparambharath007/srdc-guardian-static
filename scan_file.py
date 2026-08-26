"""Command-line entry point for SRDC Guardian static analysis."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import static_analysis


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run local static checks: hashes, magic bytes, entropy, size, YARA, and optional VT hash lookup."
    )
    parser.add_argument("file", type=Path, help="File to inspect")
    parser.add_argument("--json", action="store_true", help="Print the full result as JSON")
    args = parser.parse_args()

    target = args.file.expanduser()
    if not target.is_file():
        parser.error(f"not a readable file: {target}")

    result = static_analysis.run_all(str(target))
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"File: {target}")
        print(f"SHA-256: {result['hashes']['sha256']}")
        print(f"Magic: {result['magic']['detail'] or 'OK'}")
        print(f"Entropy: {result['entropy']['detail']}")
        print(f"Size: {result['size']['detail']}")
        print(f"YARA: {result['yara']['detail']}")
        print(f"VirusTotal: {result['vt']['detail']}")
        print(f"Signals found: {'yes' if result['any_flag'] else 'no'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
