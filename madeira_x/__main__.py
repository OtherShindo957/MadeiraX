import argparse
import json
import sys
from pathlib import Path

from .macho import MachOError
from .scanner import scan


def main():
    parser = argparse.ArgumentParser(description="Inspect a macOS .app or Mach-O without executing it")
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(scan(args.path), indent=2))
    except (MachOError, OSError) as error:
        print(f"[MX:MACHO] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
