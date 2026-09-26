import argparse
import json
import sys
from pathlib import Path

from .loader import prepare_image
from .macho import MachOError
from .scanner import scan


def main():
    parser = argparse.ArgumentParser(description="Inspect a macOS .app or Mach-O without executing it")
    parser.add_argument("path", type=Path)
    parser.add_argument("--prepare", action="store_true", help="produce a validated virtual image plan; never executes code")
    args = parser.parse_args()
    try:
        if args.prepare:
            path = args.path
            if path.is_dir():
                path = Path(scan(path)["executable"])
            report = prepare_image(path.read_bytes())
            report["virtual_address_space"] = {"segments": report["segments"]}
            print(json.dumps(report, indent=2))
        else:
            print(json.dumps(scan(args.path), indent=2))
    except (MachOError, OSError) as error:
        print(f"[MX:MACHO] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
