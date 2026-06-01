"""
Generate shared demo key material once, then copy validation_keys.msgpack to all laptops.

Run from dual_sig_research/:
  python demo_nodes/prepare_demo_keys.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from network_validation import DEFAULT_KEYS_FILE, _load_or_create_keys


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate validation_keys.msgpack for the 3-laptop classroom demo.",
    )
    parser.add_argument(
        "--keys-file",
        default="",
        help=f"Key file path (default: {DEFAULT_KEYS_FILE.name} in dual_sig_research/)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    keys_path = Path(args.keys_file) if args.keys_file else DEFAULT_KEYS_FILE
    created = not keys_path.exists()
    _load_or_create_keys(keys_path)

    print(f"Keys file: {keys_path.resolve()}")
    if created:
        print("Created new manufacturer + device key pairs.")
    else:
        print("Loaded existing keys (unchanged).")
    print()
    print("Before the demo, copy this file to the same path on all three laptops:")
    print(f"  dual_sig_research/{keys_path.name}")
    print()
    print("Then start nodes in order: receiver -> mitm -> sender.")


if __name__ == "__main__":
    main()
