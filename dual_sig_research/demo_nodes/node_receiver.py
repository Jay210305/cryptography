"""
IoT device (Node B) — listen, decrypt, verify dual signatures (AND).

Run from dual_sig_research/ (start first):
  python demo_nodes/node_receiver.py
  python demo_nodes/node_receiver.py --host 0.0.0.0 --port 5001
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from network_validation import DEFAULT_KEYS_FILE, _load_or_create_keys, run_receiver


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Node B: IoT receiver for the 3-laptop classroom demo.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5001, help="Listen port (default: 5001)")
    parser.add_argument(
        "--keys-file",
        default="",
        help=f"Shared keys file (default: {DEFAULT_KEYS_FILE.name})",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    keys_path = Path(args.keys_file) if args.keys_file else DEFAULT_KEYS_FILE
    manufacturer, device = _load_or_create_keys(keys_path)
    run_receiver(
        args.host,
        args.port,
        device,
        manufacturer["pk_c"],
        manufacturer["pk_q"],
    )


if __name__ == "__main__":
    main()
