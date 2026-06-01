"""
Manufacturer (Node A) — sign, encapsulate, encrypt, send firmware update.

Run from dual_sig_research/ (start last, after receiver and MITM):
  python demo_nodes/node_sender.py --target <IP_OF_LAPTOP_C>
  python demo_nodes/node_sender.py --target 192.168.1.30 --firmware firmware_samples/firmware_1kb.bin
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from network_validation import DEFAULT_KEYS_FILE, _load_or_create_keys, run_sender


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Node A: manufacturer sender for the 3-laptop classroom demo.",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="MITM (Node C) IP address",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="MITM listen port (default: 5000)",
    )
    parser.add_argument(
        "--firmware",
        default="",
        help="Firmware file path (relative to dual_sig_research/). Prompts if omitted.",
    )
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
    run_sender(
        args.target,
        args.port,
        manufacturer,
        device["pk_x"],
        device["pk_kem"],
        manufacturer["pk_c"],
        manufacturer["pk_q"],
        firmware_path=args.firmware,
    )


if __name__ == "__main__":
    main()
