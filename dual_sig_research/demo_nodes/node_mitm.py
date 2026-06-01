"""
MITM proxy (Node C) — intercept, display attacker view, forward to receiver.

Run from dual_sig_research/ (start second, after receiver):
  python demo_nodes/node_mitm.py --target <IP_OF_LAPTOP_B>
  python demo_nodes/node_mitm.py --target 192.168.1.20 --attack --flip ciphertext
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from network_validation import run_local_attack_mitm, run_mitm


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Node C: MITM proxy for the 3-laptop classroom demo.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Listen port (default: 5000)")
    parser.add_argument(
        "--target",
        required=True,
        help="Receiver (Node B) IP address",
    )
    parser.add_argument(
        "--target-port",
        type=int,
        default=5001,
        help="Receiver port (default: 5001)",
    )
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Flip one bit before forwarding (active attack demo)",
    )
    parser.add_argument(
        "--flip",
        choices=("ciphertext", "kem"),
        default="ciphertext",
        help="Field to corrupt when --attack is set (default: ciphertext)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    if args.attack:
        run_local_attack_mitm(
            args.host,
            args.port,
            args.target,
            args.target_port,
            args.flip,
        )
    else:
        run_mitm(args.host, args.port, args.target, args.target_port)


if __name__ == "__main__":
    main()
