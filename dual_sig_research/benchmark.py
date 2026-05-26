"""Reproducible benchmark suite for hybrid SIGN → ENCRYPT firmware protocol."""

from __future__ import annotations

import csv
import json
import logging
import os
import sys
import time
from pathlib import Path
from statistics import mean, median, stdev
from typing import Any

import oqs
from tabulate import tabulate

from protocol import (
    ML_DSA_ALG,
    ML_KEM_ALG,
    KeyMaterial,
    decrypt_payload,
    deserialize_packet,
    encrypt_payload,
    hash_firmware,
    hybrid_kem_decapsulate,
    hybrid_kem_encapsulate,
    keygen,
    protect_firmware,
    select_cipher,
    serialize_packet,
    sign,
    unprotect_firmware,
    verify,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
FIRMWARE_DIR = ROOT / "firmware_samples"

ITERATIONS = 100
PAYLOAD_SIZES: dict[str, int] = {
    "firmware_1kb.bin": 1024,
    "firmware_10kb.bin": 10_240,
    "firmware_100kb.bin": 102_400,
    "firmware_1mb.bin": 1_048_576,
    "firmware_10mb.bin": 10_485_760,
}


def _require_oqs() -> None:
    sigs = oqs.get_enabled_sig_mechanisms()
    kems = oqs.get_enabled_kem_mechanisms()
    if ML_DSA_ALG not in sigs:
        print(f"ERROR: {ML_DSA_ALG} unavailable", file=sys.stderr)
        sys.exit(1)
    if ML_KEM_ALG not in kems:
        print(f"ERROR: {ML_KEM_ALG} unavailable", file=sys.stderr)
        sys.exit(1)


def _stats_ns(samples_ns: list[int]) -> dict[str, float]:
    """Aggregate timing samples (nanoseconds) to milliseconds."""
    if not samples_ns:
        return {
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "std_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0,
        }
    ms = [x / 1_000_000.0 for x in samples_ns]
    std_val = stdev(ms) if len(ms) > 1 else 0.0
    return {
        "mean_ms": mean(ms),
        "median_ms": median(ms),
        "std_ms": std_val,
        "min_ms": min(ms),
        "max_ms": max(ms),
    }


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    for attempt in range(2):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            return
        except OSError:
            if attempt == 0:
                path.parent.mkdir(parents=True, exist_ok=True)
                continue
            raise


def _write_json(path: Path, data: Any) -> None:
    for attempt in range(2):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return
        except OSError:
            if attempt == 0:
                path.parent.mkdir(parents=True, exist_ok=True)
                continue
            raise


def generate_firmware_samples() -> dict[str, bytes]:
    """Create fixed firmware blobs once (never inside timing loops)."""
    FIRMWARE_DIR.mkdir(parents=True, exist_ok=True)
    samples: dict[str, bytes] = {}
    for name, size in PAYLOAD_SIZES.items():
        path = FIRMWARE_DIR / name
        if path.exists() and path.stat().st_size == size:
            samples[name] = path.read_bytes()
        else:
            data = os.urandom(size)
            path.write_bytes(data)
            samples[name] = data
    return samples


def run_sanity_tests(firmware: bytes, mfg: KeyMaterial, dev: KeyMaterial) -> None:
    """Pre-benchmark protocol checks."""
    bundle = sign(firmware, mfg["sk_c"], mfg["sk_q"], mfg["pk_q"])
    if not verify(bundle, mfg["pk_c"], mfg["pk_q"]):
        raise AssertionError("Sanity: sign/verify failed")

    packet = protect_firmware(firmware, mfg, dev["pk_x"], dev["pk_kem"])
    wire = serialize_packet(packet)
    restored = deserialize_packet(wire)
    _, ok = unprotect_firmware(restored, dev, mfg["pk_c"], mfg["pk_q"])
    if not ok:
        raise AssertionError("Sanity: full pipeline failed")
    print("All sanity tests passed.")


def _bench_sign(firmware: bytes, mfg: KeyMaterial, n: int) -> list[int]:
    times: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        sign(firmware, mfg["sk_c"], mfg["sk_q"], mfg["pk_q"])
        times.append(time.perf_counter_ns() - t0)
    return times


def _bench_verify(firmware: bytes, mfg: KeyMaterial, n: int) -> list[int]:
    bundle = sign(firmware, mfg["sk_c"], mfg["sk_q"], mfg["pk_q"])
    times: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        verify(bundle, mfg["pk_c"], mfg["pk_q"])
        times.append(time.perf_counter_ns() - t0)
    return times


def _bench_kem_enc(dev: KeyMaterial, n: int) -> list[int]:
    times: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        hybrid_kem_encapsulate(dev["pk_x"], dev["pk_kem"])
        times.append(time.perf_counter_ns() - t0)
    return times


def _bench_kem_dec(
    dev: KeyMaterial,
    x_pub: bytes,
    ml_ct: bytes,
    n: int,
) -> list[int]:
    times: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        hybrid_kem_decapsulate(x_pub, ml_ct, dev["sk_x"], dev["sk_kem"])
        times.append(time.perf_counter_ns() - t0)
    return times


def _bench_encrypt(plaintext: bytes, sym_key: bytes, cipher_id: str, n: int) -> list[int]:
    times: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        encrypt_payload(plaintext, sym_key, cipher_id)
        times.append(time.perf_counter_ns() - t0)
    return times


def _bench_decrypt(
    nonce: bytes,
    ct: bytes,
    tag: bytes,
    sym_key: bytes,
    cipher_id: str,
    n: int,
) -> list[int]:
    times: list[int] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        decrypt_payload(nonce, ct, tag, sym_key, cipher_id)
        times.append(time.perf_counter_ns() - t0)
    return times


def benchmark_firmware_size(
    firmware: bytes,
    fw_size: int,
    mfg: KeyMaterial,
    dev: KeyMaterial,
    iterations: int,
) -> dict[str, Any]:
    """Benchmark all phases for one firmware size."""
    bundle = sign(firmware, mfg["sk_c"], mfg["sk_q"], mfg["pk_q"])
    from protocol import pack_signed_payload

    plaintext = pack_signed_payload(bundle)
    cipher_id = select_cipher(len(plaintext))
    x_pub, ml_ct, sym_key = hybrid_kem_encapsulate(dev["pk_x"], dev["pk_kem"])
    nonce, ct, tag = encrypt_payload(plaintext, sym_key, cipher_id)

    sign_t = _bench_sign(firmware, mfg, iterations)
    verify_t = _bench_verify(firmware, mfg, iterations)
    kem_enc_t = _bench_kem_enc(dev, iterations)
    kem_dec_t = _bench_kem_dec(dev, x_pub, ml_ct, iterations)
    enc_t = _bench_encrypt(plaintext, sym_key, cipher_id, iterations)
    dec_t = _bench_decrypt(nonce, ct, tag, sym_key, cipher_id, iterations)

    e2e: list[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        pkt = protect_firmware(firmware, mfg, dev["pk_x"], dev["pk_kem"])
        wire = serialize_packet(pkt)
        restored = deserialize_packet(wire)
        unprotect_firmware(restored, dev, mfg["pk_c"], mfg["pk_q"])
        e2e.append(time.perf_counter_ns() - t0)

    packet = protect_firmware(firmware, mfg, dev["pk_x"], dev["pk_kem"])
    wire = serialize_packet(packet)

    row: dict[str, Any] = {
        "fw_size_bytes": fw_size,
        "cipher_selected": cipher_id,
        "serialized_packet_bytes": len(wire),
        "ciphertext_bytes": len(packet["ciphertext"]),
        "overhead_pct": (len(wire) - fw_size) / fw_size * 100.0,
        "throughput_mbps": (fw_size * 8) / (mean(e2e) / 1e9) / 1e6 if e2e else 0.0,
    }
    for prefix, samples in (
        ("sign", sign_t),
        ("verify", verify_t),
        ("kem_enc", kem_enc_t),
        ("kem_dec", kem_dec_t),
        ("encrypt", enc_t),
        ("decrypt", dec_t),
        ("e2e", e2e),
    ):
        stats = _stats_ns(samples)
        for k, v in stats.items():
            row[f"{prefix}_{k}"] = v
    return row


def benchmark_keygen(iterations: int) -> dict[str, Any]:
    """Hybrid key generation benchmark."""
    times: list[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        keygen()
        times.append(time.perf_counter_ns() - t0)
    return _stats_ns(times)


def main() -> None:
    """Run full benchmark suite and export CSV/JSON."""
    logging.basicConfig(level=logging.WARNING)
    _require_oqs()
    print(f"liboqs version: {oqs.oqs_version()}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    samples = generate_firmware_samples()

    print("Generating hybrid keys (reused across benchmarks)...")
    mfg = keygen()
    dev = keygen()

    run_sanity_tests(samples["firmware_1kb.bin"], mfg, dev)

    keygen_stats = benchmark_keygen(ITERATIONS)
    print("\nKeygen (hybrid):")
    print(tabulate([keygen_stats], headers="keys", tablefmt="simple"))

    rows: list[dict[str, Any]] = []
    for name, size in PAYLOAD_SIZES.items():
        print(f"\nBenchmarking {name} ({size} B)...")
        row = benchmark_firmware_size(
            samples[name], size, mfg, dev, ITERATIONS
        )
        rows.append(row)

    csv_path = RESULTS_DIR / "benchmark_full_protocol.csv"
    json_path = RESULTS_DIR / "benchmark_full_protocol.json"

    if rows:
        fieldnames = list(rows[0].keys())
        _write_csv(csv_path, fieldnames, rows)
        _write_json(
            json_path,
            {
                "iterations": ITERATIONS,
                "keygen": keygen_stats,
                "by_size": rows,
            },
        )

    display_cols = [
        "fw_size_bytes",
        "cipher_selected",
        "sign_mean_ms",
        "verify_mean_ms",
        "kem_enc_mean_ms",
        "kem_dec_mean_ms",
        "encrypt_mean_ms",
        "decrypt_mean_ms",
        "e2e_mean_ms",
        "serialized_packet_bytes",
        "throughput_mbps",
    ]
    table = [{k: r.get(k) for k in display_cols} for r in rows]
    print("\n" + "=" * 72)
    print("BENCHMARK SUMMARY")
    print("=" * 72)
    print(tabulate(table, headers="keys", tablefmt="simple", floatfmt=".4f"))
    print(f"\nCSV:  {csv_path}")
    print(f"JSON: {json_path}")


if __name__ == "__main__":
    main()
