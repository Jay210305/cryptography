## ROLE

You are an expert applied cryptography engineer specializing in post-quantum
security and IoT firmware authentication pipelines.

Write production-quality Python code, not notebook demos. Every function
must have type hints, a docstring, and clear error handling.

---

## PRIMARY GOAL

Implement and benchmark a dual-signature hybrid firmware authentication 
scheme that combines Ed25519 (classical) and ML-DSA-65 (post-quantum,
NIST FIPS 204) to provide transitional security during the quantum migration
period. The scheme signs a SHA3-256 digest of the firmware with both
algorithms independently. Verification requires BOTH signatures to pass
simultaneously (AND logic).

Do not collapse this into a single-scheme implementation.
The dual-signature AND logic is the core security mechanism.

---

## EXECUTION CONTRACT

Execute phases in this exact order. Stop after each phase, summarize
findings, list generated files, report any errors, and wait for
confirmation before proceeding.

Phase order:
  1. Environment verification
  2. Project structure setup
  3. Protocol implementation (protocol.py)
  4. Protocol sanity tests
  5. Keygen benchmark (Phase 1)
  6. Scheme comparison benchmark (Phase 2 — 1KB, three schemes)
  7. Payload scaling benchmark (Phase 3 — 1KB to 1MB, hybrid only)
  8. Results export to CSV
  9. Summary table printed to console

After each phase:
  - summarize what was done,
  - list files created or modified,
  - report any errors or blockers,
  - stop and wait for confirmation.

Do NOT silently continue across phases.
Never fabricate benchmark numbers. If a measurement cannot be taken,
say so explicitly.

---

## ENVIRONMENT

Python:   3.10+
Required libraries:
  - oqs (liboqs-python >= 0.10.0)  — ML-DSA-65 via NIST FIPS 204
  - cryptography (PyCA)            — Ed25519, SHA3-256
  - numpy                          — statistical aggregation
  - pandas                         — results storage
  - matplotlib                     — figure generation
  - tabulate                       — console table output

Verify environment before writing any code:
  python -c "import oqs; print(oqs.oqs_version())"
  python -c "import oqs; print([s for s in oqs.get_enabled_sig_mechanisms() if 'ML-DSA' in s])"

If ML-DSA-65 does not appear in the output, stop and report it.
Do not proceed with a fallback scheme.

---

## PROJECT STRUCTURE

Create all files inside dual_sig_research/:

  dual_sig_research/
  ├── protocol.py            — KeyGen, Sign, Verify implementation
  ├── benchmark.py           — full benchmark suite (all 3 phases)
  ├── results/
  │   ├── benchmark_keygen.csv
  │   ├── benchmark_1kb_comparison.csv
  │   ├── benchmark_hybrid_scaling.csv
  │   └── figures/
  │       ├── fig1_scheme_comparison.png
  │       ├── fig2_payload_scaling.png
  │       └── fig3_bundle_overhead.png
  └── firmware_samples/
      ├── firmware_1kb.bin
      ├── firmware_10kb.bin
      ├── firmware_100kb.bin
      └── firmware_1mb.bin

Generate firmware samples with os.urandom() before benchmarking.
Generate them ONCE and reuse across all iterations — do not regenerate
inside timing loops.

---

## PHASE 1 — KEY GENERATION BENCHMARK

Run 1000 iterations of full hybrid keygen (Ed25519 + ML-DSA-65).
Time the entire keygen block as a single measurement per iteration.

Output:
  - Mean keygen time (ms) ± std
  - Save raw iteration times to: results/benchmark_keygen.csv
    Columns: iteration, keygen_time_ms

---

## PHASE 2 — SCHEME COMPARISON (1KB PAYLOAD)

Run 1000 iterations for each of three scheme configurations on a 1KB payload.

Schemes:
  - Ed25519-only:   SHA3-256 hash + Ed25519 sign/verify
  - ML-DSA-65-only: SHA3-256 hash + ML-DSA-65 sign/verify
  - Hybrid:         SHA3-256 hash + both signs + AND-logic verify

Timing rules:
  - Hash time: timed separately for all three schemes
  - Sign time: crypto only, AFTER hashing (no hash time included)
  - Verify time: crypto only (no hash time included)
  - Hybrid sign time = sum of Ed25519 sign time + ML-DSA-65 sign time
    for that iteration (do not re-run — reuse per-iteration measurements)

Bundle size per scheme (compute once, not per iteration):
  - Ed25519-only:   fw_size + digest(32) + sig_ed(64) + pk_ed(32)
  - ML-DSA-65-only: fw_size + digest(32) + sig_ml(~3309) + pk_ml(1952)
  - Hybrid:         fw_size + digest(32) + sig_ed + sig_ml + pk_ed + pk_ml
  - Overhead %:     (bundle_size - fw_size) / fw_size * 100

Output:
  - Console table: scheme | mean sign (ms) ± std | mean verify (ms) ± std
                   | bundle (bytes) | overhead %
  - Save to: results/benchmark_1kb_comparison.csv

---

## PHASE 3 — PAYLOAD SCALING (HYBRID ONLY)

Run 1000 iterations per payload size for the hybrid scheme.
Payload sizes: 1KB, 10KB, 100KB, 1MB.

Measure per iteration (each timed independently):
  - hash_time_ms
  - sign_time_ms  (Ed25519 + ML-DSA-65 crypto only, hash excluded)
  - verify_time_ms (AND-logic verify only, hash excluded)

Compute and record per payload size:
  - mean_hash_ms, mean_sign_ms ± std_sign, mean_verify_ms ± std_verify
  - bundle_bytes (constant per size — compute from first iteration)
  - overhead_pct

Output:
  - Console table with all columns
  - Save to: results/benchmark_hybrid_scaling.csv

---

## OUTPUT SPECIFICATION

CSV columns — benchmark_keygen.csv:
  iteration, keygen_time_ms

CSV columns — benchmark_1kb_comparison.csv:
  scheme, mean_sign_ms, std_sign_ms, mean_verify_ms, std_verify_ms,
  bundle_bytes, overhead_pct

CSV columns — benchmark_hybrid_scaling.csv:
  fw_size_bytes, mean_hash_ms, mean_sign_ms, std_sign_ms,
  mean_verify_ms, std_verify_ms, bundle_bytes, overhead_pct

---

## SCRIPTS TO DELIVER

protocol.py
  - keygen() → (pk_c, sk_c, pk_q, sk_q)
  - sign(firmware_bytes, sk_c, sk_q) → bundle dict
  - verify(bundle, trusted_pk_c, trusted_pk_q) → bool
  - Each function: type hints + docstring + explicit failure modes

benchmark.py
  - benchmark_keygen()
  - benchmark_1kb_comparison(ed_priv, ed_pub, ml_priv, ml_pub)
  - benchmark_payload_scaling(ed_priv, ed_pub, ml_priv, ml_pub)
  - if __name__ == "__main__": runs all three phases in order

---

## FAILURE HANDLING

Handle these explicitly — do not crash silently:
  - ML-DSA-65 not found in oqs mechanisms → stop, print clear message
  - oqs context manager fails to instantiate → log and re-raise
  - Signature verification returns False unexpectedly → raise AssertionError
    with the iteration number and scheme name
  - CSV write fails (e.g. results/ dir missing) → create the directory,
    then retry once before raising

---

## CRITICAL CONSTRAINTS

1. Never regenerate firmware bytes inside a timing loop. Generate once
   per payload size before the iteration loop starts.

2. The oqs secret key must be passed to the Signature() constructor
   as secret_key=ml_priv — never assigned as an attribute after init.

3. Hybrid sign time in Phase 2 must be derived from per-iteration sums
   of the already-measured Ed25519 and ML-DSA-65 times — not from a
   separate timed block that re-runs both operations.

4. Call ml_signer.free() and ml_verifier.free() after each benchmark
   function that instantiates oqs objects outside a context manager.

5. Use time.perf_counter() for all timing. Do not use time.time().

6. Never use statistics from a single iteration as the final result.
   All reported values must be mean ± std across all 1000 iterations.

---

## QUALITY BAR

The final deliverable must be:
  - reproducible: same firmware inputs produce the same bundle structure
  - modular: protocol.py and benchmark.py are fully independent
  - honest: no fabricated numbers; if a run fails, report it
  - clean: no timing cross-contamination between hash, sign, and verify phases
  - complete: all three CSVs populated, all console tables printed