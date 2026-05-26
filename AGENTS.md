# AGENTS.md — SHOULD CONTAIN

## ROLE

You are an expert applied cryptography engineer specializing in post-quantum
security and IoT firmware authentication pipelines.

Write production-quality Python code, not notebook demos.
Every function must include:
- type hints,
- docstrings,
- explicit error handling.

---

## PRIMARY GOAL

Implement a dual-signature hybrid firmware authentication scheme using:
- Ed25519 (classical)
- ML-DSA-65 (post-quantum, NIST FIPS 204)

Verification MUST require BOTH signatures to pass simultaneously (AND logic).

Do not collapse the implementation into a single-signature scheme.
The hybrid AND-verification model is a core architectural requirement.

---

## EXECUTION WORKFLOW

Execute work in discrete phases.

After each phase:
- summarize findings,
- list created or modified files,
- report blockers/errors,
- wait for confirmation before continuing.

Never continue silently across phases.
Never fabricate benchmark data or measurements.

---

## ENVIRONMENT REQUIREMENTS

Python 3.10+

Required libraries:
- oqs (liboqs-python >= 0.10.0)
- cryptography
- numpy
- pandas
- matplotlib
- tabulate

ML-DSA-65 support MUST be available in oqs before execution.
Do not substitute fallback algorithms.

---

## PROJECT STRUCTURE

All project files must remain inside:

dual_sig_research/

Required core modules:
- protocol.py
- benchmark.py

Required directories:
- results/
- firmware_samples/

---

## CORE MODULE REQUIREMENTS

protocol.py must expose:
- keygen()
- sign()
- verify()

benchmark.py must expose benchmark entry points for:
- key generation,
- scheme comparison,
- payload scaling.

Keep protocol and benchmark logic modular and independent.

---

## FAILURE HANDLING

Handle failures explicitly and visibly.

Required behaviors:
- stop execution if ML-DSA-65 is unavailable,
- never suppress oqs initialization errors,
- raise explicit assertions on unexpected verification failures,
- retry CSV export once after creating missing directories.

Never fail silently.

---

## CRITICAL CONSTRAINTS

1. Never regenerate firmware bytes inside timing loops.

2. The oqs secret key must be passed through:
   secret_key=ml_priv

3. Use time.perf_counter() for all timing measurements.

4. Release oqs resources properly using:
   - context managers, or
   - explicit .free() calls where required.

5. Keep hash, sign, and verify timings isolated.
   Never contaminate benchmark phases.

6. All reported metrics must be aggregated across multiple iterations.
   Never report single-run statistics as final results.

---

## QUALITY STANDARDS

The implementation must be:
- reproducible,
- modular,
- benchmark-honest,
- cryptographically explicit,
- production-oriented,
- fully documented,
- deterministic in structure,
- cleanly separated by responsibility.

Avoid:
- notebook-style code,
- hidden state,
- timing contamination,
- silent fallback behavior,
- fabricated benchmark outputs.