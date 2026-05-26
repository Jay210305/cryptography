# Project Briefing: Dual-Signature Hybrid Authentication Scheme for IoT Firmware Signing

> **For:** Team members  
> **Purpose:** Full project overview — from research rationale to implementation details  
> **Sprint duration:** 2 weeks  
> **Final deliverable:** Bachelor-level preprint submitted to arXiv (cs.CR)

---

## Table of Contents

1. [What Are We Building and Why](#1-what-are-we-building-and-why)
2. [The Core Security Problem](#2-the-core-security-problem)
3. [Our Contribution](#3-our-contribution)
4. [Protocol Design — How It Works](#4-protocol-design--how-it-works)
5. [Security Guarantees and Threat Model](#5-security-guarantees-and-threat-model)
6. [2-Week Sprint Plan](#6-2-week-sprint-plan)
7. [Day-by-Day Schedule](#7-day-by-day-schedule)
8. [Implementation Guide](#8-implementation-guide)
9. [Benchmarking Plan](#9-benchmarking-plan)
10. [Paper Structure](#10-paper-structure)
11. [Tools & Environment Setup](#11-tools--environment-setup)
12. [References We Need](#12-references-we-need)
13. [Risk Management](#13-risk-management)
14. [Hard Scope Limits — What NOT to Do](#14-hard-scope-limits--what-not-to-do)

---

## 1. What Are We Building and Why

### Paper Title (working)

> **"A Hybrid Dual-Signature Authentication Scheme for IoT Firmware Integrity: Combining Ed25519 and ML-DSA for Classical and Post-Quantum Security"**

### The One-Sentence Summary

We are building, implementing, and benchmarking a firmware signing protocol that requires **two independent digital signatures** — one classical (Ed25519) and one post-quantum (ML-DSA-65) — to both be valid before a firmware update is accepted on an IoT device.

### Type of Paper

This is an **empirical + protocol design paper**, not a theoretical cryptography paper. We do **not** need to write new proofs. Our audience is applied security researchers, IoT security engineers, and systems practitioners. A clean protocol specification + reproducible benchmarks is sufficient contribution at the bachelor preprint level.

---

## 2. The Core Security Problem

### The Quantum Transition Problem

Right now, two worlds of cryptography exist side by side:

| Category | Example Algorithm | Strength | Weakness |
|---|---|---|---|
| Classical (current standard) | Ed25519, ECDSA | Fast, compact, battle-tested | Broken by Shor's algorithm on a quantum computer |
| Post-Quantum (new standard) | ML-DSA-65 (NIST FIPS 204) | Quantum-resistant | Larger keys/signatures, newer, less battle-tested |

Neither option is ideal **on its own** during this transition period:
- Using **only Ed25519**: fast and trusted, but a future quantum computer (CRQC) will break it.
- Using **only ML-DSA**: quantum-resistant, but if it has an undiscovered classical weakness, we're exposed today.

National agencies like **ANSSI** (France) and **NIST** (USA) explicitly recommend hybrid approaches until post-quantum cryptography fully matures.

### Why Firmware Signing Specifically?

Firmware signing is the **best** domain to apply a hybrid scheme because:

- Signatures are verified infrequently (once per firmware update, not per-packet), so the additional overhead of a second signature is fully acceptable.
- A compromised firmware signature can **brick devices** or create permanent backdoors — the stakes are very high.
- IoT devices have **long deployment lifetimes (5–15 years)**, meaning devices deployed today will still be running when quantum computers capable of breaking classical crypto may exist.
- The "Harvest Now, Decrypt Later" threat is real: an adversary can record signed firmware updates today and forge them later once quantum hardware is available.

### Our Core Claim

> A dual-signature scheme requiring **both** Ed25519 and ML-DSA-65 to verify simultaneously provides a stronger security guarantee than either scheme alone during the post-quantum transition, with overhead that is fully acceptable for firmware signing workflows.

---

## 3. Our Contribution

### What Already Exists in the Literature

- Hybrid key exchange schemes (X25519 + ML-KEM) — well documented
- Individual benchmarks of ML-DSA on embedded hardware — exist
- ANSSI and NIST recommendations for hybrid transitions — policy documents only
- Dual-signature ideas mentioned in surveys — but **rarely implemented and benchmarked for a specific domain**

### What Our Paper Adds

1. **A concrete, specified protocol** for dual-signature firmware authentication (not just a concept)
2. **Empirical benchmarks** comparing single vs. dual-signature performance across multiple payload sizes
3. **A domain-specific analysis** of why firmware signing tolerates the overhead where protocols like TLS handshakes would not
4. **An honest limitation analysis** scoping where the scheme does and does not apply

This is enough for a bachelor preprint. Benchmarking studies with novel application contexts are routinely published in applied security venues.

---

## 4. Protocol Design — How It Works

### Notation Reference

| Symbol | Meaning |
|---|---|
| `F` | Firmware binary blob |
| `H(F)` | SHA3-256 hash of the firmware |
| `sk_c, pk_c` | Classical Ed25519 signing/verification keypair |
| `sk_q, pk_q` | Post-quantum ML-DSA-65 signing/verification keypair |
| `sig_c` | Classical signature over H(F) |
| `sig_q` | Post-quantum signature over H(F) |
| `B` | Signed firmware bundle transmitted to the device |

---

### Phase 1 — Key Generation

Performed **once** by the firmware signing authority (the device manufacturer).

```
KeyGen():
  (sk_c, pk_c) ← Ed25519.KeyGen()
  (sk_q, pk_q) ← ML-DSA-65.KeyGen()

  Store securely:  (sk_c, sk_q)  → signing server (HSM or secure enclave)
  Distribute:      (pk_c, pk_q)  → embedded in device read-only memory at manufacturing time
```

**Key point:** Both keypairs are completely independent. Compromise of one does not expose the other. Key storage and distribution are explicitly **out of scope** for this paper (noted as future work).

---

### Phase 2 — Signing

Performed by the firmware release pipeline before distributing an update.

```
Sign(F, sk_c, sk_q):
  digest ← SHA3-256(F)                // hash the full firmware binary once
  sig_c  ← Ed25519.Sign(sk_c, digest)
  sig_q  ← ML-DSA-65.Sign(sk_q, digest)

  Bundle B ← {
    firmware:   F,
    digest:     digest,
    sig_c:      sig_c,
    pk_c:       pk_c,
    sig_q:      sig_q,
    pk_q:       pk_q,
    timestamp:  Unix timestamp,
    version:    firmware version string
  }

  return B
```

**Design decision:** Both signatures are computed over the **same hash** `H(F)`, not over each other. This keeps the two schemes fully independent and avoids unexpected cross-scheme interactions that could create attack surfaces.

---

### Phase 3 — Verification

Performed by the IoT device's bootloader or update daemon when it receives bundle `B`.

```
Verify(B):
  // Step 1: Recompute digest
  digest' ← SHA3-256(B.firmware)
  if digest' ≠ B.digest → REJECT ("Integrity failure")

  // Step 2: Verify classical signature
  result_c ← Ed25519.Verify(B.pk_c, B.digest, B.sig_c)
  if result_c = INVALID → REJECT ("Classical signature failure")

  // Step 3: Verify post-quantum signature
  result_q ← ML-DSA-65.Verify(B.pk_q, B.digest, B.sig_q)
  if result_q = INVALID → REJECT ("Post-quantum signature failure")

  // Step 4: Check public keys against trusted keys embedded in device
  if B.pk_c ≠ trusted_pk_c → REJECT ("Untrusted classical key")
  if B.pk_q ≠ trusted_pk_q → REJECT ("Untrusted PQ key")

  // Only if ALL checks pass:
  return ACCEPT
```

**Critical property:** The `AND` logic is the core security mechanism. An attacker must forge **both** signatures simultaneously to pass verification. Forging only one is not sufficient.

---

### Full Protocol Flow Diagram

```
 MANUFACTURER SIDE                         DEVICE SIDE
 ─────────────────                         ───────────

 [Firmware Binary F]
        │
        ▼
 SHA3-256(F) = digest
        │
        ├──────────────────────┐
        │                      │
        ▼                      ▼
 Ed25519.Sign(sk_c)     ML-DSA-65.Sign(sk_q)
        │                      │
        └──────────┬───────────┘
                   │
                   ▼
         Bundle B = {F, digest,
                     sig_c, pk_c,
                     sig_q, pk_q}
                   │
            (transmitted over network / stored on update server)
                   │
                   ▼
         ┌─── Verify(B) ───────────────────────────────┐
         │  1. SHA3-256(F) == digest?         → check  │
         │  2. Ed25519.Verify(sig_c)?         → check  │
         │  3. ML-DSA-65.Verify(sig_q)?       → check  │
         │  4. pk_c == trusted_pk_c?          → check  │
         │  5. pk_q == trusted_pk_q?          → check  │
         │  ALL pass → ACCEPT firmware                 │
         │  ANY fail → REJECT, abort update            │
         └─────────────────────────────────────────────┘
```

### Design Rationale — FAQ

| Design Choice | Reason |
|---|---|
| SHA3-256 instead of SHA-256 | Consistent with ML-DSA's internal hash family |
| ML-DSA-65 instead of ML-DSA-44 or ML-DSA-87 | NIST Level 3 security — the best balance between performance and security margin |
| Ed25519 instead of ECDSA P-256 | Faster, smaller signatures, deterministic, same 128-bit security level |
| Sign the hash, not the raw firmware | Standard practice; significantly more efficient for large payloads |
| Independent signatures (not one signing the other) | Avoids cross-scheme coupling; keeps security reduction clean |

---

## 5. Security Guarantees and Threat Model

### Properties Claimed

| Property | Description | How Achieved |
|---|---|---|
| **Unforgeability** | Attacker cannot create a valid bundle for malicious firmware | Must forge both sig_c AND sig_q simultaneously |
| **Classical security** | Secure against non-quantum adversaries today | Ed25519 based on ECDLP hardness (128-bit security) |
| **Post-quantum security** | Secure against quantum adversaries | ML-DSA-65 based on M-SIS/M-LWE lattice hardness (NIST Level 3) |
| **Transitional robustness** | Secure even if one primitive is broken | AND logic — single-scheme failure is insufficient for an attacker |
| **Firmware integrity** | Payload cannot be silently modified in transit | SHA3-256 digest checked before signature verification |

### Threat Scenarios

**Scenario A — Classical adversary (today):**
Cannot break Ed25519 (ECDLP is hard classically). Even if ML-DSA has an unknown classical weakness, Ed25519 holds. → **SECURE**

**Scenario B — Quantum adversary (future CRQC):**
Shor's algorithm breaks Ed25519. ML-DSA-65 remains secure (lattice problems are quantum-resistant). → **SECURE**

**Scenario C — Both schemes broken (hypothetical):**
An adversary with both a CRQC and a lattice-breaking algorithm. → **NOT SECURE** — acknowledged as residual risk. Mitigation via crypto-agility (future work).

**Scenario D — Implementation attacks (side-channel, fault injection):**
Out of scope. Explicitly acknowledged in the limitations section.

### What We Do NOT Claim

- We do **not** claim formal provable security reductions
- We do **not** address key management, revocation, or PKI design
- We do **not** address physical device security
- We do **not** claim this is the optimal scheme — only that it is **strictly better** than single-scheme alternatives during the quantum transition period

---

## 6. 2-Week Sprint Plan

### Week 1 — Foundation, Design, Implementation

| Days | Focus | Output |
|---|---|---|
| 1–2 | Targeted literature reading | Annotated bibliography (8–12 sources) |
| 3 | Protocol design on paper (no code) | Final protocol specification |
| 4–5 | Python implementation | Working protocol.py + benchmark.py |
| 6–7 | Run all experiments + collect data | Complete results tables + raw CSV data |

### Week 2 — Writing, Analysis, Submission

| Days | Focus | Output |
|---|---|---|
| 8–9 | Write Methodology + Results sections | 2 complete sections drafted |
| 10–11 | Write Security Analysis + Background | 2 more sections drafted |
| 12 | Write Introduction + Abstract | Full first draft complete |
| 13 | Full revision pass + figure generation | Polished draft |
| 14 | Final read-through + preprint submission | Submitted to arXiv |

---

## 7. Day-by-Day Schedule

### Day 1 — Literature Setup

**Goal:** Identify exactly what to read. Do not read everything.

- Set up Zotero or a `.bib` file for citation management
- Download and **skim** (abstracts + conclusions only) these papers:
  - ANSSI PQC transition guidelines
  - arXiv:2509.10551 — Hybrid Encryption Framework
  - MDPI Cryptography 2025 — Post-Quantum PKI benchmarking
  - liboqs GitHub README and ML-DSA documentation
- Write 2–3 bullet points per paper: *What did they do? What did they NOT do?*

**End-of-day check:** Can you name 3 papers that motivate our work and 2 gaps they leave?

---

### Day 2 — Literature Consolidation + Gap Articulation

**Goal:** Write the "gap" paragraph that justifies the paper.

- Read (fully) Section 2.1 of the background document for ML-DSA background
- Read the NIST FIPS 204 summary (intro section only)
- Write a 200-word paragraph: *"Why does a dual-signature firmware scheme not exist as a concrete, benchmarked implementation in the literature?"*
- Confirm final use case: **firmware update signing for IoT devices**
- Set up Overleaf with IEEE conference template (two-column)

**End-of-day check:** Is the gap paragraph written? Is Overleaf ready?

---

### Day 3 — Protocol Design (No Code Yet)

**Goal:** Write the complete protocol specification on paper before touching a keyboard.

- Draw the protocol flow diagram by hand first
- Write out all three phases (KeyGen, Sign, Verify) in pseudocode
- Answer these design questions explicitly (your answers will go directly in the paper):
  - Why SHA3-256 and not SHA-256?
  - Why ML-DSA-65 and not ML-DSA-44 or ML-DSA-87?
  - Why Ed25519 and not ECDSA P-256?
  - Why sign the hash and not the raw firmware?
- Write the Bundle B structure with all fields and their estimated sizes
- Write the verification logic with all failure modes labeled

**Do NOT start coding today.** A protocol designed on paper catches logical errors early.

**End-of-day check:** Can you walk through the protocol verbally from memory without notes?

---

### Day 4 — Environment Setup + Skeleton Code

**Goal:** Get the environment working and write the code structure (no logic yet).

- Install required libraries:

```bash
pip install oqs cryptography numpy pandas matplotlib tabulate
```

- Verify the installation:

```python
import oqs
print(oqs.get_enabled_sig_mechanisms())  # must list ML-DSA variants
```

- Create the project folder structure:

```
dual_sig_research/
├── protocol.py
├── benchmark.py
├── results/
│   ├── raw_data.csv
│   └── figures/
├── firmware_samples/
│   ├── firmware_1kb.bin
│   ├── firmware_10kb.bin
│   ├── firmware_100kb.bin
│   └── firmware_1mb.bin
└── notes/
    └── protocol_spec.md
```

- Generate test firmware blobs (random bytes, done once):

```python
import os
for size in [1024, 10240, 102400, 1048576]:
    with open(f'firmware_{size//1024}kb.bin', 'wb') as f:
        f.write(os.urandom(size))
```

- Write `protocol.py` with function stubs (signatures + docstrings only, no logic)

**End-of-day check:** Does `import oqs` work? Does ML-DSA-65 appear in the enabled mechanisms?

---

### Day 5 — Full Implementation

**Goal:** Complete working implementation of all three protocol phases.

- Implement `keygen()`, `sign()`, and `verify()` in `protocol.py`
- Write a sanity test to confirm correctness:

```python
pk_c, sk_c, pk_q, sk_q = keygen()
bundle = sign('firmware_samples/firmware_1kb.bin', sk_c, sk_q)
assert verify(bundle, pk_c, pk_q) == True

# Test rejection with tampered firmware
bundle['firmware'] = b'malicious firmware'
assert verify(bundle, pk_c, pk_q) == False

print("All sanity tests passed.")
```

- Implement `benchmark.py` with timing using `time.perf_counter()`
- Benchmark runs **1000 iterations** per scenario and records mean ± std deviation

**End-of-day check:** Does the sanity test pass? Does tampered firmware get correctly rejected?

---

### Day 6 — Run All Experiments

**Goal:** Collect all data needed for the results section.

**Experiment 1 — Scheme Comparison (1KB firmware, 1000 iterations):**
- Ed25519 only: keygen time, sign time, verify time, signature size, public key size
- ML-DSA-65 only: same metrics
- Hybrid (both): same metrics

**Experiment 2 — Payload Size Scaling (hybrid only):**
- Run sign + verify for: 1KB, 10KB, 100KB, 1MB
- Record how sign time scales (should be roughly linear)
- Record how verify time scales (should be nearly flat — hash-dominated)

**Experiment 3 — Bundle Size Analysis:**
- For each payload size, record total bundle size in bytes
- Break down: firmware + sig_c + sig_q + pk_c + pk_q
- Calculate overhead %: `(bundle_size - firmware_size) / firmware_size * 100`

**Save all results to CSV immediately.** Do not rely on terminal output.

**End-of-day check:** Are all 3 experiments complete with data saved to CSV?

---

### Day 7 — Data Analysis + Figure Generation

**Goal:** Transform raw data into tables and figures for the paper.

- **Figure 1:** Bar chart — KeyGen/Sign/Verify times across all three schemes (1KB)
- **Figure 2:** Line chart — Sign time vs. payload size (1KB → 1MB) for hybrid scheme
- **Figure 3:** Stacked bar chart — Bundle size breakdown by component
- **Table 1:** Scheme comparison (all metrics, three schemes)
- **Table 2:** Payload scaling results

Sanity-check all numbers against expected values from literature:

| Metric | Expected Value |
|---|---|
| Ed25519 sign time | ~0.05–0.2 ms |
| ML-DSA-65 sign time | ~1–5 ms |
| Ed25519 signature size | 64 bytes |
| ML-DSA-65 signature size | ~3,293 bytes |

**End-of-day check:** Are all figures saved as PDF/PNG? Are all tables complete?

---

### Days 8–9 — Write Methodology + Results Sections

- Transfer protocol pseudocode from Day 3 notes into LaTeX
- Write rationale paragraph for each design choice
- Write implementation subsection: libraries used, language, hardware spec
- Embed all figures and tables into LaTeX
- Write one paragraph per experiment describing what the data shows
- Write a synthesis paragraph: *"Taken together, these results demonstrate that..."*

---

### Days 10–11 — Write Security Analysis + Background

- Security Analysis: one paragraph per threat scenario + a clear "what we do NOT claim" paragraph + limitations paragraph
- Background: The quantum threat → Ed25519 → ML-DSA → Hybrid approaches → Gap/related work

**Tone guidance:** Be confident about what we DO show. Be precise about what we don't. A clear limitations paragraph makes reviewers trust you more, not less.

---

### Day 12 — Write Introduction + Abstract + Conclusion

**Introduction structure:**
1. Motivate the problem (quantum threat + long IoT device lifespans)
2. Identify the gap (no concrete dual-signature firmware scheme exists)
3. State contributions (what we did + what we found)
4. Road map sentence: *"The remainder of this paper is organized as follows..."*

**Abstract structure (~150 words):**
- Sentence 1: Problem
- Sentence 2: Gap
- Sentence 3: What we propose
- Sentence 4: How we evaluated it
- Sentence 5: Key finding (your main benchmark number)
- Sentence 6: Conclusion/implication

**Conclusion should list 3–4 concrete future work directions:**
- Hardware benchmarking on ARM Cortex-M4
- Key management and revocation protocol design
- Formal verification with ProVerif
- Crypto-agility layer for algorithm substitution

---

### Day 13 — Full Revision Pass

Revision checklist:
- [ ] Read the entire paper out loud — mark awkward sentences
- [ ] Every figure and table is referenced in the text
- [ ] Every claim has a citation
- [ ] All algorithm names are consistent — use **ML-DSA-65**, never "Dilithium"; **ML-KEM**, never "Kyber"
- [ ] All numbers in text match the tables
- [ ] Abstract matches the actual paper content
- [ ] Generate PDF and check for layout issues
- [ ] Count pages — target is **6–8 pages** in IEEE format

---

### Day 14 — Final Polish + Submission

- Fix all Day 13 issues
- Generate final PDF
- Double-check author information, institution, date
- Submit to **arXiv** (cs.CR category) — recommended for maximum visibility
- Share the arXiv link with your supervisor

---

## 8. Implementation Guide

### Core File: `protocol.py`

```python
import oqs
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)

def keygen():
    """
    Generate keypairs for both signature schemes.
    Returns: (pk_c_bytes, sk_c, pk_q_bytes, sk_q_bytes)
    """
    # Classical Ed25519
    sk_c = Ed25519PrivateKey.generate()
    pk_c = sk_c.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Post-quantum ML-DSA-65
    with oqs.Signature("ML-DSA-65") as signer:
        pk_q = signer.generate_keypair()
        sk_q = signer.export_secret_key()

    return pk_c, sk_c, pk_q, sk_q


def sign(firmware_bytes: bytes, sk_c, sk_q_bytes: bytes) -> dict:
    """
    Sign firmware with both schemes.
    Returns a bundle dictionary.
    """
    digest = hashlib.sha3_256(firmware_bytes).digest()
    sig_c = sk_c.sign(digest)

    with oqs.Signature("ML-DSA-65", sk_q_bytes) as signer:
        sig_q = signer.sign(digest)

    pk_c = sk_c.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return {
        'firmware': firmware_bytes,
        'digest': digest,
        'sig_c': sig_c,
        'sig_q': sig_q,
    }


def verify(bundle: dict, trusted_pk_c: bytes, trusted_pk_q: bytes) -> bool:
    """
    Verify a firmware bundle. Returns True only if ALL checks pass.
    """
    # Step 1: Integrity check
    computed = hashlib.sha3_256(bundle['firmware']).digest()
    if computed != bundle['digest']:
        return False

    # Step 2: Classical verification
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pk_c_obj = Ed25519PublicKey.from_public_bytes(trusted_pk_c)
        pk_c_obj.verify(bundle['sig_c'], bundle['digest'])
    except Exception:
        return False

    # Step 3: Post-quantum verification
    with oqs.Signature("ML-DSA-65") as verifier:
        valid_q = verifier.verify(bundle['digest'], bundle['sig_q'], trusted_pk_q)
    if not valid_q:
        return False

    return True  # Only reached if ALL checks pass
```

### Core File: `benchmark.py`

```python
import time
import os
import csv
import numpy as np
from protocol import keygen, sign, verify

ITERATIONS = 1000
PAYLOAD_SIZES = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB

def benchmark_scheme(scheme_name: str, firmware: bytes, iterations: int) -> dict:
    """Run timing benchmark for a given scheme configuration."""
    pk_c, sk_c, pk_q, sk_q = keygen()

    keygen_times, sign_times, verify_times = [], [], []

    for _ in range(iterations):
        t0 = time.perf_counter()
        pk_c, sk_c, pk_q, sk_q = keygen()
        keygen_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        bundle = sign(firmware, sk_c, sk_q)
        sign_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        result = verify(bundle, pk_c, pk_q)
        verify_times.append(time.perf_counter() - t0)

        assert result == True

    return {
        'scheme': scheme_name,
        'payload_size_bytes': len(firmware),
        'keygen_mean_ms': np.mean(keygen_times) * 1000,
        'keygen_std_ms': np.std(keygen_times) * 1000,
        'sign_mean_ms': np.mean(sign_times) * 1000,
        'sign_std_ms': np.std(sign_times) * 1000,
        'verify_mean_ms': np.mean(verify_times) * 1000,
        'verify_std_ms': np.std(verify_times) * 1000,
        'sig_size_bytes': len(bundle['sig_c']) + len(bundle.get('sig_q', b'')),
    }
```

### Critical Implementation Rules

1. **Never regenerate firmware bytes inside a timing loop.** Generate once per payload size before the iteration loop starts.
2. **Pass the oqs secret key to the `Signature()` constructor** as `secret_key=ml_priv` — never assign it as an attribute after init.
3. **Use `time.perf_counter()`** for all timing. Do not use `time.time()`.
4. **All reported values must be mean ± std across all 1000 iterations.** Never use a single iteration as the final result.
5. **Call `ml_signer.free()` and `ml_verifier.free()`** after each benchmark function that instantiates oqs objects outside a context manager.
6. **Hybrid sign time** must be derived from per-iteration sums of the already-measured Ed25519 and ML-DSA-65 times — not from a separate timed block that re-runs both operations.

---

## 9. Benchmarking Plan

### Three Benchmark Phases

**Phase 1 — Key Generation Benchmark**

Run 1000 iterations of full hybrid keygen (Ed25519 + ML-DSA-65). Report mean ± std.

Output CSV columns: `iteration, keygen_time_ms`

---

**Phase 2 — Scheme Comparison (1KB Payload)**

Run 1000 iterations for each of three configurations on a 1KB firmware payload:
- Ed25519-only
- ML-DSA-65-only
- Hybrid (both)

Timing rules:
- Hash time: timed separately for all three schemes
- Sign time: crypto only, **after** hashing (hash time excluded)
- Verify time: crypto only (hash time excluded)

Bundle size per scheme (compute once, not per iteration):

| Scheme | Bundle = firmware + ... |
|---|---|
| Ed25519-only | digest(32) + sig_ed(64) + pk_ed(32) |
| ML-DSA-65-only | digest(32) + sig_ml(~3309) + pk_ml(1952) |
| Hybrid | digest(32) + sig_ed(64) + sig_ml(~3309) + pk_ed(32) + pk_ml(1952) |

Output CSV columns: `scheme, mean_sign_ms, std_sign_ms, mean_verify_ms, std_verify_ms, bundle_bytes, overhead_pct`

---

**Phase 3 — Payload Scaling (Hybrid Only)**

Run 1000 iterations per payload size: 1KB, 10KB, 100KB, 1MB.

Output CSV columns: `fw_size_bytes, mean_hash_ms, mean_sign_ms, std_sign_ms, mean_verify_ms, std_verify_ms, bundle_bytes, overhead_pct`

### Expected Results (Pre-Experiment Estimates)

| Metric | Ed25519 | ML-DSA-65 | Hybrid |
|---|---|---|---|
| KeyGen | ~0.1 ms | ~1–2 ms | ~1–2 ms |
| Sign (1KB) | ~0.1 ms | ~2–4 ms | ~2–4 ms |
| Verify (1KB) | ~0.1 ms | ~1–2 ms | ~1–2 ms |
| Signature size | 64 bytes | 3,293 bytes | 3,357 bytes |
| Public key size | 32 bytes | 1,952 bytes | 1,984 bytes |

*These are estimates. Actual measured results will fill the paper's tables.*

### Figures to Generate

| Figure | Type | What It Shows |
|---|---|---|
| Figure 1 | Grouped bar chart | KeyGen/Sign/Verify times across 3 schemes (1KB payload) |
| Figure 2 | Line chart | Sign time vs. payload size (1KB → 1MB), hybrid scheme |
| Figure 3 | Stacked bar chart | Bundle size breakdown by component |
| Figure 4 (optional) | Heatmap table | Overhead % across payload sizes |

---

## 10. Paper Structure

### Final Paper Layout (IEEE Two-Column, ~7 pages)

```
Title + Authors + Abstract                              (~150 words)

I.   INTRODUCTION                                       (~0.5 pages)
     A. The Quantum Transition Problem
     B. Why Firmware Signing is Critical
     C. Paper Contributions

II.  BACKGROUND AND RELATED WORK                        (~1.5 pages)
     A. The Quantum Threat to Asymmetric Cryptography
     B. Ed25519: Properties and Security
     C. ML-DSA: The Post-Quantum Standard
     D. Hybrid Schemes: State of the Art
     E. Gap: Firmware-Specific Dual-Signature Schemes

III. PROPOSED DUAL-SIGNATURE PROTOCOL                   (~1.5 pages)
     A. System Model and Assumptions
     B. Key Generation Phase
     C. Signing Phase
     D. Verification Phase
     E. Design Rationale

IV.  EXPERIMENTAL EVALUATION                            (~1.5 pages)
     A. Implementation Setup
     B. Benchmarking Methodology
     C. Scheme Comparison Results (Table I + Figure 1)
     D. Payload Scaling Results (Table II + Figure 2)
     E. Bundle Overhead Analysis (Figure 3)

V.   SECURITY ANALYSIS                                  (~1 page)
     A. Threat Model
     B. Classical Adversary Resistance
     C. Quantum Adversary Resistance
     D. Transitional Security Properties
     E. Limitations and Scope

VI.  DISCUSSION                                         (~0.5 pages)
     A. Suitability for Firmware Signing Specifically
     B. Comparison with Related Hybrid Approaches
     C. Future Work

VII. CONCLUSION                                         (~0.25 pages)

REFERENCES                                              (8–12 sources)
```

### Writing Order (counterintuitive but faster)

| Order | Section | Day |
|---|---|---|
| 1 | III — Protocol | Day 8 |
| 2 | IV — Results | Day 9 |
| 3 | V — Security Analysis | Day 10 |
| 4 | II — Background | Day 11 |
| 5 | I — Introduction | Day 12 |
| 6 | Abstract | Day 12 |
| 7 | VI + VII — Discussion + Conclusion | Day 12 |

### Word Count Targets

| Section | Target Words |
|---|---|
| Abstract | 150 |
| Introduction | 400 |
| Background | 700 |
| Protocol | 700 |
| Evaluation | 700 |
| Security Analysis | 500 |
| Discussion | 300 |
| Conclusion | 200 |
| **Total** | **~3,650 words** |

This fits approximately 7 pages in IEEE two-column format when combined with figures and tables.

---

## 11. Tools & Environment Setup

### Technology Stack

| Component | Tool | Reason |
|---|---|---|
| Programming language | Python 3.10+ | Fast to write, liboqs bindings available |
| PQC algorithms | `liboqs` + `oqs-python` (≥ 0.10.0) | Official OQS project, includes FIPS 204 ML-DSA |
| Classical crypto | `cryptography` (PyCA) | Industry standard, includes Ed25519 |
| Hashing | `hashlib` (stdlib) | SHA3-256 built-in |
| Benchmarking | `time.perf_counter()` | High-resolution, cross-platform |
| Data storage | `pandas` + CSV | Reproducible, easy to share |
| Figures | `matplotlib` | Standard, sufficient for preprint |
| Paper writing | Overleaf + IEEE template | Handles two-column formatting automatically |
| Citations | BibTeX / Zotero | Consistent citation format |

### Installation

```bash
# Python environment setup
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

# Install dependencies
pip install oqs cryptography numpy pandas matplotlib tabulate

# Verify oqs
python -c "import oqs; print('OQS version:', oqs.oqs_version())"
python -c "import oqs; sigs = oqs.get_enabled_sig_mechanisms(); print([s for s in sigs if 'ML-DSA' in s])"
```

If ML-DSA-65 does **not** appear in the output, **stop** and do not proceed with a fallback scheme. Use Docker as a fallback: `openquantumsafe/oqs-demos`.

### Overleaf Setup

1. Go to overleaf.com → New Project → Upload Project
2. Upload the IEEE Conference template (search "IEEEtran" on Overleaf templates)
3. Set compiler to **pdfLaTeX**
4. Create: `main.tex`, `references.bib`, `figures/` folder

### Useful LaTeX Snippets

**Algorithm pseudocode:**
```latex
\usepackage{algorithm}
\usepackage{algpseudocode}
```

**Comparison table:**
```latex
\begin{table}[t]
\caption{Signature Scheme Performance Comparison}
\label{tab:comparison}
\centering
\begin{tabular}{lccc}
\hline
\textbf{Metric} & \textbf{Ed25519} & \textbf{ML-DSA-65} & \textbf{Hybrid} \\
\hline
Sign (ms)    & X.XX & X.XX & X.XX \\
Verify (ms)  & X.XX & X.XX & X.XX \\
Sig size (B) & 64   & 3293 & 3357 \\
\hline
\end{tabular}
\end{table}
```

---

## 12. References We Need

Aim for **10–12 references total**. These are the priority targets:

| # | Source | Why Needed |
|---|---|---|
| 1 | NIST FIPS 204 (ML-DSA standard) | Authoritative source for ML-DSA |
| 2 | ANSSI PQC Transition Guidelines | Motivates hybrid requirement |
| 3 | arXiv:2509.10551 (Hybrid Encryption Framework) | Closest related work |
| 4 | MDPI Cryptography — PQC PKI Benchmarks | Benchmarking baseline |
| 5 | RFC 8032 — Ed25519 specification | Authoritative source for Ed25519 |
| 6 | liboqs paper / OQS project reference | Implementation reference |
| 7 | Shor's algorithm original paper (1994) | Quantum threat motivation |
| 8 | NIST PQC standardization announcement 2024 | Standards context |
| 9 | IoT security / firmware attack case study | Domain motivation |
| 10 | PQC survey paper (arXiv:2508.16078) | Related work |

**Rule:** Every factual claim in the paper needs a citation. Do not leave unsupported assertions.

**Naming convention:** Always use standardized NIST names in the paper:
- ✅ ML-DSA-65 — ❌ Dilithium
- ✅ ML-KEM — ❌ Kyber
- ✅ SLH-DSA — ❌ SPHINCS+

---

## 13. Risk Management

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| `oqs` installation fails on your OS | Medium | High | Use Docker with `openquantumsafe/oqs-demos` image |
| Benchmark results differ from expected | Low | Low | Report actual numbers — unexpected results are still valid data |
| Paper too long (>8 pages) | Medium | Medium | Cut Discussion section, merge with Conclusion |
| Paper too short (<6 pages) | Low | Medium | Expand security analysis, add more payload size tests |
| Not enough time for all figures | Medium | Low | Prioritize Table I; figures are secondary |
| Writer's block | Medium | High | Use day-by-day targets strictly; write badly first, fix later |
| liboqs ML-DSA version mismatch with FIPS 204 | Low | Medium | Ensure `oqs` version ≥ 0.10.0 which includes FIPS-compliant ML-DSA |

---

## 14. Hard Scope Limits — What NOT to Do

These are **explicitly out of scope**. If you find yourself doing any of these, stop and return to the plan.

- ❌ Do NOT implement ASCON or any hash function substitution
- ❌ Do NOT add a third signature scheme
- ❌ Do NOT implement QPSO, BQS, or any AI optimization layer
- ❌ Do NOT design a PKI or certificate revocation system
- ❌ Do NOT propose a new or modified cryptographic primitive
- ❌ Do NOT attempt formal proofs (ProVerif, Tamarin) — acknowledge as future work
- ❌ Do NOT benchmark on physical embedded hardware — desktop is fine for a preprint
- ❌ Do NOT write more than 8 pages — cut content before adding
- ❌ Do NOT read more than 12 papers — depth over breadth

---

## Final Submission Checklist

- [ ] Abstract accurately describes the paper content
- [ ] All figures have captions and are referenced in the text
- [ ] All tables have captions and are referenced in the text
- [ ] All numerical claims in text match the tables
- [ ] All algorithm names use standardized NIST names (ML-DSA-65, not Dilithium)
- [ ] Limitations section is present and honest
- [ ] References are complete with correct metadata
- [ ] PDF compiles without errors in Overleaf
- [ ] Paper is between 6 and 8 pages
- [ ] Author name, institution, and date are correct on the title page
- [ ] Submitted to arXiv cs.CR or institutional repository
- [ ] arXiv link shared with supervisor

---

*This document was compiled from the research plan and implementation specification for team reference. Target submission: arXiv cs.CR.*