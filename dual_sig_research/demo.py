"""
Interactive visual demo of Scenario A — single terminal.

Shows step-by-step: user input → hash → sign → KEM → encrypt → MITM interception → decrypt → verify.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from typing import Any

from protocol import (
    CIPHER_AES,
    CIPHER_CHACHA,
    ML_DSA_ALG,
    ML_KEM_ALG,
    FirmwareBundle,
    SecurePacket,
    _require_ml_dsa,
    _require_ml_kem,
    decrypt_payload,
    deserialize_packet,
    encrypt_payload,
    hash_firmware,
    hybrid_kem_decapsulate,
    hybrid_kem_encapsulate,
    keygen,
    pack_signed_payload,
    select_cipher,
    serialize_packet,
    sign,
    verify,
)

# ---------------------------------------------------------------------------
# ANSI colors for terminal
# ---------------------------------------------------------------------------

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_DARK = "\033[40m"


def _hr(char: str = "─", width: int = 72) -> str:
    return char * width


def _box(title: str, content: str, color: str = CYAN) -> None:
    print(f"\n{color}{BOLD}┌{'─' * 70}┐{RESET}")
    print(f"{color}{BOLD}│ {title:<68} │{RESET}")
    print(f"{color}{BOLD}├{'─' * 70}┤{RESET}")
    for line in content.split("\n"):
        truncated = line[:68]
        print(f"{color}│{RESET} {truncated:<68} {color}│{RESET}")
    print(f"{color}{BOLD}└{'─' * 70}┘{RESET}")


def _step(number: int, title: str) -> None:
    print(f"\n{YELLOW}{BOLD}{'═' * 72}{RESET}")
    print(f"{YELLOW}{BOLD}  STEP {number}: {title}{RESET}")
    print(f"{YELLOW}{BOLD}{'═' * 72}{RESET}")


_interactive = True


def _pause() -> None:
    if not _interactive:
        return
    print(f"\n{DIM}  Press Enter to continue...{RESET}", end="")
    try:
        input()
    except EOFError:
        pass


def _hex_block(data: bytes, label: str, color: str = DIM, max_lines: int = 4) -> None:
    hex_str = data.hex()
    line_width = 64
    lines = [hex_str[i:i + line_width] for i in range(0, len(hex_str), line_width)]
    print(f"  {BOLD}{label}{RESET} ({len(data)} bytes):")
    for i, line in enumerate(lines[:max_lines]):
        formatted = " ".join(line[j:j+2] for j in range(0, len(line), 2))
        print(f"  {color}{formatted}{RESET}")
    if len(lines) > max_lines:
        print(f"  {color}... ({len(lines) - max_lines} more lines){RESET}")


def _arrow(msg: str) -> None:
    print(f"\n  {GREEN}{BOLD}>>> {msg}{RESET}")


def _alert(msg: str) -> None:
    print(f"\n  {RED}{BOLD}[!] {msg}{RESET}")


def _ok(msg: str) -> None:
    print(f"\n  {GREEN}{BOLD}[✓] {msg}{RESET}")


def _info(msg: str) -> None:
    print(f"  {CYAN}• {msg}{RESET}")


# ---------------------------------------------------------------------------
# Demo flow
# ---------------------------------------------------------------------------


def main() -> None:
    os.system("")  # enable ANSI on Windows
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    print(f"\n{BOLD}{MAGENTA}{'=' * 72}{RESET}")
    print(f"{BOLD}{MAGENTA}   HYBRID POST-QUANTUM FIRMWARE SECURITY -- INTERACTIVE DEMO{RESET}")
    print(f"{BOLD}{MAGENTA}   Scenario A: Manufacturer -> MITM Proxy -> IoT Device{RESET}")
    print(f"{BOLD}{MAGENTA}{'=' * 72}{RESET}")
    print(f"\n{WHITE}  Protocol: SIGN -> THEN -> ENCRYPT{RESET}")
    print(f"{WHITE}  Signatures: Ed25519 + ML-DSA-65 (AND logic){RESET}")
    print(f"{WHITE}  KEM: X25519 + ML-KEM-768 (hybrid){RESET}")
    print(f"{WHITE}  AEAD: ChaCha20-Poly1305 / AES-256-GCM (adaptive){RESET}")

    global _interactive
    if "--no-pause" in sys.argv:
        _interactive = False

    _require_ml_dsa()
    _require_ml_kem()

    # --- User input ---
    _step(1, "FIRMWARE INPUT")
    print(f"\n  {WHITE}Type a message to simulate firmware content.{RESET}")
    print(f"  {DIM}(Or press Enter for random 1KB binary){RESET}\n")
    try:
        user_input = input(f"  {BOLD}Firmware payload > {RESET}")
    except EOFError:
        user_input = ""

    if user_input.strip():
        firmware = user_input.encode("utf-8")
        print(f"\n  {DIM}Using your message as firmware ({len(firmware)} bytes){RESET}")
    else:
        firmware = os.urandom(1024)
        print(f"\n  {DIM}Generated random firmware ({len(firmware)} bytes){RESET}")

    _hex_block(firmware[:64], "Firmware (first 64 bytes)", BLUE)
    _pause()

    # --- Key generation ---
    _step(2, "KEY GENERATION")
    print(f"\n  {WHITE}Generating cryptographic keys for manufacturer and IoT device...{RESET}\n")

    t0 = time.perf_counter_ns()
    manufacturer = keygen()
    mfg_time = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    device = keygen()
    dev_time = (time.perf_counter_ns() - t0) / 1e6

    _box("MANUFACTURER KEYS", "\n".join([
        f"Ed25519 public key:  {manufacturer['pk_c'].hex()[:48]}...",
        f"ML-DSA-65 public key: {manufacturer['pk_q'].hex()[:48]}...",
        f"X25519 public key:   {manufacturer['pk_x'].hex()}",
        f"ML-KEM-768 pub key:  {manufacturer['pk_kem'].hex()[:48]}...",
        f"",
        f"Key sizes: Ed25519={len(manufacturer['pk_c'])}B, ML-DSA={len(manufacturer['pk_q'])}B,",
        f"           X25519={len(manufacturer['pk_x'])}B, ML-KEM={len(manufacturer['pk_kem'])}B",
        f"Generation time: {mfg_time:.3f} ms",
    ]), BLUE)

    _box("IoT DEVICE KEYS", "\n".join([
        f"Ed25519 public key:  {device['pk_c'].hex()[:48]}...",
        f"ML-DSA-65 public key: {device['pk_q'].hex()[:48]}...",
        f"X25519 public key:   {device['pk_x'].hex()}",
        f"ML-KEM-768 pub key:  {device['pk_kem'].hex()[:48]}...",
        f"",
        f"Generation time: {dev_time:.3f} ms",
    ]), MAGENTA)

    _pause()

    # --- Hashing ---
    _step(3, "FIRMWARE HASHING (SHA3-256)")
    digest = hash_firmware(firmware)
    _info(f"Algorithm: SHA3-256")
    _info(f"Input size: {len(firmware)} bytes")
    _hex_block(digest, "SHA3-256 Digest", GREEN)
    _pause()

    # --- Signing ---
    _step(4, "HYBRID DIGITAL SIGNATURE (Ed25519 + ML-DSA-65)")
    print(f"\n  {WHITE}Signing the digest with BOTH algorithms (AND-security model):{RESET}")
    print(f"  {WHITE}VALID = Ed25519_OK AND ML-DSA-65_OK{RESET}\n")

    t0 = time.perf_counter_ns()
    bundle = sign(firmware, manufacturer["sk_c"], manufacturer["sk_q"], manufacturer["pk_q"])
    sign_time = (time.perf_counter_ns() - t0) / 1e6

    _hex_block(bundle["sig_c"], "Ed25519 Signature", BLUE)
    print()
    _hex_block(bundle["sig_q"][:128], "ML-DSA-65 Signature (first 128 bytes)", MAGENTA)
    print()
    _info(f"Ed25519 signature size: {len(bundle['sig_c'])} bytes")
    _info(f"ML-DSA-65 signature size: {len(bundle['sig_q'])} bytes")
    _info(f"Total signing time: {sign_time:.3f} ms")
    _ok("Both signatures created successfully")
    _pause()

    # --- Payload construction ---
    _step(5, "PAYLOAD CONSTRUCTION")
    plaintext = pack_signed_payload(bundle)
    _info(f"Firmware + digest + signatures + public keys → MessagePack")
    _info(f"Signed payload size: {len(plaintext)} bytes")
    _hex_block(plaintext[:64], "Signed payload (first 64 bytes)", DIM)
    _pause()

    # --- KEM ---
    _step(6, "HYBRID KEY ENCAPSULATION (X25519 + ML-KEM-768)")
    print(f"\n  {WHITE}Encapsulating shared secret to IoT device's public keys...{RESET}\n")

    t0 = time.perf_counter_ns()
    x_pub, mlkem_ct, sym_key = hybrid_kem_encapsulate(device["pk_x"], device["pk_kem"])
    kem_time = (time.perf_counter_ns() - t0) / 1e6

    _hex_block(x_pub, "Ephemeral X25519 public key", CYAN)
    print()
    _hex_block(mlkem_ct[:64], "ML-KEM-768 ciphertext (first 64 bytes)", MAGENTA)
    print()
    _hex_block(sym_key, "Derived symmetric key (HKDF-SHA3-256)", GREEN)
    print()
    _info(f"X25519 ephemeral key: {len(x_pub)} bytes")
    _info(f"ML-KEM-768 ciphertext: {len(mlkem_ct)} bytes")
    _info(f"Symmetric key: {len(sym_key)} bytes (256-bit)")
    _info(f"KEM encapsulation time: {kem_time:.3f} ms")
    _ok("Shared secret established via hybrid KEM")
    _pause()

    # --- Encryption ---
    _step(7, "ADAPTIVE SYMMETRIC ENCRYPTION")
    cipher_id = select_cipher(len(plaintext))
    _info(f"Payload size: {len(plaintext)} bytes")
    _info(f"Threshold: 100 KB")
    if cipher_id == CIPHER_CHACHA:
        _info(f"Selected: ChaCha20-Poly1305 (payload < 100 KB)")
    else:
        _info(f"Selected: AES-256-GCM (payload >= 100 KB)")
    print()

    aad = hashlib.sha3_256(x_pub + mlkem_ct + cipher_id.encode("ascii")).digest()
    t0 = time.perf_counter_ns()
    nonce, ciphertext, tag = encrypt_payload(plaintext, sym_key, cipher_id, aad=aad)
    enc_time = (time.perf_counter_ns() - t0) / 1e6

    _hex_block(nonce, "Nonce (unique per packet)", YELLOW)
    print()
    _hex_block(ciphertext[:64], "Ciphertext (first 64 bytes)", RED)
    print()
    _hex_block(tag, "Authentication tag (Poly1305/GMAC)", RED)
    print()
    _info(f"Nonce: {len(nonce)} bytes")
    _info(f"Ciphertext: {len(ciphertext)} bytes")
    _info(f"Auth tag: {len(tag)} bytes")
    _info(f"Encryption time: {enc_time:.3f} ms")
    _ok(f"Encrypted with {cipher_id}")
    _pause()

    # --- Packet serialization ---
    _step(8, "PACKET SERIALIZATION & TRANSMISSION")
    packet = SecurePacket(
        protocol_version=1,
        cipher_identifier=cipher_id,
        nonce=nonce,
        ciphertext=ciphertext,
        auth_tag=tag,
        ed25519_signature=bundle["sig_c"],
        mldsa_signature=bundle["sig_q"],
        x25519_public_key=x_pub,
        mlkem_ciphertext=mlkem_ct,
        metadata={"fw_size": len(firmware), "cipher": cipher_id},
    )
    wire = serialize_packet(packet)

    _box("WIRE PACKET (sent over TCP)", "\n".join([
        f"Protocol version:    {packet['protocol_version']}",
        f"Cipher:              {packet['cipher_identifier']}",
        f"Nonce:               {nonce.hex()}",
        f"Ciphertext:          {len(ciphertext)} bytes (encrypted firmware+sigs)",
        f"Auth tag:            {tag.hex()}",
        f"Ed25519 signature:   {len(bundle['sig_c'])} bytes",
        f"ML-DSA-65 signature: {len(bundle['sig_q'])} bytes",
        f"X25519 pubkey:       {x_pub.hex()}",
        f"ML-KEM ciphertext:   {len(mlkem_ct)} bytes",
        f"",
        f"Total serialized packet: {len(wire)} bytes",
    ]), CYAN)

    _arrow(f"Packet transmitted to network ({len(wire)} bytes)")
    _pause()

    # --- MITM interception ---
    _step(9, "MITM PROXY — INTERCEPTION (Node C)")
    print(f"\n  {RED}{BOLD}  An attacker intercepts the packet in transit...{RESET}\n")

    _box("ATTACKER'S VIEW (no keys, cannot decrypt)", "\n".join([
        f"Intercepted {len(wire)} bytes of encrypted data:",
        f"",
        f"ciphertext: {ciphertext[:32].hex()}...",
        f"            (opaque, no firmware visible)",
        f"",
        f"mlkem_ct:   {mlkem_ct[:32].hex()}...",
        f"            (cannot derive symmetric key)",
        f"",
        f"nonce:      {nonce.hex()}",
        f"tag:        {tag.hex()}",
        f"",
        f"The attacker CANNOT:",
        f"  - Read the firmware content",
        f"  - Recover the symmetric key",
        f"  - Forge valid signatures",
        f"  - Modify the payload without detection",
    ]), RED)

    print(f"\n  {DIM}Forwarding packet unchanged to IoT device...{RESET}")
    _pause()

    # --- Receiver: decryption ---
    _step(10, "IoT DEVICE — DECRYPTION (Node B)")
    print(f"\n  {WHITE}Device received {len(wire)} bytes. Starting decryption...{RESET}\n")

    restored = deserialize_packet(wire)
    _info(f"Deserialized packet fields: {list(restored.keys())}")
    print()

    t0 = time.perf_counter_ns()
    recovered_key = hybrid_kem_decapsulate(
        restored["x25519_public_key"],
        restored["mlkem_ciphertext"],
        device["sk_x"],
        device["sk_kem"],
    )
    decap_time = (time.perf_counter_ns() - t0) / 1e6

    _hex_block(recovered_key, "Recovered symmetric key (KEM decapsulation)", GREEN)
    _info(f"Key matches sender's key: {recovered_key == sym_key}")
    _info(f"Decapsulation time: {decap_time:.3f} ms")
    print()

    aad_recv = hashlib.sha3_256(
        restored["x25519_public_key"]
        + restored["mlkem_ciphertext"]
        + restored["cipher_identifier"].encode("ascii")
    ).digest()

    t0 = time.perf_counter_ns()
    recovered_plaintext = decrypt_payload(
        restored["nonce"],
        restored["ciphertext"],
        restored["auth_tag"],
        recovered_key,
        restored["cipher_identifier"],
        aad=aad_recv,
    )
    dec_time = (time.perf_counter_ns() - t0) / 1e6

    _info(f"Decrypted payload: {len(recovered_plaintext)} bytes")
    _info(f"Decryption time: {dec_time:.3f} ms")
    _ok("AEAD decryption successful — integrity confirmed at ciphertext level")
    _pause()

    # --- Receiver: signature verification ---
    _step(11, "IoT DEVICE — HYBRID SIGNATURE VERIFICATION")
    print(f"\n  {WHITE}Verifying BOTH signatures (AND logic):{RESET}")
    print(f"  {WHITE}Firmware is accepted ONLY if Ed25519 AND ML-DSA-65 pass.{RESET}\n")

    from protocol import _unpack_signed_payload
    recovered_bundle = _unpack_signed_payload(recovered_plaintext)

    recomputed_digest = hash_firmware(recovered_bundle["firmware"])
    digest_match = recomputed_digest == recovered_bundle["digest"]

    _info(f"Re-computed SHA3-256: {recomputed_digest.hex()}")
    _info(f"Bundle digest:        {recovered_bundle['digest'].hex()}")
    if digest_match:
        _ok("Digest integrity: MATCH")
    else:
        _alert("Digest integrity: MISMATCH")

    print()
    t0 = time.perf_counter_ns()
    verified = verify(recovered_bundle, manufacturer["pk_c"], manufacturer["pk_q"])
    verify_time = (time.perf_counter_ns() - t0) / 1e6

    if verified:
        _ok(f"Ed25519 signature:   VALID")
        _ok(f"ML-DSA-65 signature: VALID")
        _ok(f"Hybrid verification: PASSED (AND)")
    else:
        _alert("Hybrid verification: FAILED")

    _info(f"Verification time: {verify_time:.3f} ms")
    _pause()

    # --- Final result ---
    _step(12, "FINAL RESULT")
    if verified and digest_match:
        recovered_text = recovered_bundle["firmware"]
        print(f"\n{GREEN}{BOLD}  ┌{'─' * 68}┐{RESET}")
        print(f"{GREEN}{BOLD}  │ {'FIRMWARE ACCEPTED — ALL CHECKS PASSED':<66} │{RESET}")
        print(f"{GREEN}{BOLD}  └{'─' * 68}┘{RESET}")
        print()
        _info(f"Firmware size: {len(recovered_text)} bytes")
        if user_input.strip():
            _info(f"Recovered message: \"{recovered_text.decode('utf-8', errors='replace')}\"")
        else:
            _hex_block(recovered_text[:32], "Recovered firmware (first 32 bytes)", GREEN)
    else:
        print(f"\n{RED}{BOLD}  ┌{'─' * 68}┐{RESET}")
        print(f"{RED}{BOLD}  │ {'FIRMWARE REJECTED — SECURITY ALERT':<66} │{RESET}")
        print(f"{RED}{BOLD}  └{'─' * 68}┘{RESET}")

    # --- Summary ---
    print(f"\n\n{BOLD}{'─' * 72}{RESET}")
    print(f"{BOLD}  PROTOCOL SUMMARY{RESET}")
    print(f"{BOLD}{'─' * 72}{RESET}")
    print(f"  Signing time:           {sign_time:.3f} ms")
    print(f"  KEM encapsulation:      {kem_time:.3f} ms")
    print(f"  Encryption time:        {enc_time:.3f} ms")
    print(f"  KEM decapsulation:      {decap_time:.3f} ms")
    print(f"  Decryption time:        {dec_time:.3f} ms")
    print(f"  Verification time:      {verify_time:.3f} ms")
    print(f"  Total packet size:      {len(wire)} bytes")
    print(f"  Cipher used:            {cipher_id}")
    print(f"  Post-quantum safe:      Yes (ML-DSA-65 + ML-KEM-768)")
    print(f"{BOLD}{'─' * 72}{RESET}\n")


if __name__ == "__main__":
    main()
