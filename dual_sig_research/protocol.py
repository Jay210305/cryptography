"""
Hybrid post-quantum firmware security protocol.

Pipeline: hash → hybrid sign (Ed25519 + ML-DSA-65) → payload build →
hybrid KEM (X25519 + ML-KEM-768) → HKDF → adaptive AEAD → serialize.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sys
from typing import Any, Final, TypedDict

import msgpack
import oqs
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger(__name__)

PROTOCOL_VERSION: Final[int] = 1
ML_DSA_ALG: Final[str] = "ML-DSA-65"
ML_KEM_ALG: Final[str] = "ML-KEM-768"
DIGEST_SIZE: Final[int] = 32
AEAD_TAG_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
SYMMETRIC_KEY_SIZE: Final[int] = 32
HKDF_INFO: Final[bytes] = b"hybrid-firmware-kem-v1"

CIPHER_CHACHA: Final[str] = "chacha20-poly1305"
CIPHER_AES: Final[str] = "aes-256-gcm"
DEFAULT_CIPHER_THRESHOLD: Final[int] = 100 * 1024


class FirmwareBundle(TypedDict):
    """Signed firmware bundle (plaintext before encryption)."""

    firmware: bytes
    digest: bytes
    sig_c: bytes
    sig_q: bytes
    pk_c: bytes
    pk_q: bytes
    metadata: dict[str, Any]


class KeyMaterial(TypedDict):
    """Full hybrid key material for signing and KEM."""

    pk_c: bytes
    sk_c: Ed25519PrivateKey
    pk_q: bytes
    sk_q: bytes
    pk_x: bytes
    sk_x: x25519.X25519PrivateKey
    pk_kem: bytes
    sk_kem: bytes


class SecurePacket(TypedDict):
    """Wire-format secure firmware packet."""

    protocol_version: int
    cipher_identifier: str
    nonce: bytes
    ciphertext: bytes
    auth_tag: bytes
    ed25519_signature: bytes
    mldsa_signature: bytes
    x25519_public_key: bytes
    mlkem_ciphertext: bytes
    metadata: dict[str, Any]


# ---------------------------------------------------------------------------
# Environment / primitives
# ---------------------------------------------------------------------------


def _require_ml_dsa() -> None:
    """Ensure ML-DSA-65 is enabled in liboqs; abort if not."""
    mechanisms = oqs.get_enabled_sig_mechanisms()
    if ML_DSA_ALG not in mechanisms:
        print(
            f"ERROR: {ML_DSA_ALG} not found in enabled oqs mechanisms.\n"
            f"Available ML-DSA: {[m for m in mechanisms if 'ML-DSA' in m]}",
            file=sys.stderr,
        )
        sys.exit(1)


def _require_ml_kem() -> None:
    """Ensure ML-KEM-768 is enabled in liboqs; abort if not."""
    mechanisms = oqs.get_enabled_kem_mechanisms()
    if ML_KEM_ALG not in mechanisms:
        print(
            f"ERROR: {ML_KEM_ALG} not found in enabled oqs mechanisms.\n"
            f"Available ML-KEM: {[m for m in mechanisms if 'ML-KEM' in m]}",
            file=sys.stderr,
        )
        sys.exit(1)


def hash_firmware(firmware_bytes: bytes) -> bytes:
    """Compute SHA3-256 digest of firmware."""
    return hashlib.sha3_256(firmware_bytes).digest()


def select_cipher(
    payload_size: int,
    threshold: int = DEFAULT_CIPHER_THRESHOLD,
) -> str:
    """
    Deterministic adaptive AEAD selection.

    Payloads below ``threshold`` use ChaCha20-Poly1305; otherwise AES-256-GCM.
    """
    if payload_size < threshold:
        return CIPHER_CHACHA
    return CIPHER_AES


def _derive_symmetric_key(ss_x25519: bytes, ss_mlkem: bytes) -> bytes:
    """Combine hybrid KEM shared secrets via HKDF-SHA3-256."""
    ikm = ss_x25519 + ss_mlkem
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=SYMMETRIC_KEY_SIZE,
        salt=None,
        info=HKDF_INFO,
    ).derive(ikm)


def _x25519_public_bytes(key: x25519.X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _x25519_public_from_bytes(raw: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def keygen() -> KeyMaterial:
    """
    Generate hybrid signing and KEM key material.

    Returns:
        KeyMaterial with Ed25519, ML-DSA-65, X25519, and ML-KEM-768 keys.
    """
    _require_ml_dsa()
    _require_ml_kem()

    sk_c = Ed25519PrivateKey.generate()
    pk_c = sk_c.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    with oqs.Signature(ML_DSA_ALG) as signer:
        pk_q = signer.generate_keypair()
        sk_q = signer.export_secret_key()

    sk_x = x25519.X25519PrivateKey.generate()
    pk_x = _x25519_public_bytes(sk_x)

    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        pk_kem = kem.generate_keypair()
        sk_kem = kem.export_secret_key()

    return KeyMaterial(
        pk_c=pk_c,
        sk_c=sk_c,
        pk_q=pk_q,
        sk_q=sk_q,
        pk_x=pk_x,
        sk_x=sk_x,
        pk_kem=pk_kem,
        sk_kem=sk_kem,
    )


# ---------------------------------------------------------------------------
# Authentication (SIGN layer)
# ---------------------------------------------------------------------------


def sign(
    firmware_bytes: bytes,
    sk_c: Ed25519PrivateKey,
    sk_q: bytes,
    pk_q: bytes,
    metadata: dict[str, Any] | None = None,
) -> FirmwareBundle:
    """
    Sign firmware with Ed25519 and ML-DSA-65 over SHA3-256 digest (AND model).
    """
    _require_ml_dsa()
    if not isinstance(firmware_bytes, (bytes, bytearray)):
        raise TypeError("firmware_bytes must be bytes")
    if not sk_q:
        raise ValueError("sk_q must be non-empty ML-DSA-65 secret key bytes")
    if not pk_q:
        raise ValueError("pk_q must be the ML-DSA-65 public key from keygen()")

    digest = hash_firmware(firmware_bytes)
    sig_c = sk_c.sign(digest)
    pk_c = sk_c.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    with oqs.Signature(ML_DSA_ALG, secret_key=sk_q) as signer:
        sig_q = signer.sign(digest)

    meta = dict(metadata) if metadata else {}
    meta.setdefault("digest_alg", "sha3-256")
    meta.setdefault("sign_schemes", ["ed25519", ML_DSA_ALG])

    return FirmwareBundle(
        firmware=bytes(firmware_bytes),
        digest=digest,
        sig_c=sig_c,
        sig_q=sig_q,
        pk_c=pk_c,
        pk_q=pk_q,
        metadata=meta,
    )


def verify(
    bundle: dict[str, Any],
    trusted_pk_c: bytes,
    trusted_pk_q: bytes,
) -> bool:
    """
    Verify bundle with AND logic; log security alert on failure.
    """
    _require_ml_dsa()

    required = ("firmware", "digest", "sig_c", "sig_q", "pk_c", "pk_q")
    for key in required:
        if key not in bundle:
            logger.critical("[ALERT] Missing bundle field: %s", key)
            return False

    computed = hash_firmware(bundle["firmware"])
    if not hmac.compare_digest(computed, bundle["digest"]):
        logger.critical("[ALERT] Integrity verification failed — digest mismatch")
        return False

    if not hmac.compare_digest(bundle["pk_c"], trusted_pk_c):
        logger.critical("[ALERT] Integrity verification failed — untrusted Ed25519 key")
        return False
    if not hmac.compare_digest(bundle["pk_q"], trusted_pk_q):
        logger.critical("[ALERT] Integrity verification failed — untrusted ML-DSA key")
        return False

    ed_ok = False
    try:
        pk_c_obj = Ed25519PublicKey.from_public_bytes(trusted_pk_c)
        pk_c_obj.verify(bundle["sig_c"], bundle["digest"])
        ed_ok = True
    except (InvalidSignature, ValueError, TypeError) as exc:
        logger.critical("[ALERT] Hybrid signature verification failed — Ed25519: %s", exc)

    with oqs.Signature(ML_DSA_ALG) as verifier:
        ml_ok = verifier.verify(
            bundle["digest"],
            bundle["sig_q"],
            trusted_pk_q,
        )
    if not ml_ok:
        logger.critical("[ALERT] Hybrid signature verification failed — ML-DSA-65")

    if ed_ok and ml_ok:
        logger.info("[OK] Hybrid signature validation successful")
        logger.info("[OK] Firmware integrity verified")
        return True

    logger.critical("[ALERT] Integrity verification failed")
    return False


# ---------------------------------------------------------------------------
# Hybrid KEM
# ---------------------------------------------------------------------------


def hybrid_kem_encapsulate(
    recipient_pk_x: bytes,
    recipient_pk_kem: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    X25519 + ML-KEM-768 encapsulation with HKDF-derived symmetric key.

    Returns:
        (ephemeral_x25519_pubkey, mlkem_ciphertext, symmetric_key)
    """
    _require_ml_kem()

    ephemeral_sk = x25519.X25519PrivateKey.generate()
    ephemeral_pk = _x25519_public_bytes(ephemeral_sk)
    recipient_x = _x25519_public_from_bytes(recipient_pk_x)
    ss_x = ephemeral_sk.exchange(recipient_x)

    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        mlkem_ct, ss_ml = kem.encap_secret(recipient_pk_kem)

    sym_key = _derive_symmetric_key(ss_x, ss_ml)
    return ephemeral_pk, mlkem_ct, sym_key


def hybrid_kem_decapsulate(
    ephemeral_pk_x: bytes,
    mlkem_ciphertext: bytes,
    recipient_sk_x: x25519.X25519PrivateKey,
    recipient_sk_kem: bytes,
) -> bytes:
    """Recover HKDF-derived symmetric key at the recipient."""
    _require_ml_kem()

    ephemeral_pub = _x25519_public_from_bytes(ephemeral_pk_x)
    ss_x = recipient_sk_x.exchange(ephemeral_pub)

    with oqs.KeyEncapsulation(ML_KEM_ALG, secret_key=recipient_sk_kem) as kem:
        ss_ml = kem.decap_secret(mlkem_ciphertext)

    return _derive_symmetric_key(ss_x, ss_ml)


# ---------------------------------------------------------------------------
# Adaptive AEAD (ENCRYPT layer)
# ---------------------------------------------------------------------------


def encrypt_payload(
    plaintext: bytes,
    symmetric_key: bytes,
    cipher_id: str,
    aad: bytes | None = None,
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with selected AEAD.

    Returns:
        (nonce, ciphertext_without_tag, auth_tag)
    """
    if len(symmetric_key) != SYMMETRIC_KEY_SIZE:
        raise ValueError(f"symmetric_key must be {SYMMETRIC_KEY_SIZE} bytes")
    nonce = os.urandom(NONCE_SIZE)
    aad_bytes = aad or b""

    if cipher_id == CIPHER_CHACHA:
        aead = ChaCha20Poly1305(symmetric_key)
    elif cipher_id == CIPHER_AES:
        aead = AESGCM(symmetric_key)
    else:
        raise ValueError(f"Unsupported cipher: {cipher_id}")

    combined = aead.encrypt(nonce, plaintext, aad_bytes)
    if len(combined) < AEAD_TAG_SIZE:
        raise ValueError("AEAD output shorter than tag size")
    ciphertext = combined[:-AEAD_TAG_SIZE]
    tag = combined[-AEAD_TAG_SIZE:]
    return nonce, ciphertext, tag


def decrypt_payload(
    nonce: bytes,
    ciphertext: bytes,
    auth_tag: bytes,
    symmetric_key: bytes,
    cipher_id: str,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt AEAD payload; raises InvalidTag on failure."""
    if len(symmetric_key) != SYMMETRIC_KEY_SIZE:
        raise ValueError(f"symmetric_key must be {SYMMETRIC_KEY_SIZE} bytes")
    aad_bytes = aad or b""

    if cipher_id == CIPHER_CHACHA:
        aead = ChaCha20Poly1305(symmetric_key)
    elif cipher_id == CIPHER_AES:
        aead = AESGCM(symmetric_key)
    else:
        raise ValueError(f"Unsupported cipher: {cipher_id}")

    return aead.decrypt(nonce, ciphertext + auth_tag, aad_bytes)


# ---------------------------------------------------------------------------
# Full protocol: SIGN → ENCRYPT
# ---------------------------------------------------------------------------


def pack_signed_payload(bundle: FirmwareBundle) -> bytes:
    return msgpack.packb(
        {
            "firmware": bundle["firmware"],
            "digest": bundle["digest"],
            "sig_c": bundle["sig_c"],
            "sig_q": bundle["sig_q"],
            "pk_c": bundle["pk_c"],
            "pk_q": bundle["pk_q"],
            "metadata": bundle.get("metadata", {}),
        },
        use_bin_type=True,
    )


def _unpack_signed_payload(data: bytes) -> FirmwareBundle:
    obj = msgpack.unpackb(data, raw=False, strict_map_key=False)
    if not isinstance(obj, dict):
        raise ValueError("Signed payload must be a map")
    required = ("firmware", "digest", "sig_c", "sig_q", "pk_c", "pk_q")
    for key in required:
        if key not in obj:
            raise KeyError(f"Missing signed payload field: {key}")
    return FirmwareBundle(
        firmware=obj["firmware"],
        digest=obj["digest"],
        sig_c=obj["sig_c"],
        sig_q=obj["sig_q"],
        pk_c=obj["pk_c"],
        pk_q=obj["pk_q"],
        metadata=obj.get("metadata", {}),
    )


def protect_firmware(
    firmware_bytes: bytes,
    sender: KeyMaterial,
    recipient_pk_x: bytes,
    recipient_pk_kem: bytes,
    metadata: dict[str, Any] | None = None,
    cipher_threshold: int = DEFAULT_CIPHER_THRESHOLD,
) -> SecurePacket:
    """
    Full SIGN → ENCRYPT pipeline for outbound firmware.

    Order: hash/sign → payload → KEM → derive key → AEAD → packet.
    """
    bundle = sign(
        firmware_bytes,
        sender["sk_c"],
        sender["sk_q"],
        sender["pk_q"],
        metadata=metadata,
    )
    plaintext = pack_signed_payload(bundle)
    cipher_id = select_cipher(len(plaintext), cipher_threshold)
    logger.info("Selected AEAD cipher: %s (payload %d bytes)", cipher_id, len(plaintext))

    x_pub, mlkem_ct, sym_key = hybrid_kem_encapsulate(recipient_pk_x, recipient_pk_kem)
    aad = hashlib.sha3_256(
        x_pub + mlkem_ct + cipher_id.encode("ascii")
    ).digest()
    nonce, ciphertext, tag = encrypt_payload(plaintext, sym_key, cipher_id, aad=aad)

    outer_meta: dict[str, Any] = {
        "plaintext_size": len(plaintext),
        "firmware_size": len(firmware_bytes),
        "cipher_threshold": cipher_threshold,
    }
    if bundle.get("metadata"):
        outer_meta["inner"] = bundle["metadata"]

    return SecurePacket(
        protocol_version=PROTOCOL_VERSION,
        cipher_identifier=cipher_id,
        nonce=nonce,
        ciphertext=ciphertext,
        auth_tag=tag,
        ed25519_signature=bundle["sig_c"],
        mldsa_signature=bundle["sig_q"],
        x25519_public_key=x_pub,
        mlkem_ciphertext=mlkem_ct,
        metadata=outer_meta,
    )


def unprotect_firmware(
    packet: SecurePacket | dict[str, Any],
    recipient: KeyMaterial,
    trusted_pk_c: bytes,
    trusted_pk_q: bytes,
) -> tuple[FirmwareBundle, bool]:
    """
    DECRYPT → DECAPSULATE → VERIFY pipeline for inbound firmware.

    Returns:
        (bundle, accepted) where accepted is True only if decrypt and AND-verify pass.
    """
    if packet.get("protocol_version") != PROTOCOL_VERSION:
        logger.critical("[ALERT] Unsupported protocol version")
        return _empty_bundle(), False

    cipher_id = packet.get("cipher_identifier", "")
    x_pub = packet.get("x25519_public_key", b"")
    mlkem_ct = packet.get("mlkem_ciphertext", b"")
    nonce = packet.get("nonce", b"")
    ciphertext = packet.get("ciphertext", b"")
    tag = packet.get("auth_tag", b"")

    try:
        sym_key = hybrid_kem_decapsulate(
            x_pub,
            mlkem_ct,
            recipient["sk_x"],
            recipient["sk_kem"],
        )
        aad = hashlib.sha3_256(
            x_pub + mlkem_ct + cipher_id.encode("ascii")
        ).digest()
        plaintext = decrypt_payload(
            nonce, ciphertext, tag, sym_key, cipher_id, aad=aad
        )
    except InvalidTag as exc:
        logger.critical("[ALERT] Integrity/Decryption Failure: %s", exc)
        return _empty_bundle(), False
    except (ValueError, TypeError, OSError) as exc:
        logger.critical("[ALERT] Decryption failure: %s", exc)
        return _empty_bundle(), False

    try:
        bundle = _unpack_signed_payload(plaintext)
    except (ValueError, KeyError, msgpack.UnpackException) as exc:
        logger.critical("[ALERT] Packet parsing failure: %s", exc)
        return _empty_bundle(), False

    if not verify(bundle, trusted_pk_c, trusted_pk_q):
        return bundle, False

    return bundle, True


def _empty_bundle() -> FirmwareBundle:
    return FirmwareBundle(
        firmware=b"",
        digest=b"",
        sig_c=b"",
        sig_q=b"",
        pk_c=b"",
        pk_q=b"",
        metadata={},
    )


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def serialize_packet(packet: SecurePacket | dict[str, Any]) -> bytes:
    """Serialize secure packet with MessagePack."""
    return msgpack.packb(dict(packet), use_bin_type=True)


def deserialize_packet(data: bytes) -> SecurePacket:
    """Deserialize and validate required packet fields."""
    try:
        obj = msgpack.unpackb(data, raw=False, strict_map_key=False)
    except msgpack.UnpackException as exc:
        raise ValueError("Invalid MessagePack packet") from exc
    if not isinstance(obj, dict):
        raise ValueError("Packet must be a map")

    required = (
        "protocol_version",
        "cipher_identifier",
        "nonce",
        "ciphertext",
        "auth_tag",
        "ed25519_signature",
        "mldsa_signature",
        "x25519_public_key",
        "mlkem_ciphertext",
        "metadata",
    )
    for key in required:
        if key not in obj:
            raise KeyError(f"Missing packet field: {key}")

    for field in (
        "nonce",
        "ciphertext",
        "auth_tag",
        "ed25519_signature",
        "mldsa_signature",
        "x25519_public_key",
        "mlkem_ciphertext",
    ):
        if not isinstance(obj[field], bytes):
            raise TypeError(f"Field {field} must be bytes")

    return SecurePacket(
        protocol_version=int(obj["protocol_version"]),
        cipher_identifier=str(obj["cipher_identifier"]),
        nonce=obj["nonce"],
        ciphertext=obj["ciphertext"],
        auth_tag=obj["auth_tag"],
        ed25519_signature=obj["ed25519_signature"],
        mldsa_signature=obj["mldsa_signature"],
        x25519_public_key=obj["x25519_public_key"],
        mlkem_ciphertext=obj["mlkem_ciphertext"],
        metadata=obj.get("metadata", {}),
    )


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------


def _run_smoke_test() -> None:
    """End-to-end: sign → KEM → encrypt → serialize → reverse → verify."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    _require_ml_dsa()
    _require_ml_kem()

    firmware = os.urandom(2048)
    manufacturer = keygen()
    device = keygen()

    packet = protect_firmware(
        firmware,
        manufacturer,
        device["pk_x"],
        device["pk_kem"],
        metadata={"smoke": True},
    )
    wire = serialize_packet(packet)
    restored = deserialize_packet(wire)

    bundle, ok = unprotect_firmware(
        restored,
        device,
        manufacturer["pk_c"],
        manufacturer["pk_q"],
    )
    if not ok:
        raise AssertionError("Smoke test: unprotect_firmware returned False")
    if bundle["firmware"] != firmware:
        raise AssertionError("Smoke test: firmware mismatch after round-trip")

    tampered = dict(restored)
    tampered["ciphertext"] = bytearray(restored["ciphertext"])
    tampered["ciphertext"][0] ^= 1
    tampered["ciphertext"] = bytes(tampered["ciphertext"])
    _, bad = unprotect_firmware(
        tampered,
        device,
        manufacturer["pk_c"],
        manufacturer["pk_q"],
    )
    if bad:
        raise AssertionError("Smoke test: tampered ciphertext must be rejected")

    print("[OK] protocol.py smoke test passed")


if __name__ == "__main__":
    _run_smoke_test()
