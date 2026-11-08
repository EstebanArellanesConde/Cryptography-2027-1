"""
Secure Digital Document Vault - Deliverable D2: Symmetric AEAD Module (ChaCha20-Poly1305)
Cryptography 2027-1 (Team 6)

This module provides authenticated encryption and decryption using ChaCha20-Poly1305
with a 256-bit symmetric key, 96-bit nonce, 128-bit authentication tag, and AAD binding.
Enforces fail-closed operation (AD-08 / SR-10) and memory boundaries (max 256 MiB).
"""

import os
import json
from datetime import datetime, timezone
from base64 import b64encode, b64decode
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Maximum allowed file size for in-memory AEAD processing (256 MiB = 268,435,456 bytes)
MAX_FILE_SIZE = 256 * 1024 * 1024


class VaultSecurityError(Exception):
    """Base exception for all vault cryptographic, structural, and security failures."""
    pass


class IntegrityError(VaultSecurityError, InvalidTag):
    """
    Raised when ciphertext, tag, header, or AAD authentication fails.
    Inherits from both VaultSecurityError and cryptography's InvalidTag
    to preserve backward compatibility while enforcing standard vault error handling.
    """
    pass


class InvalidContainerError(VaultSecurityError):
    """Raised when container format, JSON schema, or field encodings are invalid."""
    pass


def _canonical_aad(header: dict) -> bytes:
    """Produces deterministic, canonical JSON-encoded bytes for Additional Authenticated Data (AAD)."""
    return json.dumps(header, sort_keys=True, separators=(',', ':')).encode('utf-8')


def encrypt_bytes(plaintext: bytes, filename: str) -> tuple[bytes, bytes]:
    """
    Encrypts in-memory bytes using ChaCha20-Poly1305 AEAD.

    Security properties:
    - Fresh 256-bit key generated per encryption.
    - Fresh 96-bit nonce from OS CSPRNG per encryption.
    - Sensitive metadata (filename, UTC ISO timestamp, plaintext_size) is encrypted inside payload.
    - Public container header is bound as Additional Authenticated Data (AAD).
    - Enforces 256 MiB maximum payload restriction.

    Returns:
        tuple[bytes, bytes]: (container_json_bytes, symmetric_key_32_bytes)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes or bytearray")

    if len(plaintext) > MAX_FILE_SIZE:
        raise ValueError(
            f"Plaintext size ({len(plaintext)} bytes) exceeds maximum limit of 256 MiB ({MAX_FILE_SIZE} bytes)."
        )

    # 1. Generate 256-bit key and 96-bit nonce via CSPRNG
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)

    # 2. Encrypt metadata inside payload for confidentiality
    metadata = {
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "plaintext_size": len(plaintext)
    }
    meta_bytes = json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode('utf-8')
    meta_len = len(meta_bytes).to_bytes(4, 'big')

    payload = meta_len + meta_bytes + bytes(plaintext)

    # 3. Canonical AAD from public header
    header = {
        "format": "SecureVault",
        "version": "1.0",
        "algorithm": "ChaCha20-Poly1305"
    }
    aad = _canonical_aad(header)

    # 4. AEAD encryption
    chacha = ChaCha20Poly1305(key)
    ct_with_tag = chacha.encrypt(nonce, payload, aad)

    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    # 5. Build transport container
    container = {
        "header": header,
        "nonce": b64encode(nonce).decode('utf-8'),
        "ciphertext": b64encode(ciphertext).decode('utf-8'),
        "tag": b64encode(tag).decode('utf-8')
    }

    return json.dumps(container, indent=2).encode('utf-8'), key


def decrypt_bytes(container_data: bytes | str | dict, key: bytes) -> tuple[bytes, dict]:
    """
    Decrypts and authenticates a ChaCha20-Poly1305 AEAD container.

    Security properties:
    - Enforces fail-closed operation (AD-08 / SR-10).
    - Validates container schema, lengths, and Base64 encodings before processing.
    - Verifies Poly1305 authentication tag and AAD header before releasing plaintext.
    - Cross-verifies authenticated metadata (plaintext_size).

    Returns:
        tuple[bytes, dict]: (recovered_plaintext, authenticated_metadata)
    """
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        raise ValueError("Key must be exactly 32 bytes (256 bits)")

    if isinstance(container_data, (bytes, bytearray)):
        try:
            container = json.loads(container_data.decode('utf-8'))
        except Exception as exc:
            raise InvalidContainerError("Malformed container JSON") from exc
    elif isinstance(container_data, str):
        try:
            container = json.loads(container_data)
        except Exception as exc:
            raise InvalidContainerError("Malformed container JSON") from exc
    elif isinstance(container_data, dict):
        container = container_data
    else:
        raise InvalidContainerError("Container data must be bytes, str, or dict")

    # Validate required fields
    required_fields = ("header", "nonce", "ciphertext", "tag")
    for field in required_fields:
        if field not in container:
            raise InvalidContainerError(f"Missing required field in container: '{field}'")

    try:
        nonce = b64decode(container["nonce"], validate=True)
        ciphertext = b64decode(container["ciphertext"], validate=True)
        tag = b64decode(container["tag"], validate=True)
    except Exception as exc:
        raise InvalidContainerError("Corrupted Base64 encoding in container") from exc

    if len(nonce) != 12:
        raise InvalidContainerError(f"Invalid nonce length ({len(nonce)} bytes; expected 12 bytes)")
    if len(tag) != 16:
        raise InvalidContainerError(f"Invalid tag length ({len(tag)} bytes; expected 16 bytes)")

    ct_with_tag = ciphertext + tag
    aad = _canonical_aad(container["header"])

    # AEAD Decryption and verification
    try:
        chacha = ChaCha20Poly1305(key)
        payload = chacha.decrypt(nonce, ct_with_tag, aad)
    except InvalidTag as exc:
        raise IntegrityError("Authentication failed: invalid tag, corrupted ciphertext, altered AAD, or wrong key") from exc

    # Parse and validate internal metadata
    if len(payload) < 4:
        raise IntegrityError("Corrupted payload structure")

    meta_len = int.from_bytes(payload[:4], 'big')
    if meta_len < 0 or len(payload) < 4 + meta_len:
        raise IntegrityError("Corrupted metadata length in payload")

    try:
        metadata = json.loads(payload[4:4+meta_len].decode('utf-8'))
    except Exception as exc:
        raise IntegrityError("Corrupted metadata payload JSON") from exc

    plaintext = payload[4+meta_len:]
    if metadata.get("plaintext_size") != len(plaintext):
        raise IntegrityError("Plaintext size mismatch against authenticated metadata")

    return plaintext, metadata


def encrypt_file(input_path: str, output_path: str) -> bytes:
    """
    Encrypts a file using ChaCha20-Poly1305 and writes the container to output_path.
    Returns the generated 256-bit symmetric key.
    Enforces maximum file size limit before reading into memory.
    """
    file_size = os.path.getsize(input_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File size ({file_size} bytes) exceeds maximum limit of 256 MiB ({MAX_FILE_SIZE} bytes)."
        )

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    container_bytes, key = encrypt_bytes(plaintext, os.path.basename(input_path))

    with open(output_path, 'wb') as f:
        f.write(container_bytes)

    return key


def decrypt_file(input_path: str, output_path: str, key: bytes, overwrite: bool = False) -> dict:
    """
    Decrypts an encrypted container file and safely writes the verified plaintext to output_path.
    Fails closed if authentication fails or if output_path already exists (unless overwrite=True).
    Ensures no partial plaintext file is written on error.
    """
    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError(f"Output path already exists: {output_path}")

    with open(input_path, 'rb') as f:
        container_bytes = f.read()

    plaintext, metadata = decrypt_bytes(container_bytes, key)

    temp_output = f"{output_path}.tmp.{os.urandom(8).hex()}"
    try:
        with open(temp_output, 'wb') as f:
            f.write(plaintext)
        os.replace(temp_output, output_path)
    finally:
        if os.path.exists(temp_output):
            try:
                os.remove(temp_output)
            except OSError:
                pass

    return metadata
