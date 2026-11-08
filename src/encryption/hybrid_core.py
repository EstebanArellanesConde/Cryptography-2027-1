"""
Secure Digital Document Vault - Deliverable D3: Multi-Recipient Hybrid Encryption Module
Cryptography 2027-1 (Team 6)

This module implements a hybrid cryptosystem supporting both:
1. Asymmetric Key Wrapping with RSA-OAEP (SHA-256 and 3072-bit keys)
2. Elliptic Curve Integrated Encryption Scheme (ECIES via SECP256R1 / ECDH + HKDF-SHA256)
Together with:
- Symmetric AEAD (ChaCha20-Poly1305) with a 256-bit Document Encryption Key (DEK).
- Deterministic SHA-256 fingerprints of SubjectPublicKeyInfo DER structures.
- Cryptographic binding of the recipient list into ChaCha20-Poly1305 Additional Authenticated Data (AAD).
- Strict fail-closed error handling (AD-08 / SR-10).
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from base64 import b64encode, b64decode
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization

from .chacha20_core import (
    VaultSecurityError,
    IntegrityError,
    InvalidContainerError,
    MAX_FILE_SIZE,
)
from .ecies_core import (
    generate_ec_key_pair,
    compute_ec_fingerprint,
    ecies_encrypt,
    ecies_decrypt,
    ECIESDecryptionError,
)

RecipientPublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
RecipientPrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


class UnauthorizedRecipientError(VaultSecurityError):
    """Raised when the provided private key does not match any authorized recipient in the container."""
    pass


class KeyUnwrapError(VaultSecurityError):
    """Raised when asymmetric key unwrapping fails (e.g. invalid key or corrupted wrapped key)."""
    pass


def generate_rsa_key_pair(key_size: int = 3072) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates an RSA key pair using the operating system CSPRNG.
    Default key size is 3072 bits, adhering to Deliverable D3 requirements and NIST post-2030 standards.
    """
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits (3072 bits strongly recommended).")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()


def compute_key_fingerprint(public_key: RecipientPublicKey) -> str:
    """
    Computes a deterministic, collision-resistant recipient identifier:
    the SHA-256 hex digest of the public key (RSA or EC) encoded in DER under SubjectPublicKeyInfo (SPKI).
    """
    if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise TypeError("public_key must be an instance of rsa.RSAPublicKey or ec.EllipticCurvePublicKey")

    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der_bytes).hexdigest()


def _canonical_json(data: dict) -> bytes:
    """Produces canonical, deterministic JSON bytes with sorted keys and compact separators."""
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')


def encrypt_hybrid_bytes(
    plaintext: bytes,
    filename: str,
    recipients_public_keys: list[RecipientPublicKey]
) -> bytes:
    """
    Encrypts a document for multiple authorized recipients using a hybrid cryptosystem.
    Supports both RSA (RSA-OAEP 3072b) and ECC (ECIES SECP256R1).
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext must be bytes or bytearray")

    if len(plaintext) > MAX_FILE_SIZE:
        raise ValueError(
            f"Plaintext size ({len(plaintext)} bytes) exceeds maximum limit of 256 MiB ({MAX_FILE_SIZE} bytes)."
        )

    if not recipients_public_keys:
        raise ValueError("At least one authorized recipient public key must be provided.")

    # 1. Single fresh symmetric DEK and fresh 96-bit nonce
    dek = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)

    # 2. Key wrapping: RSA-OAEP or ECIES for each recipient
    recipients_list = []
    seen_fingerprints = set()

    for pub_key in recipients_public_keys:
        if not isinstance(pub_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise TypeError("Each recipient key must be an instance of rsa.RSAPublicKey or ec.EllipticCurvePublicKey")

        fingerprint = compute_key_fingerprint(pub_key)
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)

        if isinstance(pub_key, rsa.RSAPublicKey):
            # RSA-OAEP key wrapping
            encrypted_dek = pub_key.encrypt(
                dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            recipients_list.append({
                "recipient_id": fingerprint,
                "scheme": "RSA-OAEP-SHA256",
                "encrypted_key": b64encode(encrypted_dek).decode('utf-8')
            })
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            # ECIES key wrapping (ECDH + HKDF + ChaCha20-Poly1305)
            ecies_pkg = ecies_encrypt(pub_key, dek, aad=b"DEK-WRAP")
            recipients_list.append({
                "recipient_id": fingerprint,
                "scheme": "ECIES-SECP256R1",
                "encrypted_key": ecies_pkg["ciphertext"],
                "ephemeral_public_key": ecies_pkg["ephemeral_public_key"],
                "nonce": ecies_pkg["nonce"],
                "tag": ecies_pkg["tag"]
            })

    # Sort recipients deterministically by recipient_id
    recipients_list.sort(key=lambda r: r["recipient_id"])

    # 3. Public header
    header = {
        "format": "SecureVault-Hybrid",
        "version": "1.0",
        "algorithm": "ChaCha20-Poly1305-Hybrid"
    }

    # 4. Bind public header AND recipient list into AAD
    aad_structure = {
        "header": header,
        "recipients": recipients_list
    }
    aad = _canonical_json(aad_structure)

    # 5. Encrypt metadata inside payload for confidentiality
    metadata = {
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "plaintext_size": len(plaintext)
    }
    meta_bytes = _canonical_json(metadata)
    meta_len = len(meta_bytes).to_bytes(4, 'big')

    payload = meta_len + meta_bytes + bytes(plaintext)

    # 6. AEAD encryption
    chacha = ChaCha20Poly1305(dek)
    ct_with_tag = chacha.encrypt(nonce, payload, aad)

    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    # 7. Package container
    container = {
        "header": header,
        "recipients": recipients_list,
        "nonce": b64encode(nonce).decode('utf-8'),
        "ciphertext": b64encode(ciphertext).decode('utf-8'),
        "tag": b64encode(tag).decode('utf-8')
    }

    return json.dumps(container, indent=2).encode('utf-8')


def decrypt_hybrid_bytes(
    container_data: bytes | str | dict,
    recipient_private_key: RecipientPrivateKey
) -> tuple[bytes, dict]:
    """
    Decrypts a hybrid container for an authorized recipient (RSA or ECC).
    Fails closed on any error.
    """
    if not isinstance(recipient_private_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise TypeError("recipient_private_key must be an instance of rsa.RSAPrivateKey or ec.EllipticCurvePrivateKey")

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

    # Validate container schema
    required_fields = ("header", "recipients", "nonce", "ciphertext", "tag")
    for field in required_fields:
        if field not in container:
            raise InvalidContainerError(f"Missing required field in hybrid container: '{field}'")

    if not isinstance(container["recipients"], list) or len(container["recipients"]) == 0:
        raise InvalidContainerError("Hybrid container must include a non-empty 'recipients' list")

    # Identify recipient entry via public key fingerprint
    my_fingerprint = compute_key_fingerprint(recipient_private_key.public_key())

    matching_entry = None
    for entry in container["recipients"]:
        if not isinstance(entry, dict) or "recipient_id" not in entry or "encrypted_key" not in entry:
            raise InvalidContainerError("Invalid recipient entry structure")
        if entry["recipient_id"] == my_fingerprint:
            matching_entry = entry
            break

    if matching_entry is None:
        raise UnauthorizedRecipientError(
            "Recipient is not authorized or not present in container recipient list."
        )

    # Unwrap symmetric DEK based on key type
    if isinstance(recipient_private_key, rsa.RSAPrivateKey):
        try:
            enc_dek_bytes = b64decode(matching_entry["encrypted_key"], validate=True)
        except Exception as exc:
            raise InvalidContainerError("Corrupted Base64 in encrypted symmetric key") from exc

        try:
            dek = recipient_private_key.decrypt(
                enc_dek_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as exc:
            raise KeyUnwrapError("Failed to unwrap symmetric key with provided RSA private key") from exc

    elif isinstance(recipient_private_key, ec.EllipticCurvePrivateKey):
        try:
            ecies_package = {
                "ephemeral_public_key": matching_entry["ephemeral_public_key"],
                "nonce": matching_entry["nonce"],
                "ciphertext": matching_entry["encrypted_key"],
                "tag": matching_entry["tag"]
            }
            dek = ecies_decrypt(recipient_private_key, ecies_package, aad=b"DEK-WRAP")
        except Exception as exc:
            raise KeyUnwrapError("Failed to unwrap symmetric key with provided EC private key") from exc

    if len(dek) != 32:
        raise KeyUnwrapError("Unwrapped symmetric key length is invalid (expected 32 bytes)")

    # Decode nonce, ciphertext, and tag
    try:
        nonce = b64decode(container["nonce"], validate=True)
        ciphertext = b64decode(container["ciphertext"], validate=True)
        tag = b64decode(container["tag"], validate=True)
    except Exception as exc:
        raise InvalidContainerError("Corrupted Base64 encoding in nonce, ciphertext, or tag") from exc

    if len(nonce) != 12:
        raise InvalidContainerError(f"Invalid nonce length ({len(nonce)} bytes; expected 12 bytes)")
    if len(tag) != 16:
        raise InvalidContainerError(f"Invalid tag length ({len(tag)} bytes; expected 16 bytes)")

    ct_with_tag = ciphertext + tag

    # Reconstruct canonical AAD exactly as packaged in container
    aad_structure = {
        "header": container["header"],
        "recipients": container["recipients"]
    }
    aad = _canonical_json(aad_structure)

    # AEAD Decryption and authentication
    try:
        chacha = ChaCha20Poly1305(dek)
        payload = chacha.decrypt(nonce, ct_with_tag, aad)
    except InvalidTag as exc:
        raise IntegrityError(
            "Authentication failed: container tampering detected in ciphertext, tag, header, or recipient list"
        ) from exc

    # Extract authenticated metadata and plaintext
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


def encrypt_hybrid_file(
    input_path: str,
    output_path: str,
    recipients_public_keys: list[RecipientPublicKey]
) -> None:
    """
    Encrypts a file for multiple authorized recipients and writes the hybrid container to output_path.
    Enforces maximum file size limit (256 MiB) before reading into memory.
    """
    file_size = os.path.getsize(input_path)
    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File size ({file_size} bytes) exceeds maximum limit of 256 MiB ({MAX_FILE_SIZE} bytes)."
        )

    with open(input_path, 'rb') as f:
        plaintext = f.read()

    container_bytes = encrypt_hybrid_bytes(
        plaintext=plaintext,
        filename=os.path.basename(input_path),
        recipients_public_keys=recipients_public_keys
    )

    with open(output_path, 'wb') as f:
        f.write(container_bytes)


def decrypt_hybrid_file(
    input_path: str,
    output_path: str,
    recipient_private_key: RecipientPrivateKey,
    overwrite: bool = False
) -> dict:
    """
    Decrypts a hybrid container file and writes recovered plaintext to output_path.
    Fails closed if authentication fails or output_path already exists (unless overwrite=True).
    Ensures no partial plaintext file is written on error.
    """
    if os.path.exists(output_path) and not overwrite:
        raise FileExistsError(f"Output path already exists: {output_path}")

    with open(input_path, 'rb') as f:
        container_bytes = f.read()

    plaintext, metadata = decrypt_hybrid_bytes(container_bytes, recipient_private_key)

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
