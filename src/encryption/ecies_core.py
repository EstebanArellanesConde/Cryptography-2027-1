"""
Secure Digital Document Vault - ECIES Module (Elliptic Curve Integrated Encryption Scheme)
Cryptography 2027-1 (Team 6)
Session: 22 de Octubre - Cifrado Asimétrico con Curvas Elípticas

This module implements ECIES following standard cryptographic specifications (ISO/IEC 18033-2, SEC 1):
1. Key Agreement: ECDH (Elliptic Curve Diffie-Hellman) using SECP256R1 (NIST P-256) or SECP256K1.
2. Key Derivation: HKDF-SHA256 (RFC 5869) to derive a 256-bit symmetric encryption key.
3. Authenticated Encryption (AEAD): ChaCha20-Poly1305 (or AES-GCM) with 96-bit nonce and 128-bit MAC tag.
4. Ephemeral Key: Fresh ephemeral EC key pair generated for every encryption operation.
5. Fail-Closed Error Handling: Immediate rejection on tampering without leaking side-channel clues.
"""

import os
import json
import hashlib
from base64 import b64encode, b64decode
from typing import Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .chacha20_core import VaultSecurityError, IntegrityError, InvalidContainerError


class ECIESDecryptionError(VaultSecurityError):
    """Raised when ECIES decryption fails due to invalid key, altered tag, or corrupted ciphertext."""
    pass


def generate_ec_key_pair(
    curve: Optional[ec.EllipticCurve] = None
) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """
    Generates a cryptographically secure Elliptic Curve key pair using the OS CSPRNG.
    Default curve is SECP256R1 (NIST P-256), providing 128 bits of security with 256-bit keys.

    Args:
        curve (Optional[ec.EllipticCurve]): The curve to use (defaults to ec.SECP256R1()).

    Returns:
        tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]: Private and public key pair.
    """
    selected_curve = curve or ec.SECP256R1()
    private_key = ec.generate_private_key(selected_curve)
    return private_key, private_key.public_key()


def compute_ec_fingerprint(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Computes a deterministic, collision-resistant identifier:
    the SHA-256 hex digest of the EC public key encoded in DER SubjectPublicKeyInfo (SPKI).

    Args:
        public_key (ec.EllipticCurvePublicKey): The public key.

    Returns:
        str: 64-character hexadecimal SHA-256 digest.
    """
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("public_key must be an instance of ec.EllipticCurvePublicKey")

    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der_bytes).hexdigest()


def ecies_encrypt(
    recipient_public_key: ec.EllipticCurvePublicKey,
    plaintext: bytes,
    aad: bytes = b"",
    info: bytes = b"ECIES-SECP256R1-HKDF-ChaCha20Poly1305"
) -> dict:
    """
    Encrypts a secret message for a recipient using ECIES:
    1. Generates fresh ephemeral EC private key r and public key R = r * G.
    2. Performs ECDH with recipient's public key Q_B: S = r * Q_B = r * (d_B * G).
    3. Derives 256-bit symmetric key K via HKDF-SHA256 from shared secret S.
    4. Encrypts plaintext using ChaCha20-Poly1305 with fresh 96-bit nonce.
    5. Returns dict containing serialized ephemeral public key R, nonce, ciphertext, and tag.
    """
    if not isinstance(recipient_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("recipient_public_key must be an instance of ec.EllipticCurvePublicKey")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes or bytearray")

    # 1. Ephemeral key pair (r, R)
    ephemeral_private_key = ec.generate_private_key(recipient_public_key.curve)
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Ephemeral public key bytes in canonical compressed SEC1 format
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )

    # 2. Key Agreement via ECDH: S = r * Q_B
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # 3. Key Derivation via HKDF-SHA256
    # Salt incorporates ephemeral public key to guarantee domain separation
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub_bytes,
        info=info
    )
    symmetric_key = kdf.derive(shared_secret)

    # 4. AEAD Encryption (ChaCha20-Poly1305)
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(symmetric_key)
    ct_with_tag = chacha.encrypt(nonce, bytes(plaintext), aad)

    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    # 5. Packaged container
    return {
        "scheme": "ECIES-SECP256R1-HKDF-ChaCha20Poly1305",
        "ephemeral_public_key": b64encode(ephemeral_pub_bytes).decode('utf-8'),
        "nonce": b64encode(nonce).decode('utf-8'),
        "ciphertext": b64encode(ciphertext).decode('utf-8'),
        "tag": b64encode(tag).decode('utf-8')
    }


def ecies_decrypt(
    recipient_private_key: ec.EllipticCurvePrivateKey,
    package: Union[dict, str, bytes],
    aad: bytes = b"",
    info: bytes = b"ECIES-SECP256R1-HKDF-ChaCha20Poly1305"
) -> bytes:
    """
    Decrypts an ECIES package using the recipient's private key:
    1. Parses ephemeral public key R from the package.
    2. Performs ECDH: S = d_B * R = d_B * (r * G) = r * (d_B * G).
    3. Derives the identical 256-bit symmetric key K via HKDF-SHA256.
    4. Decrypts and authenticates ciphertext and tag using ChaCha20-Poly1305.
    5. Fails closed with ECIESDecryptionError if key is wrong or data is tampered.
    """
    if not isinstance(recipient_private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("recipient_private_key must be an instance of ec.EllipticCurvePrivateKey")

    if isinstance(package, (bytes, bytearray)):
        try:
            package_dict = json.loads(package.decode('utf-8'))
        except Exception as exc:
            raise InvalidContainerError("Malformed ECIES container JSON") from exc
    elif isinstance(package, str):
        try:
            package_dict = json.loads(package)
        except Exception as exc:
            raise InvalidContainerError("Malformed ECIES container JSON") from exc
    elif isinstance(package, dict):
        package_dict = package
    else:
        raise InvalidContainerError("Package must be dict, str, or bytes")

    required = ("ephemeral_public_key", "nonce", "ciphertext", "tag")
    for field in required:
        if field not in package_dict:
            raise InvalidContainerError(f"Missing required field in ECIES package: '{field}'")

    try:
        ephemeral_pub_bytes = b64decode(package_dict["ephemeral_public_key"], validate=True)
        nonce = b64decode(package_dict["nonce"], validate=True)
        ciphertext = b64decode(package_dict["ciphertext"], validate=True)
        tag = b64decode(package_dict["tag"], validate=True)
    except Exception as exc:
        raise InvalidContainerError("Corrupted Base64 encoding in ECIES package") from exc

    # Load ephemeral public key point
    try:
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            recipient_private_key.curve,
            ephemeral_pub_bytes
        )
    except Exception as exc:
        raise ECIESDecryptionError("Invalid ephemeral public key point") from exc

    # Perform ECDH: S = d_B * R
    try:
        shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
    except Exception as exc:
        raise ECIESDecryptionError("ECDH key agreement failed") from exc

    # Derive symmetric key via HKDF
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=ephemeral_pub_bytes,
        info=info
    )
    try:
        symmetric_key = kdf.derive(shared_secret)
    except Exception as exc:
        raise ECIESDecryptionError("KDF derivation failed") from exc

    # AEAD Decryption and Authentication
    ct_with_tag = ciphertext + tag
    try:
        chacha = ChaCha20Poly1305(symmetric_key)
        plaintext = chacha.decrypt(nonce, ct_with_tag, aad)
    except InvalidTag as exc:
        raise ECIESDecryptionError(
            "Authentication failed: tag mismatch, corrupted ciphertext, altered AAD, or wrong key"
        ) from exc

    return plaintext


def export_private_key_pem(private_key: ec.EllipticCurvePrivateKey, password: Optional[bytes] = None) -> bytes:
    """Exports an EC private key to PEM format, optionally encrypted with a password."""
    encryption_algorithm: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )


def export_public_key_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Exports an EC public key to PEM format (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key_pem(pem_bytes: bytes, password: Optional[bytes] = None) -> ec.EllipticCurvePrivateKey:
    """Loads an EC private key from PEM bytes."""
    key = serialization.load_pem_private_key(pem_bytes, password=password)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("Key in PEM is not an EllipticCurvePrivateKey")
    return key


def load_public_key_pem(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Loads an EC public key from PEM bytes."""
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError("Key in PEM is not an EllipticCurvePublicKey")
    return key
