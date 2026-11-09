"""D5: primitive operations for Ed25519 digital signatures.

The caller supplies a 32-byte SHA-256 digest of the canonical container data.
This module does not select which container fields to hash or change D3.
"""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def generate_signing_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 private/public signing key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def signer_key_id(public_key: Ed25519PublicKey) -> str:
    """SHA-256 fingerprint of the DER-encoded signing public key."""
    public_der = public_key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()


def _validate_digest(digest: bytes) -> None:
    """Require exactly one SHA-256 digest (32 bytes)."""
    if not isinstance(digest, bytes) or len(digest) != 32:
        raise ValueError("digest must be a 32-byte SHA-256 digest")


def sign_digest(digest: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Sign a SHA-256 digest using the sender's Ed25519 private key."""
    _validate_digest(digest)
    return private_key.sign(digest)


def verify_digest(
    digest: bytes,
    signature: bytes,
    public_key: Ed25519PublicKey,
) -> bool:
    """Return True only if the Ed25519 signature verifies correctly."""
    _validate_digest(digest)
    if not isinstance(signature, bytes):
        return False
    try:
        public_key.verify(signature, digest)
        return True
    except InvalidSignature:
        return False
