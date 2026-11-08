"""
Secure Digital Document Vault - Encryption Package
Cryptography 2027-1 (Team 6)
"""

from .chacha20_core import (
    encrypt_bytes,
    decrypt_bytes,
    encrypt_file,
    decrypt_file,
    MAX_FILE_SIZE,
    VaultSecurityError,
    IntegrityError,
    InvalidContainerError,
)
from .ecies_core import (
    generate_ec_key_pair,
    compute_ec_fingerprint,
    ecies_encrypt,
    ecies_decrypt,
    ECIESDecryptionError,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
)
from .hybrid_core import (
    generate_rsa_key_pair,
    compute_key_fingerprint,
    encrypt_hybrid_bytes,
    decrypt_hybrid_bytes,
    encrypt_hybrid_file,
    decrypt_hybrid_file,
    UnauthorizedRecipientError,
    KeyUnwrapError,
)

__all__ = [
    # Symmetric AEAD
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_file",
    "decrypt_file",
    "MAX_FILE_SIZE",
    "VaultSecurityError",
    "IntegrityError",
    "InvalidContainerError",
    # ECIES
    "generate_ec_key_pair",
    "compute_ec_fingerprint",
    "ecies_encrypt",
    "ecies_decrypt",
    "ECIESDecryptionError",
    "export_private_key_pem",
    "export_public_key_pem",
    "load_private_key_pem",
    "load_public_key_pem",
    # Hybrid Multi-Recipient
    "generate_rsa_key_pair",
    "compute_key_fingerprint",
    "encrypt_hybrid_bytes",
    "decrypt_hybrid_bytes",
    "encrypt_hybrid_file",
    "decrypt_hybrid_file",
    "UnauthorizedRecipientError",
    "KeyUnwrapError",
]
