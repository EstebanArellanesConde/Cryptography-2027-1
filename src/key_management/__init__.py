"""D6: Password-protected Key Management System (Keystore)."""

from src.key_management.keystore import (
    KeystoreAccessError,
    KeystoreError,
    KeystoreIntegrityError,
    KeystoreLifecycleError,
    backup_keystore,
    create_keystore,
    decrypt_file_with_keystore,
    prompt_password,
    restore_keystore,
    revoke_key,
    rotate_key,
    secure_delete_keystore,
    unlock_private_key,
    use_private_key,
)

__all__ = [
    "KeystoreError",
    "KeystoreAccessError",
    "KeystoreIntegrityError",
    "KeystoreLifecycleError",
    "backup_keystore",
    "create_keystore",
    "decrypt_file_with_keystore",
    "prompt_password",
    "restore_keystore",
    "revoke_key",
    "rotate_key",
    "secure_delete_keystore",
    "unlock_private_key",
    "use_private_key",
]

