"""D6 automated security tests for Key Management System."""

import os
import stat
import base64
import json
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.encryption.hybrid_core import (
    encrypt_hybrid,
    generate_keypair,
    get_key_id,
)
from src.key_management import (
    KeystoreAccessError,
    KeystoreIntegrityError,
    KeystoreLifecycleError,
    backup_keystore,
    create_keystore,
    decrypt_file_with_keystore,
    restore_keystore,
    revoke_key,
    rotate_key,
    secure_delete_keystore,
    unlock_private_key,
)


def _load_public_key_from_metadata(metadata: dict):
    pub_der = base64.b64decode(metadata["public_key_der_b64"])
    return serialization.load_der_public_key(pub_der)


def test_correct_password_grants_access_and_decrypts_d3(tmp_path):
    """1. Correct password -> access granted."""
    ks_dir = tmp_path / "keystore"
    password = "Strong-Vault-Password-2026!"
    meta = create_keystore(ks_dir, usage="encryption", password=password)

    pub_key = _load_public_key_from_metadata(meta)
    assert get_key_id(pub_key) == meta["key_id"]

    # Unlock private key with correct password
    priv_key = unlock_private_key(ks_dir, password=password, expected_usage="encryption")
    assert isinstance(priv_key, X25519PrivateKey)

    # Verify integration with D3 hybrid encryption (requires >= 2 recipients)
    _, second_pub = generate_keypair()
    container = encrypt_hybrid(
        b"confidential document", "secret.txt", [pub_key, second_pub]
    )
    plaintext, file_meta = decrypt_file_with_keystore(container, ks_dir, password=password)
    assert plaintext == b"confidential document"
    assert file_meta["filename"] == "secret.txt"


def test_wrong_password_denies_access(tmp_path):
    """2. Wrong password -> access denied."""
    ks_dir = tmp_path / "keystore"
    create_keystore(ks_dir, usage="encryption", password="CorrectPassword123!")

    with pytest.raises(KeystoreAccessError):
        unlock_private_key(ks_dir, password="WrongPassword999!")


def test_modified_keystore_fails(tmp_path):
    """3. Modified keystore -> failure."""
    ks_dir = tmp_path / "keystore"
    password = "CorrectPassword123!"
    create_keystore(ks_dir, usage="encryption", password=password)

    # Tamper with encrypted_private_key ciphertext
    enc_path = ks_dir / "encrypted_private_key"
    data = bytearray(enc_path.read_bytes())
    data[-1] ^= 0xFF
    enc_path.write_bytes(bytes(data))

    with pytest.raises(KeystoreAccessError):
        unlock_private_key(ks_dir, password=password)


def test_modified_metadata_fails_aad_check(tmp_path):
    """3b. Modified metadata -> failure (AAD integrity check)."""
    ks_dir = tmp_path / "keystore"
    password = "CorrectPassword123!"
    create_keystore(ks_dir, usage="encryption", password=password)

    meta_path = ks_dir / "metadata"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    meta["key_id"] = "0" * 64
    meta_path.write_text(json.dumps(meta), encoding="utf-8")

    with pytest.raises(KeystoreAccessError):
        unlock_private_key(ks_dir, password=password)


def test_backup_and_restore_works(tmp_path):
    """4. Backup -> restore works."""
    ks_dir = tmp_path / "keystore_orig"
    backup_zip = tmp_path / "backups" / "keystore_backup.zip"
    restored_dir = tmp_path / "keystore_restored"
    password = "BackupPassword2026!"

    meta = create_keystore(ks_dir, usage="signing", password=password)
    backup_keystore(ks_dir, backup_zip)
    shutil.rmtree(ks_dir)

    restore_keystore(backup_zip, restored_dir)
    priv_key = unlock_private_key(restored_dir, password=password, expected_usage="signing")
    assert priv_key is not None
    assert json.loads((restored_dir / "metadata").read_text(encoding="utf-8"))["key_id"] == meta["key_id"]


def test_stolen_keystore_alone_cannot_decrypt(tmp_path):
    """5. Stolen keystore alone -> cannot decrypt."""
    ks_dir = tmp_path / "keystore"
    password = "SecretPassword2026!"
    meta = create_keystore(ks_dir, usage="encryption", password=password)
    pub_key = _load_public_key_from_metadata(meta)
    _, second_pub = generate_keypair()
    container = encrypt_hybrid(b"top secret", "plan.pdf", [pub_key, second_pub])

    # Attacker steals raw encrypted_private_key bytes without password
    raw_encrypted = (ks_dir / "encrypted_private_key").read_bytes()
    with pytest.raises(ValueError):
        serialization.load_der_private_key(raw_encrypted, password=None)

    # Attacker cannot unlock keystore without password
    with pytest.raises(KeystoreAccessError):
        unlock_private_key(ks_dir, password="")

    # Attacker cannot decrypt D3 container without unlocking the private key
    with pytest.raises(KeystoreAccessError):
        decrypt_file_with_keystore(container, ks_dir, password="guessed-password")


def test_key_separation_and_lifecycle(tmp_path):
    """Verify key usage separation, rotation, and compromise revocation."""
    enc_dir = tmp_path / "enc_ks"
    rot_dir = tmp_path / "enc_ks_v2"
    password = "LifecyclePassword1!"

    create_keystore(enc_dir, usage="encryption", password=password)

    # Encryption key cannot be used as signing key
    with pytest.raises(KeystoreLifecycleError):
        unlock_private_key(enc_dir, password=password, expected_usage="signing")

    # Rotation marks old key as rotated and creates new active key
    new_meta = rotate_key(enc_dir, rot_dir, old_password=password)
    assert new_meta["status"] == "active"
    old_meta = json.loads((enc_dir / "metadata").read_text(encoding="utf-8"))
    assert old_meta["status"] == "rotated"

    # Revocation blocks all future unlocking
    revoke_key(rot_dir, password=password)
    with pytest.raises(KeystoreLifecycleError):
        unlock_private_key(rot_dir, password=password)

    # Secure deletion wipes and removes keystore directory
    secure_delete_keystore(rot_dir)
    assert not rot_dir.exists()

def test_create_keystore_prevents_overwrite(tmp_path):
    """
    D6: comprueba que crear un keystore existente
    no destruya las claves ni los metadatos anteriores.
    """

    keystore_dir = tmp_path / "alice_keystore"

    # Crear el primer keystore.
    create_keystore(
        keystore_dir,
        usage="encryption",
        password="PasswordSegura123!",
    )

    # Guardar una copia de los archivos originales.
    filenames = (
        "encrypted_private_key",
        "salt",
        "kdf_parameters",
        "metadata",
    )

    original_files = {
        name: (keystore_dir / name).read_bytes()
        for name in filenames
    }

    # Intentar crear otro keystore en la misma ruta.
    # La implementacion segura debe rechazarlo.
    with pytest.raises(FileExistsError):
        create_keystore(
            keystore_dir,
            usage="encryption",
            password="PasswordNueva456!",
        )

    # Verificar que los archivos originales no cambiaron.
    for name in filenames:
        assert (keystore_dir / name).read_bytes() == original_files[name]


def test_keystore_restrictive_file_permissions(tmp_path):
    """
    D6: verifica que el directorio y los archivos
    del Keystore tengan permisos restrictivos.

    Directorio: 0700
    Archivos: 0600
    """

    keystore_dir = tmp_path / "secure_keystore"

    # Simular una configuracion comun de permisos Linux.
    # Restaurar siempre la umask original.
    original_umask = os.umask(0o022)

    try:
        create_keystore(
            keystore_dir,
            usage="encryption",
            password="PasswordSegura123!",
        )
    finally:
        os.umask(original_umask)

    # 1. Verificar permisos del directorio.
    directory_mode = stat.S_IMODE(
        keystore_dir.stat().st_mode
    )

    assert directory_mode == 0o700, (
        f"Permisos del directorio incorrectos: "
        f"{oct(directory_mode)}"
    )

    # 2. Verificar permisos de los archivos.
    filenames = (
        "encrypted_private_key",
        "salt",
        "kdf_parameters",
        "metadata",
    )

    for filename in filenames:
        file_path = keystore_dir / filename

        assert file_path.is_file()

        file_mode = stat.S_IMODE(
            file_path.stat().st_mode
        )

        assert file_mode == 0o600, (
            f"{filename} tiene permisos inseguros: "
            f"{oct(file_mode)}"
        )
