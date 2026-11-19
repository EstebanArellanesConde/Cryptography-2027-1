"""D6: Key Management System for Secure Digital Document Vault.

Protects P-256 (D3 encryption) and Ed25519 (D5 signing) private keys at rest
using Argon2id key derivation and AES-256-GCM authenticated encryption.
"""

from __future__ import annotations

import base64
import gc
import getpass
import json
import os
import shutil
import zipfile
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from src.encryption.hybrid_core import (
    decrypt_hybrid,
    generate_keypair,
    get_key_id,
)
from src.encryption.signatures import (
    generate_signing_keypair,
    get_signer_id,
)

REQUIRED_FILES = (
    "encrypted_private_key",
    "salt",
    "kdf_parameters",
    "metadata",
)

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_LENGTH = 32

DEFAULT_KDF_PARAMS = {
    "kdf": "Argon2id",
    "iterations": 3,
    "lanes": 1,
    "memory_cost": 65536,  # 64 MiB
    "length": KEY_LENGTH,
}

USAGE_TO_ALGORITHM = {
    "encryption": "X25519",
    "signing": "Ed25519",
}


class KeystoreError(Exception):
    """Base exception for keystore operations."""


class KeystoreAccessError(KeystoreError):
    """Raised when unlocking fails (wrong password or invalid credentials)."""


class KeystoreIntegrityError(KeystoreError):
    """Raised when keystore files are missing, malformed, or tampered with."""


class KeystoreLifecycleError(KeystoreError):
    """Raised when key status, expiration, or usage policy blocks access."""


def prompt_password(prompt_text: str = "Enter keystore password: ") -> str:
    """Prompt the user for a password without echoing it to the terminal."""
    password = getpass.getpass(prompt_text)
    if not password:
        raise KeystoreAccessError("Password cannot be empty.")
    return password


def _zero_bytearray(buf: bytearray) -> None:
    """Best-effort in-memory zeroing of mutable sensitive buffers in RAM."""
    for i in range(len(buf)):
        buf[i] = 0


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_kek(
    password: str,
    salt: bytes,
    kdf_params: dict,
) -> bytes:
    """
    Deriva una clave AES-256 mediante Argon2id.

    Valida los parametros antes de ejecutar Argon2id
    para evitar consumo excesivo de recursos.
    """

    # 1. Validar la contrasena.
    if not isinstance(password, str) or not password:
        raise KeystoreAccessError(
            "Password must be a non-empty string."
        )

    # 2. Validar el algoritmo permitido.
    if not isinstance(kdf_params, dict):
        raise KeystoreIntegrityError(
            "Invalid KDF parameters."
        )

    if kdf_params.get("kdf") != "Argon2id":
        raise KeystoreIntegrityError(
            "Unsupported KDF."
        )

    # 3. Limites de seguridad definidos para D6.
    # memory_cost se expresa en KiB.
    limits = {
        "iterations": (3, 6),
        "lanes": (1, 4),
        "memory_cost": (65536, 131072),
        "length": (32, 32),
    }

    # 4. Validar todos los parametros antes de derivar.
    for parameter, (minimum, maximum) in limits.items():
        value = kdf_params.get(parameter)

        if type(value) is not int:
            raise KeystoreIntegrityError(
                f"Invalid Argon2id parameter: {parameter}"
            )

        if not minimum <= value <= maximum:
            raise KeystoreIntegrityError(
                f"Unsafe Argon2id parameter: {parameter}"
            )

    # 5. Crear Argon2id solamente con parametros seguros.
    try:
        kdf = Argon2id(
            salt=salt,
            length=kdf_params["length"],
            iterations=kdf_params["iterations"],
            lanes=kdf_params["lanes"],
            memory_cost=kdf_params["memory_cost"],
        )

    except (KeyError, TypeError, ValueError) as exc:
        raise KeystoreIntegrityError(
            "Invalid KDF parameters."
        ) from exc

    # 6. Derivar la clave.
    return kdf.derive(password.encode("utf-8"))


def _build_aad(kdf_params: dict, metadata: dict) -> bytes:
    return _canonical_json_bytes(kdf_params) + b"|" + _canonical_json_bytes(metadata)


def _encrypt_private_key_bytes(
    private_der: bytes,
    password: str,
    salt: bytes,
    kdf_params: dict,
    metadata: dict,
) -> bytes:
    kek_buf = bytearray(_derive_kek(password, salt, kdf_params))
    try:
        nonce = os.urandom(NONCE_SIZE)
        aad = _build_aad(kdf_params, metadata)
        ciphertext = AESGCM(bytes(kek_buf)).encrypt(nonce, private_der, aad)
        return nonce + ciphertext
    finally:
        _zero_bytearray(kek_buf)


def _load_keystore_files(keystore_dir: str | Path) -> tuple[bytes, bytes, dict, dict]:
    base = Path(keystore_dir)
    if not base.is_dir():
        raise KeystoreIntegrityError(f"Keystore directory not found: {base}")

    for filename in REQUIRED_FILES:
        if not (base / filename).is_file():
            raise KeystoreIntegrityError(f"Missing keystore file: {filename}")

    encrypted_blob = (base / "encrypted_private_key").read_bytes()
    salt = (base / "salt").read_bytes()
    if len(salt) != SALT_SIZE:
        raise KeystoreIntegrityError("Invalid salt length.")
    if len(encrypted_blob) < NONCE_SIZE + 16:
        raise KeystoreIntegrityError("Invalid encrypted_private_key length.")

    try:
        kdf_params = json.loads((base / "kdf_parameters").read_text(encoding="utf-8"))
        metadata = json.loads((base / "metadata").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KeystoreIntegrityError("Corrupted keystore JSON metadata.") from exc

    if not isinstance(kdf_params, dict) or not isinstance(metadata, dict):
        raise KeystoreIntegrityError("Keystore parameters and metadata must be JSON objects.")

    return encrypted_blob, salt, kdf_params, metadata

def _write_keystore_files(
    keystore_dir: str | Path,
    encrypted_blob: bytes,
    salt: bytes,
    kdf_params: dict,
    metadata: dict,
) -> None:
    """
    Guarda los archivos del Keystore con permisos restrictivos.

    En Linux:
    - Directorio: 0700.
    - Archivos: 0600.

    Cada archivo se prepara temporalmente y se reemplaza
    de forma atomica por separado.
    """

    base = Path(keystore_dir)

    # 1. No aceptar un directorio Keystore simbolico.
    if base.is_symlink():
        raise ValueError("No se permite un Keystore simbolico.")

    # 2. Preparar el directorio privado.
    base.mkdir(parents=True, exist_ok=True, mode=0o700)

    if os.name == "posix":
        base.chmod(0o700)

    # 3. Preparar los contenidos de los cuatro archivos.
    files = {
        "encrypted_private_key": encrypted_blob,
        "salt": salt,
        "kdf_parameters": json.dumps(
            kdf_params,
            indent=2,
            sort_keys=True,
        ).encode("utf-8"),
        "metadata": json.dumps(
            metadata,
            indent=2,
            sort_keys=True,
        ).encode("utf-8"),
    }

    # 4. Guardar cada archivo con permisos seguros.
    for filename, content in files.items():

        # Crear archivo temporal dentro del mismo directorio.
        # mkstemp utiliza permisos restrictivos en POSIX.
        fd, temporary_path = tempfile.mkstemp(
            prefix=f".{filename}.",
            dir=base,
        )

        try:
            with os.fdopen(fd, "wb") as file:

                # Asegurar permisos 0600 antes de escribir.
                if os.name == "posix":
                    os.fchmod(file.fileno(), 0o600)

                file.write(content)
                file.flush()
                os.fsync(file.fileno())

            # Reemplazar un archivo completo, no uno parcial.
            os.replace(
                temporary_path,
                base / filename,
            )

        finally:
            # Eliminar el temporal si ocurrio algun error.
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)


def _serialize_raw_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def create_keystore(
    keystore_dir: str | Path,
    usage: str,
    password: str | None = None,
    expires_at: str | None = None,
) -> dict:
    """Generate a new keypair and store the encrypted private key in keystore_dir."""
    if usage not in USAGE_TO_ALGORITHM:
        raise ValueError("usage must be 'encryption' or 'signing'")

    if password is None:
        password = prompt_password("Create keystore password: ")

    if usage == "encryption":
        private_key, public_key = generate_keypair()
        key_id = get_key_id(public_key)
    else:
        private_key, public_key = generate_signing_keypair()
        key_id = get_signer_id(public_key)

    private_raw = _serialize_raw_private_key(private_key)
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    salt = os.urandom(SALT_SIZE)
    kdf_params = dict(DEFAULT_KDF_PARAMS)
    metadata = {
        "key_id": key_id,
        "algorithm": USAGE_TO_ALGORITHM[usage],
        "usage": usage,
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": expires_at,
        "public_key_der_b64": base64.b64encode(public_der).decode("ascii"),
    }

    encrypted_blob = _encrypt_private_key_bytes(
        private_raw, password, salt, kdf_params, metadata
    )
    Path(keystore_dir).mkdir(parents=True, exist_ok=False, mode=0o700)
    _write_keystore_files(keystore_dir, encrypted_blob, salt, kdf_params, metadata)
    return metadata


def unlock_private_key(
    keystore_dir: str | Path,
    password: str | None = None,
    expected_usage: str | None = None,
    allow_rotated: bool = True,
):
    """Derive the KEK from password and decrypt the private key on demand.

    Does not store the password or cache the decrypted key.
    """
    encrypted_blob, salt, kdf_params, metadata = _load_keystore_files(keystore_dir)

    if password is None:
        password = prompt_password("Enter keystore password: ")

    kek_buf = bytearray(_derive_kek(password, salt, kdf_params))
    nonce = encrypted_blob[:NONCE_SIZE]
    ciphertext = encrypted_blob[NONCE_SIZE:]
    aad = _build_aad(kdf_params, metadata)
    private_raw_buf = bytearray()

    try:
        try:
            private_raw_buf.extend(AESGCM(bytes(kek_buf)).decrypt(nonce, ciphertext, aad))
        except InvalidTag as exc:
            raise KeystoreAccessError(
                "Failed to unlock keystore: wrong password or modified keystore."
            ) from exc

        status = metadata.get("status")
        if status == "revoked":
            raise KeystoreLifecycleError("Key has been revoked due to compromise.")
        if status == "rotated" and not allow_rotated:
            raise KeystoreLifecycleError("Key has been rotated and is no longer active.")
        if status not in ("active", "rotated"):
            raise KeystoreIntegrityError(f"Unknown key status: {status}")

        expires_at = metadata.get("expires_at")
        if expires_at is not None:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                raise KeystoreLifecycleError("Key has expired.")

        usage = metadata.get("usage")
        if expected_usage is not None and usage != expected_usage:
            raise KeystoreLifecycleError(
                f"Key usage mismatch: expected '{expected_usage}', got '{usage}'."
            )

        if usage == "encryption":
            private_key = X25519PrivateKey.from_private_bytes(bytes(private_raw_buf))
            derived_id = get_key_id(private_key.public_key())
        elif usage == "signing":
            private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_raw_buf))
            derived_id = get_signer_id(private_key.public_key())
        else:
            raise KeystoreIntegrityError(f"Unsupported key usage: {usage}")
    finally:
        _zero_bytearray(kek_buf)
        _zero_bytearray(private_raw_buf)

    if derived_id != metadata.get("key_id"):
        raise KeystoreIntegrityError("Key identity mismatch between private key and metadata.")

    return private_key


@contextmanager
def use_private_key(
    keystore_dir: str | Path,
    password: str | None = None,
    expected_usage: str | None = None,
    allow_rotated: bool = True,
) -> Iterator[object]:
    """Context manager that unlocks a private key only for the duration of an operation."""
    private_key = unlock_private_key(
        keystore_dir,
        password=password,
        expected_usage=expected_usage,
        allow_rotated=allow_rotated,
    )
    try:
        yield private_key
    finally:
        del private_key
        gc.collect()


def rotate_key(
    old_keystore_dir: str | Path,
    new_keystore_dir: str | Path,
    old_password: str | None = None,
    new_password: str | None = None,
    expires_at: str | None = None,
) -> dict:
    """Rotate a key: mark the old key as 'rotated' and generate a new active key."""
    if old_password is None:
        old_password = prompt_password("Enter current keystore password: ")
    if new_password is None:
        new_password = old_password

    private_key = unlock_private_key(
        old_keystore_dir, password=old_password, allow_rotated=False
    )
    _, _, _, old_metadata = _load_keystore_files(old_keystore_dir)
    usage = old_metadata["usage"]

    old_metadata["status"] = "rotated"
    old_metadata["rotated_at"] = datetime.now(timezone.utc).isoformat()
    old_private_raw = _serialize_raw_private_key(private_key)
    new_salt = os.urandom(SALT_SIZE)
    new_kdf_params = dict(DEFAULT_KDF_PARAMS)
    updated_blob = _encrypt_private_key_bytes(
        old_private_raw, old_password, new_salt, new_kdf_params, old_metadata
    )
    _write_keystore_files(
        old_keystore_dir, updated_blob, new_salt, new_kdf_params, old_metadata
    )

    return create_keystore(
        new_keystore_dir,
        usage=usage,
        password=new_password,
        expires_at=expires_at,
    )


def revoke_key(keystore_dir: str | Path, password: str | None = None) -> dict:
    """Revoke a compromised key so it can no longer be unlocked."""
    if password is None:
        password = prompt_password("Enter keystore password to revoke: ")

    private_key = unlock_private_key(
        keystore_dir, password=password, allow_rotated=True
    )
    _, _, _, metadata = _load_keystore_files(keystore_dir)
    metadata["status"] = "revoked"
    metadata["revoked_at"] = datetime.now(timezone.utc).isoformat()

    private_raw = _serialize_raw_private_key(private_key)
    new_salt = os.urandom(SALT_SIZE)
    new_kdf_params = dict(DEFAULT_KDF_PARAMS)
    updated_blob = _encrypt_private_key_bytes(
        private_raw, password, new_salt, new_kdf_params, metadata
    )
    _write_keystore_files(keystore_dir, updated_blob, new_salt, new_kdf_params, metadata)
    return metadata


def backup_keystore(keystore_dir: str | Path, backup_path: str | Path) -> Path:
    """Create an encrypted zip backup of the keystore (never contains plaintext keys)."""
    _load_keystore_files(keystore_dir)
    src = Path(keystore_dir)
    dst = Path(backup_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dst, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename in REQUIRED_FILES:
            zf.write(src / filename, arcname=filename)
    return dst


def restore_keystore(
    backup_path: str | Path,
    target_dir: str | Path,
) -> Path:
    """
    D6: restaura un Keystore desde un respaldo ZIP.

    - Rechaza respaldos corruptos.
    - No sobrescribe Keystores existentes.
    - Utiliza permisos restrictivos.
    - Limpia el directorio si ocurre un error.
    """

    src_zip = Path(backup_path)
    dst = Path(target_dir)

    # 1. Verificar que exista el respaldo.
    if not src_zip.is_file():
        raise KeystoreIntegrityError(
            f"Backup file not found: {src_zip}"
        )

    # 2. Leer y validar el ZIP antes de crear el destino.
    try:
        with zipfile.ZipFile(src_zip, "r") as zf:
            names = zf.namelist()

            # Cada archivo obligatorio debe aparecer
            # exactamente una vez.
            for filename in REQUIRED_FILES:
                if names.count(filename) != 1:
                    raise KeystoreIntegrityError(
                        "Backup archive has missing "
                        "or duplicate keystore files."
                    )

            # Recuperar los archivos del respaldo.
            contents = {
                filename: zf.read(filename)
                for filename in REQUIRED_FILES
            }

    except (zipfile.BadZipFile, EOFError,
            RuntimeError, OSError) as exc:
        raise KeystoreIntegrityError(
            "Corrupted or invalid backup ZIP."
        ) from exc

    # 3. No sobrescribir un Keystore existente.
    if dst.exists() or dst.is_symlink():
        raise FileExistsError(
            f"Destination already exists: {dst}"
        )

    # 4. Crear exclusivamente el directorio.
    dst.mkdir(
        parents=True,
        exist_ok=False,
        mode=0o700,
    )

    try:
        if os.name == "posix":
            dst.chmod(0o700)

        # 5. Escribir cada archivo con permisos 0600.
        for filename, data in contents.items():
            file_path = dst / filename

            fd = os.open(
                file_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )

            with os.fdopen(fd, "wb") as f:
                if os.name == "posix":
                    os.fchmod(f.fileno(), 0o600)

                f.write(data)

        # 6. Validar la estructura restaurada.
        _load_keystore_files(dst)

    except Exception:
        # 7. No dejar un Keystore incompleto.
        shutil.rmtree(dst, ignore_errors=True)
        raise

    return dst


def secure_delete_keystore(keystore_dir: str | Path) -> None:
    """Securely wipe keystore files (random overwrite + zero pass) before deleting."""
    base = Path(keystore_dir)
    if not base.exists():
        return
    for filename in REQUIRED_FILES:
        file_path = base / filename
        if file_path.is_file():
            size = file_path.stat().st_size
            with open(file_path, "r+b") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
                f.seek(0)
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())
            file_path.unlink()
    try:
        base.rmdir()
    except OSError:
        pass


def decrypt_file_with_keystore(
    container: dict,
    keystore_dir: str | Path,
    password: str | None = None,
) -> tuple[bytes, dict]:
    """Unlock the P-256 encryption key on demand and decrypt a D3 hybrid container."""
    with use_private_key(
        keystore_dir, password=password, expected_usage="encryption"
    ) as private_key:
        return decrypt_hybrid(container, private_key)

