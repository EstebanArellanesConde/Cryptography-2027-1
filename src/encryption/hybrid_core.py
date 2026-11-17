
"""
D3 - Hybrid Encryption
Secure Digital Document Vault

Cifrado hibrido para multiples destinatarios.
ChaCha20-Poly1305 + ECIES (X25519, HKDF-SHA256).
"""

import os
import json
import hashlib

from base64 import b64encode, b64decode
from datetime import datetime, timezone
from binascii import Error as Base64Error

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization


# ============================================================
# REQUISITO 6: SECURE PUBLIC KEY USAGE
# Generacion de claves X25519 para cada destinatario.
# ============================================================

def generate_keypair():
    """
    Genera un par de claves X25519 (curva eliptica).
    Cada destinatario conserva su clave privada
    y comparte su clave publica.
    """

    private_key = x25519.X25519PrivateKey.generate()

    return private_key, private_key.public_key()


def _raw_public(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


# ============================================================
# REQUISITO 3: KEY IDENTIFICATION MECHANISM
# Identificacion mediante SHA-256 de la clave publica.
# ============================================================

def get_key_id(public_key) -> str:
    """
    Calcula el identificador de una clave publica
    (SHA-256 de sus 32 bytes en formato raw).
    """

    return hashlib.sha256(_raw_public(public_key)).hexdigest()


# ============================================================
# REQUISITO 6: SECURE PUBLIC KEY USAGE
# ECIES: X25519 efimero + HKDF-SHA256 + ChaCha20-Poly1305.
# Solo se protege la clave simetrica del archivo.
# ============================================================

def _derive_kek(shared_secret: bytes, eph_pub: bytes,
                recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureVault-key-wrap" + eph_pub + recipient_pub
    ).derive(shared_secret)


def encrypt_file_key(file_key: bytes, public_key) -> bytes:
    """
    Protege la clave simetrica para un destinatario.
    Resultado: clave publica efimera (32) || nonce (12) || cifrado (48).
    """

    if len(file_key) != 32:
        raise ValueError("La clave simetrica debe tener 32 bytes.")

    eph_private = x25519.X25519PrivateKey.generate()
    eph_pub = _raw_public(eph_private.public_key())
    recipient_pub = _raw_public(public_key)

    kek = _derive_kek(
        eph_private.exchange(public_key), eph_pub, recipient_pub
    )

    nonce = os.urandom(12)
    wrapped = ChaCha20Poly1305(kek).encrypt(nonce, file_key, recipient_pub)

    return eph_pub + nonce + wrapped


def decrypt_file_key(encrypted_key: bytes, private_key) -> bytes:
    """
    Recupera la clave simetrica con la clave privada
    X25519 correspondiente.
    """

    if len(encrypted_key) != 32 + 12 + 48:
        raise ValueError("Clave cifrada con longitud invalida.")

    eph_pub = encrypted_key[:32]
    nonce = encrypted_key[32:44]
    wrapped = encrypted_key[44:]
    recipient_pub = _raw_public(private_key.public_key())

    try:
        shared = private_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(eph_pub)
        )
        kek = _derive_kek(shared, eph_pub, recipient_pub)
        file_key = ChaCha20Poly1305(kek).decrypt(
            nonce, wrapped, recipient_pub
        )
    except (InvalidTag, ValueError) as error:
        raise ValueError("No se pudo recuperar la clave.") from error

    return file_key


# ============================================================
# REQUISITO 5: METADATA + AAD INTEGRATION
# Representacion consistente de datos autenticados.
# ============================================================

def build_aad(header: dict, recipients: list) -> bytes:
    """
    Construye el AAD con el encabezado y la lista
    completa de destinatarios, incluyendo key_id
    y encrypted_key.

    Cualquier modificacion invalida la autenticacion.
    """

    authenticated_data = {
        "header": header,
        "recipients": recipients
    }

    return json.dumps(
        authenticated_data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# ============================================================
# REQUISITOS 1, 4 Y 5:
# MULTI-RECIPIENT ENCRYPTION
# UPDATED CONTAINER FORMAT
# METADATA + AAD INTEGRATION
# ============================================================

def encrypt_hybrid(
    plaintext: bytes,
    filename: str,
    recipients: list
) -> bytes:
    """
    Cifra el archivo una sola vez mediante
    ChaCha20-Poly1305.

    La misma clave simetrica se protege para cada
    destinatario usando ECIES (X25519).

    Devuelve un contenedor JSON en bytes.
    """

    # 1. Verificar un minimo de dos destinatarios.
    if len(recipients) < 2:
        raise ValueError("Se requieren al menos dos destinatarios.")

    # 2. Generar clave simetrica y nonce nuevos.
    file_key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)

    # 3. Crear metadatos privados.
    metadata = {
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "plaintext_size": len(plaintext)
    }

    meta_bytes = json.dumps(metadata).encode("utf-8")
    meta_len = len(meta_bytes).to_bytes(4, "big")

    # Los metadatos privados se cifran con el archivo.
    payload = meta_len + meta_bytes + plaintext

    # 4. Proteger la clave para cada destinatario.
    recipient_entries = []
    seen_ids = set()

    for public_key in recipients:
        key_id = get_key_id(public_key)

        if key_id in seen_ids:
            raise ValueError("Hay destinatarios duplicados.")

        seen_ids.add(key_id)

        encrypted_key = encrypt_file_key(
            file_key,
            public_key
        )

        recipient_entries.append({
            "key_id": key_id,
            "encrypted_key": b64encode(
                encrypted_key
            ).decode("utf-8")
        })

    # 5. Crear encabezado publico.
    header = {
        "format": "SecureVault",
        "version": "3.0",
        "algorithm": "ChaCha20-Poly1305",
        "key_encryption": "X25519-HKDF-SHA256-ChaCha20Poly1305"
    }

    # 6. Autenticar metadatos y destinatarios con AAD.
    aad = build_aad(header, recipient_entries)

    # 7. Cifrar el archivo una sola vez.
    cipher = ChaCha20Poly1305(file_key)
    ct_with_tag = cipher.encrypt(nonce, payload, aad)

    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    # 8. Construir el contenedor hibrido.
    container = {
        "header": header,
        "recipients": recipient_entries,
        "nonce": b64encode(nonce).decode("utf-8"),
        "ciphertext": b64encode(ciphertext).decode("utf-8"),
        "tag": b64encode(tag).decode("utf-8")
    }

    return json.dumps(container, indent=2).encode("utf-8")


# ============================================================
# REQUISITO 4: UPDATED CONTAINER FORMAT
# Validacion basica del contenedor antes del descifrado.
# ============================================================

def validate_container(container: dict) -> None:
    """
    Comprueba la estructura obligatoria del contenedor
    y evita destinatarios duplicados.
    """

    if not isinstance(container, dict):
        raise ValueError("El contenedor debe ser un objeto JSON.")

    required_fields = {
        "header", "recipients", "nonce", "ciphertext", "tag"
    }

    if set(container.keys()) != required_fields:
        raise ValueError("Campos del contenedor invalidos o incompletos.")

    if not isinstance(container["header"], dict):
        raise ValueError("Encabezado invalido.")

    entries = container["recipients"]

    if not isinstance(entries, list) or len(entries) < 2:
        raise ValueError("Lista de destinatarios invalida.")

    seen_ids = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Entrada de destinatario invalida.")

        if set(entry.keys()) != {"key_id", "encrypted_key"}:
            raise ValueError("Campos de destinatario invalidos.")

        key_id = entry["key_id"]
        encrypted_key = entry["encrypted_key"]

        if not isinstance(key_id, str):
            raise ValueError("Identificador de clave invalido.")

        if len(key_id) != 64 or any(
            c not in "0123456789abcdef" for c in key_id
        ):
            raise ValueError("Identificador SHA-256 invalido.")

        if not isinstance(encrypted_key, str):
            raise ValueError("Clave cifrada invalida.")

        if key_id in seen_ids:
            raise ValueError("Identificadores de destinatarios duplicados.")

        seen_ids.add(key_id)

    for field in ("nonce", "ciphertext", "tag"):
        if not isinstance(container[field], str):
            raise ValueError(f"Campo {field} invalido.")


# ============================================================
# REQUISITOS 2, 3 Y 5:
# RECIPIENT-BASED DECRYPTION
# KEY IDENTIFICATION
# METADATA + AAD INTEGRATION
# ============================================================

def decrypt_hybrid(
    container_bytes: bytes,
    private_key
) -> tuple:
    """
    Descifra un contenedor hibrido usando la clave
    privada de un destinatario autorizado.

    Devuelve:
        (plaintext, metadata)
    """

    # 1. Leer y validar el contenedor.
    container = json.loads(container_bytes)

    validate_container(container)

    # 2. Verificar version y algoritmos.
    expected_header = {
        "format": "SecureVault",
        "version": "3.0",
        "algorithm": "ChaCha20-Poly1305",
        "key_encryption": "X25519-HKDF-SHA256-ChaCha20Poly1305"
    }

    if container["header"] != expected_header:
        raise ValueError("Formato o algoritmos no compatibles.")

    # 3. Identificar al destinatario mediante su clave.
    public_key = private_key.public_key()
    recipient_id = get_key_id(public_key)

    recipient_entries = container["recipients"]

    # 4. Localizar su clave simetrica cifrada.
    matches = [
        entry for entry in recipient_entries
        if entry["key_id"] == recipient_id
    ]

    if len(matches) != 1:
        raise ValueError("Destinatario no autorizado o duplicado.")

    # 5. Decodificar y recuperar la clave simetrica.
    try:
        encrypted_key = b64decode(
            matches[0]["encrypted_key"],
            validate=True
        )
    except Base64Error as error:
        raise ValueError(
            "La clave cifrada contiene Base64 invalido."
        ) from error

    file_key = decrypt_file_key(
        encrypted_key,
        private_key
    )

    # 6. Reconstruir el AAD.
    aad = build_aad(
        container["header"],
        recipient_entries
    )

    # 7. Recuperar datos cifrados.
    try:
        nonce = b64decode(container["nonce"], validate=True)
        ciphertext = b64decode(
            container["ciphertext"], validate=True
        )
        tag = b64decode(container["tag"], validate=True)
    except Base64Error as error:
        raise ValueError(
            "El contenedor contiene Base64 invalido."
        ) from error

    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Nonce o tag invalido.")

    # 8. Descifrar y verificar la autenticacion.
    cipher = ChaCha20Poly1305(file_key)

    payload = cipher.decrypt(
        nonce,
        ciphertext + tag,
        aad
    )

    # 9. Recuperar metadatos privados.
    if len(payload) < 4:
        raise ValueError("Payload invalido.")

    meta_len = int.from_bytes(payload[:4], "big")

    if meta_len > len(payload) - 4:
        raise ValueError("Longitud de metadatos invalida.")

    metadata = json.loads(
        payload[4:4 + meta_len].decode("utf-8")
    )

    if not isinstance(metadata, dict):
        raise ValueError("Metadatos invalidos.")

    # 10. Recuperar el archivo original.
    plaintext = payload[4 + meta_len:]

    if metadata.get("plaintext_size") != len(plaintext):
        raise ValueError("Tamano del archivo inconsistente.")

    return plaintext, metadata
