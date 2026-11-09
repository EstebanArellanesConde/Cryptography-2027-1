"""D3: cifrado híbrido para múltiples destinatarios con ECIES (P-256).

El archivo se cifra UNA sola vez con ChaCha20-Poly1305 (como en D2).
Cada destinatario recibe una copia de su clave de archivo protegida mediante:
    ECDH efímero (secp256r1) -> HKDF-SHA256 -> AES-256-GCM.

Interfaz conservada: get_key_id(), encrypt_file_key(), decrypt_file_key(),
build_aad(), encrypt_hybrid(), validate_container(), decrypt_hybrid().
Formato nuevo (versión 3.0); NO descifra los contenedores RSA anteriores.
"""

import hashlib
import json
import os
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Identificadores del formato (también forman parte del AAD).
HEADER = {
    "format": "SecureVault",
    "version": "3.0",
    "algorithm": "ChaCha20-Poly1305",
    "key_encryption": "ECIES-P256-ECDH-HKDF-SHA256-AESGCM",
}

# Clave pública efímera P-256 sin comprimir (65 bytes), salt (16), nonce (12).
EPHEMERAL_KEY_SIZE = 65
SALT_SIZE = 16
WRAP_NONCE_SIZE = 12
FILE_KEY_SIZE = 32
GCM_TAG_SIZE = 16


def generate_ecies_keypair():
    """Genera claves EC independientes para un destinatario (curva P-256)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def get_key_id(public_key) -> str:
    """Identificador estable: SHA-256 de SubjectPublicKeyInfo codificado en DER."""
    _require_p256_public_key(public_key)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_bytes).hexdigest()


def _require_p256_public_key(public_key) -> None:
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, ec.SECP256R1
    ):
        raise ValueError("Se requiere una clave publica EC de la curva P-256.")


def _require_p256_private_key(private_key) -> None:
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise ValueError("Se requiere una clave privada EC de la curva P-256.")


def _derive_wrapping_key(shared_secret: bytes, salt: bytes, key_id: str) -> bytes:
    """Separa el uso de la clave ECDH del cifrado de contenidos y liga el receptor."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=FILE_KEY_SIZE,
        salt=salt,
        info=b"SecureVault-D3-ECIES-P256-wrap-v1|" + key_id.encode("ascii"),
    ).derive(shared_secret)


def encrypt_file_key(file_key: bytes, public_key) -> bytes:
    """ECIES: protege solo los 32 bytes de clave ChaCha del archivo.

    Salida binaria: public_key_efimera(65) || salt(16) || nonce(12)
                  || AESGCM(file_key, AAD=recipient_key_id)(48).
    """
    _require_p256_public_key(public_key)
    if not isinstance(file_key, bytes) or len(file_key) != FILE_KEY_SIZE:
        raise ValueError("La clave simetrica debe tener 32 bytes.")

    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_bytes = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(WRAP_NONCE_SIZE)
    key_id = get_key_id(public_key)
    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
    wrapping_key = _derive_wrapping_key(shared_secret, salt, key_id)
    ciphertext_and_tag = AESGCM(wrapping_key).encrypt(
        nonce, file_key, key_id.encode("ascii")
    )
    return ephemeral_public_bytes + salt + nonce + ciphertext_and_tag


def decrypt_file_key(encrypted_key: bytes, private_key) -> bytes:
    """Recupera la clave de archivo con la clave privada EC correspondiente.

    Cualquier clave errónea, envoltura dañada o punto inválido se rechaza.
    """
    _require_p256_private_key(private_key)
    expected_size = (
        EPHEMERAL_KEY_SIZE + SALT_SIZE + WRAP_NONCE_SIZE
        + FILE_KEY_SIZE + GCM_TAG_SIZE
    )
    if not isinstance(encrypted_key, bytes) or len(encrypted_key) != expected_size:
        raise ValueError("Envoltura ECIES invalida.")

    ephem_end = EPHEMERAL_KEY_SIZE
    salt_end = ephem_end + SALT_SIZE
    nonce_end = salt_end + WRAP_NONCE_SIZE
    try:
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), encrypted_key[:ephem_end]
        )
        salt = encrypted_key[ephem_end:salt_end]
        nonce = encrypted_key[salt_end:nonce_end]
        ciphertext_and_tag = encrypted_key[nonce_end:]
        key_id = get_key_id(private_key.public_key())
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
        wrapping_key = _derive_wrapping_key(shared_secret, salt, key_id)
        file_key = AESGCM(wrapping_key).decrypt(
            nonce, ciphertext_and_tag, key_id.encode("ascii")
        )
    except (InvalidTag, ValueError) as error:
        raise ValueError("No se pudo recuperar la clave ECIES.") from error

    if len(file_key) != FILE_KEY_SIZE:
        raise ValueError("Longitud de clave recuperada invalida.")
    return file_key


def build_aad(header: dict, recipients: list) -> bytes:
    """Protege encabezado, algoritmos, IDs y envolturas para todos los receptores."""
    return json.dumps(
        {"header": header, "recipients": recipients},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def encrypt_hybrid(plaintext: bytes, filename: str, recipients: list) -> bytes:
    """Cifra UNA vez y produce un contenedor JSON serializado a bytes."""
    if not isinstance(plaintext, bytes) or not isinstance(filename, str):
        raise ValueError("Se necesitan contenido bytes y nombre str.")
    if not isinstance(recipients, list) or len(recipients) < 2:
        raise ValueError("Se requieren al menos dos destinatarios.")

    file_key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    metadata = {
        "filename": filename,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "plaintext_size": len(plaintext),
    }
    meta_bytes = json.dumps(metadata).encode("utf-8")
    payload = len(meta_bytes).to_bytes(4, "big") + meta_bytes + plaintext

    entries = []
    seen_ids = set()
    for public_key in recipients:
        key_id = get_key_id(public_key)
        if key_id in seen_ids:
            raise ValueError("Hay destinatarios duplicados.")
        seen_ids.add(key_id)
        entries.append({
            "key_id": key_id,
            "encrypted_key": b64encode(
                encrypt_file_key(file_key, public_key)
            ).decode("ascii"),
        })

    header = HEADER.copy()
    aad = build_aad(header, entries)
    ct_with_tag = ChaCha20Poly1305(file_key).encrypt(nonce, payload, aad)
    container = {
        "header": header,
        "recipients": entries,
        "nonce": b64encode(nonce).decode("ascii"),
        "ciphertext": b64encode(ct_with_tag[:-16]).decode("ascii"),
        "tag": b64encode(ct_with_tag[-16:]).decode("ascii"),
    }
    return json.dumps(container, indent=2).encode("utf-8")


def validate_container(container: dict) -> None:
    """Verifica sintaxis y duplicados antes de operaciones criptográficas."""
    if not isinstance(container, dict):
        raise ValueError("El contenedor debe ser un objeto JSON.")
    if set(container) != {"header", "recipients", "nonce", "ciphertext", "tag"}:
        raise ValueError("Campos del contenedor invalidos o incompletos.")
    if not isinstance(container["header"], dict):
        raise ValueError("Encabezado invalido.")
    entries = container["recipients"]
    if not isinstance(entries, list) or len(entries) < 2:
        raise ValueError("Lista de destinatarios invalida.")
    seen_ids = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"key_id", "encrypted_key"}:
            raise ValueError("Campos de destinatario invalidos.")
        key_id = entry["key_id"]
        if (not isinstance(key_id, str) or len(key_id) != 64
                or any(char not in "0123456789abcdef" for char in key_id)):
            raise ValueError("Identificador SHA-256 invalido.")
        if key_id in seen_ids:
            raise ValueError("Identificadores de destinatarios duplicados.")
        seen_ids.add(key_id)
        if not isinstance(entry["encrypted_key"], str):
            raise ValueError("Clave cifrada invalida.")
    for field in ("nonce", "ciphertext", "tag"):
        if not isinstance(container[field], str):
            raise ValueError(f"Campo {field} invalido.")


def _decode_base64(value: str, field: str) -> bytes:
    try:
        return b64decode(value, validate=True)
    except (Base64Error, ValueError) as error:
        raise ValueError(f"Base64 invalido en campo {field}.") from error


def decrypt_hybrid(container_bytes: bytes, private_key) -> tuple[bytes, dict]:
    """Localiza envoltura propia; descifra y autentica archivo + AAD."""
    _require_p256_private_key(private_key)
    try:
        container = json.loads(container_bytes)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("JSON invalido.") from error
    validate_container(container)
    if container["header"] != HEADER:
        raise ValueError("Formato o algoritmos no compatibles.")

    recipient_id = get_key_id(private_key.public_key())
    matches = [entry for entry in container["recipients"]
               if entry["key_id"] == recipient_id]
    if len(matches) != 1:
        raise ValueError("Destinatario no autorizado o duplicado.")

    encrypted_key = _decode_base64(matches[0]["encrypted_key"], "encrypted_key")
    file_key = decrypt_file_key(encrypted_key, private_key)
    aad = build_aad(container["header"], container["recipients"])
    nonce = _decode_base64(container["nonce"], "nonce")
    ciphertext = _decode_base64(container["ciphertext"], "ciphertext")
    tag = _decode_base64(container["tag"], "tag")
    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Nonce o tag invalido.")

    # InvalidTag se deja propagar: demuestra manipulación del contenedor.
    payload = ChaCha20Poly1305(file_key).decrypt(nonce, ciphertext + tag, aad)
    if len(payload) < 4:
        raise ValueError("Payload invalido.")
    meta_len = int.from_bytes(payload[:4], "big")
    if meta_len > len(payload) - 4:
        raise ValueError("Longitud de metadatos invalida.")
    try:
        metadata = json.loads(payload[4:4 + meta_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Metadatos invalidos.") from error
    if not isinstance(metadata, dict):
        raise ValueError("Metadatos invalidos.")
    plaintext = payload[4 + meta_len:]
    if metadata.get("plaintext_size") != len(plaintext):
        raise ValueError("Tamano del archivo inconsistente.")
    return plaintext, metadata
