"""
D5 - Signatures & Authentication
Secure Digital Document Vault

Firmas digitales Ed25519 sobre el contenedor hibrido.
Flujo: Cifrar -> Agregar metadata -> Firmar -> Guardar.
Verificacion: Leer -> Verificar firma -> (si es valida) Descifrar.
"""

import json
import hashlib

from base64 import b64encode, b64decode
from binascii import Error as Base64Error

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .hybrid_core import decrypt_hybrid

# Datos cubiertos por la firma: AAD de D3 + ciphertext, tag y firmante.
SIGNED_FIELDS = (
    "header", "recipients", "nonce", "ciphertext", "tag", "signer_id"
)


def generate_signing_keypair():
    """Par de claves Ed25519, distinto del par X25519 de cifrado."""

    private_key = ed25519.Ed25519PrivateKey.generate()

    return private_key, private_key.public_key()


def get_signer_id(public_key) -> str:
    """Identificador del firmante: SHA-256 de la clave publica raw."""

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return hashlib.sha256(raw).hexdigest()


def build_signed_data(container: dict) -> bytes:
    """Serializacion canonica de los datos que se firman."""

    try:
        data = {field: container[field] for field in SIGNED_FIELDS}
    except KeyError as error:
        raise ValueError("Contenedor incompleto.") from error

    return json.dumps(
        data, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_container(container_bytes: bytes, signing_private_key) -> bytes:
    """Hash (SHA-256) -> Sign (Ed25519) -> agrega signer_id y signature."""

    container = json.loads(container_bytes)
    container["signer_id"] = get_signer_id(
        signing_private_key.public_key()
    )

    digest = hashlib.sha256(build_signed_data(container)).digest()
    container["signature"] = b64encode(
        signing_private_key.sign(digest)
    ).decode("utf-8")

    return json.dumps(container, indent=2).encode("utf-8")


def verify_container(container_bytes: bytes, sender_public_key) -> dict:
    """Verifica la firma; lanza ValueError si el contenedor es invalido."""

    try:
        container = json.loads(container_bytes)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("Contenedor JSON invalido.") from error

    if not isinstance(container, dict):
        raise ValueError("El contenedor debe ser un objeto JSON.")

    if "signature" not in container or "signer_id" not in container:
        raise ValueError("Contenedor sin firma.")

    if container["signer_id"] != get_signer_id(sender_public_key):
        raise ValueError("El firmante no coincide con la clave publica.")

    try:
        signature = b64decode(container["signature"], validate=True)
    except (Base64Error, TypeError, ValueError) as error:
        raise ValueError("Firma con Base64 invalido.") from error

    digest = hashlib.sha256(build_signed_data(container)).digest()

    try:
        sender_public_key.verify(signature, digest)
    except InvalidSignature as error:
        raise ValueError("Firma invalida: contenedor rechazado.") from error

    return container


def decrypt_signed(container_bytes: bytes, private_key, sender_public_key):
    """Verifica la firma PRIMERO y solo entonces descifra."""

    container = verify_container(container_bytes, sender_public_key)

    container.pop("signature")
    container.pop("signer_id")

    return decrypt_hybrid(json.dumps(container).encode("utf-8"), private_key)

