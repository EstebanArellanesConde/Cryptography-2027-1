"""D5: integración de D3 (ECIES), SHA-256 y firmas Ed25519.

Flujo de escritura: cifrar con D3 -> agregar signer_id -> hash -> firmar.
Flujo de lectura: verificar firma con clave pública confiable -> descifrar D3.

No genera ni almacena claves persistentes: el emisor/receptor las proporciona.
Los contenedores D3 sin firma NO se aceptan por esta interfaz D5.
"""

import json
from base64 import b64decode, b64encode
from binascii import Error as Base64Error

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from encryption.hybrid_core import (
    HEADER,
    decrypt_hybrid,
    encrypt_hybrid,
    validate_container,
)
from signatures.signable_payload import (
    hash_signed_payload,
    validate_signable_container,
)
from signatures.signature_core import (
    sign_digest,
    signer_key_id,
    verify_digest,
)


# Campos adicionales que exige D5. El resto pertenece al contenedor D3.
D5_FIELDS = frozenset({"signer_id", "signature"})


def _reject_duplicate_fields(pairs):
    """Evita interpretaciones ambiguas del JSON con claves repetidas."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Campo JSON duplicado: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value):
    raise ValueError(f"Valor JSON no permitido: {value}")


def _read_container(container_bytes: bytes) -> dict:
    """Lee un objeto JSON único (rechaza campos repetidos y valores NaN)."""
    if not isinstance(container_bytes, bytes):
        raise ValueError("Se requiere un contenedor JSON en bytes.")
    try:
        container = json.loads(
            container_bytes,
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Contenedor JSON inválido.") from exc
    if not isinstance(container, dict):
        raise ValueError("El contenedor debe ser un objeto JSON.")
    return container


def _write_container(container: dict) -> bytes:
    return json.dumps(
        container, indent=2, ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def sign_hybrid_container(
    unsigned_container_bytes: bytes,
    signing_private_key: Ed25519PrivateKey,
) -> bytes:
    """Firma un contenedor YA cifrado por D3, sin volver a cifrar el archivo."""
    if not isinstance(signing_private_key, Ed25519PrivateKey):
        raise ValueError("Se necesita una clave privada Ed25519.")

    container = _read_container(unsigned_container_bytes)
    validate_container(container)  # D3 exige exactamente sus cinco campos.
    if container["header"] != HEADER:
        raise ValueError("D5 requiere el contenedor ECIES P-256 de D3.")

    container["signer_id"] = signer_key_id(signing_private_key.public_key())
    digest = hash_signed_payload(container)  # Módulo de Axel.
    signature = sign_digest(digest, signing_private_key)  # Módulo de Esteban.
    container["signature"] = b64encode(signature).decode("ascii")
    return _write_container(container)


def encrypt_signed_hybrid(
    plaintext: bytes,
    filename: str,
    recipients: list,
    signing_private_key: Ed25519PrivateKey,
) -> bytes:
    """Realiza D3 y D5 en una llamada: cifrar -> firmar -> almacenar."""
    unsigned = encrypt_hybrid(plaintext, filename, recipients)
    return sign_hybrid_container(unsigned, signing_private_key)


def verify_signed_hybrid(
    signed_container_bytes: bytes,
    trusted_signer_public_key: Ed25519PublicKey,
) -> dict:
    """Verifica D5 y devuelve el contenedor D3 sin campos de firma.

    Es obligatorio pasar una clave pública Ed25519 previamente confiable.
    Nunca se obtiene la clave pública desde el JSON controlado por el atacante.
    """
    if not isinstance(trusted_signer_public_key, Ed25519PublicKey):
        raise ValueError("Se necesita una clave pública Ed25519 confiable.")

    container = _read_container(signed_container_bytes)
    validate_signable_container(container)  # Módulo de Axel.
    if "signature" not in container:
        raise ValueError("El contenedor no contiene una firma digital.")
    if container["header"] != HEADER:
        raise ValueError("Formato D3/ECIES incorrecto.")

    expected_id = signer_key_id(trusted_signer_public_key)
    if container["signer_id"] != expected_id:
        raise ValueError("El firmante no coincide con la clave pública confiable.")

    try:
        signature = b64decode(container["signature"], validate=True)
    except (Base64Error, ValueError) as exc:
        raise ValueError("La firma no es Base64 válido.") from exc
    if len(signature) != 64:
        raise ValueError("La firma Ed25519 tiene longitud inválida.")

    digest = hash_signed_payload(container)
    if not verify_digest(digest, signature, trusted_signer_public_key):
        raise ValueError("Firma digital inválida: contenedor rechazado.")

    # D3 no reconoce 'signer_id' ni 'signature': se retiran SOLO tras verificar.
    unsigned = {key: value for key, value in container.items()
                if key not in D5_FIELDS}
    validate_container(unsigned)
    return unsigned


def decrypt_signed_hybrid(
    signed_container_bytes: bytes,
    recipient_private_key,
    trusted_signer_public_key: Ed25519PublicKey,
) -> tuple[bytes, dict]:
    """Verifica ANTES de llamar al descifrado de D3."""
    verified_d3 = verify_signed_hybrid(
        signed_container_bytes, trusted_signer_public_key
    )
    return decrypt_hybrid(_write_container(verified_d3), recipient_private_key)
