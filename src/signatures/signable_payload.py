"""D5: construir y resumir los campos de un contenedor que deben firmarse.

Este módulo es independiente del código Ed25519 de Esteban.
Axel define los bytes exactos del contenedor que se firmarán en D5.
Cristian conectará SHA-256 con sign_digest/verify_digest de Esteban.
"""

import hashlib
import json
import re
from typing import Any


_SIGNED_FIELDS = frozenset({
    "header", "recipients", "nonce", "ciphertext", "tag", "signer_id"
})
_ALLOWED_FIELDS = _SIGNED_FIELDS | {"signature"}
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def validate_signable_container(container: dict[str, Any]) -> None:
    """Valida el conjunto de campos que D5 firmará.

    El campo ``signature`` puede faltar antes de firmar. Ningún otro
    campo puede quedar sin autenticar por accidente.
    """
    if not isinstance(container, dict):
        raise ValueError("El contenedor debe ser un objeto JSON.")

    actual = set(container)
    if not _SIGNED_FIELDS.issubset(actual) or not actual.issubset(_ALLOWED_FIELDS):
        raise ValueError("Faltan campos firmados o hay campos sin autenticar.")

    if not isinstance(container["header"], dict) or not container["header"]:
        raise ValueError("El encabezado es inválido.")

    recipients = container["recipients"]
    if not isinstance(recipients, list) or len(recipients) < 2:
        raise ValueError("Se requieren al menos dos destinatarios.")

    seen = set()
    for entry in recipients:
        if not isinstance(entry, dict) or set(entry) != {"key_id", "encrypted_key"}:
            raise ValueError("Cada destinatario debe tener key_id y encrypted_key.")
        key_id = entry["key_id"]
        if not isinstance(key_id, str) or not _HEX_SHA256.fullmatch(key_id):
            raise ValueError("El key_id del destinatario debe ser SHA-256 hexadecimal.")
        if not isinstance(entry["encrypted_key"], str) or not entry["encrypted_key"]:
            raise ValueError("La clave envuelta del destinatario es inválida.")
        if key_id in seen:
            raise ValueError("No se permiten destinatarios duplicados.")
        seen.add(key_id)

    for field in ("nonce", "ciphertext", "tag"):
        if not isinstance(container[field], str) or not container[field]:
            raise ValueError(f"Campo '{field}' inválido.")

    if not isinstance(container["signer_id"], str) or not _HEX_SHA256.fullmatch(
        container["signer_id"]
    ):
        raise ValueError("El signer_id debe ser SHA-256 hexadecimal.")

    if "signature" in container and not isinstance(container["signature"], str):
        raise ValueError("La firma debe estar codificada como texto.")


def canonical_signable_data(container: dict[str, Any]) -> bytes:
    """Serializa de modo determinista TODOS los campos de seguridad excepto signature.

    Al ordenar las claves, una reordenación superficial del JSON no afecta
    al resultado, pero alterar contenido/recipientes/signer_id sí lo hace.
    El orden de los DESTINATARIOS se conserva (forma parte de los datos).
    """
    validate_signable_container(container)
    payload = {name: container[name] for name in _SIGNED_FIELDS}
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("El contenedor contiene valores que no son JSON válido.") from exc


def hash_signed_payload(container: dict[str, Any]) -> bytes:
    """Retorna un digest SHA-256 de 32 bytes, compatible con sign_digest()."""
    return hashlib.sha256(canonical_signable_data(container)).digest()
