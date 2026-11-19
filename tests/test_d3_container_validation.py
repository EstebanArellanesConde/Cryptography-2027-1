"""D3: pruebas de validacion estructural de contenedores."""

import json

import pytest

from encryption.hybrid_core import (
    generate_keypair,
    encrypt_hybrid,
    validate_container,
)


@pytest.mark.parametrize(
    "invalid_key",
    [
        "%%%",   # Base64 invalido.
        "",      # Clave protegida vacia.
        "AA==",  # Base64 valido, longitud incorrecta.
    ],
)
def test_reject_invalid_recipient_protected_key(invalid_key):
    """
    Verifica que D3 rechace claves protegidas malformadas
    en cualquier destinatario.
    """

    # 1. Generar claves X25519 para Alice y Bob.
    _, alice_public = generate_keypair()
    _, bob_public = generate_keypair()

    # 2. Cifrar un documento para dos destinatarios.
    container_bytes = encrypt_hybrid(
        b"Documento confidencial",
        "documento.txt",
        [alice_public, bob_public],
    )

    # 3. Convertir el contenedor JSON a diccionario.
    container = json.loads(container_bytes)

    # 4. Simular una clave protegida malformada para Bob.
    container["recipients"][1]["encrypted_key"] = invalid_key

    # 5. La validacion estructural debe rechazarla.
    with pytest.raises(ValueError):
        validate_container(container)


def test_accept_valid_recipient_protected_keys():
    """
    Verifica que un contenedor legitimo conserve
    su estructura valida.
    """

    _, alice_public = generate_keypair()
    _, bob_public = generate_keypair()

    container_bytes = encrypt_hybrid(
        b"Documento confidencial",
        "documento.txt",
        [alice_public, bob_public],
    )

    container = json.loads(container_bytes)

    # No debe producir ninguna excepcion.
    validate_container(container)
