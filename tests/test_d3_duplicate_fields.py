"""D3: comprobar rechazo de campos JSON duplicados."""

import pytest

from encryption.hybrid_core import (
    generate_keypair,
    encrypt_hybrid,
    decrypt_hybrid,
)


def test_reject_duplicate_json_fields():
    # Generar dos destinatarios autorizados.
    alice_private, alice_public = generate_keypair()
    _, bob_public = generate_keypair()

    # Crear un contenedor D3 valido.
    original = b"Documento confidencial"

    container = encrypt_hybrid(
        original,
        "documento.txt",
        [alice_public, bob_public],
    )

    # Insertar un campo nonce duplicado.
    modified_container = container.replace(
        b'"nonce":',
        b'"nonce": "AAAA", "nonce":',
        1,
    )

    assert modified_container != container

    # El sistema debe rechazar campos JSON duplicados.
    with pytest.raises(ValueError, match="duplicad"):
        decrypt_hybrid(
            modified_container,
            alice_private,
        )
