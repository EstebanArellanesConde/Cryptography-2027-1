"""D3: pruebas de rechazo de contenedores malformados."""

import json

import pytest

from encryption.hybrid_core import (
    generate_keypair,
    encrypt_hybrid,
    decrypt_hybrid,
)


@pytest.mark.parametrize(
    "scenario",
    [
        "invalid_json",
        "missing_nonce",
        "wrong_recipients_type",
        "unexpected_field",
    ],
)
def test_reject_malformed_d3_container(scenario):
    """
    Verifica que D3 rechace contenedores con
    errores estructurales antes de descifrar.
    """

    # 1. Generar dos destinatarios autorizados.
    alice_private, alice_public = generate_keypair()
    _, bob_public = generate_keypair()

    # 2. Crear un contenedor D3 valido.
    original = encrypt_hybrid(
        b"Documento confidencial",
        "documento.txt",
        [alice_public, bob_public],
    )

    container = json.loads(original)

    # 3. Modificar la estructura del contenedor.
    if scenario == "invalid_json":
        modified = b'{"header":'

    else:
        if scenario == "missing_nonce":
            del container["nonce"]

        elif scenario == "wrong_recipients_type":
            container["recipients"] = "incorrecto"

        elif scenario == "unexpected_field":
            container["campo_extra"] = "no permitido"

        modified = json.dumps(container).encode("utf-8")

    # 4. El contenedor debe rechazarse.
    with pytest.raises(ValueError):
        decrypt_hybrid(
            modified,
            alice_private,
        )
