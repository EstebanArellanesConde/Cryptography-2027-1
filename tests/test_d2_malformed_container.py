"""D2: pruebas de seguridad para contenedores malformados."""

import json

import pytest

from encryption.chacha20_core import (
    encrypt_bytes,
    decrypt_file,
)

@pytest.mark.parametrize(
    "scenario",
    [
        "invalid_json",
    ],
)
def test_reject_malformed_container(tmp_path, scenario):
    """
    Comprueba que un contenedor D2 malformado sea
    rechazado mediante un error controlado.

    Nunca debe generarse un archivo descifrado.
    """

    # 1. Crear un contenedor cifrado valido.
    container_bytes, key = encrypt_bytes(
        b"Documento confidencial de Alice",
        "documento.txt",
    )

    container = json.loads(container_bytes)

    # 2. Simular distintos contenedores malformados.
    if scenario == "invalid_json":
        modified_bytes = b'{"header":'

    else:
        if scenario == "missing_nonce":
            del container["nonce"]

        elif scenario == "wrong_ciphertext_type":
            container["ciphertext"] = 12345

        elif scenario == "invalid_base64":
            container["nonce"] = "%%%"
            
        modified_bytes = json.dumps(
            container
        ).encode("utf-8")

    # 3. Guardar el contenedor manipulado.
    encrypted_file = tmp_path / "damaged.vault"
    encrypted_file.write_bytes(modified_bytes)

    output_file = tmp_path / "recovered.txt"

    # 4. El sistema debe rechazarlo de forma controlada.
    with pytest.raises(
        ValueError,
        match="Contenedor D2 invalido",
    ):
        decrypt_file(
            str(encrypted_file),
            str(output_file),
            key,
        )

    # 5. No se debe generar un archivo de salida.
    assert not output_file.exists()

    @pytest.mark.parametrize(
        "scenario",
        [
            "invalid_json",
            "missing_nonce",
        ],
    )