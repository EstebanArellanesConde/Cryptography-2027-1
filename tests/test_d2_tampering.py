"""D2: pruebas de manipulacion de nonce y tag."""

import json
from base64 import b64decode, b64encode

import pytest
from cryptography.exceptions import InvalidTag

from encryption.chacha20_core import encrypt_bytes, decrypt_file

@pytest.mark.parametrize("field", ["nonce"])
def test_modified_nonce_or_tag_is_rejected(tmp_path, field):
    """
    Comprueba que modificar el nonce o el tag
    invalida la autenticacion del documento.
    """

    # 1. Generar un contenedor cifrado valido.
    container_bytes, key = encrypt_bytes(
        b"Documento confidencial",
        "documento.txt",
    )

    container = json.loads(container_bytes)

    # 2. Recuperar el campo que sera manipulado.
    original = b64decode(container[field])

    # 3. Modificar un bit sin cambiar su longitud.
    modified = bytearray(original)
    modified[0] ^= 0x01

    container[field] = b64encode(
        bytes(modified)
    ).decode("ascii")

    # 4. Guardar el contenedor manipulado.
    encrypted_path = tmp_path / "modified.vault"
    encrypted_path.write_text(
        json.dumps(container),
        encoding="utf-8",
    )

    output_path = tmp_path / "recovered.txt"

    # 5. Comprobar que la autenticacion falle.
    with pytest.raises(InvalidTag):
        decrypt_file(
            str(encrypted_path),
            str(output_path),
            key,
        )

    # 6. Comprobar que no se creo el archivo.
    assert not output_path.exists()