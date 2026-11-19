"""D2: pruebas de proteccion contra sobrescritura."""

import pytest
from encryption.chacha20_core import encrypt_file, decrypt_file

def test_encrypt_file_does_not_overwrite(tmp_path):
    # Crear documento original.
    original = tmp_path / "documento.txt"
    original.write_bytes(b"Documento confidencial")

    # Crear un archivo destino que ya existe.
    destination = tmp_path / "documento.vault"
    destination.write_bytes(b"ARCHIVO EXISTENTE")

    # El cifrado debe rechazar la sobrescritura.
    with pytest.raises(FileExistsError):
        encrypt_file(str(original), str(destination))

    # Verificar que el archivo existente no cambio.
    assert destination.read_bytes() == b"ARCHIVO EXISTENTE"