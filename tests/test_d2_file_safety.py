"""D2: pruebas de proteccion contra sobrescritura."""

import pytestgit add tests/test_d2_file_safety.py
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

def test_decrypt_file_does_not_overwrite(tmp_path):
    original = tmp_path / "documento.txt"
    original.write_bytes(b"Documento confidencial")

    encrypted = tmp_path / "documento.vault"

    # Generar un contenedor valido para descifrar.
    key = encrypt_file(str(original), str(encrypted))

    destination = tmp_path / "recuperado.txt"
    destination.write_bytes(b"ARCHIVO IMPORTANTE")

    # El descifrado debe rechazar la sobrescritura.
    with pytest.raises(FileExistsError):
        decrypt_file(str(encrypted), str(destination), key)

    # El contenido previo debe permanecer intacto.
    assert destination.read_bytes() == b"ARCHIVO IMPORTANTE"