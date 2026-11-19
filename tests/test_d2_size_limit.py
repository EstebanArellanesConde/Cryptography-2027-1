"""D2: pruebas del limite maximo de archivos."""

import pytest
from encryption import chacha20_core as core

def test_encrypt_bytes_rejects_oversized_file(monkeypatch):
    """Rechazar datos que superen el limite."""
    monkeypatch.setattr(core, "MAX_FILE_SIZE", 16)

    with pytest.raises(ValueError, match="limite"):
        core.encrypt_bytes(b"A" * 17, "documento.txt")


def test_encrypt_file_rejects_oversized_file(
    tmp_path, monkeypatch
):
    """Rechazar un archivo grande antes de cifrarlo."""
    monkeypatch.setattr(core, "MAX_FILE_SIZE", 16)

    original = tmp_path / "documento.txt"
    original.write_bytes(b"A" * 17)

    destination = tmp_path / "documento.vault"

    with pytest.raises(ValueError, match="limite"):
        core.encrypt_file(str(original), str(destination))

    assert not destination.exists()


def test_decrypt_file_rejects_oversized_output(
    tmp_path, monkeypatch
):
    """Rechazar un archivo descifrado demasiado grande."""

    # Crear un contenedor valido usando el limite normal.
    container, key = core.encrypt_bytes(
        b"A" * 17,
        "documento.txt",
    )

    encrypted = tmp_path / "documento.vault"
    encrypted.write_bytes(container)

    destination = tmp_path / "recuperado.txt"

    # Reducir el limite solo durante la prueba.
    monkeypatch.setattr(core, "MAX_FILE_SIZE", 16)

    with pytest.raises(ValueError, match="limite"):
        core.decrypt_file(
            str(encrypted),
            str(destination),
            key,
        )

    assert not destination.exists()