"""D2: pruebas del limite maximo de archivos."""

import pytest
from encryption import chacha20_core as core

def test_encrypt_bytes_rejects_oversized_file(monkeypatch):
    """Rechazar datos que superen el limite."""
    monkeypatch.setattr(core, "MAX_FILE_SIZE", 16)

    with pytest.raises(ValueError, match="limite"):
        core.encrypt_bytes(b"A" * 17, "documento.txt")