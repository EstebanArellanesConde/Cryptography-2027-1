"""Pruebas de D3: cinco obligatorias y verificaciones ECIES adicionales."""
import base64
import json

import pytest
from cryptography.exceptions import InvalidTag

from encryption.hybrid_core import (
    decrypt_file_key,
    decrypt_hybrid,
    encrypt_hybrid,
    generate_ecies_keypair,
    get_key_id,
)


def _keys():
    alice_private, alice_public = generate_ecies_keypair()
    bob_private, bob_public = generate_ecies_keypair()
    return alice_private, alice_public, bob_private, bob_public


def _repack(container):
    return json.dumps(container).encode("utf-8")


# D3 prueba 1: ambos destinatarios recuperan exactamente el archivo.
def test_two_authorized_recipients():
    alice_private, alice_public, bob_private, bob_public = _keys()
    original = b"Archivo secreto para Alice y Bob"
    encrypted = encrypt_hybrid(original, "documento.txt", [alice_public, bob_public])
    alice_data, alice_meta = decrypt_hybrid(encrypted, alice_private)
    bob_data, bob_meta = decrypt_hybrid(encrypted, bob_private)
    assert alice_data == bob_data == original
    assert alice_meta["filename"] == bob_meta["filename"] == "documento.txt"
    assert json.loads(encrypted)["header"]["key_encryption"].startswith("ECIES-P256")


# D3 prueba 2: Charlie no aparece en la lista de destinatarios.
def test_unauthorized_recipient_fails():
    _, alice_public, _, bob_public = _keys()
    charlie_private, _ = generate_ecies_keypair()
    encrypted = encrypt_hybrid(b"Confidencial", "a.txt", [alice_public, bob_public])
    with pytest.raises(ValueError, match="Destinatario no autorizado"):
        decrypt_hybrid(encrypted, charlie_private)


# D3 prueba 3: manipular entrada de Bob invalida el AAD para Alice.
def test_tampered_recipient_list_fails():
    alice_private, alice_public, _, bob_public = _keys()
    container = json.loads(encrypt_hybrid(b"Secreto", "a.txt", [alice_public, bob_public]))
    wrapped = bytearray(base64.b64decode(container["recipients"][1]["encrypted_key"]))
    wrapped[0] ^= 0xFF
    container["recipients"][1]["encrypted_key"] = base64.b64encode(wrapped).decode()
    with pytest.raises(InvalidTag):
        decrypt_hybrid(_repack(container), alice_private)


# D3 prueba 4: Bob no puede abrir la envoltura ECIES de Alice.
def test_wrong_private_key_fails():
    _, alice_public, bob_private, bob_public = _keys()
    container = json.loads(encrypt_hybrid(b"Secreto", "a.txt", [alice_public, bob_public]))
    wrapped = next(entry["encrypted_key"] for entry in container["recipients"]
                   if entry["key_id"] == get_key_id(alice_public))
    with pytest.raises(ValueError):
        decrypt_file_key(base64.b64decode(wrapped), bob_private)


# D3 prueba 5: eliminación de Bob deniega acceso e invalida AAD de Alice.
def test_removed_recipient_fails():
    alice_private, alice_public, bob_private, bob_public = _keys()
    _, charlie_public = generate_ecies_keypair()
    container = json.loads(encrypt_hybrid(
        b"Secreto", "a.txt", [alice_public, bob_public, charlie_public]
    ))
    container["recipients"] = [entry for entry in container["recipients"]
                               if entry["key_id"] != get_key_id(bob_public)]
    with pytest.raises(ValueError, match="Destinatario no autorizado"):
        decrypt_hybrid(_repack(container), bob_private)
    with pytest.raises(InvalidTag):
        decrypt_hybrid(_repack(container), alice_private)


# Extra 6: encabezado público modificado: no puede hacerse pasar por otro esquema.
def test_header_tamper_fails():
    alice_private, alice_public, _, bob_public = _keys()
    container = json.loads(encrypt_hybrid(b"Secreto", "a.txt", [alice_public, bob_public]))
    container["header"]["algorithm"] = "AES-ECB"
    with pytest.raises(ValueError, match="algoritmos no compatibles"):
        decrypt_hybrid(_repack(container), alice_private)


# Extra 7: metadatos sensibles no aparecen en texto claro.
def test_metadata_confidentiality():
    _, alice_public, _, bob_public = _keys()
    encrypted = encrypt_hybrid(b"Secreto", "nombre_reservado_123.txt", [alice_public, bob_public])
    assert b"nombre_reservado_123.txt" not in encrypted


# Extra 8: no se admiten destinatarios repetidos.
def test_duplicate_recipients_fails():
    _, alice_public = generate_ecies_keypair()
    with pytest.raises(ValueError, match="duplicados"):
        encrypt_hybrid(b"Secreto", "a.txt", [alice_public, alice_public])


# Extra 9: un cambio al ciphertext externo se detecta mediante su tag.
def test_ciphertext_tamper_fails():
    alice_private, alice_public, _, bob_public = _keys()
    container = json.loads(encrypt_hybrid(b"Secreto", "a.txt", [alice_public, bob_public]))
    original = bytearray(base64.b64decode(container["ciphertext"]))
    original[-1] ^= 1
    container["ciphertext"] = base64.b64encode(original).decode()
    with pytest.raises(InvalidTag):
        decrypt_hybrid(_repack(container), alice_private)
