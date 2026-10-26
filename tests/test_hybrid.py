
"""
D3 - Hybrid Encryption
Required Security Tests

Cinco pruebas obligatorias del trabajo D3.
"""

import json
import base64
import pytest

from cryptography.exceptions import InvalidTag

from encryption.hybrid_core import (
    generate_rsa_keypair,
    get_key_id,
    encrypt_hybrid,
    decrypt_hybrid,
    decrypt_file_key
)


# ============================================================
# PRUEBA OBLIGATORIA 1
# File shared with 2 recipients; both decrypt successfully.
# ============================================================

def test_two_authorized_recipients():
    """
    Verifica que Alice y Bob recuperen exactamente
    el mismo archivo usando sus claves privadas.
    """

    # Generar claves independientes.
    alice_private, alice_public = generate_rsa_keypair()
    bob_private, bob_public = generate_rsa_keypair()

    original_data = b"Archivo secreto para Alice y Bob"

    # Cifrar una sola vez para ambos destinatarios.
    container = encrypt_hybrid(
        original_data,
        "documento.txt",
        [alice_public, bob_public]
    )

    # Cada destinatario descifra con su propia clave.
    alice_data, alice_metadata = decrypt_hybrid(
        container, alice_private
    )

    bob_data, bob_metadata = decrypt_hybrid(
        container, bob_private
    )

    # Verificar contenido y metadatos.
    assert alice_data == original_data
    assert bob_data == original_data

    assert alice_metadata["filename"] == "documento.txt"
    assert bob_metadata["filename"] == "documento.txt"


# ============================================================
# PRUEBA OBLIGATORIA 2
# Unauthorized user cannot decrypt the file.
# ============================================================

def test_unauthorized_recipient_fails():
    """
    Charlie no aparece entre los destinatarios
    autorizados y no debe recuperar el archivo.
    """

    alice_private, alice_public = generate_rsa_keypair()
    bob_private, bob_public = generate_rsa_keypair()
    charlie_private, charlie_public = generate_rsa_keypair()

    # Solamente Alice y Bob estan autorizados.
    container = encrypt_hybrid(
        b"Documento confidencial",
        "secreto.txt",
        [alice_public, bob_public]
    )

    # Charlie debe ser rechazado.
    with pytest.raises(
        ValueError,
        match="Destinatario no autorizado"
    ):
        decrypt_hybrid(container, charlie_private)


# ============================================================
# PRUEBA OBLIGATORIA 3
# Tampered recipient list causes authentication failure.
# ============================================================

def test_tampered_recipient_list_fails():
    """
    Modificar la clave cifrada de Bob debe invalidar
    el AAD incluso cuando Alice utiliza su clave correcta.
    """

    alice_private, alice_public = generate_rsa_keypair()
    bob_private, bob_public = generate_rsa_keypair()

    container_bytes = encrypt_hybrid(
        b"Documento confidencial",
        "documento.txt",
        [alice_public, bob_public]
    )

    container = json.loads(container_bytes)

    # Alterar un byte de la clave cifrada de Bob.
    encrypted_key = bytearray(
        base64.b64decode(
            container["recipients"][1]["encrypted_key"]
        )
    )

    encrypted_key[0] ^= 0xFF

    container["recipients"][1]["encrypted_key"] = (
        base64.b64encode(encrypted_key).decode("utf-8")
    )

    modified_container = json.dumps(container).encode("utf-8")

    # Alice conserva su propia clave, pero el AAD cambio.
    with pytest.raises(InvalidTag):
        decrypt_hybrid(modified_container, alice_private)


# ============================================================
# PRUEBA OBLIGATORIA 4
# Wrong private key fails.
# ============================================================

def test_wrong_private_key_fails():
    """
    Bob no puede recuperar la clave simetrica
    cifrada especificamente para Alice.
    """

    alice_private, alice_public = generate_rsa_keypair()
    bob_private, bob_public = generate_rsa_keypair()

    container_bytes = encrypt_hybrid(
        b"Documento protegido con RSA-OAEP",
        "documento.txt",
        [alice_public, bob_public]
    )

    container = json.loads(container_bytes)

    # Obtener la clave cifrada correspondiente a Alice.
    alice_key_id = get_key_id(alice_public)

    encrypted_key_alice = next(
        entry["encrypted_key"]
        for entry in container["recipients"]
        if entry["key_id"] == alice_key_id
    )

    encrypted_key_alice = base64.b64decode(
        encrypted_key_alice
    )

    # Intentar descifrar la clave de Alice con la privada de Bob.
    with pytest.raises(ValueError):
        decrypt_file_key(encrypted_key_alice, bob_private)


# ============================================================
# PRUEBA OBLIGATORIA 5
# Removing a recipient entry breaks access.
# ============================================================

def test_removed_recipient_fails():
    """
    Eliminar a Bob impide su acceso y modifica el AAD,
    invalidando tambien el descifrado de Alice.
    """

    # Tres destinatarios para mantener dos tras eliminar uno.
    alice_private, alice_public = generate_rsa_keypair()
    bob_private, bob_public = generate_rsa_keypair()
    charlie_private, charlie_public = generate_rsa_keypair()

    container_bytes = encrypt_hybrid(
        b"Archivo compartido con tres destinatarios",
        "documento.txt",
        [alice_public, bob_public, charlie_public]
    )

    container = json.loads(container_bytes)

    # Eliminar la entrada correspondiente a Bob.
    bob_key_id = get_key_id(bob_public)

    container["recipients"] = [
        entry for entry in container["recipients"]
        if entry["key_id"] != bob_key_id
    ]

    modified_container = json.dumps(container).encode("utf-8")

    # Bob no encuentra su clave cifrada.
    with pytest.raises(
        ValueError,
        match="Destinatario no autorizado"
    ):
        decrypt_hybrid(modified_container, bob_private)

    # Alice permanece autorizada, pero el AAD fue alterado.
    with pytest.raises(InvalidTag):
        decrypt_hybrid(modified_container, alice_private)
