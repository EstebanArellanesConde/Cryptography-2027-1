"""
Unit and Security Tests for ECIES (Elliptic Curve Integrated Encryption Scheme)
Secure Digital Document Vault (Cryptography 2027-1, Team 6)
Session: 22 de Octubre
"""

import pytest
import os
import json
import base64

from cryptography.hazmat.primitives.asymmetric import ec
from encryption.ecies_core import (
    generate_ec_key_pair,
    compute_ec_fingerprint,
    ecies_encrypt,
    ecies_decrypt,
    ECIESDecryptionError,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
)
from encryption.hybrid_core import (
    encrypt_hybrid_bytes,
    decrypt_hybrid_bytes,
    generate_rsa_key_pair,
)
from encryption.chacha20_core import InvalidContainerError, IntegrityError


def test_ecies_roundtrip_basic():
    """Valida el ciclo completo de cifrado y descifrado ECIES entre Alice y Bob."""
    bob_priv, bob_pub = generate_ec_key_pair()
    secret_message = b"Clave simetrica secreta de 256 bits: \x01\x02\x03\x04\x05"

    # Alice cifra con la clave pública de Bob
    package = ecies_encrypt(bob_pub, secret_message, aad=b"VaultAAD")

    # Bob descifra con su clave privada
    decrypted = ecies_decrypt(bob_priv, package, aad=b"VaultAAD")

    assert decrypted == secret_message


def test_ecies_wrong_private_key_fails():
    """Valida que un atacante (Eve) no pueda descifrar el paquete con su clave privada."""
    bob_priv, bob_pub = generate_ec_key_pair()
    eve_priv, eve_pub = generate_ec_key_pair()

    secret = b"Documento clasificado"
    package = ecies_encrypt(bob_pub, secret)

    with pytest.raises(ECIESDecryptionError):
        ecies_decrypt(eve_priv, package)


def test_ecies_tampered_ciphertext_fails():
    """Valida que alterar un byte del ciphertext produzca fallo de autenticación en Poly1305."""
    bob_priv, bob_pub = generate_ec_key_pair()
    package = ecies_encrypt(bob_pub, b"Mensaje autenticado")

    # Alterar ciphertext
    raw_ct = bytearray(base64.b64decode(package["ciphertext"]))
    raw_ct[0] ^= 0x01
    package["ciphertext"] = base64.b64encode(raw_ct).decode('utf-8')

    with pytest.raises(ECIESDecryptionError):
        ecies_decrypt(bob_priv, package)


def test_ecies_tampered_ephemeral_key_fails():
    """Valida que alterar la clave pública efímera impida reconstruir el secreto compartido."""
    bob_priv, bob_pub = generate_ec_key_pair()
    package = ecies_encrypt(bob_pub, b"Mensaje autenticado")

    # Reemplazar la clave efímera por la de otro par
    other_priv, other_pub = generate_ec_key_pair()
    package["ephemeral_public_key"] = base64.b64encode(
        other_pub.public_bytes(
            encoding=ec._serialization.Encoding.X962,
            format=ec._serialization.PublicFormat.CompressedPoint
        )
    ).decode('utf-8')

    with pytest.raises(ECIESDecryptionError):
        ecies_decrypt(bob_priv, package)


def test_ecies_aad_mismatch_fails():
    """Valida que los Datos Autenticados Adicionales (AAD) estén estrictamente ligados."""
    bob_priv, bob_pub = generate_ec_key_pair()
    package = ecies_encrypt(bob_pub, b"Mensaje con AAD", aad=b"Cabecera-v1")

    with pytest.raises(ECIESDecryptionError):
        ecies_decrypt(bob_priv, package, aad=b"Cabecera-v2")


def test_ecies_pem_serialization_roundtrip():
    """Valida exportación e importación en formato PEM."""
    priv, pub = generate_ec_key_pair()
    priv_pem = export_private_key_pem(priv)
    pub_pem = export_public_key_pem(pub)

    reloaded_priv = load_private_key_pem(priv_pem)
    reloaded_pub = load_public_key_pem(pub_pem)

    assert compute_ec_fingerprint(pub) == compute_ec_fingerprint(reloaded_pub)

    # Cifrar con original y descifrar con recargada
    msg = b"Prueba de serializacion PEM"
    pkg = ecies_encrypt(reloaded_pub, msg)
    assert ecies_decrypt(reloaded_priv, pkg) == msg


def test_hybrid_vault_with_ecies_recipients():
    """Valida que el contenedor multireceptor de la bóveda funcione con claves EC (ECIES)."""
    alice_priv, alice_pub = generate_ec_key_pair()
    bob_priv, bob_pub = generate_ec_key_pair()

    data = b"Archivo protegido en la boveda usando ECIES"
    container_bytes = encrypt_hybrid_bytes(data, "doc_ec.txt", [alice_pub, bob_pub])

    # Alice descifra con su clave privada EC
    rec_alice, meta_alice = decrypt_hybrid_bytes(container_bytes, alice_priv)
    assert rec_alice == data
    assert meta_alice["filename"] == "doc_ec.txt"

    # Bob descifra con su clave privada EC
    rec_bob, meta_bob = decrypt_hybrid_bytes(container_bytes, bob_priv)
    assert rec_bob == data


def test_hybrid_vault_mixed_rsa_and_ecies_recipients():
    """Valida interoperabilidad mixta: un destinatario con RSA y otro con ECIES en el mismo archivo."""
    rsa_priv, rsa_pub = generate_rsa_key_pair(3072)
    ec_priv, ec_pub = generate_ec_key_pair()

    data = b"Contenido compartido entre receptor RSA y receptor ECIES"
    container_bytes = encrypt_hybrid_bytes(data, "mixed.txt", [rsa_pub, ec_pub])

    # El receptor RSA descifra
    rec_rsa, _ = decrypt_hybrid_bytes(container_bytes, rsa_priv)
    assert rec_rsa == data

    # El receptor ECIES descifra
    rec_ec, _ = decrypt_hybrid_bytes(container_bytes, ec_priv)
    assert rec_ec == data
