"""
Security Test Suite for Deliverable D3: Multi-Recipient Hybrid Encryption Module
Secure Digital Document Vault (Cryptography 2027-1, Team 6)

Mandatory Security Tests (per D3 Specification):
- Test 1: Dos receptores autorizados descifran el mismo archivo.
- Test 2: Un receptor no autorizado no puede descifrar el archivo.
- Test 3: La modificación de un elemento en la lista de receptores causa fallo de autenticación AAD.
- Test 4: El uso de una clave privada RSA incorrecta impide recuperar la clave simétrica.
- Test 5: La eliminación de una entrada de receptor rompe el acceso y la integridad del paquete.

Supplementary Tests:
- Deterministic SPKI SHA-256 fingerprint validation.
- Nonce and ciphertext uniqueness across encryptions.
- Atomic fail-closed file writing.
"""

import pytest
import os
import json
import base64
from cryptography.exceptions import InvalidTag

from encryption.hybrid_core import (
    generate_rsa_key_pair,
    compute_key_fingerprint,
    encrypt_hybrid_bytes,
    decrypt_hybrid_bytes,
    encrypt_hybrid_file,
    decrypt_hybrid_file,
    UnauthorizedRecipientError,
    KeyUnwrapError,
    IntegrityError,
    InvalidContainerError,
    VaultSecurityError,
)
from encryption.chacha20_core import MAX_FILE_SIZE


# ---------------------------------------------------------------------------
# Test 1: Dos receptores autorizados descifran el mismo archivo
# ---------------------------------------------------------------------------
def test_two_authorized_recipients_decrypt_same_file(tmp_path):
    """
    Test 1: Confirma que el contenido del archivo se cifra UNA sola vez con
    ChaCha20-Poly1305 y que dos receptores autorizados con diferentes pares de
    claves RSA (3072 bits) descifran exitosamente exactamente el mismo contenido.
    """
    # 1. Generar pares de claves RSA de 3072 bits para Alice y Bob
    alice_priv, alice_pub = generate_rsa_key_pair(3072)
    bob_priv, bob_pub = generate_rsa_key_pair(3072)

    # 2. Preparar archivo de entrada
    input_file = tmp_path / "secret_document.pdf"
    output_vault = tmp_path / "secret_document.pdf.svlt"
    alice_recovered = tmp_path / "alice_recovered.pdf"
    bob_recovered = tmp_path / "bob_recovered.pdf"

    original_content = b"%PDF-1.7 Documento Confidencial Compartido entre Alice y Bob"
    input_file.write_bytes(original_content)

    # 3. Cifrar una sola vez para ambos receptores
    encrypt_hybrid_file(
        str(input_file),
        str(output_vault),
        [alice_pub, bob_pub]
    )

    # 4. Alice descifra el archivo con su clave privada
    alice_meta = decrypt_hybrid_file(str(output_vault), str(alice_recovered), alice_priv)
    assert alice_recovered.read_bytes() == original_content
    assert alice_meta["filename"] == "secret_document.pdf"
    assert alice_meta["plaintext_size"] == len(original_content)

    # 5. Bob descifra el mismo contenedor con su clave privada
    bob_meta = decrypt_hybrid_file(str(output_vault), str(bob_recovered), bob_priv)
    assert bob_recovered.read_bytes() == original_content
    assert bob_meta["filename"] == "secret_document.pdf"
    assert bob_meta["plaintext_size"] == len(original_content)

    # 6. Validar estructura del contenedor: un único ciphertext y dos destinatarios envueltos
    container = json.loads(output_vault.read_text())
    assert len(container["recipients"]) == 2
    recipient_ids = {r["recipient_id"] for r in container["recipients"]}
    assert compute_key_fingerprint(alice_pub) in recipient_ids
    assert compute_key_fingerprint(bob_pub) in recipient_ids


# ---------------------------------------------------------------------------
# Test 2: Un receptor no autorizado no puede descifrar el archivo
# ---------------------------------------------------------------------------
def test_unauthorized_recipient_cannot_decrypt(tmp_path):
    """
    Test 2: Confirma que un receptor no autorizado (cuya clave pública no fue incluida
    durante el empaquetado) es rechazado inmediatamente bajo el principio fail-closed
    sin filtrar información ni realizar operaciones innecesarias.
    """
    alice_priv, alice_pub = generate_rsa_key_pair(3072)
    eve_priv, eve_pub = generate_rsa_key_pair(3072)  # Atacante no autorizado

    input_file = tmp_path / "classified.txt"
    output_vault = tmp_path / "classified.svlt"
    eve_recovered = tmp_path / "eve_recovered.txt"

    original_content = b"Solo para ojos de Alice"
    input_file.write_bytes(original_content)

    # Cifrar exclusivamente para Alice
    encrypt_hybrid_file(str(input_file), str(output_vault), [alice_pub])

    # Eve intenta descifrar con su clave privada
    with pytest.raises(UnauthorizedRecipientError):
        decrypt_hybrid_file(str(output_vault), str(eve_recovered), eve_priv)

    # Confirmar principio fail-closed: el archivo destino NO fue creado
    assert not eve_recovered.exists()


# ---------------------------------------------------------------------------
# Test 3: Modificación de un elemento en la lista de receptores causa fallo AAD
# ---------------------------------------------------------------------------
def test_tampered_recipient_list_causes_aad_failure(tmp_path):
    """
    Test 3: Confirma que la lista completa de receptores forma parte del AAD de
    ChaCha20-Poly1305. Cualquier modificación a un elemento de la lista (clave envuelta
    o identificador) rompe la autenticación AEAD y produce un fallo de integridad.
    """
    alice_priv, alice_pub = generate_rsa_key_pair(3072)
    bob_priv, bob_pub = generate_rsa_key_pair(3072)

    input_file = tmp_path / "data.txt"
    output_vault = tmp_path / "data.svlt"
    alice_recovered = tmp_path / "alice_recovered.txt"

    input_file.write_bytes(b"Datos protegidos con AAD vinculado a receptores")
    encrypt_hybrid_file(str(input_file), str(output_vault), [alice_pub, bob_pub])

    container = json.loads(output_vault.read_text())

    # Identificar la entrada de Bob y alterar su clave cifrada
    bob_fingerprint = compute_key_fingerprint(bob_pub)
    for entry in container["recipients"]:
        if entry["recipient_id"] == bob_fingerprint:
            raw_enc = bytearray(base64.b64decode(entry["encrypted_key"]))
            raw_enc[10] ^= 0x55  # Alterar un byte
            entry["encrypted_key"] = base64.b64encode(raw_enc).decode('utf-8')
            break

    output_vault.write_text(json.dumps(container))

    # Alice (cuya clave privada y entrada individual están intactas) intenta descifrar.
    # Dado que la lista completa de receptores forma parte del AAD, la verificación
    # Poly1305 debe fallar inmediatamente.
    with pytest.raises((IntegrityError, InvalidTag)):
        decrypt_hybrid_file(str(output_vault), str(alice_recovered), alice_priv)

    assert not alice_recovered.exists()


# ---------------------------------------------------------------------------
# Test 4: Clave privada RSA incorrecta impide recuperar la clave simétrica
# ---------------------------------------------------------------------------
def test_wrong_rsa_private_key_fails_key_recovery(tmp_path):
    """
    Test 4: Confirma que el uso de una clave privada RSA incorrecta impide
    desenvolver la clave simétrica DEK mediante RSA-OAEP, fallando de forma segura
    sin actuar como oráculo de padding.
    """
    alice_priv, alice_pub = generate_rsa_key_pair(3072)
    charlie_priv, charlie_pub = generate_rsa_key_pair(3072)

    input_file = tmp_path / "test.txt"
    output_vault = tmp_path / "test.svlt"
    charlie_recovered = tmp_path / "charlie_recovered.txt"

    input_file.write_bytes(b"Secreto bancario o financiero")
    encrypt_hybrid_file(str(input_file), str(output_vault), [alice_pub])

    # Charlie altera el JSON del contenedor para colocar su recipient_id, pero manteniendo
    # la clave envuelta cifrada con la clave pública de Alice.
    container = json.loads(output_vault.read_text())
    charlie_fp = compute_key_fingerprint(charlie_pub)
    container["recipients"][0]["recipient_id"] = charlie_fp
    output_vault.write_text(json.dumps(container))

    # Charlie intenta descifrar con su clave privada. RSA-OAEP no puede desenvolver la DEK.
    with pytest.raises(KeyUnwrapError):
        decrypt_hybrid_file(str(output_vault), str(charlie_recovered), charlie_priv)

    assert not charlie_recovered.exists()


# ---------------------------------------------------------------------------
# Test 5: La eliminación de una entrada de receptor rompe integridad del paquete
# ---------------------------------------------------------------------------
def test_deleted_recipient_breaks_access_and_integrity(tmp_path):
    """
    Test 5: Confirma que un atacante que elimine a un receptor de la lista en el
    contenedor no puede pasar desapercibido: el AAD no coincide con el tag Poly1305,
    impidiendo el acceso incluso a los receptores que permanecen en la lista.
    """
    alice_priv, alice_pub = generate_rsa_key_pair(3072)
    bob_priv, bob_pub = generate_rsa_key_pair(3072)

    input_file = tmp_path / "multi.txt"
    output_vault = tmp_path / "multi.svlt"
    alice_recovered = tmp_path / "alice_recovered.txt"
    bob_recovered = tmp_path / "bob_recovered.txt"

    input_file.write_bytes(b"Documento critico para ambos socios")
    encrypt_hybrid_file(str(input_file), str(output_vault), [alice_pub, bob_pub])

    # El atacante elimina la entrada de Bob de la lista de receptores
    container = json.loads(output_vault.read_text())
    bob_fp = compute_key_fingerprint(bob_pub)
    container["recipients"] = [r for r in container["recipients"] if r["recipient_id"] != bob_fp]
    assert len(container["recipients"]) == 1
    output_vault.write_text(json.dumps(container))

    # 1. Bob no puede descifrar porque fue eliminado de los receptores
    with pytest.raises(UnauthorizedRecipientError):
        decrypt_hybrid_file(str(output_vault), str(bob_recovered), bob_priv)

    # 2. Alice (cuya clave envuelta permanece intacta) intenta descifrar.
    # Como el receptor fue eliminado, el AAD se altera y la verificación AEAD falla.
    with pytest.raises((IntegrityError, InvalidTag)):
        decrypt_hybrid_file(str(output_vault), str(alice_recovered), alice_priv)

    assert not alice_recovered.exists()
    assert not bob_recovered.exists()


# ---------------------------------------------------------------------------
# Pruebas de Seguridad Adicionales
# ---------------------------------------------------------------------------
def test_deterministic_spki_fingerprint():
    """Valida que el fingerprint SHA-256 de SubjectPublicKeyInfo DER sea determinista y consistente."""
    priv, pub = generate_rsa_key_pair(3072)
    fp1 = compute_key_fingerprint(pub)
    fp2 = compute_key_fingerprint(pub)
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string


def test_hybrid_multiple_encryptions_produce_unique_nonces_and_ciphertexts():
    """Confirma que cifrar el mismo archivo dos veces genera nonces y ciphertexts distintos."""
    priv, pub = generate_rsa_key_pair(3072)
    data = b"Mismo texto para dos cifrados distintos"

    c1 = json.loads(encrypt_hybrid_bytes(data, "doc.txt", [pub]))
    c2 = json.loads(encrypt_hybrid_bytes(data, "doc.txt", [pub]))

    assert c1["nonce"] != c2["nonce"]
    assert c1["ciphertext"] != c2["ciphertext"]
    assert c1["recipients"][0]["encrypted_key"] != c2["recipients"][0]["encrypted_key"]


def test_hybrid_rejection_over_256_mib():
    """Verifica que se rechacen datos que excedan el límite de 256 MiB."""
    priv, pub = generate_rsa_key_pair(3072)
    # Crear un buffer simulado de tamaño > 256 MiB sin consumir toda la RAM real mediante un memoryview/bytearray mock
    class LargeBytes(bytes):
        def __len__(self):
            return MAX_FILE_SIZE + 1

    large_dummy = LargeBytes()
    with pytest.raises(ValueError, match="exceeds maximum limit of 256 MiB"):
        encrypt_hybrid_bytes(large_dummy, "huge.bin", [pub])


def test_hybrid_modified_ciphertext_fails(tmp_path):
    """Verifica que la modificación de un solo bit en el ciphertext sea detectada por Poly1305."""
    priv, pub = generate_rsa_key_pair(3072)
    input_file = tmp_path / "sample.txt"
    output_vault = tmp_path / "sample.svlt"
    recovered = tmp_path / "recovered.txt"

    input_file.write_bytes(b"Autenticidad AEAD ChaCha20-Poly1305")
    encrypt_hybrid_file(str(input_file), str(output_vault), [pub])

    container = json.loads(output_vault.read_text())
    raw_ct = bytearray(base64.b64decode(container["ciphertext"]))
    raw_ct[0] ^= 0x01
    container["ciphertext"] = base64.b64encode(raw_ct).decode('utf-8')
    output_vault.write_text(json.dumps(container))

    with pytest.raises((IntegrityError, InvalidTag)):
        decrypt_hybrid_file(str(output_vault), str(recovered), priv)

    assert not recovered.exists()


def test_hybrid_output_already_exists_fails_unless_overwrite(tmp_path):
    """Verifica que decrypt_hybrid_file no sobreescriba un archivo existente a menos que se indique."""
    priv, pub = generate_rsa_key_pair(3072)
    input_file = tmp_path / "msg.txt"
    output_vault = tmp_path / "msg.svlt"
    recovered = tmp_path / "existing.txt"

    input_file.write_bytes(b"Contenido importante")
    encrypt_hybrid_file(str(input_file), str(output_vault), [pub])

    recovered.write_bytes(b"Ya existia")

    with pytest.raises(FileExistsError):
        decrypt_hybrid_file(str(output_vault), str(recovered), priv, overwrite=False)

    # Con overwrite=True sí debe permitirlo
    decrypt_hybrid_file(str(output_vault), str(recovered), priv, overwrite=True)
    assert recovered.read_bytes() == b"Contenido importante"
