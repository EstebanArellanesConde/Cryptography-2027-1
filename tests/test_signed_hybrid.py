"""Pruebas de Cristian: flujo D3 -> D5 -> verificación -> D3."""

import copy
import json
from base64 import b64decode, b64encode

import pytest

from encryption import signed_hybrid
from encryption.hybrid_core import encrypt_hybrid, generate_ecies_keypair
from encryption.signed_hybrid import (
    decrypt_signed_hybrid,
    encrypt_signed_hybrid,
    sign_hybrid_container,
    verify_signed_hybrid,
)
from signatures.signature_core import generate_signing_keypair, signer_key_id


@pytest.fixture
def actors():
    alice_priv, alice_pub = generate_ecies_keypair()
    bob_priv, bob_pub = generate_ecies_keypair()
    charlie_priv, _ = generate_ecies_keypair()
    signing_priv, signing_pub = generate_signing_keypair()
    _, wrong_signing_pub = generate_signing_keypair()
    return {
        "alice": alice_priv, "bob": bob_priv, "charlie": charlie_priv,
        "recipients": [alice_pub, bob_pub],
        "sign_priv": signing_priv, "sign_pub": signing_pub,
        "wrong_sign_pub": wrong_signing_pub,
    }


@pytest.fixture
def signed(actors):
    return encrypt_signed_hybrid(
        b"Documento de prueba confidencial", "ejemplo.txt",
        actors["recipients"], actors["sign_priv"]
    )


def modify(signed: bytes, field: str, value):
    obj = json.loads(signed)
    obj[field] = value
    return json.dumps(obj).encode("utf-8")


def test_two_authorized_recipients_can_verify_and_decrypt(signed, actors):
    container = json.loads(signed)
    assert set(container) == {"header", "recipients", "nonce", "ciphertext", "tag", "signer_id", "signature"}
    assert container["signer_id"] == signer_key_id(actors["sign_pub"])
    assert len(b64decode(container["signature"])) == 64
    for recipient in ("alice", "bob"):
        plaintext, metadata = decrypt_signed_hybrid(
            signed, actors[recipient], actors["sign_pub"]
        )
        assert plaintext == b"Documento de prueba confidencial"
        assert metadata["filename"] == "ejemplo.txt"


def test_existing_d3_ciphertext_can_be_signed_without_reencryption(actors):
    d3 = encrypt_hybrid(b"Archivo", "texto.txt", actors["recipients"])
    d5 = sign_hybrid_container(d3, actors["sign_priv"])
    assert json.loads(d3)["ciphertext"] == json.loads(d5)["ciphertext"]
    plaintext, _ = decrypt_signed_hybrid(d5, actors["bob"], actors["sign_pub"])
    assert plaintext == b"Archivo"


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "tag", "header", "recipients", "signer_id"])
def test_any_signed_field_change_is_rejected_before_decrypt(
    signed, actors, monkeypatch, field
):
    """Si falla la firma no se llega siquiera a intentar descifrar."""
    obj = json.loads(signed)
    if field == "header":
        obj["header"]["format"] = "fake"
    elif field == "recipients":
        obj["recipients"][0]["encrypted_key"] += "A"
    elif field == "signer_id":
        obj[field] = "0" * 64
    else:
        obj[field] += "A"

    def should_not_decrypt(*args, **kwargs):
        raise AssertionError("¡Se intentó descifrar antes de verificar!")

    monkeypatch.setattr(signed_hybrid, "decrypt_hybrid", should_not_decrypt)
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(
            json.dumps(obj).encode(), actors["alice"], actors["sign_pub"]
        )


def test_wrong_public_signing_key_is_rejected(signed, actors):
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(
            signed, actors["alice"], actors["wrong_sign_pub"]
        )


def test_modified_signature_is_rejected(signed, actors):
    obj = json.loads(signed)
    signature = bytearray(b64decode(obj["signature"]))
    signature[0] ^= 1
    obj["signature"] = b64encode(signature).decode()
    with pytest.raises(ValueError):
        verify_signed_hybrid(json.dumps(obj).encode(), actors["sign_pub"])


def test_missing_signature_is_rejected(signed, actors):
    obj = json.loads(signed)
    obj.pop("signature")
    with pytest.raises(ValueError):
        verify_signed_hybrid(json.dumps(obj).encode(), actors["sign_pub"])


def test_unauthorized_recipient_cannot_decrypt_even_with_valid_signature(signed, actors):
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(signed, actors["charlie"], actors["sign_pub"])


def test_container_with_unsigned_extra_field_is_rejected(signed, actors):
    with pytest.raises(ValueError):
        verify_signed_hybrid(
            modify(signed, "extra", "no firmado"), actors["sign_pub"]
        )


def test_original_unsigned_d3_container_is_not_accepted(actors):
    unsigned = encrypt_hybrid(b"data", "data.txt", actors["recipients"])
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(
            unsigned, actors["alice"], actors["sign_pub"]
        )


def test_duplicate_json_field_rejected(signed, actors):
    # El parser detecta duplicados, aunque el valor sea igual.
    data = signed.replace(b'"signature":', b'"signature": "AA==", "signature":', 1)
    with pytest.raises(ValueError, match="duplicado"):
        verify_signed_hybrid(data, actors["sign_pub"])


def test_json_reordered_keys_keep_valid_signature(signed, actors):
    obj = json.loads(signed)
    reordered = dict(reversed(list(obj.items())))
    unsigned = verify_signed_hybrid(json.dumps(reordered).encode(), actors["sign_pub"])
    assert "signature" not in unsigned
    assert "signer_id" not in unsigned
