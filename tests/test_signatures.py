"""
D5 - Signatures & Authentication
Required Tests A-E
"""

import json
import base64
import pytest

from encryption.hybrid_core import generate_keypair, encrypt_hybrid
from encryption.signatures import (
    generate_signing_keypair,
    sign_container,
    verify_container,
    decrypt_signed,
)


@pytest.fixture
def setup():
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    sign_priv, sign_pub = generate_signing_keypair()

    data = b"Documento confidencial"
    signed = sign_container(
        encrypt_hybrid(data, "doc.txt", [alice_pub, bob_pub]), sign_priv
    )

    return data, signed, bob_priv, sign_pub


def _tamper(signed: bytes, mutate) -> bytes:
    container = json.loads(signed)
    mutate(container)
    return json.dumps(container).encode("utf-8")


# PRUEBA A: Valid signature -> file accepted
def test_valid_signature_accepted(setup):
    data, signed, bob_priv, sign_pub = setup
    plaintext, metadata = decrypt_signed(signed, bob_priv, sign_pub)
    assert plaintext == data
    assert metadata["filename"] == "doc.txt"


# PRUEBA B: Modified ciphertext -> rejected
def test_modified_ciphertext_rejected(setup):
    _, signed, _, sign_pub = setup

    def mutate(c):
        raw = bytearray(base64.b64decode(c["ciphertext"]))
        raw[0] ^= 0xFF
        c["ciphertext"] = base64.b64encode(raw).decode()

    with pytest.raises(ValueError, match="Firma invalida"):
        verify_container(_tamper(signed, mutate), sign_pub)


# PRUEBA C: Modified metadata -> rejected
def test_modified_metadata_rejected(setup):
    _, signed, _, sign_pub = setup

    def mutate(c):
        c["header"]["algorithm"] = "AES-GCM"

    with pytest.raises(ValueError, match="Firma invalida"):
        verify_container(_tamper(signed, mutate), sign_pub)


# PRUEBA C2: Modified recipient list -> rejected
def test_modified_recipients_rejected(setup):
    _, signed, _, sign_pub = setup

    with pytest.raises(ValueError, match="Firma invalida"):
        verify_container(
            _tamper(signed, lambda c: c["recipients"].pop()), sign_pub
        )


# PRUEBA D: Wrong public key -> rejected
def test_wrong_public_key_rejected(setup):
    _, signed, bob_priv, _ = setup
    _, other_pub = generate_signing_keypair()

    with pytest.raises(ValueError):
        decrypt_signed(signed, bob_priv, other_pub)


# PRUEBA E: Signature removed -> rejected
def test_signature_removed_rejected(setup):
    _, signed, bob_priv, sign_pub = setup

    with pytest.raises(ValueError, match="sin firma"):
        decrypt_signed(
            _tamper(signed, lambda c: c.pop("signature")),
            bob_priv, sign_pub
        )

