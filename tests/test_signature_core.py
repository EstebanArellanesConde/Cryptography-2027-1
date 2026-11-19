"""Tests for the independent D5 signature module (Esteban)."""

import hashlib

import pytest

from signatures.signature_core import (
    generate_signing_keypair,
    sign_digest,
    signer_key_id,
    verify_digest,
)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def test_valid_signature():
    private_key, public_key = generate_signing_keypair()
    digest = sha256(b"secure encrypted container")
    signature = sign_digest(digest, private_key)
    assert len(signature) == 64
    assert verify_digest(digest, signature, public_key)


def test_modified_data_is_rejected():
    private_key, public_key = generate_signing_keypair()
    signature = sign_digest(sha256(b"original"), private_key)
    assert not verify_digest(sha256(b"modified"), signature, public_key)


def test_wrong_public_key_is_rejected():
    private_key, _ = generate_signing_keypair()
    _, other_public_key = generate_signing_keypair()
    digest = sha256(b"example")
    signature = sign_digest(digest, private_key)
    assert not verify_digest(digest, signature, other_public_key)


def test_modified_signature_is_rejected():
    private_key, public_key = generate_signing_keypair()
    digest = sha256(b"example")
    signature = bytearray(sign_digest(digest, private_key))
    signature[0] ^= 0x01
    assert not verify_digest(digest, bytes(signature), public_key)


def test_signer_id_is_stable_and_unique_per_key():
    private_key, public_key = generate_signing_keypair()
    _, other_public_key = generate_signing_keypair()
    assert signer_key_id(private_key.public_key()) == signer_key_id(public_key)
    assert signer_key_id(public_key) != signer_key_id(other_public_key)
    assert len(signer_key_id(public_key)) == 64


def test_invalid_digest_length_is_rejected():
    private_key, public_key = generate_signing_keypair()
    with pytest.raises(ValueError):
        sign_digest(b"too short", private_key)
    with pytest.raises(ValueError):
        verify_digest(b"too short", b"signature", public_key)


def test_missing_signature_is_rejected():
    _, public_key = generate_signing_keypair()
    assert not verify_digest(sha256(b"example"), b"", public_key)
