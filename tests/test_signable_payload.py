"""Pruebas del área de Axel: selección de datos, codificación y SHA-256."""

import copy
import hashlib
import json

import pytest

from signatures.signable_payload import (
    canonical_signable_data,
    hash_signed_payload,
    validate_signable_container,
)


def sample_container():
    return {
        "header": {"format": "SecureVault", "version": "3.0", "algorithm": "ChaCha20-Poly1305", "key_encryption": "ECIES-P256"},
        "recipients": [
            {"key_id": "a" * 64, "encrypted_key": "YXNkZA=="},
            {"key_id": "b" * 64, "encrypted_key": "YWJjZA=="},
        ],
        "nonce": "bm9uY2U=",
        "ciphertext": "Y2lwaGVydGV4dA==",
        "tag": "dGFn",
        "signer_id": "c" * 64,
    }


def test_digest_sha256_has_32_bytes():
    container = sample_container()
    output = canonical_signable_data(container)
    assert hash_signed_payload(container) == hashlib.sha256(output).digest()
    assert len(hash_signed_payload(container)) == 32


def test_json_key_order_does_not_change_digest():
    container = sample_container()
    reordered = dict(reversed(list(container.items())))
    reordered["header"] = dict(reversed(list(container["header"].items())))
    assert hash_signed_payload(container) == hash_signed_payload(reordered)


def test_signature_is_excluded_from_digest():
    container = sample_container()
    without = hash_signed_payload(container)
    container["signature"] = "base64-de-firma"
    assert hash_signed_payload(container) == without
    container["signature"] = "otra-firma"
    assert hash_signed_payload(container) == without


@pytest.mark.parametrize("field", ["header", "recipients", "nonce", "ciphertext", "tag", "signer_id"])
def test_each_security_field_change_changes_digest(field):
    original = sample_container()
    modified = copy.deepcopy(original)
    if field == "header":
        modified["header"]["version"] = "4.0"
    elif field == "recipients":
        modified["recipients"][0]["encrypted_key"] = "ZmFrZQ=="
    elif field == "signer_id":
        modified["signer_id"] = "d" * 64
    else:
        modified[field] = modified[field] + "AA"
    assert hash_signed_payload(original) != hash_signed_payload(modified)


def test_recipient_order_is_signed():
    a = sample_container()
    b = copy.deepcopy(a)
    b["recipients"].reverse()
    assert hash_signed_payload(a) != hash_signed_payload(b)


def test_missing_signer_id_is_rejected():
    container = sample_container()
    del container["signer_id"]
    with pytest.raises(ValueError):
        hash_signed_payload(container)


def test_extra_unsigned_field_is_rejected():
    container = sample_container()
    container["dangerous_metadata"] = "not-signed"
    with pytest.raises(ValueError):
        hash_signed_payload(container)


def test_duplicated_recipient_id_is_rejected():
    container = sample_container()
    container["recipients"][1]["key_id"] = "a" * 64
    with pytest.raises(ValueError):
        hash_signed_payload(container)


def test_non_json_values_are_rejected():
    container = sample_container()
    container["header"]["bad_number"] = float("nan")
    with pytest.raises(ValueError):
        hash_signed_payload(container)


def test_does_not_modify_input_container():
    container = sample_container()
    before = copy.deepcopy(container)
    hash_signed_payload(container)
    assert before == container


def test_canonical_data_are_utf8_json():
    container = sample_container()
    container["header"]["comment"] = "Criptografía"
    obj = json.loads(canonical_signable_data(container).decode("utf-8"))
    assert obj["header"]["comment"] == "Criptografía"


def test_validation_accepts_container_with_signature():
    container = sample_container()
    container["signature"] = "AA=="
    assert validate_signable_container(container) is None
