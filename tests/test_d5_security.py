"""D5 - Security acceptance tests (Fer).

Required scenarios in the assignment:
A. Valid signature is accepted.
B. Modified ciphertext is rejected.
C. Modified metadata is rejected.
D. Wrong public key is rejected.
E. Signature removed is rejected.

The tests exercise the public signed-hybrid interface developed by Cristian,
using the Ed25519 and canonical SHA-256 modules developed by Esteban and Axel.
No production code or private keys are stored in this file.
"""

import json
from base64 import b64decode, b64encode

import pytest

from encryption import signed_hybrid
from encryption.hybrid_core import generate_ecies_keypair
from encryption.signed_hybrid import decrypt_signed_hybrid, encrypt_signed_hybrid
from signatures.signature_core import generate_signing_keypair


@pytest.fixture
def scenario():
    """Generate fresh, unrelated encryption/signing keys for each test."""
    alice_private, alice_public = generate_ecies_keypair()
    bob_private, bob_public = generate_ecies_keypair()
    unauthorized_private, _ = generate_ecies_keypair()
    signer_private, signer_public = generate_signing_keypair()
    _, unrelated_signer_public = generate_signing_keypair()

    plaintext = b"Confidential document for the D5 security evaluation."
    signed = encrypt_signed_hybrid(
        plaintext,
        "d5_evidence.txt",
        [alice_public, bob_public],
        signer_private,
    )
    return {
        "signed": signed,
        "plaintext": plaintext,
        "alice_private": alice_private,
        "bob_private": bob_private,
        "unauthorized_private": unauthorized_private,
        "signer_public": signer_public,
        "wrong_signer_public": unrelated_signer_public,
    }


def _json_bytes(container: dict) -> bytes:
    """Serialize a modified container; never create a new valid signature."""
    return json.dumps(container, ensure_ascii=False).encode("utf-8")


def _assert_rejected_before_decryption(monkeypatch, container: bytes, scenario):
    """Ensure a bad signature fails *before* D3 decryption can run."""
    def forbidden_decryption(*args, **kwargs):
        pytest.fail("D3 decryption was called before signature validation")

    monkeypatch.setattr(signed_hybrid, "decrypt_hybrid", forbidden_decryption)
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(
            container, scenario["alice_private"], scenario["signer_public"]
        )


def test_a_valid_signature_is_accepted(scenario):
    """A: An authentic signed container can be opened by both recipients."""
    for private_key in (scenario["alice_private"], scenario["bob_private"]):
        recovered, metadata = decrypt_signed_hybrid(
            scenario["signed"], private_key, scenario["signer_public"]
        )
        assert recovered == scenario["plaintext"]
        assert metadata["filename"] == "d5_evidence.txt"
        assert metadata["plaintext_size"] == len(recovered)


def test_b_modified_ciphertext_is_rejected(monkeypatch, scenario):
    """B: Change a real ciphertext byte without updating the signature."""
    container = json.loads(scenario["signed"])
    ciphertext = bytearray(b64decode(container["ciphertext"], validate=True))
    assert ciphertext, "Test input unexpectedly produced an empty ciphertext"
    ciphertext[0] ^= 0x01
    container["ciphertext"] = b64encode(bytes(ciphertext)).decode("ascii")
    _assert_rejected_before_decryption(monkeypatch, _json_bytes(container), scenario)


@pytest.mark.parametrize("target", ["header", "recipients"])
def test_c_modified_metadata_is_rejected(monkeypatch, scenario, target):
    """C: A change to header metadata OR recipient list invalidates the signature."""
    container = json.loads(scenario["signed"])
    if target == "header":
        container["header"]["version"] = "tampered-version"
    else:
        # Keep the list well-formed, but alter the intended recipients.
        container["recipients"] = list(reversed(container["recipients"]))
    _assert_rejected_before_decryption(monkeypatch, _json_bytes(container), scenario)


def test_d_wrong_public_key_is_rejected(monkeypatch, scenario):
    """D: A valid container cannot be authenticated with an unrelated public key."""
    def forbidden_decryption(*args, **kwargs):
        pytest.fail("D3 decryption was called with the wrong signing key")

    monkeypatch.setattr(signed_hybrid, "decrypt_hybrid", forbidden_decryption)
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(
            scenario["signed"],
            scenario["alice_private"],
            scenario["wrong_signer_public"],
        )


def test_e_signature_removed_is_rejected(monkeypatch, scenario):
    """E: Removing the signature must never downgrade D5 to unsigned D3."""
    container = json.loads(scenario["signed"])
    del container["signature"]
    _assert_rejected_before_decryption(monkeypatch, _json_bytes(container), scenario)


def test_extra_unauthorized_recipient_cannot_open_valid_signed_file(scenario):
    """Defense in depth: a correct signature does not grant recipient access."""
    with pytest.raises(ValueError):
        decrypt_signed_hybrid(
            scenario["signed"],
            scenario["unauthorized_private"],
            scenario["signer_public"],
        )


def test_extra_reordered_json_keys_do_not_invalidate_signature(scenario):
    """The canonical hash should be independent of JSON object key order."""
    container = json.loads(scenario["signed"])
    reordered = dict(reversed(list(container.items())))
    recovered, _ = decrypt_signed_hybrid(
        _json_bytes(reordered),
        scenario["alice_private"],
        scenario["signer_public"],
    )
    assert recovered == scenario["plaintext"]
