import base64
import json

import pytest
from cryptography.exceptions import InvalidTag

from encryption.hybrid import (
    decrypt_bytes_for_recipient,
    encrypt_bytes_for_recipients,
    generate_rsa_keypair,
    public_key_id,
)


@pytest.fixture
def alice():
    private, public = generate_rsa_keypair(key_size=2048)
    return private, public


@pytest.fixture
def bob():
    private, public = generate_rsa_keypair(key_size=2048)
    return private, public


@pytest.fixture
def carol():
    private, public = generate_rsa_keypair(key_size=2048)
    return private, public


def _container(data: bytes) -> dict:
    return json.loads(data.decode("utf-8"))


def _serialize(container: dict) -> bytes:
    return json.dumps(container, sort_keys=True, indent=2).encode("utf-8")


def test_two_recipients_can_decrypt_same_content(alice, bob):
    a_priv, a_pub = alice
    b_priv, b_pub = bob
    source = b"Confidential document\nwith binary-safe payload: \x00\xff"
    encrypted = encrypt_bytes_for_recipients(
        source, "secret.bin", {"alice": a_pub, "bob": b_pub}
    )

    recovered_a, metadata_a = decrypt_bytes_for_recipient(encrypted, "alice", a_priv)
    recovered_b, metadata_b = decrypt_bytes_for_recipient(encrypted, "bob", b_priv)

    assert recovered_a == source
    assert recovered_b == source
    assert metadata_a["filename"] == "secret.bin"
    assert metadata_b["plaintext_size"] == len(source)


def test_unauthorized_recipient_cannot_decrypt(alice, bob, carol):
    _, a_pub = alice
    _, b_pub = bob
    c_priv, _ = carol
    encrypted = encrypt_bytes_for_recipients(
        b"secret", "secret.txt", {"alice": a_pub, "bob": b_pub}
    )

    with pytest.raises(ValueError, match="No wrapped file key"):
        decrypt_bytes_for_recipient(encrypted, "carol", c_priv)


def test_wrong_private_key_fails(alice, bob):
    _, a_pub = alice
    b_priv, _ = bob
    encrypted = encrypt_bytes_for_recipients(b"secret", "x.txt", {"alice": a_pub})

    with pytest.raises(ValueError, match="key ID"):
        decrypt_bytes_for_recipient(encrypted, "alice", b_priv)


def test_tampered_recipient_manifest_fails_authentication(alice, bob, carol):
    a_priv, a_pub = alice
    _, b_pub = bob
    _, c_pub = carol
    container = _container(
        encrypt_bytes_for_recipients(b"secret", "x.txt", {"alice": a_pub, "bob": b_pub})
    )
    # Add a syntactically valid-looking entry. The content AEAD authenticates the
    # entire manifest, so an edit cannot silently alter the access-control list.
    container["header"]["recipients"].append({
        "recipient_id": "carol",
        "key_id": public_key_id(c_pub),
        "wrapped_key": base64.b64encode(b"not-a-real-wrapped-key").decode("ascii"),
    })
    container["header"]["recipient_count"] += 1

    with pytest.raises(InvalidTag):
        decrypt_bytes_for_recipient(_serialize(container), "alice", a_priv)


def test_removing_recipient_entry_removes_access_and_tampering_fails(alice, bob):
    a_priv, a_pub = alice
    b_priv, b_pub = bob
    container = _container(
        encrypt_bytes_for_recipients(b"secret", "x.txt", {"alice": a_pub, "bob": b_pub})
    )
    container["header"]["recipients"] = [
        entry for entry in container["header"]["recipients"]
        if entry["recipient_id"] != "bob"
    ]
    container["header"]["recipient_count"] = 1

    # Bob no longer has an entry. Alice also detects that the manifest changed.
    with pytest.raises(ValueError, match="No wrapped file key"):
        decrypt_bytes_for_recipient(_serialize(container), "bob", b_priv)
    with pytest.raises(InvalidTag):
        decrypt_bytes_for_recipient(_serialize(container), "alice", a_priv)


def test_ciphertext_tampering_fails(alice):
    a_priv, a_pub = alice
    container = _container(encrypt_bytes_for_recipients(b"secret", "x.txt", {"alice": a_pub}))
    raw = bytearray(base64.b64decode(container["ciphertext"]))
    raw[0] ^= 0x01
    container["ciphertext"] = base64.b64encode(raw).decode("ascii")

    with pytest.raises(InvalidTag):
        decrypt_bytes_for_recipient(_serialize(container), "alice", a_priv)


def test_same_public_key_cannot_be_registered_twice(alice):
    _, a_pub = alice
    with pytest.raises(ValueError, match="same public key"):
        encrypt_bytes_for_recipients(
            b"secret", "x.txt", {"alice": a_pub, "alias-for-alice": a_pub}
        )


def test_empty_recipient_list_is_rejected():
    with pytest.raises(ValueError, match="At least one"):
        encrypt_bytes_for_recipients(b"secret", "x.txt", {})


def test_encrypted_private_key_can_be_loaded_with_password():
    password = b"long-test-only-passphrase"
    private_pem, public_pem = generate_rsa_keypair(
        key_size=2048, private_key_password=password
    )
    encrypted = encrypt_bytes_for_recipients(
        b"password-protected key test", "x.txt", {"alice": public_pem}
    )
    recovered, _ = decrypt_bytes_for_recipient(
        encrypted, "alice", private_pem, password=password
    )
    assert recovered == b"password-protected key test"


def test_container_rejects_duplicate_json_keys(alice):
    a_priv, a_pub = alice
    encrypted = encrypt_bytes_for_recipients(b"secret", "x.txt", {"alice": a_pub})
    # Duplicate "header" key is forbidden instead of relying on last-key-wins parsing.
    duplicate = b'{"header":{},"header":{},"nonce":"","ciphertext":"","tag":""}'
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        decrypt_bytes_for_recipient(duplicate, "alice", a_priv)



def test_file_helpers_create_outputs_without_overwriting(tmp_path, alice, bob):
    from encryption.hybrid import (
        encrypt_file_for_recipients,
        decrypt_file_for_recipient,
    )

    a_priv, a_pub = alice
    _, b_pub = bob
    source = tmp_path / "input.txt"
    encrypted_path = tmp_path / "input.svlt"
    recovered_path = tmp_path / "recovered.txt"
    source.write_bytes(b"file helper payload")

    encrypt_file_for_recipients(
        source, encrypted_path, {"alice": a_pub, "bob": b_pub}
    )
    metadata = decrypt_file_for_recipient(
        encrypted_path, recovered_path, "alice", a_priv
    )

    assert recovered_path.read_bytes() == b"file helper payload"
    assert metadata["filename"] == "input.txt"
    assert (recovered_path.stat().st_mode & 0o777) == 0o600

    with pytest.raises(FileExistsError):
        decrypt_file_for_recipient(encrypted_path, recovered_path, "alice", a_priv)


def test_file_helper_does_not_write_plaintext_on_authentication_failure(tmp_path, alice):
    from encryption.hybrid import decrypt_file_for_recipient

    a_priv, a_pub = alice
    container = _container(encrypt_bytes_for_recipients(b"secret", "x.txt", {"alice": a_pub}))
    container["header"]["version"] = "9.9"
    encrypted_path = tmp_path / "tampered.svlt"
    output_path = tmp_path / "must-not-exist.txt"
    encrypted_path.write_bytes(_serialize(container))

    with pytest.raises(ValueError):
        decrypt_file_for_recipient(encrypted_path, output_path, "alice", a_priv)
    assert not output_path.exists()
