"""Integrated CLI tests, isolated from the real user's keystores."""

import pytest
from vault_cli import shared
from vault_cli import axel_encryption, cristian_keys, esteban_signatures, fernanda_security
from src.key_management.keystore import KeystoreAccessError


@pytest.fixture
def demo(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "WORKSPACE", tmp_path / "secure_vault")
    pw = "long-strong-demo-password"
    cristian_keys.create_user("alice", pw)
    cristian_keys.create_user("bob", pw)
    original = tmp_path / "original.txt"
    original.write_bytes(b"UNAM FI secure exchange: test\n" * 25)
    unsigned = axel_encryption.encrypt_file_for_users(original, ["alice", "bob"])
    signed = esteban_signatures.sign_file(unsigned, "alice", pw)
    return {"password": pw, "original": original, "unsigned": unsigned, "signed": signed}


def test_complete_flow(demo):
    esteban_signatures.verify_file(demo["signed"], "alice")
    recovered = fernanda_security.recover_file(demo["signed"], "bob", "alice", demo["password"])
    assert recovered.read_bytes() == demo["original"].read_bytes()
    # Do not overwrite an existing recovery file.
    second = fernanda_security.recover_file(demo["signed"], "bob", "alice", demo["password"])
    assert second != recovered
    assert recovered.exists()


def test_attack_rejection(demo):
    assert all(fernanda_security.test_attacks(demo["signed"], "alice").values())


def test_wrong_password(demo):
    with pytest.raises(KeystoreAccessError):
        fernanda_security.recover_file(demo["signed"], "bob", "alice", "wrong-password")


def test_unsigned_not_accepted(demo):
    with pytest.raises(ValueError):
        esteban_signatures.verify_file(demo["unsigned"], "alice")


def test_invalid_recipients(demo):
    with pytest.raises(ValueError):
        axel_encryption.encrypt_file_for_users(demo["original"], ["alice"])
    with pytest.raises(ValueError):
        axel_encryption.encrypt_file_for_users(demo["original"], ["bob", "bob"])


def test_path_traversal_is_sanitized():
    assert shared.safe_filename(r"..\..\private\bad.txt") == "bad.txt"
    assert shared.safe_filename("../../etc/passwd") == "passwd"


def test_file_size_limit(tmp_path):
    huge = tmp_path / "too_large.bin"
    with huge.open("wb") as f:
        f.truncate(shared.MAX_FILE_SIZE + 1)
    with pytest.raises(ValueError):
        shared.read_limited(huge)
