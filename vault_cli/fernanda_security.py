"""FERNANDA — secure recovery and negative tests: fail closed, verify first."""
import getpass
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from encryption.hybrid_core import generate_keypair
from encryption.signed_hybrid import decrypt_signed_hybrid, verify_signed_hybrid
from src.key_management.keystore import use_private_key
from . import shared


def recover_file(signed_path: str | Path, recipient: str, trusted_signer: str, password: str) -> Path:
    signed = shared.read_limited(signed_path, container=True)
    trusted_key = shared.load_public_key(trusted_signer, "signing")
    # Verify BEFORE unlocking or decrypting. Never trust signer public key in JSON.
    verify_signed_hybrid(signed, trusted_key)
    with use_private_key(shared.key_dir(recipient, "encryption"), password, expected_usage="encryption") as private:
        plaintext, metadata = decrypt_signed_hybrid(signed, private, trusted_key)
    # Metadata is authenticated, but always sanitize output filenames.
    filename = shared.safe_filename(str(metadata.get("filename", "recovered.bin")))
    return shared.write_new("recovered", filename, plaintext)


def test_attacks(signed_path: str | Path, trusted_signer: str) -> dict[str, bool]:
    """Modify only in memory; original encrypted file stays intact."""
    signed = shared.read_limited(signed_path, container=True)
    pub = shared.load_public_key(trusted_signer, "signing")
    verify_signed_hybrid(signed, pub)
    results = {}

    # A changed ciphertext MUST invalidate the signed data.
    altered = json.loads(signed)
    text = altered["ciphertext"]
    altered["ciphertext"] = ("A" if text[0] != "A" else "B") + text[1:]
    try:
        verify_signed_hybrid(json.dumps(altered).encode("utf-8"), pub)
    except ValueError:
        results["Tampered container rejected"] = True
    else:
        results["Tampered container rejected"] = False

    # Verification with another user's untrusted key MUST fail.
    wrong_signer_pub = Ed25519PrivateKey.generate().public_key()
    try:
        verify_signed_hybrid(signed, wrong_signer_pub)
    except ValueError:
        results["Incorrect signer rejected"] = True
    else:
        results["Incorrect signer rejected"] = False

    # A fresh, non-recipient private key (Charlie scenario) MUST fail.
    unrelated_private, _ = generate_keypair()
    try:
        decrypt_signed_hybrid(signed, unrelated_private, pub)
    except ValueError:
        results["Unauthorized recipient rejected"] = True
    else:
        results["Unauthorized recipient rejected"] = False
    return results


def run() -> None:
    print("\n--- FERNANDA: SECURITY & RECOVERY ---")
    print("1. Verify and recover file     2. Run three negative security tests")
    choice = input("Option: ").strip()
    if choice == "1":
        path = input("Signed .svlt path: ").strip().strip('"')
        recipient = input("Recipient (e.g., bob): ")
        signer = input("Trusted signer (e.g., alice): ")
        password = getpass.getpass("Recipient keystore password: ")
        output = recover_file(path, recipient, signer, password)
        print(f"[OK] Signature verified; recipient authorized; recovered file: {output}")
    elif choice == "2":
        path = input("Signed .svlt path: ").strip().strip('"')
        signer = input("Trusted signer (e.g., alice): ")
        checks = test_attacks(path, signer)
        for label, passed in checks.items():
            print(f"[{'PASS' if passed else 'FAIL'}] {label}")
        if not all(checks.values()):
            raise AssertionError("SECURITY DEMONSTRATION FAILED")
        print("[OK] All three attack scenarios rejected")
    else:
        print("Cancelled")
