
"""
ESTEBAN - D5 Digital Signatures.

Secure Digital Document Vault
Cryptography Coursework 2027-1
Facultad de Ingenieria, UNAM - Team 6

Signs existing D3 containers using Ed25519.
Verifies signatures using locally trusted public keys.

No file re-encryption is performed.
"""

from __future__ import annotations

import getpass
import hashlib
from pathlib import Path

from encryption.signed_hybrid import (
    sign_hybrid_container,
    verify_signed_hybrid,
)
from signatures.signature_core import signer_key_id
from src.key_management.keystore import use_private_key

from . import shared


def sign_file(
    unsigned_path: str | Path,
    signer: str,
    password: str,
) -> Path:
    """Sign an existing D3 container without re-encrypting it."""

    signer = shared.username(signer)
    source = Path(unsigned_path).expanduser()

    # Read using the common CLI size restrictions.
    unsigned = shared.read_limited(
        source,
        container=True,
    )

    # Retrieve the locally trusted public signing key.
    trusted_public = shared.load_public_key(
        signer,
        "signing",
    )

    # Unlock the private signing key temporarily.
    with use_private_key(
        shared.key_dir(signer, "signing"),
        password,
        expected_usage="signing",
        allow_rotated=False,
    ) as private:

        signed = sign_hybrid_container(
            unsigned,
            private,
        )

    # Verify the generated signature before saving.
    verify_signed_hybrid(
        signed,
        trusted_public,
    )

    # Ensure the result can be opened by the CLI.
    if len(signed) > shared.MAX_CONTAINER_SIZE:
        raise ValueError(
            "Signed container exceeds the maximum size."
        )

    name = (
        source.stem.removesuffix(".unsigned")
        + ".signed.svlt"
    )

    # Exclusive output creation through shared helpers.
    return shared.write_new(
        "outbox",
        name,
        signed,
    )


def verify_file(
    signed_path: str | Path,
    trusted_signer: str,
) -> None:
    """Verify a container using a locally trusted Ed25519 key."""

    trusted_signer = shared.username(trusted_signer)

    signed = shared.read_limited(
        signed_path,
        container=True,
    )

    trusted_public = shared.load_public_key(
        trusted_signer,
        "signing",
    )

    # Raises ValueError if verification fails.
    verify_signed_hybrid(
        signed,
        trusted_public,
    )


def show_signature_details(
    path: str | Path,
    signer: str,
) -> None:
    """Display verification details after successful verification."""

    signer = shared.username(signer)

    signed = shared.read_limited(
        path,
        container=True,
    )

    public_key = shared.load_public_key(
        signer,
        "signing",
    )

    # Verify the same bytes that will be described.
    verify_signed_hybrid(signed, public_key)

    print("\n==========================================")
    print("         DIGITAL SIGNATURE DETAILS")
    print("==========================================")
    print("Algorithm    : Ed25519")
    print("Payload hash : SHA-256")
    print(f"Signer       : {signer}")
    print(f"Signer ID    : {signer_key_id(public_key)}")
    print(f"File SHA-256 : {hashlib.sha256(signed).hexdigest()}")
    print(f"Size         : {len(signed)} bytes")
    print("Signature    : VALID")
    print("Trust source : Locally provisioned public key")
    print("==========================================")


def _prompt_file(message: str) -> Path:
    """Request an existing regular file."""

    value = input(message).strip().strip('"')

    if not value:
        raise ValueError("A file path is required.")

    path = Path(value).expanduser()

    if not path.is_file():
        raise ValueError(
            f"Not a valid file: {path}"
        )

    return path


def run() -> None:
    """D5 interactive entry point used by vault_cli."""

    while True:

        print("\n==========================================")
        print("       SECURE VAULT - D5 SIGNATURES")
        print("==========================================")
        print("1. Sign an encrypted D3 container")
        print("2. Verify a signed container")
        print("0. Return to main menu")
        print("==========================================")

        choice = input("Option: ").strip()

        if choice == "0":
            return

        if choice == "1":

            path = _prompt_file(
                "Unsigned .svlt path: "
            )

            signer = shared.username(
                input("Signer user (e.g., alice): ")
            )

            # Check the file size and available public key
            # before requesting the private key password.
            shared.read_limited(path, container=True)
            shared.load_public_key(signer, "signing")

            password = getpass.getpass(
                "Signer keystore password: "
            )

            try:
                output = sign_file(
                    path,
                    signer,
                    password,
                )
            finally:
                # Drop the reference; Python does not
                # guarantee secure memory zeroization.
                del password

            print("\n[OK] Container signed successfully.")
            print(f"[OK] Signed file: {output}")

            show_signature_details(
                output,
                signer,
            )

        elif choice == "2":

            path = _prompt_file(
                "Signed .svlt path: "
            )

            signer = shared.username(
                input("Trusted signer (e.g., alice): ")
            )

            show_signature_details(
                path,
                signer,
            )

            print(
                "\n[OK] Valid signature from "
                "locally trusted signer."
            )

        else:
            print("[ERROR] Invalid option.")
