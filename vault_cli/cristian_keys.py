"""CRISTIAN — D6: generate password-protected X25519 and Ed25519 keystores."""
import getpass
import json

from src.key_management.keystore import create_keystore, unlock_private_key
from . import shared


def create_user(user: str, password: str) -> None:
    user = shared.username(user)
    if not password or len(password) < 8:
        raise ValueError("For this demo, use a password of at least 8 characters")
    root = shared.WORKSPACE / "keystores" / user
    if root.exists():
        raise ValueError("User already exists; existing keystores will not be overwritten")
    create_keystore(shared.key_dir(user, "encryption"), "encryption", password=password)
    create_keystore(shared.key_dir(user, "signing"), "signing", password=password)
    print(f"[OK] User {user}: X25519 and Ed25519 keystores created with Argon2id/AES-GCM")


def list_users() -> None:
    parent = shared.WORKSPACE / "keystores"
    found = False
    for root in sorted(parent.iterdir()) if parent.is_dir() else []:
        if root.is_dir() and (root / "encryption" / "metadata").is_file():
            print(f"- {root.name}")
            found = True
    if not found:
        print("No users yet. Create Alice, Bob and Charlie first.")


def run() -> None:
    print("\n--- CRISTIAN: KEY MANAGEMENT (D6) ---")
    print("1. Create user     2. List users     3. Test password unlock")
    choice = input("Option: ").strip()
    if choice == "1":
        user = input("New user ID (e.g., alice): ")
        password = getpass.getpass("Password (hidden): ")
        repeated = getpass.getpass("Repeat password: ")
        if password != repeated:
            raise ValueError("Passwords do not match")
        create_user(user, password)
    elif choice == "2":
        list_users()
    elif choice == "3":
        user = input("User ID: ")
        password = getpass.getpass("Password: ")
        unlock_private_key(shared.key_dir(user, "encryption"), password, expected_usage="encryption")
        print("[OK] Password unlock successful; private key was not printed")
    else:
        print("Cancelled")
