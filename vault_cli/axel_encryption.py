"""AXEL — D2/D3: validate input, select multiple recipients and encrypt once."""
from pathlib import Path

from encryption.hybrid_core import encrypt_hybrid
from . import shared


def encrypt_file_for_users(input_path: str | Path, recipients: list[str]) -> Path:
    source = Path(input_path).expanduser()
    recipients = [shared.username(r) for r in recipients]
    if len(recipients) < 2 or len(set(recipients)) != len(recipients):
        raise ValueError("D3 requires at least two distinct authorized recipients")
    plaintext = shared.read_limited(source)
    keys = [shared.load_public_key(user, "encryption") for user in recipients]
    unsigned = encrypt_hybrid(plaintext, source.name, keys)
    out = shared.write_new("outbox", f"{shared.safe_filename(source.stem)}.unsigned.svlt", unsigned)
    return out


def run() -> None:
    print("\n--- AXEL: FILE ENCRYPTION (D2 + D3) ---")
    path = input("Path to file (PDF, TXT, etc.): ").strip().strip('"')
    recipients = input("Authorized users, comma-separated (e.g., alice,bob): ").split(",")
    out = encrypt_file_for_users(path, recipients)
    print(f"[OK] Encrypted file: {out}")
    print("[NEXT] Sign this unsigned container in Esteban's module before sharing.")
