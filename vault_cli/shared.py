"""Shared CLI helpers: isolated workspace, input validation, trusted local keys.

Trust assumption: the local user profile and OS are not compromised. Public keys
are bound to identities only through locally provisioned keystores; this is NOT PKI.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from encryption.hybrid_core import get_key_id
from src.encryption.signatures import get_signer_id

# Much smaller than the D2 256 MiB limit to keep this in-memory demo practical.
MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_CONTAINER_SIZE = 28 * 1024 * 1024
WORKSPACE = Path(os.environ.get("SECURE_VAULT_HOME", str(Path.home() / ".secure_vault_demo"))).expanduser()
USER_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")


def username(value: str) -> str:
    value = value.strip().lower()
    if not USER_PATTERN.fullmatch(value):
        raise ValueError("User ID must be 1-32 chars: lowercase letters, numbers, _ or -, starting with a letter.")
    return value


def key_dir(user: str, usage: str) -> Path:
    if usage not in {"encryption", "signing"}:
        raise ValueError("Invalid key purpose")
    return WORKSPACE / "keystores" / username(user) / usage


def safe_filename(value: str) -> str:
    # Never interpret a filename supplied in encrypted metadata as a path.
    name = value.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name).strip(".")[:120]
    return name if name not in {"", ".", ".."} else "recovered.bin"


def load_public_key(user: str, usage: str):
    """Read a previously provisioned, locally trusted public key, NOT one in a .svlt."""
    base = key_dir(user, usage)
    try:
        meta = json.loads((base / "metadata").read_text(encoding="utf-8"))
        if meta.get("usage") != usage or meta.get("status") != "active":
            raise ValueError("Keystore is not an active key of the requested purpose")
        data = base64.b64decode(meta["public_key_der_b64"], validate=True)
        pub = serialization.load_der_public_key(data)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Cannot load locally trusted {usage} public key for {user}") from exc

    if usage == "encryption":
        if not isinstance(pub, X25519PublicKey) or get_key_id(pub) != meta.get("key_id"):
            raise ValueError("Encryption public key metadata mismatch")
    else:
        if not isinstance(pub, Ed25519PublicKey) or get_signer_id(pub) != meta.get("key_id"):
            raise ValueError("Signing public key metadata mismatch")
    return pub


def read_limited(path: str | Path, *, container: bool = False) -> bytes:
    path = Path(path).expanduser()
    if not path.is_file():
        raise ValueError(f"File does not exist: {path}")
    maximum = MAX_CONTAINER_SIZE if container else MAX_FILE_SIZE
    if path.stat().st_size > maximum:
        raise ValueError(f"File exceeds demo limit: {maximum // (1024 * 1024)} MiB")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("File exceeds demo size limit")
    return data


def write_new(folder: str, filename: str, data: bytes) -> Path:
    target_dir = WORKSPACE / folder
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = safe_filename(filename)
    stem, suffix = Path(name).stem, Path(name).suffix
    for number in range(10000):
        candidate = target_dir / (name if not number else f"{stem}_{number}{suffix}")
        try:
            # Exclusive creation avoids unintended overwrite of user data.
            with candidate.open("xb") as stream:
                stream.write(data)
            if os.name == "posix":
                candidate.chmod(0o600)
            return candidate
        except FileExistsError:
            continue
    raise ValueError("Too many output filename collisions")
