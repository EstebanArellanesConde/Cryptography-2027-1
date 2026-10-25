"""D3: multi-recipient hybrid encryption for SecureVault.

The file content is encrypted once with ChaCha20-Poly1305. Its fresh 256-bit
content key is wrapped independently for each recipient with RSA-OAEP-SHA256.
This module is an educational project implementation, not a reviewed production
format.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Mapping, Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

FORMAT = "SecureVault"
VERSION = "3.0"
CONTENT_ALGORITHM = "ChaCha20-Poly1305"
KEY_ENCRYPTION_ALGORITHM = "RSA-OAEP-SHA256"
KEY_ID_ALGORITHM = "SHA-256(SPKI-DER)"
_NONCE_SIZE = 12
_TAG_SIZE = 16
_MAX_RECIPIENTS = 128
_MAX_CONTAINER_BYTES = 1_073_741_824  # 1 GiB cap for this in-memory implementation
_MAX_PLAINTEXT_BYTES = 734_003_200  # Leaves room for Base64/JSON overhead below 1 GiB
_LABEL_PREFIX = b"SecureVault-D3-v1\x00"


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_json(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("container must be bytes")
    if len(data) > _MAX_CONTAINER_BYTES:
        raise ValueError("Container exceeds the configured size limit")
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid SecureVault JSON container") from exc
    if not isinstance(obj, dict):
        raise ValueError("Container root must be a JSON object")
    return obj


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a Base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError(f"Invalid Base64 in {field}") from exc


def _load_public_key(key: rsa.RSAPublicKey | bytes | str) -> rsa.RSAPublicKey:
    if isinstance(key, rsa.RSAPublicKey):
        loaded = key
    else:
        raw = key.encode("utf-8") if isinstance(key, str) else key
        try:
            loaded_any = serialization.load_pem_public_key(raw)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid PEM public key") from exc
        if not isinstance(loaded_any, rsa.RSAPublicKey):
            raise TypeError("D3 currently supports RSA public keys only")
        loaded = loaded_any
    if loaded.key_size < 2048:
        raise ValueError("RSA keys must be at least 2048 bits")
    return loaded


def _load_private_key(
    key: rsa.RSAPrivateKey | bytes | str, password: bytes | None = None
) -> rsa.RSAPrivateKey:
    if isinstance(key, rsa.RSAPrivateKey):
        loaded = key
    else:
        raw = key.encode("utf-8") if isinstance(key, str) else key
        try:
            loaded_any = serialization.load_pem_private_key(raw, password=password)
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid or password-protected PEM private key") from exc
        if not isinstance(loaded_any, rsa.RSAPrivateKey):
            raise TypeError("D3 currently supports RSA private keys only")
        loaded = loaded_any
    if loaded.key_size < 2048:
        raise ValueError("RSA keys must be at least 2048 bits")
    return loaded


def public_key_id(public_key: rsa.RSAPublicKey | bytes | str) -> str:
    """Return a stable SHA-256 identifier for an RSA SubjectPublicKeyInfo DER key."""
    key = _load_public_key(public_key)
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def generate_rsa_keypair(
    *, key_size: int = 3072, private_key_password: bytes | None = None
) -> tuple[bytes, bytes]:
    """Generate a recipient keypair; returns (private PEM, public PEM).

    Protect the private PEM with an appropriate password / OS secret store when
    persisting it. This helper returns an unencrypted private PEM for test/demo use.
    """
    if key_size < 2048 or key_size % 256 != 0:
        raise ValueError("key_size must be a multiple of 256 and at least 2048")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(private_key_password)
            if private_key_password
            else serialization.NoEncryption()
        ),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _oaep_label(recipient_id: str, key_id: str) -> bytes:
    return _LABEL_PREFIX + _canonical_json(
        {"recipient_id": recipient_id, "key_id": key_id, "version": VERSION}
    )


def _aad(header: dict[str, Any]) -> bytes:
    # The full recipient manifest, including wrapped keys and IDs, is authenticated.
    return _canonical_json(header)


def encrypt_bytes_for_recipients(
    plaintext: bytes,
    filename: str,
    recipients: Mapping[str, rsa.RSAPublicKey | bytes | str],
) -> bytes:
    """Encrypt bytes once for one or more named RSA recipients.

    recipients maps a stable application-level recipient ID to their public key.
    Do not treat the label itself as identity proof: verify keys/fingerprints out
    of band or through a trusted certificate directory before calling this API.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if len(plaintext) > _MAX_PLAINTEXT_BYTES:
        raise ValueError("Plaintext exceeds the configured in-memory size limit")
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        raise ValueError("filename must be a non-empty string without NUL")
    if not isinstance(recipients, Mapping) or not recipients:
        raise ValueError("At least one recipient is required")
    if len(recipients) > _MAX_RECIPIENTS:
        raise ValueError(f"At most {_MAX_RECIPIENTS} recipients are supported")
    if any(not isinstance(rid, str) or not rid or "\x00" in rid for rid in recipients):
        raise ValueError("Recipient IDs must be non-empty strings without NUL")
    if len(set(recipients)) != len(recipients):
        raise ValueError("Duplicate recipient IDs")

    # Generate a fresh file key for every container. Never reuse it across files.
    file_key = ChaCha20Poly1305.generate_key()
    entries: list[dict[str, str]] = []
    seen_key_ids: set[str] = set()

    # Sort for deterministic canonical representation; encryption itself remains random.
    for recipient_id in sorted(recipients):
        public_key = _load_public_key(recipients[recipient_id])
        key_id = public_key_id(public_key)
        if key_id in seen_key_ids:
            raise ValueError("The same public key cannot be assigned to multiple recipients")
        seen_key_ids.add(key_id)
        wrapped = public_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=_oaep_label(recipient_id, key_id),
            ),
        )
        entries.append({
            "recipient_id": recipient_id,
            "key_id": key_id,
            "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
        })

    header: dict[str, Any] = {
        "format": FORMAT,
        "version": VERSION,
        "content_algorithm": CONTENT_ALGORITHM,
        "key_encryption_algorithm": KEY_ENCRYPTION_ALGORITHM,
        "key_id_algorithm": KEY_ID_ALGORITHM,
        "recipient_count": len(entries),
        "recipients": entries,
    }
    metadata = {
        "filename": filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "plaintext_size": len(plaintext),
    }
    payload = _canonical_json(metadata) + b"\n" + plaintext
    nonce = os.urandom(_NONCE_SIZE)
    ciphertext_and_tag = ChaCha20Poly1305(file_key).encrypt(
        nonce, payload, _aad(header)
    )
    container = {
        "header": header,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext_and_tag[:-_TAG_SIZE]).decode("ascii"),
        "tag": base64.b64encode(ciphertext_and_tag[-_TAG_SIZE:]).decode("ascii"),
    }
    return json.dumps(
        container, sort_keys=True, indent=2, ensure_ascii=False
    ).encode("utf-8")


def decrypt_bytes_for_recipient(
    container_bytes: bytes,
    recipient_id: str,
    private_key: rsa.RSAPrivateKey | bytes | str,
    *,
    password: bytes | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Decrypt a D3 container for recipient_id; return (plaintext, private metadata).

    No plaintext is returned unless ChaCha20-Poly1305 authenticates the complete
    header/recipient manifest and ciphertext.
    """
    if not isinstance(recipient_id, str) or not recipient_id:
        raise ValueError("recipient_id must be a non-empty string")
    container = _decode_json(container_bytes)
    expected_top = {"header", "nonce", "ciphertext", "tag"}
    if set(container) != expected_top:
        raise ValueError("Unexpected or missing top-level container fields")
    header = container["header"]
    if not isinstance(header, dict):
        raise ValueError("header must be an object")
    required_header = {
        "format", "version", "content_algorithm", "key_encryption_algorithm",
        "key_id_algorithm", "recipient_count", "recipients",
    }
    if set(header) != required_header:
        raise ValueError("Unexpected or missing header fields")
    expected_algorithms = (
        header.get("format") == FORMAT
        and header.get("version") == VERSION
        and header.get("content_algorithm") == CONTENT_ALGORITHM
        and header.get("key_encryption_algorithm") == KEY_ENCRYPTION_ALGORITHM
        and header.get("key_id_algorithm") == KEY_ID_ALGORITHM
    )
    if not expected_algorithms:
        raise ValueError("Unsupported SecureVault format, version, or algorithm")
    entries = header.get("recipients")
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_RECIPIENTS:
        raise ValueError("Invalid recipient manifest")
    if header.get("recipient_count") != len(entries):
        raise ValueError("Recipient count does not match manifest")

    ids: set[str] = set()
    key_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"recipient_id", "key_id", "wrapped_key"}:
            raise ValueError("Invalid recipient entry")
        rid, kid = entry["recipient_id"], entry["key_id"]
        if not isinstance(rid, str) or not rid or not isinstance(kid, str):
            raise ValueError("Invalid recipient identity")
        if rid in ids or kid in key_ids:
            raise ValueError("Duplicate recipient ID or key ID")
        ids.add(rid)
        key_ids.add(kid)
        if len(kid) != 64 or any(ch not in "0123456789abcdef" for ch in kid):
            raise ValueError("Invalid key ID")
        _b64decode(entry["wrapped_key"], "wrapped_key")

    matching = [entry for entry in entries if entry["recipient_id"] == recipient_id]
    if len(matching) != 1:
        raise ValueError("No wrapped file key for this recipient")
    private = _load_private_key(private_key, password=password)
    entry = matching[0]
    actual_key_id = public_key_id(private.public_key())
    if actual_key_id != entry["key_id"]:
        raise ValueError("Private key does not match the recipient key ID")

    try:
        file_key = private.decrypt(
            _b64decode(entry["wrapped_key"], "wrapped_key"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=_oaep_label(recipient_id, entry["key_id"]),
            ),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Unable to unwrap the file key for this recipient") from exc

    nonce = _b64decode(container["nonce"], "nonce")
    ciphertext = _b64decode(container["ciphertext"], "ciphertext")
    tag = _b64decode(container["tag"], "tag")
    if len(nonce) != _NONCE_SIZE or len(tag) != _TAG_SIZE:
        raise ValueError("Invalid nonce or authentication tag length")
    try:
        payload = ChaCha20Poly1305(file_key).decrypt(
            nonce, ciphertext + tag, _aad(header)
        )
    except InvalidTag:
        # Authentication failure: do not release partial plaintext.
        raise

    metadata_raw, separator, plaintext = payload.partition(b"\n")
    if not separator:
        raise ValueError("Malformed authenticated payload")
    try:
        metadata = json.loads(metadata_raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Malformed authenticated metadata") from exc
    if not isinstance(metadata, dict):
        raise ValueError("Authenticated metadata must be an object")
    if metadata.get("plaintext_size") != len(plaintext):
        raise ValueError("Authenticated plaintext size does not match payload")
    if not isinstance(metadata.get("filename"), str):
        raise ValueError("Authenticated filename is invalid")
    return plaintext, metadata


def _write_new_file(path: str | os.PathLike[str], data: bytes) -> None:
    """Create a new output file with owner-only permissions; never overwrite."""
    destination = os.fspath(path)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise


def encrypt_file_for_recipients(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    recipients: Mapping[str, rsa.RSAPublicKey | bytes | str],
) -> None:
    """Encrypt a file into a new container file, refusing to overwrite output."""
    source = Path(input_path)
    plaintext = source.read_bytes()
    container = encrypt_bytes_for_recipients(plaintext, source.name, recipients)
    _write_new_file(output_path, container)


def decrypt_file_for_recipient(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    recipient_id: str,
    private_key: rsa.RSAPrivateKey | bytes | str,
    *,
    password: bytes | None = None,
) -> dict[str, Any]:
    """Authenticate/decrypt a container, then create a new plaintext file.

    The output path is supplied by the caller; the encrypted filename metadata is
    never used as a filesystem path. Existing files are never overwritten.
    """
    container = Path(input_path).read_bytes()
    plaintext, metadata = decrypt_bytes_for_recipient(
        container, recipient_id, private_key, password=password
    )
    _write_new_file(output_path, plaintext)
    return metadata
