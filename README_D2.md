# D2 — Secure Symmetric Encryption Module

## Selected AEAD

This module selects **ChaCha20-Poly1305** through PyCA `cryptography`. It is an authenticated-encryption-with-associated-data (AEAD) construction: it encrypts the plaintext and verifies authenticity/integrity when decrypting. The implementation does not implement ChaCha20 or Poly1305 manually.

- Key: 256 bits (32 bytes), freshly generated per file using the library's key-generation function.
- Nonce: 96 bits (12 bytes), freshly generated using the operating system CSPRNG for each encryption.
- Tag: 128 bits (16 bytes), generated and verified by the AEAD implementation.
- AAD: domain-separated canonical header containing format name, version, and algorithm. Header changes are rejected or fail authentication.
- Metadata: filename, UTC creation timestamp, and plaintext size are encrypted inside the payload. They are therefore confidential and authenticated, rather than exposed as plaintext JSON fields.
- Container: JSON with `header`, `nonce`, `ciphertext`, and `tag`. The ciphertext and tag are split only for readable container representation; the library's decrypt call receives `ciphertext || tag`.

## Key handling

`encrypt_bytes` returns `(container_bytes, key)`. `encrypt_file` writes the container and returns the key to the caller. The key is deliberately **not** stored in the container or automatically written beside it. The caller must store it through a separate secure key-management mechanism. Do not log it, commit it, or send it through untrusted storage.

This is a single-owner D2 module. Recipient key wrapping, public-key exchange, signatures, and sender identity verification are not implemented in this stage. AEAD proves that the ciphertext was created by someone who knows the symmetric key; it does not independently identify a real-world sender.

## Why AEAD instead of encryption plus a hash?

A plain hash is not keyed: an attacker who changes the ciphertext can calculate a new hash. AEAD authenticates ciphertext and AAD with a secret key, so unauthorized modifications cause decryption to fail. Do not release or use plaintext if authentication fails.

## Nonce uniqueness and reuse

A nonce must not be reused with the same key. Reuse with ChaCha20-Poly1305 can reveal relationships between plaintexts and undermine the Poly1305 authentication security, potentially enabling forgeries. This implementation creates a new random key for each file and obtains a fresh 96-bit nonce from the OS CSPRNG for every encryption. Never manually seed randomness. Never use UNIX/C `rand()`/`srand()` or Python's non-cryptographic `random` module for keys, nonces, salts, tokens, or other security-sensitive values.

Random nonce collisions are still theoretically possible. Fresh per-file keys greatly reduce the consequences of cross-file nonce collisions; the design still requires a CSPRNG and prohibits reusing a nonce with a given key.

## Threat model

Defends against an attacker who can read, copy, replace, truncate, or modify a stored container but does not know the file key. Confidentiality and tamper detection are provided for container contents. Deletion/denial of service, a compromised endpoint, stolen keys, and malicious code running inside the trusted process are out of scope.

## File-size limitation

The high-level `ChaCha20Poly1305` API processes a complete message in memory. This D2 implementation therefore limits files to 256 MiB. Do not split a large file into ad-hoc chunks using the same key/nonce. Large-file support requires a separately designed and reviewed authenticated streaming format.

## Tests

Tests cover round-trip equality, wrong-key rejection, ciphertext/tag/nonce tampering, header/version modification, fresh output across repeated encryptions, metadata confidentiality, and malformed JSON rejection.

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
python -m pip install -e '.[test]'
pytest -q
```

## Example

```python
from secure_vault import encrypt_file, decrypt_file

key = encrypt_file("input.pdf", "input.pdf.svlt")
# Save `key` using your approved secure key-management mechanism.
metadata = decrypt_file("input.pdf.svlt", "recovered.pdf", key)
print(metadata["plaintext_size"])
```

The output path must not already exist. Decryption authenticates the entire container before creating the recovered file. This is an academic D2 module, not a production payment or banking system.
