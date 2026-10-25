# D3 — Hybrid multi-recipient encryption

## Scope

D3 encrypts a document **once** with a fresh 256-bit content-encryption key (CEK), then wraps that CEK independently for each intended recipient. It reuses D2's selected content cipher, ChaCha20-Poly1305.

This implementation uses RSA-OAEP with SHA-256 to wrap the short CEK. RSA is never used to encrypt the document itself. RSA keys must be at least 2048 bits; 3072 bits is the helper's default.

> Academic implementation: review the threat model and limitations below before using it with sensitive real-world files. This is not a formally reviewed or production-ready protocol.

## Format and algorithms

The JSON container has:
- `header.format`, `header.version`;
- `header.content_algorithm`, `header.key_encryption_algorithm`, `header.key_id_algorithm`;
- `header.recipient_count` and a sorted `header.recipients` manifest;
- a 96-bit random nonce, ciphertext and 128-bit Poly1305 tag.

Each recipient entry includes a stable application recipient ID, a SHA-256 key ID and a Base64-wrapped CEK. The key ID is SHA-256 over the recipient's DER-encoded SubjectPublicKeyInfo (SPKI). The OAEP label binds the wrapped CEK to the recipient ID, key ID and format version.

The canonical JSON serialization of the entire header—including all recipient entries and wrapped keys—is passed as AEAD associated data. Consequently, a recipient-list change or a change to a key/algorithm identifier causes authentication to fail for recipients whose wrapped key remains present. Removing a recipient's entry removes that recipient's access from that specific container.

The filename, timestamp and plaintext size are inside the encrypted payload. The parser rejects duplicate JSON keys, unexpected fields, invalid Base64, duplicate recipient IDs/key IDs, unsupported algorithms, invalid nonce/tag lengths and malformed manifests. Decryption returns plaintext only after the AEAD tag verifies.

## API example

```python
from encryption.hybrid import (
    generate_rsa_keypair,
    encrypt_bytes_for_recipients,
    decrypt_bytes_for_recipient,
)

# Demo only: for a real deployment, persist private keys encrypted and/or
# in an OS key store. Never publish private keys in source control.
alice_private_pem, alice_public_pem = generate_rsa_keypair(
    key_size=3072, private_key_password=b"replace-with-a-strong-passphrase"
)
bob_private_pem, bob_public_pem = generate_rsa_keypair(
    key_size=3072, private_key_password=b"another-strong-passphrase"
)

document = b"Confidential contents"
container = encrypt_bytes_for_recipients(
    document,
    filename="document.txt",
    recipients={
        "alice": alice_public_pem,
        "bob": bob_public_pem,
    },
)

alice_plaintext, alice_metadata = decrypt_bytes_for_recipient(
    container, "alice", alice_private_pem,
    password=b"replace-with-a-strong-passphrase",
)
bob_plaintext, bob_metadata = decrypt_bytes_for_recipient(
    container, "bob", bob_private_pem,
    password=b"another-strong-passphrase",
)
assert alice_plaintext == bob_plaintext == document
```

For files, use `encrypt_file_for_recipients(input_path, output_path, recipients)` and `decrypt_file_for_recipient(input_path, output_path, recipient_id, private_key, password=None)`. The helpers refuse to overwrite existing outputs and create new files with owner-only permissions. Decryption authenticates the whole container before creating the plaintext output; the caller chooses the destination path, so untrusted filename metadata is never treated as a filesystem path.

`generate_rsa_keypair` returns PEM bytes and, unless a password is supplied, an unencrypted private PEM for development/tests. The example passwords are placeholders, not recommended literal passwords. In production, obtain keys from a protected key store and never hard-code passwords.

## Tests

Run from the repository root in the project's virtual environment:

```bash
python -m pytest -q
```

D3 tests cover:
- two authorized recipients can recover the same document;
- an unauthorized recipient has no wrapped key;
- a mismatched private key fails;
- adding/removing recipient entries is detected;
- ciphertext tampering fails authentication;
- malformed/duplicate JSON keys are rejected;
- empty recipient sets and reuse of the same public key under multiple IDs are rejected.

## Threat model and limitations

**Addressed:** passive observers cannot read file contents; ciphertext and the public recipient manifest are authenticated; each file uses a fresh CEK and nonce; recipients only receive a wrapped CEK for their own key; wrong keys and modifications fail closed.

**Not addressed automatically:**
- **Identity / man-in-the-middle:** a key ID is an identifier, not proof that a public key belongs to Alice or Bob. Verify fingerprints out of band or add a certificate/identity trust model. Merely attaching an X.509 certificate does not make it trusted.
- **Sender authentication / non-repudiation:** AEAD proves integrity under the CEK, not who created the container. A later extension can add a sender signature (e.g. Ed25519) over a precisely canonicalized container. Keep signing keys separate from encryption keys.
- **Revocation:** deleting a recipient from a new container does not revoke old copies, already-decrypted plaintext, or an earlier CEK that recipient retained. Re-encrypt with a fresh CEK and distribute a new container.
- **Private-key theft / weak passphrases:** if a private key is password-encrypted, an attacker can try offline guesses with tools such as John the Ripper or Hashcat, depending on key format. Use a long unique passphrase, OS key storage, access controls and an appropriate memory-hard KDF for any application-level password-derived key wrapping. This module does not implement a password KDF or private-key lifecycle manager.
- **Compromised endpoints, memory dumps, backups and plaintext copies:** encryption cannot protect data after a trusted endpoint or private key is compromised.
- **Traffic analysis:** recipient IDs, key IDs, algorithm names and approximate ciphertext length are visible.
- **Large files:** this implementation is in-memory and caps the serialized container at 1 GiB. Do not add ad hoc chunking; large-file support needs a separately reviewed streaming AEAD format with authenticated ordering, lengths and finalization.
- **Side channels, secure deletion and memory zeroization:** not guaranteed by Python.

## Future work

1. Add a certificate/trust-store policy and explicit key-fingerprint verification.
2. Add sender signatures with separate signing keys and tests for signature tampering.
3. Consider a standardized HPKE-based recipient-key wrapping suite if approved by the course and supported by a maintained library.
4. Add safe streaming support only with a specified, tested format.
5. Add CI for supported Python versions and dependency auditing.
