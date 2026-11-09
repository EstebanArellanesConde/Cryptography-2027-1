# D3 — Hybrid Encryption (ECIES / P-256)

## 1. Goal

Extend the D2 **Secure Digital Document Vault** to allow multiple authorized recipients to decrypt the same file. The file is encrypted **once** with ChaCha20-Poly1305, and its fresh symmetric key is protected **separately for each recipient** with ECIES-style elliptic-curve encryption.

## 2. Hybrid design

- **Why hybrid encryption?** Symmetric encryption efficiently protects the whole file, while public-key cryptography protects only the short file key.
- **Why is symmetric encryption still needed?** Encrypting a large file using public-key operations is inefficient. D2's ChaCha20-Poly1305 continues to provide confidentiality, integrity, and tamper detection.
- **Why wrap for each recipient?** Alice and Bob have independent key pairs and can recover the same file key without sharing private keys.

### Algorithms

| Purpose | Algorithm |
| --- | --- |
| File encryption and authentication (D2) | ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit tag) |
| Recipient key pair | ECC secp256r1 (NIST P-256) |
| Shared secret per recipient | ECDH with a new ephemeral P-256 key |
| Key derivation | HKDF-SHA256 (random 16-byte salt, 32-byte output, fixed domain-separated context and `key_id`) |
| File-key wrap | AES-256-GCM (new random 12-byte nonce) |
| Recipient ID | SHA-256 of DER SubjectPublicKeyInfo of their public key |

**ECIES** is a *scheme*, not a particular curve. Our implementation uses the ECIES-style sequence **ephemeral ECDH → HKDF → AES-GCM**, using the existing `cryptography` library. The protected 32-byte file key is never sent in plaintext.

The per-recipient `encrypted_key` is Base64 of the binary concatenation:

`ephemeral_public_key (65 B) || HKDF_salt (16 B) || AESGCM_nonce (12 B) || AESGCM(file_key) (48 B)`

The AES-GCM AAD for the file-key wrap is the recipient's `key_id`. The HKDF context contains a domain separator and this same ID.

## 3. Key identification and security decisions

A deterministic SHA-256 fingerprint of the recipient's public key is stored as `key_id`. During decryption, the recipient derives their public key from their private key, calculates the fingerprint, and selects **exactly one** matching entry. Duplicate IDs are rejected.

Public-key fingerprints identify a key, **not a verified human identity**. The application assumes authentic public keys have been exchanged before encrypting; full certificate/PKI validation is outside this D3 scope.

If a wrong public key was used, the intended recipient cannot recover the file key. If a different private key is used, AES-GCM verification of the wrapped key fails. If an attacker edits, adds, removes or swaps recipient entries, the file-level **AAD** changes; decryption is rejected by ChaCha20-Poly1305, even by other authorized recipients, unless they re-encrypt/re-authenticate the container legitimately.

## 4. Container format (version 3.0)

```json
{
  "header": {
    "format": "SecureVault",
    "version": "3.0",
    "algorithm": "ChaCha20-Poly1305",
    "key_encryption": "ECIES-P256-ECDH-HKDF-SHA256-AESGCM"
  },
  "recipients": [
    {"key_id": "<Alice SHA256 fingerprint>", "encrypted_key": "<Base64 ECIES wrapping>"},
    {"key_id": "<Bob SHA256 fingerprint>", "encrypted_key": "<Base64 ECIES wrapping>"}
  ],
  "nonce": "<Base64>",
  "ciphertext": "<Base64>",
  "tag": "<Base64>"
}
```

Private metadata (`filename`, UTC `timestamp`, `plaintext_size`) is placed *inside* the encrypted payload. The public `header` and the complete `recipients` list (including key IDs, encrypted keys and algorithm identifiers) form the canonical JSON AAD (sorted keys, compact separators). No private keys are serialized in the container.

## 5. Encrypt/decrypt flow

1. Generate a random 32-byte symmetric key and a random 12-byte file nonce.
2. Package confidential metadata with plaintext; generate one ChaCha20-Poly1305 ciphertext for the file.
3. For each recipient, generate an ephemeral P-256 key, calculate ECDH, use HKDF to derive an AES-256-GCM wrapping key, and encrypt the symmetric file key.
4. Store the wrapped keys and identifiers in the authenticated JSON container.
5. On decryption, find the recipient's entry, recover the symmetric key using their EC private key, reconstruct AAD and verify/decrypt the ChaCha20-Poly1305 ciphertext.

## 6. Running the tests

From the repository root:

```powershell
python -m pip install -r requirements.txt
python -m pytest tests/test_hybrid.py -v
python -m pytest tests/ -v
```

D3 includes five mandatory scenarios (two recipients, unauthorized recipient, tampered list, wrong private key, removed recipient), plus additional integrity/validation checks.

## 7. Migration and compatibility

- The **public Python API** keeps `encrypt_hybrid`, `decrypt_hybrid`, `get_key_id`, `encrypt_file_key`, `decrypt_file_key`, and `build_aad`.
- Replace `generate_rsa_keypair()` with `generate_ecies_keypair()` in callers/tests.
- Previous RSA-OAEP containers use version 2.0 and **are not decryptable** by this ECIES-only version 3.0 implementation. Keep a copy of the earlier Git commit if old data must remain accessible. Never relabel an old RSA container as ECIES.
- D2 source code is **unchanged**. D3 continues to use D2's symmetric algorithm and private-metadata approach.

## 8. D5 — planned extension (not yet implemented)

D5 will add `signature` and `signer_id` to the container, and verify the sender's Ed25519 signature **before** recovering the file key. Sign the canonical bytes of **all existing fields** (`header`, `recipients`, `nonce`, `ciphertext`, `tag`), excluding `signature` and `signer_id` from the signed payload itself, while binding `signer_id` as authenticated context. Trust in the sender's public signature key must be established independently. D5 is a separate PR/deliverable.

## 9. Scope limitations

This is an **academic** Secure Digital Document Vault module, not a security-audited production implementation. It does not yet provide origin signatures (D5), trusted public-key distribution, private-key recovery, compromised endpoint protection, or streaming of very large files. ECIES confidentiality does not authenticate who sent a file. Private keys must remain outside the repository.
