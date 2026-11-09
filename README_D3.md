
# D3 — Hybrid Encryption

## 1. Overview

This module extends the D2 Secure Symmetric Encryption Module to support secure file sharing with multiple authorized recipients using hybrid encryption.

The file is encrypted only once using ChaCha20-Poly1305. The symmetric file key is then encrypted separately for each recipient using RSA-OAEP with SHA-256.

Only recipients with the corresponding private keys can recover the symmetric key and decrypt the file.

## 2. Hybrid Design Explanation

### Why is hybrid encryption used?

Hybrid encryption combines symmetric and asymmetric cryptography to achieve secure and efficient file sharing.

Symmetric encryption protects the file contents, while asymmetric encryption protects the symmetric key for each authorized recipient.

This avoids encrypting large files directly with public-key cryptography.

### Why is symmetric encryption still needed?

Symmetric encryption is efficient for encrypting file contents of different sizes.

This module uses ChaCha20-Poly1305, an authenticated encryption algorithm that provides confidentiality, integrity, and tamper detection.

The file is encrypted only once, regardless of the number of authorized recipients.

### Why is per-recipient key encryption required?

Each recipient has a different RSA public and private key pair.

The same symmetric file key is encrypted separately with each recipient's public key.

This allows multiple users to access the same encrypted file without sharing their private keys.

## 3. Cryptographic Algorithms

The implementation uses:

- **ChaCha20-Poly1305:** Encrypts and authenticates the file.
- **RSA-OAEP with SHA-256:** Encrypts the symmetric file key for each recipient.
- **SHA-256:** Generates deterministic public-key identifiers.
- **AAD:** Authenticates the public header and complete recipient list.

The symmetric key is 256 bits, the nonce is 96 bits, and the authentication tag is 128 bits.

RSA keys are generated with a size of 3072 bits.

## 4. Key Identification Mechanism

Each recipient is identified using a SHA-256 fingerprint of their RSA public key.

The public key is serialized using DER encoding with the SubjectPublicKeyInfo format before calculating its fingerprint.

When decrypting, the system derives the identifier from the recipient's private key and searches for the matching entry in the container.

Duplicate identifiers are rejected to avoid ambiguity.

A public-key fingerprint identifies a cryptographic key but does not independently prove the real-world identity of its owner. Public keys must therefore be obtained and verified through a trusted mechanism.

## 5. Updated Container Format

The encrypted file is represented as a JSON container with the following structure:

```json
{
  "header": {
    "format": "SecureVault",
    "version": "2.0",
    "algorithm": "ChaCha20-Poly1305",
    "key_encryption": "RSA-OAEP-SHA256"
  },
  "recipients": [
    {
      "key_id": "SHA256_PUBLIC_KEY_FINGERPRINT",
      "encrypted_key": "BASE64_ENCRYPTED_KEY"
    },
    {
      "key_id": "SHA256_PUBLIC_KEY_FINGERPRINT",
      "encrypted_key": "BASE64_ENCRYPTED_KEY"
    }
  ],
  "nonce": "BASE64_NONCE",
  "ciphertext": "BASE64_CIPHERTEXT",
  "tag": "BASE64_AUTHENTICATION_TAG"
}
```

The recipient list stores a separate encrypted copy of the same symmetric file key for every authorized recipient.

The original filename, UTC timestamp, and plaintext size are included inside the encrypted payload to preserve their confidentiality.

## 6. Metadata and AAD Integration

The Additional Authenticated Data (AAD) includes:

- The public header.
- The complete recipient list.
- Public-key identifiers.
- Encrypted symmetric keys.
- Cryptographic algorithm identifiers.

The AAD is constructed using a consistent JSON serialization with sorted keys.

If an attacker modifies the authenticated recipient list or header, the integrity verification fails and the file cannot be decrypted.

## 7. Security Decisions

### How do recipients identify their key?

Each recipient calculates the SHA-256 fingerprint of their RSA public key and searches for the corresponding key identifier in the container.

The matching encrypted symmetric key is recovered using the recipient's private key.

### What happens if an attacker modifies the recipient list?

The complete recipient list is included in the AAD.

Any modification changes the authenticated information, causing ChaCha20-Poly1305 verification to fail.

Removing a recipient also prevents that recipient from locating their encrypted file key.

### What happens if the wrong public key is used?

If a file key is encrypted using the wrong public key, the intended recipient cannot recover it with their private key.

RSA-OAEP decryption requires the corresponding private key.

The system does not automatically authenticate the identity of public-key owners; public keys must be verified before encryption.

## 8. Required Security Tests

The module includes the five required tests:

1. **Two authorized recipients:** Alice and Bob can decrypt the same encrypted file.
2. **Unauthorized recipient:** Charlie cannot decrypt a file shared only with Alice and Bob.
3. **Tampered recipient list:** Modifying an encrypted key entry causes authentication failure.
4. **Wrong private key:** An incorrect RSA private key cannot recover another recipient's encrypted file key.
5. **Removed recipient:** Removing a recipient prevents their access and invalidates the authenticated recipient list.

The tests are implemented in `tests/test_hybrid.py`.

## 9. Running the Tests

Install the project dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the D3 tests:

```bash
python -m pytest tests/test_hybrid.py -v
```

Run all D2 and D3 tests:

```bash
python -m pytest tests/ -v
```

The expected result is five passing tests for D3 and ten passing tests in total when combined with the five existing D2 tests.

## 10. Security Scope

The module protects the confidentiality and integrity of encrypted data against an attacker who can access or modify the encrypted container but does not possess an authorized private key.

The module does not provide digital signatures, independent sender authentication, trusted public-key distribution, or protection against compromised private keys and endpoints.

The implementation processes file contents as bytes in memory and is intended for the academic Secure Digital Document Vault project.
