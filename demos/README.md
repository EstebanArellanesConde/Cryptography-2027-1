
# D3 + D5 - Security Demonstrations

## Overview

These demonstrations show how the Secure Digital Document Vault
uses hybrid encryption and digital signatures to protect documents.

Cryptographic mechanisms:
- X25519 + HKDF-SHA256 for recipient key protection.
- ChaCha20-Poly1305 for authenticated file encryption.
- Ed25519 for digital signatures.
- SHA-256 for the canonical signing digest.

No RSA encryption is used.

## Demo 1: Alice and Bob

Run:

```bash
python demos/demo_alice_bob.py
```

### Expected behavior

1. Alice and Bob generate X25519 key pairs.
2. Alice encrypts a confidential document.
3. The file key is protected for authorized recipients.
4. Alice signs the encrypted container using Ed25519.
5. Bob receives the container through a local simulation.
6. Bob verifies Alice's signature before decryption.
7. Bob decrypts the document using his private key.
8. The recovered content matches the original document.

### Security properties

- Confidentiality
- Integrity
- Sender authentication
- Recipient-based access control

## Demo 2: Security Failures

Run:

```bash
python demos/demo_security_failures.py
```

### Expected behavior

Scenario 1: Modified ciphertext
- The digital signature verification fails.
- The modified container is rejected.

Scenario 2: Incorrect signing public key
- The trusted signer identity does not match.
- The container is rejected.

Scenario 3: Unauthorized recipient
- Charlie cannot recover the protected file key.
- Decryption is rejected.

## Automated Tests

Run D5 integration tests:

```bash
python -m pytest tests/test_d5_security.py tests/test_signed_hybrid.py -v
```

Verified baseline: 24 tests passed.

Run the complete test suite:

```bash
python -m pytest -q
```

Latest verified run (2026-11-25): 103 tests passed.

## Scope and Limitations

- File exchange is simulated locally; no network transfer occurs.
- Signing public keys must be obtained from a trusted source.
- These demonstrations do not implement replay protection.
- Successful tests do not constitute a complete security audit.
- Persistent private-key protection is handled separately by D6.
