# D5 — Digital Signatures & Authentication

## 1. Goal

Extend the **Secure Digital Document Vault** (D2 and D3) to authenticate the sender and detect changes to the encrypted container. The recipient must **verify the digital signature before decryption** and reject modified, unsigned, or untrusted containers.

D5 builds on the existing D3 multi-recipient file encryption system. It does not replace authenticated encryption or recipient access control.

## 2. Cryptographic design

| Purpose | Algorithm / component | Team responsibility |
| --- | --- | --- |
| File encryption and integrity | ChaCha20-Poly1305 (D2/D3) | Existing D2/D3 implementation |
| File-key protection per recipient | ECIES-style P-256: ephemeral ECDH, HKDF-SHA256, AES-256-GCM (D3) | Existing D3 implementation |
| Canonical data and digest | Deterministic JSON + SHA-256 (32 bytes) | Axel |
| Digital signature | Ed25519 signature over the 32-byte digest | Esteban |
| Signing / verification workflow | Signed container; verify first, decrypt second | Cristian |
| Security acceptance tests and documentation | `pytest`; cases A–E below | Fer |

Ed25519 is the preferred digital-signature algorithm in the assignment. The implementation explicitly computes **SHA-256 over canonical container data** before passing the resulting digest to Ed25519, following the requested *Hash → Sign → Verify* workflow. This is a project design choice: standard Ed25519 already performs internal hashing, so an external SHA-256 digest is **not a universal requirement of Ed25519**. The verifier must use the same representation and digest method.

**Important:** the Ed25519 signing key pair is separate from each P-256 encryption key pair. Private keys must not be included in the container or committed to GitHub.

## 3. What is signed?

The D5 signature covers **all security-relevant fields** of the D3 container, plus the signer identifier:

- `header`: format, version, and declared algorithms;
- `recipients`: ordered list of recipient `key_id` and `encrypted_key` entries;
- `nonce`: file-encryption nonce;
- `ciphertext`: encrypted content;
- `tag`: ChaCha20-Poly1305 authentication tag;
- `signer_id`: SHA-256 fingerprint of the DER-encoded Ed25519 public signing key.

The `signature` field itself is **excluded**, because it cannot include itself in the signed material. The canonical JSON representation sorts object keys and uses fixed separators and UTF-8 encoding. Recipient list order is preserved and therefore authenticated.

The original filename, UTC timestamp and plaintext length remain **inside the encrypted D3 payload**. They are protected by authenticated encryption; they are not separate cleartext D5 fields.

### D5 container structure (illustrative)

```json
{
  "header": {"format": "SecureVault", "version": "3.0", "algorithm": "ChaCha20-Poly1305", "key_encryption": "ECIES-P256-ECDH-HKDF-SHA256-AESGCM"},
  "recipients": [
    {"key_id": "<SHA-256 fingerprint>", "encrypted_key": "<Base64 ECIES wrapped key>"},
    {"key_id": "<SHA-256 fingerprint>", "encrypted_key": "<Base64 ECIES wrapped key>"}
  ],
  "nonce": "<Base64>",
  "ciphertext": "<Base64>",
  "tag": "<Base64>",
  "signer_id": "<SHA-256 Ed25519 public key fingerprint>",
  "signature": "<Base64 Ed25519 signature>"
}
```

## 4. Signing workflow

1. **Encrypt** the file once with D3 and protect its file key independently for each authorized recipient.
2. Add a deterministic `signer_id` derived from the sender's public signing key.
3. Create the canonical bytes of all protected container fields, excluding `signature`.
4. Compute `SHA-256(canonical_data)`.
5. **Sign** the 32-byte digest with the sender's Ed25519 private key.
6. Store the Base64-encoded signature with the encrypted container.

## 5. Verification workflow — verify before decrypt

1. Read the received JSON container and check its structure, required fields, and duplicate fields.
2. Obtain the sender's **trusted** Ed25519 public key from outside the untrusted container.
3. Confirm that `signer_id` corresponds to this trusted public key.
4. Recompute SHA-256 over the same canonical protected fields.
5. **Verify the Ed25519 signature. If verification fails or the signature is missing, reject the container without decrypting it.**
6. Only after successful verification, pass the authenticated D3 portion to the existing D3 decryptor. The intended recipient must still have the correct P-256 private key and pass ChaCha20-Poly1305 integrity checks.

### Why sign ciphertext rather than plaintext?

The recipient can verify the **encrypted package before attempting decryption**, while plaintext and private metadata remain confidential. Signing the cleartext would require access to that plaintext for verification and would not, by itself, bind the full encrypted container structure.

### Why verify first?

Without verification, the application could process an unauthenticated container and cannot establish who signed it. Verification is a fail-closed authentication gate; authenticated encryption still independently validates the encrypted content and associated data.

### What if metadata is excluded from the signature?

An attacker might alter unprotected sender, recipient, algorithm, or context fields without invalidating the signature, creating attribution or interpretation errors. D5 therefore signs the relevant container metadata, and D3 also authenticates its header and recipients as AAD.

## 6. Security decisions and limitations

- **Trusted key binding:** the verifier accepts an Ed25519 public key obtained and validated through a prior trusted process. `signer_id` alone does **not** prove a real-world identity, and an attacker-controlled public key from the container must never be treated as trusted.
- **No signature downgrade:** an unsigned D3 container is rejected by the D5 verification interface rather than silently accepted.
- **No unsupported fields:** unexpected top-level fields are rejected so that security-relevant information cannot be excluded from the signature by accident.
- **Scope:** this academic implementation does not include a full PKI/certificate authority, secure long-term key storage, key rotation, revocation, recovery or replay protection. It also does not protect an already compromised endpoint or against an authorized recipient redistributing plaintext.
- **Interoperability:** older RSA-based D3 containers are not accepted by the new ECIES P-256 D3 implementation. D5 requires signed D3/ECIES containers.

## 7. Required D5 security tests (Fer)

File: `tests/test_d5_security.py`.

| Requirement | Test | Expected result |
| --- | --- | --- |
| A. Valid signature | `test_a_valid_signature_is_accepted` | Both authorized recipients can open a correctly signed file. |
| B. Modified ciphertext | `test_b_modified_ciphertext_is_rejected` | Modified ciphertext is rejected **before** D3 decryption. |
| C. Modified metadata | `test_c_modified_metadata_is_rejected` | Changing the header or ordered recipient list invalidates the signature. |
| D. Wrong public key | `test_d_wrong_public_key_is_rejected` | A signature cannot be verified with another sender's public key. |
| E. Signature removed | `test_e_signature_removed_is_rejected` | Missing signature is rejected; no fallback to unsigned D3. |

Additional regression tests verify that an unauthorized recipient cannot decrypt a valid signed file and that reordering JSON object keys does not invalidate canonical signatures.

**Execution after integrating the dependency PRs:**

```bash
python -m pip install -r requirements.txt
python -m pytest tests/test_d5_security.py -v
python -m pytest tests/ -v
```

**Test evidence:** record the terminal results after testing the integrated branch. Do not claim that tests passed in the team repository before running them there. Deprecation warnings from D2 (`datetime.utcnow()`) are separate from the D5 signature tests.

## 8. Team contributions

| Member | Primary contribution | Files |
| --- | --- | --- |
| Esteban | Ed25519 key generation, signing and verification | `src/signatures/signature_core.py`, `tests/test_signature_core.py` |
| Axel | Canonical payload and SHA-256 digest | `src/signatures/signable_payload.py`, `tests/test_signable_payload.py` |
| Cristian | Signed-container integration and verify-before-decrypt workflow | `src/encryption/signed_hybrid.py`, `tests/test_signed_hybrid.py` |
| Fer | Mandatory A–E security tests and D5 documentation | `tests/test_d5_security.py`, `README_D5.md` |

Every contribution is submitted through its own feature branch and pull request, with review before merging into `main`.

## 9. References

- National Institute of Standards and Technology. (2015). *Secure Hash Standard (SHS)* (FIPS PUB 180-4). https://doi.org/10.6028/NIST.FIPS.180-4
- Josefsson, S., & Liusvaara, I. (2017). *Edwards-curve digital signature algorithm (EdDSA)* (RFC 8032). Internet Engineering Task Force. https://www.rfc-editor.org/rfc/rfc8032
- National Institute of Standards and Technology. (2020). *Recommendation for key management: Part 1 — General* (SP 800-57 Part 1 Rev. 5). https://doi.org/10.6028/NIST.SP.800-57pt1r5
