# D6 – Key Management

## 1. Goal & Security Goal

Design and implement a secure key management system (`src/key_management/keystore.py`) for the **Secure Digital Document Vault** so that private keys remain confidential and usable only by authorized users, even if storage is compromised.

## 2. Key Management Design

### 2.1 Private & Public Key Protection and KDF Selection

Private keys are **never stored in plaintext**. Before writing to disk, each private key (serialized as **Raw 32 binary bytes**, consistent with the project's key format specification) is encrypted using **AES-256-GCM** with a 32-byte Key Encryption Key (KEK) derived from the user's password via **Argon2id** (`cryptography.hazmat.primitives.kdf.argon2.Argon2id`). Argon2id was selected over PBKDF2 because it is **memory-hard** and provides stronger resistance against GPU/ASIC brute-force attacks.

Public keys (`public_key_der_b64`, encoded as **SubjectPublicKeyInfo DER**) are stored inside `metadata` and **integrity-protected via AES-256-GCM AAD** (alongside `kdf_parameters`), preventing silent public-key substitution or metadata tampering, and are verified against `key_id` on every unlock.

**Selected KDF Parameters:**
- **Algorithm:** `Argon2id` (memory-hard, resistant to GPU/ASIC brute-force attacks)
- **Salt:** 16 random bytes (`os.urandom(16)`) generated per keystore
- **Iterations:** `3`
- **Memory Cost:** `65536` KiB (64 MiB)
- **Lanes (Parallelism):** `1`
- **Derived Key Length:** `32` bytes (256 bits)
- **AEAD Cipher:** `AES-256-GCM` with a 12-byte random nonce (`os.urandom(12)`) and AAD binding `kdf_parameters` and `metadata`

### 2.2 Password-Based Access & Secure RAM/Cache Handling

- The system prompts for the password (`getpass.getpass`) or accepts it at unlock time when accessing a private key.
- The KEK is derived on demand and the private key is decrypted in memory only for the duration of the operation (`use_private_key` context manager).
- Sensitive mutable buffers (KEK and decrypted Raw 32-byte private key `bytearray`) are **best-effort zeroed in RAM** (`_zero_bytearray`) in `finally` blocks, followed by reference deletion and `gc.collect()`.
- The system **never** stores the password on disk or in global state, and **never** caches decrypted private keys indefinitely.

### 2.3 Key Storage Format

Each key is stored in a structured directory:

```text
keystore/
  ├── encrypted_private_key   # 12-byte nonce || AES-256-GCM ciphertext || 16-byte tag
  ├── salt                    # 16 random bytes
  ├── kdf_parameters          # JSON: {"kdf", "iterations", "lanes", "memory_cost", "length"}
  └── metadata                # JSON: key_id, algorithm, usage, status, created_at, expires_at, public_key_der_b64
```

- `kdf_parameters` and `metadata` are authenticated as **AAD** during AES-256-GCM encryption, so any tampering with either file or the ciphertext invalidates the authentication tag.

### 2.4 Key Lifecycle Definition

1. **Key Generation (`create_keystore`):** Generates independent keypairs depending on usage: `X25519` for `"encryption"` and `Ed25519` for `"signing"`.
2. **Key Usage (`unlock_private_key` / `use_private_key`):** Enforces `expected_usage`, checks `status` (`active`, `rotated`, `revoked`), and checks `expires_at` if configured.
3. **Key Rotation (`rotate_key`):** Verifies ownership of the current key, marks its status as `"rotated"` (kept encrypted only for decrypting historical data), and generates a new `"active"` keypair. Key rotation does not automatically re-encrypt previously encrypted documents. Documents encrypted with an old key still require that corresponding private key for decryption. The old keystore must be securely preserved if access to historical documents is required. If the old private key is permanently deleted, those documents cannot be recovered using the newly generated key alone.
4. **Key Compromise & Algorithm Breakage Response (`revoke_key` / Algorithm Agility):** Marks a compromised key as `"revoked"` in `metadata` (blocking all future unlocking), requiring generation of a new keypair and re-encryption of shared file keys (D3). Because `kdf_parameters` and `metadata` explicitly record the KDF and key algorithms, unsupported or broken/deprecated algorithms are rejected at unlock time and keys can be rotated/re-encrypted to stronger algorithms.
5. **Key Expiration & Secure Deletion (`secure_delete_keystore`):** Supports optional `expires_at` (ISO-8601 UTC timestamp) in `metadata`, and provides `secure_delete_keystore()` to overwrite keystore files with random bytes and zeros (`os.fsync`) before unlinking from disk.

### 2.5 Backup Strategy

- **Backup (`backup_keystore`):** Packages the four encrypted keystore files (`encrypted_private_key`, `salt`, `kdf_parameters`, `metadata`) into a `.zip` archive. Plaintext keys and passwords are never exported.
- **Restore (`restore_keystore`):** Extracts and validates the four required files into the target directory, preserving the exact encrypted state and password protection.

### 2.6 Access Control via Keys

- Only users who possess the correct keystore and password can unlock the X25519 private key to call `decrypt_hybrid` (`decrypt_file_with_keystore`).
- File sharing continues to rely on per-recipient encrypted file keys from D3.
- **Consistent Identity:** `key_id` uses `get_key_id()` (D3) for X25519 and `get_signer_id()` (D5) for Ed25519, verified against the decrypted private key on every unlock.
- **No Ambiguity in Key Usage:** Encryption keys (`"encryption"`) and signing keys (`"signing"`) are strictly separated and enforced via `expected_usage`.

## 3. Threat Model Alignment (D1)

- **A. What if an attacker steals the keystore?**
  The attacker only obtains the AES-256-GCM ciphertext, random salt, KDF parameters, and public metadata. Without the password, the private key cannot be decrypted, and Argon2id slows down offline brute-force attempts.
- **B. What if a password is weak?**
  An attacker with a stolen keystore can perform offline dictionary or brute-force attacks against the password. Although Argon2id increases the cost per guess, a weak or predictable password can still be cracked offline.
- **C. What if a device is compromised?**
  If malware, a keylogger, or memory-scraping attacker is present on the endpoint while the user enters the password or while the private key is temporarily decrypted in RAM, the attacker can capture the password or private key. Endpoint compromise is **out of scope** for software keystores.

### Security Assumptions
- **Protects against:** Offline theft of the keystore files, unauthorized file decryption without the password, and tampering with `encrypted_private_key`, `kdf_parameters`, or `metadata`.
- **Does NOT protect against:** Compromised endpoints (keyloggers, rootkits, RAM inspection during active use), weak user-chosen passwords, or authorized recipients redistributing already-decrypted plaintext.

## 4. Security Discussion

- **Why encrypt private keys?** If storage is compromised, plaintext private keys would immediately collapse all confidentiality (D2/D3) and authenticity (D5). Encrypting private keys at rest ensures storage compromise alone does not expose key material.
- **What happens if the password is weak?** The security of the encrypted keystore reduces to the entropy of the password. A low-entropy password weakens resistance against offline guessing attacks despite Argon2id.
- **System limitations:** Relies on user password strength, assumes a clean/uncompromised endpoint during unlock operations, and does not include hardware security modules (HSM/TPM) or a full PKI/CA revocation infrastructure.

## 5. Required Automated Tests

File: `tests/test_d6_key_management.py`

| Requirement | Test Function | Expected Result |
| --- | --- | --- |
| Correct password → access granted | `test_correct_password_grants_access_and_decrypts_d3` | Key unlocks and decrypts D3 container |
| Wrong password → access denied | `test_wrong_password_denies_access` | Raises `KeystoreAccessError` |
| Modified keystore → failure | `test_modified_keystore_fails`, `test_modified_metadata_fails_aad_check` | Tampering fails AEAD verification |
| Backup → restore works | `test_backup_and_restore_works` | Restored keystore unlocks with original password |
| Stolen keystore alone → cannot decrypt | `test_stolen_keystore_alone_cannot_decrypt` | Raw keystore cannot be loaded or used to decrypt |

Run tests with:
```bash
python -m pytest tests/test_d6_key_management.py -v
```

