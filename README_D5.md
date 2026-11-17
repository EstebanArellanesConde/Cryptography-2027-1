# D5 — Signatures & Authentication

## Signature Design

**Algorithm:** Ed25519 (RFC 8032) via `cryptography`. It is deterministic (no nonce
failures like ECDSA), fast, and has 32-byte keys / 64-byte signatures. Signing keys
are separate from the X25519 encryption keys (one key, one purpose).

**Signer identification:** `signer_id` = hex SHA-256 of the raw 32-byte Ed25519 public key.

**Encoding:** Base64 of the 64-byte Ed25519 signature, stored in the JSON container.

**What is signed:** canonical JSON (`sort_keys`, compact separators) of `header`,
`recipients` (key_id + encrypted_key), `nonce`, `ciphertext`, `tag`, `signer_id`:
the D3 AAD plus the ciphertext, tag and signer identity.

**Why hash before signing:** the signed data is large and variable; it is reduced to a
fixed-size SHA-256 digest (`Hash -> Sign -> Verify`), so the signature binds to a
collision-resistant fingerprint of the entire container.

## Flow

Sign: `Encrypt (D2/D3) -> Add metadata -> Hash -> Sign -> Store`

Verify: `Read container -> Extract metadata + ciphertext -> Verify signature ->
valid: decrypt / invalid: reject (ValueError)`

```json
{ "header", "recipients", "nonce", "ciphertext", "tag", "signer_id", "signature" }
```

## Security Decisions

**Why sign ciphertext and not plaintext?**
The recipient verifies authenticity *before* decrypting, so no attacker-controlled data is
processed. Nothing about the plaintext leaks, and the signature binds the recipients and
the whole container, so an attacker cannot re-encrypt content and claim ownership.

**What happens if the signature is not verified first?**
The system would decrypt and parse attacker-supplied containers: exposure to
chosen-container/oracle attacks, forged containers from anyone holding a recipient's
public key, and wasted work. Origin and integrity could not be trusted.

**What happens if metadata is excluded?**
An attacker could change the header (algorithm downgrade), the recipient list (add,
remove, redirect keys) or `signer_id` without invalidating the signature: context
manipulation attacks.

## Tests (`tests/test_signatures.py`)

| Test | Result |
|---|---|
| A. Valid signature | accepted |
| B. Modified ciphertext | rejected |
| C. Modified metadata / recipients | rejected |
| D. Wrong public key | rejected |
| E. Signature removed | rejected |

Run: `pip install -e .[test] && pytest`

