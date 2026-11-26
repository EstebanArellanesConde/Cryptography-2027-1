# Secure Vault — Console demonstration (D2–D6)

**Purpose:** real file encryption and signing without a graphical interface. This is a **local demonstration** of a secure file container, *not* a network messaging application. Each contributor works on a separate file under `vault_cli/`.

## Install and launch

From the repository root in Linux/WSL (with a compatible Python >=3.10 environment):

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m vault_cli
```

User files, keystores and recovered documents are created **outside the Git repository**, in `~/.secure_vault_demo/` by default. For automated tests or a separate demo, you can set `SECURE_VAULT_HOME` to a different directory. Private keys are protected by Argon2id and AES-256-GCM. Never commit or transmit keystore directories or passwords.

## Complete interactive flow (Alice / Bob)

1. **Cristian / menu 1:** Create `alice` and `bob` (optionally `charlie`). Passwords have a demo minimum of 8 characters; use strong distinct ones in practice.
2. **Axel / menu 2:** Select an actual file path (e.g. `/home/user/Documents/example.pdf`). Choose two recipients `alice,bob` (D3 requires at least two). An `*.unsigned.svlt` is created under `~/.secure_vault_demo/outbox/`. **Do not distribute this unsigned intermediate**.
3. **Esteban / menu 3:** Sign that exact `*.unsigned.svlt` using Alice's signing keystore. The shareable `*.signed.svlt` is created in the outbox. Select the verify option to confirm the signature using the locally trusted Alice key.
4. **Fernanda / menu 4:** Recover the **signed** file using Bob's private encryption key and password, with **Alice** selected as trusted signer. Recovery output is created under `~/.secure_vault_demo/recovered/`, with no overwriting of existing files. Or select the attack test to show signature tampering, wrong signer, and unrelated non-recipient rejection.

## Team ownership

| Member | File | Responsibility |
|---|---|---|
| Cristian | `vault_cli/cristian_keys.py` | create and unlock password-protected keystores |
| Axel | `vault_cli/axel_encryption.py` | validate file/recipients and encrypt D3 package |
| Esteban | `vault_cli/esteban_signatures.py` | Ed25519 signing and trusted-key signature checking |
| Fernanda | `vault_cli/fernanda_security.py` | verify-before-decrypt, safe recovered output, negative tests |
| Integration | `vault_cli/shared.py`, `vault_cli/__main__.py` | workspace, local trust, input limits, navigation |

## Limitations to disclose in presentation

- Public key identity is trusted from **previously provisioned local keystores**. D6 identifies Ed25519 public keys using a RAW fingerprint while D5 uses a DER fingerprint; the CLI validates the D6 metadata format and passes the trusted Ed25519 key itself to D5 for verification. There is no CA/PKI, remote key discovery, or secure public-key enrollment; a compromised machine or swapped local key directory is outside this demo's trust assumptions.
- Sharing is **manual**: deliver `*.signed.svlt`, not the unsigned intermediate. No server, automatic internet transfer, user accounts, or remote authentication is implemented.
- No replay detection, revocation distribution, or automated cross-machine key provisioning.
- In-memory file handling is limited by this CLI to **16 MiB input** and **28 MiB containers**. This tighter cap is specific to the demo, not D2's 256 MiB test limit.
- This CLI intentionally uses two separate actions for D3 encryption and D5 signing; **the intermediate unsigned file is not authenticated by a sender and must not be treated as safely shareable**.
- Demo keystores are tied to this operating-system user profile. To decrypt on another machine, the recipient must securely possess their own encryption keystore/password and a trusted copy of the signer's public key; secure distribution is not automated here.
- The three negative tests are illustrative evidence, not a full security audit. Retain existing automated tests and run `python -m pytest -q`.

## Run tests

```bash
python -m pytest -q
python -m pytest tests/test_vault_cli.py -v
```

Create Pull Requests from the four existing personal branches rather than editing `main` directly. Integrate the shared scaffolding first to avoid duplicated integrations.
