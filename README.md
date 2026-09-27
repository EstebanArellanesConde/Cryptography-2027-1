Repository for Cryptography Coursework 2027-1

# D1 — Architecture & Threat Model

## 1. System Overview

```bash
README.md
│
├── D1 - Architecture & Threat Model
│   ├── System Overview
│   ├── Architecture
│   ├── Security Requirements
│   ├── Threat Model
│   ├── Trust Assumptions
│   ├── Attack Surface Review
│   └── Asset → Threat → Attack Scenario
│       → Security Requirement → Design Constraint
│
└── Defined Tools To Use
    ├── Programming Language
    ├── Cryptographic Library
    ├── Hash Functions
    ├── KDF
    ├── Symmetric Cryptography
    ├── Asymmetric Cryptography
    ├── API Framework
    └── Randomness Requirements
```

### 1.1 What problem does your vault solve?

Our Secure Digital Document Vault is designed as a small secure payment network inspired by the functionality of SPEI. Its purpose is to allow users to create, protect, transmit, verify, and store digital payment messages between participants without requiring the underlying storage or transfer environment to be trusted.

The system addresses the security problem of exchanging sensitive payment information between a sender and a recipient. A payment message may contain information such as the sender, recipient, amount, transaction identifier, timestamp, and other data required to process and verify the transaction.

The main security concern is that an attacker must not be able to modify a payment message, impersonate the sender, redirect a payment to another recipient, or obtain sensitive information by simply accessing the stored or transmitted package.

The architecture therefore separates the system into trusted and untrusted environments. Cryptographic operations and private-key management take place inside the trusted local environment, while the communication and storage layer is considered untrusted. Payment messages are protected before crossing this trust boundary and are validated before being accepted by the recipient.

The system is intended to demonstrate the security architecture and cryptographic mechanisms required for a small payment network, rather than reproduce the complete infrastructure, regulatory framework, or operational scale of SPEI.

### 1.2 What are the core features?

The core features of the proposed payment vault are:

1. **Secure payment creation**
   A user can create a payment request containing information such as sender, recipient, amount, transaction identifier, and timestamp.

2. **Payment confidentiality**
   Sensitive payment information is protected before it is transmitted or stored in an untrusted environment.

3. **Payment integrity**
   Any unauthorized modification to a payment message must be detected before the transaction is accepted.

4. **Sender authentication**
   The recipient must be able to verify that a payment message was created by the claimed sender.

5. **Recipient binding**
   A payment must be associated with its intended recipient so that an attacker cannot modify the destination without detection.

6. **Transaction identification**
   Each payment must contain information that allows the system to distinguish one transaction from another and support detection of duplicated or replayed payment messages.

7. **Secure key management**
   Users' private cryptographic keys must remain within the trusted environment and must not be transmitted through the payment network or stored in the shared storage layer.

8. **Payment verification**
   The receiving side must validate the structure, authenticity, integrity, and authorization of a payment before accepting it.

9. **Protected transaction storage**
   Payment packages may be stored or transmitted through infrastructure that is considered untrusted because the security of the payment must not depend solely on the storage provider.

10. **Fail-closed behavior**
    If a payment fails validation, authentication, integrity verification, or authorization, the system must reject it instead of processing it as a valid transaction.

### 1.3 What is explicitly out of scope?

The project is a small academic payment-network prototype and does **not** attempt to implement the complete functionality or infrastructure of SPEI.

The following are explicitly out of scope:

* Reproducing the complete SPEI infrastructure or Banco de México's production architecture.
* Connecting to the real SPEI network or processing real-world bank transactions.
* Handling real money or real bank accounts.
* Integration with Mexican banks or financial institutions.
* Implementing a production-grade banking core.
* Implementing regulatory, KYC, AML, tax, or financial-compliance processes.
* Guaranteeing availability against denial-of-service attacks or infrastructure failures.
* Protecting a device whose operating system or application environment has already been completely compromised.
* Recovering lost private keys or forgotten passwords.
* Establishing a production public-key infrastructure or certificate authority.
* Protecting plaintext after the user intentionally exports it outside the application.
* Preventing a legitimate account holder from intentionally sharing their own credentials or private keys.
* Providing production-level scalability, high availability, or fault tolerance.
* Implementing hardware security modules or specialized banking hardware.
* Treating the prototype as a replacement for a regulated payment system.
* Guaranteeing that the prototype satisfies all security, operational, and regulatory requirements of an actual financial institution.
* Using the UNIX `rand()` / `srand()` functions or Python's `rand`/`srand` mechanisms for cryptographic randomness.

### 1.4 Randomness requirement

Cryptographic randomness is a security-critical part of the system. The project explicitly prohibits the use of the UNIX `rand()` / `srand()` functions and Python `rand` / `srand` mechanisms for generating security-sensitive values.

Random values required by the cryptographic design, such as salts, nonces, initialization values, or key material, must instead be generated using a cryptographically secure randomness mechanism provided by the selected cryptographic platform/library.

The random-number generation mechanism must therefore be treated as a security requirement and documented as part of the final cryptographic implementation.
