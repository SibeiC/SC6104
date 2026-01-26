# SC6104 - Bleichenbacher Attack Implementation

## Overview

This project demonstrates the Bleichenbacher padding oracle attack on RSA PKCS#1 v1.5 encryption. It consists of a vulnerable server implementation and a malicious client that exploits the vulnerability to decrypt ciphertext without knowing the private key.

## Project Structure

```plaintext
SC6104/
├── server/              # Vulnerable RSA server
│   └── server.py        # Server with padding oracle vulnerability
├── client/              # Attack implementation
│   └── attack.py        # Bleichenbacher attack client
├── run.py               # Initiate the server/client, and commence the attack
├── pyproject.toml       # Poetry dependency management
└── README.md
```

## Educational Purpose

This implementation is created for **SC6104 Introduction to Cryptography** course to demonstrate:

- The Bleichenbacher padding oracle attack (1998)
- Why PKCS#1 v1.5 padding is vulnerable
- The importance of proper error handling in cryptographic implementations
- How timing and error message leaks can compromise security

## Requirements

- Python 3.14+
- Poetry (for dependency management)

## Setup

### Option 1: Using Poetry

```bash
poetry install
poetry shell
```

## Usage

### Running the Vulnerable Server

```bash
poetry run python server/server.py
```

### Running the Attack Client

```bash
poetry run python client/attack.py --target http://localhost:8080 --ciphertext <hex_ciphertext>
```

## Attack Description

The Bleichenbacher attack exploits the padding oracle in PKCS#1 v1.5 RSA encryption by:

1. Sending modified ciphertexts to the server
2. Observing whether the server accepts or rejects the padding
3. Using these oracle responses to narrow down the plaintext value
4. Iteratively refining the search space until the plaintext is recovered

## Warning

⚠️ **This code is intentionally vulnerable and should NEVER be used in production.** It is designed solely for educational purposes to demonstrate cryptographic vulnerabilities.

## License

Educational use only - SC6104 Course Project

## References

- Bleichenbacher, D. (1998). "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
- RFC 8017 - PKCS #1: RSA Cryptography Specifications
A demonstration of weak TLS implementations
