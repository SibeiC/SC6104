# SC6104 - Bleichenbacher Attack Implementation

## Overview

This project demonstrates the **Bleichenbacher padding oracle attack** on RSA PKCS#1 v1.5 encryption. It consists of a vulnerable TLS server implementation and an attack client that exploits the padding oracle vulnerability to decrypt ciphertext without knowing the private key.

The implementation shows how error messages from improper padding validation can be used to iteratively decrypt RSA-encrypted messages through adaptive chosen-ciphertext attacks.

## Setup

### Prerequisites

- Python 3.14+
- Poetry (for dependency management)

### Installation

#### Option 1: Using Poetry (Recommended)

```bash
# Install dependencies
poetry install

# Activate virtual environment
poetry shell
```

## License

Educational use only - SC6104 Course Project  
GNU General Public License v3.0

## References

### Academic Papers

- **Bleichenbacher, D. (1998)**. "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1". *CRYPTO '98*.

---

**Disclaimer**: This project is for educational purposes only. Understanding cryptographic attacks is essential for building secure systems, but this code should never be used maliciously or in production environments.
