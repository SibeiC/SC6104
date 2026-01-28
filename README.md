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

### Running the Complete Demo

The easiest way to see the attack in action is to run the integrated demo:

```bash
./run.py
```

Or with Poetry:

```bash
poetry run python run.py
```

**Custom host/port:**

```bash
./run.py --host 0.0.0.0 --port 8080
```

**What the demo does:**

1. **Starts TLS Server**: Launches a Flask server in a separate daemon thread with TLS handshake endpoints
2. **Initializes Attack Client**: Creates a Bleichenbacher attack client targeting the server
3. **Phase 1 - TLS Handshake**: 
   - Client sends ClientHello with vulnerable cipher suite (`TLS_RSA_WITH_AES_128_CBC_SHA`)
   - Server responds with certificate and public key
   - Client sends encrypted premaster secret using RSA PKCS#1 v1.5 padding
   - Handshake completion
4. **Phase 2 - Oracle Query Demonstration**:
   - Demonstrates how modified ciphertexts are sent to the server
   - Shows server responses revealing padding validity
5. **Phase 3 - Bleichenbacher Attack**:
   - Simulates the attack algorithm
   - Uses padding oracle to iteratively narrow solution space
   - Demonstrates plaintext recovery (scaffolded implementation)
6. **Graceful Shutdown**: Automatically cleans up server thread and client connections

Press `Ctrl+C` at any time to stop the demo.

### Running Components Separately

**Server only:**

```bash
poetry run python server/server.py
```

**Client only** (requires server running):

```bash
poetry run python client/attack.py
```

## Attack Description

The Bleichenbacher attack (1998) exploits the padding oracle in PKCS#1 v1.5 RSA encryption by:

1. **Ciphertext Capture**: Intercept encrypted premaster secret during TLS handshake
2. **Ciphertext Modification**: Generate modified ciphertexts by multiplying with chosen values
3. **Oracle Queries**: Send modified ciphertexts to server and observe responses
4. **Padding Validation**: Server's response reveals if PKCS#1 v1.5 padding is valid
5. **Interval Narrowing**: Use oracle responses to iteratively narrow possible plaintext values
6. **Plaintext Recovery**: Recover the original premaster secret without the private key

**Key Vulnerability**: The server acts as a "padding oracle" by leaking information about whether the decrypted plaintext has valid PKCS#1 v1.5 padding structure through error messages, timing differences, or behavioral changes.

### Implementation Details

- **Server** ([server/server.py](server/server.py)): Flask-based TLS server with endpoints mimicking TLS handshake phases
- **Client** ([client/attack.py](client/attack.py)): Attack client with padding oracle query capabilities
- **Demo** ([run.py](run.py)): Orchestrates both components in a single process with automatic cleanup

## Warning

⚠️ **This code is intentionally vulnerable and should NEVER be used in production.** It is designed solely for educational purposes to demonstrate cryptographic vulnerabilities.

## License

Educational use only - SC6104 Course Project

## References

- Bleichenbacher, D. (1998). "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
- RFC 8017 - PKCS #1: RSA Cryptography Specifications
A demonstration of weak TLS implementations
