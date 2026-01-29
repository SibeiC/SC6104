# SC6104 - Bleichenbacher Attack Implementation

## Overview

This project demonstrates the **Bleichenbacher padding oracle attack** on RSA PKCS#1 v1.5 encryption. It consists of a vulnerable TLS server implementation and an attack client that exploits the padding oracle vulnerability to decrypt ciphertext without knowing the private key.

The implementation shows how error messages from improper padding validation can be used to iteratively decrypt RSA-encrypted messages through adaptive chosen-ciphertext attacks.

## Project Structure

```plaintext
SC6104/
├── server/              # Vulnerable RSA server
│   └── server.py        # TLS server with padding oracle vulnerability
├── client/              # Attack implementation
│   └── attack.py        # Bleichenbacher attack client
├── run.py               # Integrated demo orchestrator
├── pyproject.toml       # Poetry dependency management
├── .gitignore           # Git ignore patterns (includes *.pem)
└── README.md
```

## Educational Purpose

This implementation is created for **SC6104 Introduction to Cryptography** to demonstrate:

- ✅ The Bleichenbacher padding oracle attack (CVE-1998-xxxx)
- ✅ Why PKCS#1 v1.5 padding is cryptographically weak
- ✅ How adaptive chosen-ciphertext attacks work
- ✅ The importance of constant-time cryptographic operations
- ✅ How information leaks through error messages compromise security
- ✅ Real-world cryptanalysis techniques

### Learning Objectives

After running this demo, you should understand:

1. How RSA encryption works and its mathematical properties
2. The structure of PKCS#1 v1.5 padding
3. What constitutes an oracle in cryptographic attacks
4. How small information leaks enable complete breaks
5. Why modern protocols avoid RSA PKCS#1 v1.5

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

## Usage

### Running the Complete Demo

The easiest way to see the attack in action is with Poetry:

```bash
poetry run python run.py
```

#### Command Line Options

```bash
# Run with auto-generated RSA keys
python run.py

# Run with custom RSA keys from files
python run.py --private-key server_private_key.pem --public-key server_public_key.pem

# Run in debug mode (saves generated keys to files)
python run.py --debug

# Custom host and port
python run.py --host 0.0.0.0 --port 8080

# Display help
python run.py --help
```

#### What the Demo Does

The integrated demo performs a complete Bleichenbacher attack:

1. **Server Initialization**
   - Generates RSA-1024 key pair for fast demo (or loads from files if provided)
   - Starts Flask server with vulnerable TLS endpoints
   - Exposes padding oracle through error messages

2. **TLS Handshake Simulation**
   - Client performs handshake to obtain server's public key
   - Server provides certificate with RSA public key (PEM format)

3. **Ciphertext Capture**
   - Client requests a "captured" encrypted message from server
   - Server encrypts a sample message ("I am Iron Man") using RSA PKCS#1 v1.5
   - Simulates intercepted TLS traffic

4. **Bleichenbacher Attack Execution**
   - **Phase 1**: Identify PKCS#1 v1.5 conformant multipliers
     - Search for initial s value that produces valid padding
     - Uses binary search optimization
   - **Phase 2**: Oracle queries to narrow solution space
     - Generate modified ciphertexts: c' = c × s^e mod n
     - Query server to check padding validity
     - Use responses to refine interval bounds
   - **Phase 3**: Interval narrowing algorithm
     - Iteratively reduce possible plaintext values
     - Merge overlapping intervals
     - Continue until convergence to single value

5. **Results Display**
   - Shows number of oracle queries made
   - Displays recovered plaintext (if successful)
   - Provides attack statistics and timing

Press \`Ctrl+C\` at any time to gracefully stop the demo.

### Running Components Separately

#### Server Only

Run the vulnerable TLS server standalone:

```bash
# With auto-generated keys
python server/server.py

# With custom keys
python server/server.py --private-key my_key.pem --public-key my_pub.pem

# Debug mode (saves generated keys)
python server/server.py --debug
```

**Server Endpoints:**

- \`GET /health\` - Health check endpoint
- \`GET /certificate\` - Returns server's public key (PEM format)
- \`POST /client-key-exchange\` - Accepts encrypted premaster secret (JSON or binary)
- \`GET /captured-message\` - Returns encrypted sample message for attack demonstration

#### Client Only

Run the attack client (requires server running):

```bash
python client/attack.py
```

The client will:

1. Connect to server at \`localhost:7265\`
2. Perform handshake to get public key
3. Capture encrypted message
4. Execute Bleichenbacher attack
5. Display recovered plaintext

## Attack Description

### The Bleichenbacher Attack (1998)

The Bleichenbacher attack exploits the padding oracle in PKCS#1 v1.5 RSA encryption. It's an **adaptive chosen-ciphertext attack** that allows an attacker to decrypt messages without knowing the private key.

### How It Works

#### 1. **Ciphertext Capture**

- Intercept encrypted message during TLS handshake or network communication
- Target: RSA-encrypted premaster secret or any PKCS#1 v1.5 encrypted data

#### 2. **Padding Oracle**

The server acts as a "padding oracle" by revealing whether decrypted plaintext has valid PKCS#1 v1.5 structure:
\`\`\`
0x00 || 0x02 || [8+ non-zero random bytes] || 0x00 || [actual data]
\`\`\`

**Oracle leak**: Server returns different responses for:

- Valid padding → "ClientKeyExchange acknowledged"  
- Invalid padding → "Invalid premaster secret format" or "Decryption failed"

#### 3. **Ciphertext Modification**

Generate modified ciphertexts by mathematical property of RSA:
\`\`\`
c' = c × s^e mod n
\`\`\`
When decrypted:
\`\`\`
m' = m × s mod n
\`\`\`

#### 4. **Oracle Queries**

- Send modified ciphertext c' to server
- Observe response to determine if m' has valid PKCS#1 v1.5 padding
- Valid padding means: 2B ≤ m' < 3B (where B = 2^(8(k-2)))

#### 5. **Interval Narrowing (Bleichenbacher Algorithm)**

\`\`\`python

# Initialize interval containing plaintext

M_0 = {[2B, 3B - 1]}

# Iterative refinement

for each iteration i:
    1. Find s_i that makes c×(s_i)^e conforming
    2. For each interval [a, b] in M_{i-1}:
        - Calculate r values
        - Compute new intervals using:
          a' = max(a, ⌈(2B + r×n) / s_i⌉)
          b' = min(b, ⌊(3B - 1 + r×n) / s_i⌋)
    3. Update M_i with refined intervals
    4. Repeat until |M_i| = 1 (single value)
\`\`\`

#### 6. **Plaintext Recovery**

After convergence, the single remaining value is the original plaintext m.

### Complexity

- **Oracle queries**: ~10^6 queries for RSA-2048, much fewer for smaller keys
- **Time**: Minutes to hours for 2048-bit keys, much faster for 1024-bit demo keys
- **Success rate**: Nearly 100% with sufficient queries

### Real-World Impact

This attack affected:

- **TLS 1.0-1.2**: Vulnerable when using RSA key exchange
- **PKCS#1 v1.5**: Still used in legacy systems
- **XML Encryption**: Historic vulnerability
- **JWT tokens**: Some implementations vulnerable

**Mitigations:**

- Use TLS 1.3 (removed RSA key exchange)
- Use RSA-OAEP instead of PKCS#1 v1.5
- Implement constant-time padding checks
- Return identical errors for all padding failures

### Implementation Details

#### Server ([server/server.py](server/server.py))

- **Framework**: Flask REST API
- **RSA Key Management**:
  - Auto-generates RSA-1024 keys on startup (fast demo mode)
  - Loads keys from PEM files if provided
  - Saves keys in debug mode for inspection
- **Vulnerable Endpoint**: \`/client-key-exchange\`
  - Decrypts with RSA PKCS#1 v1.5
  - **Oracle Leak**: Returns distinct error messages for invalid padding
  - Accepts both JSON (hex-encoded) and binary data
- **Key Features**:
  - \`decrypt_secret()\`: RSA decryption with PKCS#1 v1.5
  - \`valid_format()\`: Padding validation (the oracle!)
  - \`/captured-message\`: Provides encrypted sample for testing

#### Client ([client/attack.py](client/attack.py))

- **Framework**: Python \`requests\` + \`cryptography\`
- **Attack Implementation**:
  - \`execute_bleichenbacher_attack()\`: Main attack orchestrator
  - \`_find_initial_s_value()\`: Finds first PKCS-conforming multiplier
  - \`_narrow_solution_space()\`: Implements interval narrowing algorithm
  - \`padding_oracle_query()\`: Queries server and interprets response
  - \`generate_malformed_ciphertexts()\`: Creates modified ciphertexts (c × s^e mod n)
- **Cryptographic Operations**:
  - RSA public key extraction from PEM
  - Modular arithmetic for ciphertext manipulation
  - Interval management and merging

#### Demo Orchestrator ([run.py](run.py))

- Manages server lifecycle (daemon thread)
- Coordinates attack phases
- Colorized output for clarity
- Graceful shutdown handling
- Command-line argument parsing

## Technical Details

### Dependencies

- **Flask** (>=3.0.0): Web framework for server endpoints
- **cryptography** (>=42.0.0): RSA operations, key management, PKCS#1 v1.5 padding
- **requests** (>=2.31.0): HTTP client for attack queries

### Files Generated (Debug Mode)

When running with \`--debug\` flag:

- \`server_private_key.pem\`: RSA private key (PEM format)
- \`server_public_key.pem\`: RSA public key (PEM format)

These files are automatically ignored by git (see \`.gitignore\`).

### Performance Notes

- **Key Generation**: < 1 second for RSA-1024 (demo mode)
- **Single Oracle Query**: ~5-10ms (local), ~50-100ms (network)
- **Attack Duration**: Varies by key size and search space
- **Full Attack**: RSA-1024 converges much faster than RSA-2048 (ideal for demos)

### Limitations (Educational Version)

This implementation demonstrates the core algorithm but has simplifications:

- Limited iteration count (prevents excessive queries)
- No blinding (would add anti-detection in real attack)
- No timing attack optimization
- Sequential queries (could be parallelized)
- No error recovery or retry logic

## Troubleshooting

**Error: "Address already in use"**
\`\`\`bash

# Change the port

python run.py --port 8080
\`\`\`

**Error: "Module not found"**
\`\`\`bash

# Ensure dependencies are installed

poetry install

# or

pip install flask cryptography requests
\`\`\`

**Error: "Connection refused"**
\`\`\`bash

# Server needs a few seconds to start

# The demo has built-in wait time, but for manual runs

# 1. Start server: python server/server.py

# 2. Wait 2-3 seconds

# 3. Start client: python client/attack.py

\`\`\`

## Security Notice

⚠️ **WARNING: This code is intentionally vulnerable!**

- **DO NOT** use this code in production systems
- **DO NOT** use PKCS#1 v1.5 for new applications
- **DO NOT** implement your own cryptographic protocols
- This is **ONLY** for educational and research purposes

**Responsible Disclosure**: This attack has been public knowledge since 1998. All modern TLS implementations include countermeasures.

## License

Educational use only - SC6104 Course Project  
GNU General Public License v3.0

## References

### Academic Papers

- **Bleichenbacher, D. (1998)**. "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1". *CRYPTO '98*.
- **Böck, H., et al. (2018)**. "Return Of Bleichenbacher's Oracle Threat (ROBOT)". *USENIX Security*.

### Standards & RFCs

- **RFC 8017**: PKCS #1: RSA Cryptography Specifications Version 2.2
- **RFC 5246**: TLS 1.2 Specification (vulnerable to Bleichenbacher)
- **RFC 8446**: TLS 1.3 Specification (removes RSA key exchange)

### Additional Reading

- [Bleichenbacher's Attack Explained](https://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf)
- [ROBOT Attack Website](https://robotattack.org/)
- [Cryptography Engineering by Ferguson, Schneier, Kohno](https://www.schneier.com/books/cryptography_engineering/)

---

**Disclaimer**: This project is for educational purposes only. Understanding cryptographic attacks is essential for building secure systems, but this code should never be used maliciously or in production environments.
