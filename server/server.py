#!/usr/bin/env python3
"""
TLS Handshake Server
Implements a Flask server with endpoints mimicking the TLS handshake process.
"""

import os
import sys
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import calculate_max_pss_salt_length

def decrypt_secret_raw(data: bytes, private_key) -> bytes:
    """Manually decrypt RSA ciphertext without automatic padding removal."""
    # Get the private key numbers
    private_numbers = private_key.private_numbers()
    n = private_numbers.public_numbers.n
    d = private_numbers.d
    
    # Convert ciphertext bytes to integer
    c = int.from_bytes(data, byteorder='big')
    
    # Perform raw RSA decryption: m = c^d mod n
    m = pow(c, d, n)
    
    # Convert back to bytes (should be same length as modulus)
    k = (n.bit_length() + 7) // 8
    return m.to_bytes(k, byteorder='big')

def decrypt_secret(data, private_key) -> bytes:
    """Decrypt the encrypted premaster secret using RSA private key.
    
    Returns the raw decrypted bytes including PKCS#1 v1.5 padding.
    """ 
    try:
        # Use raw decryption to get padded plaintext
        return decrypt_secret_raw(data, private_key)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def valid_format(decrypted_premaster_secret: bytes) -> bool:
    """Check if decrypted premaster secret has valid PKCS#1 v1.5 format.
    
    This is the padding oracle! It reveals whether the padding is valid.
    PKCS#1 v1.5 format: 0x00 0x02 [8+ non-zero random bytes] 0x00 [data]
    """
    if len(decrypted_premaster_secret) < 11:
        return False
    
    # Check for 0x00 0x02 header
    if decrypted_premaster_secret[0] != 0x00:
        return False
    if decrypted_premaster_secret[1] != 0x02:
        return False
    
    # Find the 0x00 separator after padding (must have at least 8 bytes of padding)
    try:
        separator_index = decrypted_premaster_secret.index(0x00, 2)
        if separator_index < 10:  # At least 8 bytes of random padding
            return False
        # Verify padding bytes are non-zero
        for i in range(2, separator_index):
            if decrypted_premaster_secret[i] == 0x00:
                return False
        return True
    except ValueError:
        # No separator found
        return False

class TLSServer:
    """
    A Flask server that mimics TLS handshake endpoints.

    Attributes:
        private_key: The server's private key object for asymmetric encryption
        public_key: The server's public key object for asymmetric encryption
        port: The port number to bind the server to
        app: Flask application instance
    """

    def __init__(self, private_key=None, public_key=None, port: int = 7265,
                 private_key_file: str = None, public_key_file: str = None,
                 debug: bool = False):
        """
        Initialize the TLS Server.

        Args:
            private_key: Server's private key object (optional)
            public_key: Server's public key object (optional)
            port: Port number to bind to (default: 7265)
            private_key_file: Path to armored private key file (optional)
            public_key_file: Path to armored public key file (optional)
            debug: Enable debug mode to save generated keys (default: False)
        """
        self.port = port
        self.debug = debug
        self.app = Flask(__name__)
        
        # Load or generate keys
        self.private_key, self.public_key = self._setup_keys(
            private_key, public_key, private_key_file, public_key_file
        )

        self.app.route('/certificate', methods=['GET'])(self.certificate)
        self.app.route('/client-key-exchange',
                       methods=['POST'])(self.client_key_exchange)
        self.app.route('/captured-message', methods=['GET'])(self.captured_message)
        self.app.route('/health', methods=['GET'])(self.health_check)

    def _setup_keys(self, private_key, public_key, private_key_file, public_key_file):
        """
        Setup RSA keys: load from files if provided, otherwise generate new keys.
        
        Args:
            private_key: Private key object (if already loaded)
            public_key: Public key object (if already loaded)
            private_key_file: Path to private key file
            public_key_file: Path to public key file
            
        Returns:
            Tuple of (private_key, public_key) objects
        """
        # If key objects are provided, use them
        if private_key and public_key:
            return private_key, public_key
        
        # Try to load from files if paths are provided
        if private_key_file and os.path.exists(private_key_file):
            print(f"[*] Loading private key from {private_key_file}")
            with open(private_key_file, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            public_key = private_key.public_key()
            return private_key, public_key
        
        if public_key_file and os.path.exists(public_key_file):
            print(f"[*] Loading public key from {public_key_file}")
            with open(public_key_file, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        
        # Generate new RSA key pair
        print("[*] Generating new RSA key pair (2048 bits)...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save keys to files in debug mode
        if self.debug:
            self._save_keys_to_files(private_key, public_key)
        
        return private_key, public_key
    
    def _save_keys_to_files(self, private_key, public_key):
        """
        Save generated keys to files in debug mode.
        
        Args:
            private_key: Private key object to save
            public_key: Public key object to save
        """
        private_key_path = 'server_private_key.pem'
        public_key_path = 'server_public_key.pem'
        
        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[DEBUG] Saved private key to {private_key_path}")
        
        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print(f"[DEBUG] Saved public key to {public_key_path}")

    def certificate(self):
        """
        Send server certificate to client.

        Returns:
            - certificate_chain: Server's certificate chain
            - public_key: Server's public key in PEM format
        """
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return jsonify({
            "status": "success",
            "public_key": public_key_pem
        }), 200

    def client_key_exchange(self):
        """
        Handle ClientKeyExchange message from client.

        Expected payload:
            - encrypted_premaster_secret: Pre-master secret encrypted with server's public key

        Returns:
            Acknowledgment of key exchange
        """
        # Try to get JSON data first, fall back to raw data
        try:
            json_data = request.get_json()
            if json_data and 'encrypted_premaster_secret' in json_data:
                # Hex-encoded data from JSON
                data = bytes.fromhex(json_data['encrypted_premaster_secret'])
            else:
                # Raw binary data
                data = request.get_data()
        except:
            # Fall back to raw data
            data = request.get_data()
        
        try:
            decrypted_premaster_secret = decrypt_secret(data, self.private_key)
            if not valid_format(decrypted_premaster_secret):
                return jsonify({
                    "status": "error",
                    "message": "Invalid premaster secret format"
                }), 400
            return jsonify({
                "status": "client_key_exchange_received",
                "message": "ClientKeyExchange acknowledged"
            }), 200
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Decryption failed: {str(e)}"
            }), 400
    
    def captured_message(self):
        """
        Endpoint to simulate captured TLS messages for the attack.
        
        Returns:
            A message encrypted by server's public key, to simulate when the attacker captured a secured
            communication in-flight.
        """
        message = "I am Iron Man"
        encrypted_message = self.public_key.encrypt(
            message.encode('utf-8'),
            padding.PKCS1v15()
        )
        return jsonify({
            "status": "success",
            "encrypted_message": encrypted_message.hex()
        }), 200

    def health_check(self):
        """
        Health check endpoint.

        Returns:
            Server status
        """
        return jsonify({
            "status": "healthy",
            "message": "TLS Server is running"
        }), 200

    def run(self, debug: bool = False):
        """
        Start the Flask server.

        Args:
            debug: Enable debug mode (default: False)
        """
        print(f"Starting TLS Server on port {self.port}...")
        self.app.run(host='0.0.0.0', port=self.port, debug=debug)


if __name__ == "__main__":
    # Example usage
    # Keys will be auto-generated if not provided
    
    # Parse command line arguments
    private_key_file = None
    public_key_file = None
    debug = '--debug' in sys.argv
    
    if '--private-key' in sys.argv:
        idx = sys.argv.index('--private-key')
        if idx + 1 < len(sys.argv):
            private_key_file = sys.argv[idx + 1]
    
    if '--public-key' in sys.argv:
        idx = sys.argv.index('--public-key')
        if idx + 1 < len(sys.argv):
            public_key_file = sys.argv[idx + 1]
    
    server = TLSServer(
        port=7265,
        private_key_file=private_key_file,
        public_key_file=public_key_file,
        debug=debug
    )
    server.run(debug=debug)
