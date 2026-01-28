#!/usr/bin/env python3
"""
Bleichenbacher Attack Demo
Demonstrates TLS server with Bleichenbacher padding oracle attack.
"""

import threading
import time
import sys
import signal
from typing import Optional

from server.server import TLSServer
from client.attack import BleichenbacherClient


class AttackDemo:
    """
    Demo orchestrator for Bleichenbacher attack simulation.
    """

    def __init__(self, host: str = "localhost", port: int = 5000):
        """
        Initialize the demo.

        Args:
            host: Server host address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.server: Optional[TLSServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.client: Optional[BleichenbacherClient] = None
        self.running = False

    def start_server(self):
        """Start the TLS server in a separate thread."""
        print("[*] Initializing TLS Server...")

        # In a real implementation, these would be actual RSA keys
        # For demo purposes, using placeholder strings
        private_key = "-----BEGIN RSA PRIVATE KEY-----\nPLACEHOLDER\n-----END RSA PRIVATE KEY-----"
        public_key = "-----BEGIN PUBLIC KEY-----\nPLACEHOLDER\n-----END PUBLIC KEY-----"

        # Create server instance
        self.server = TLSServer(
            private_key=private_key,
            public_key=public_key,
            port=self.port
        )

        # Disable Flask's default logging for cleaner output
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        # Start server in daemon thread
        self.server_thread = threading.Thread(
            target=self.server.run,
            kwargs={'debug': False},
            daemon=True
        )
        self.server_thread.start()
        self.running = True

        # Wait for server to be ready
        print(f"[*] Starting server on {self.host}:{self.port}...")
        time.sleep(2)  # Give server time to start

        print("[+] Server is running")

    def start_client(self):
        """Initialize and start the attack client."""
        print("\n[*] Initializing Bleichenbacher Attack Client...")

        self.client = BleichenbacherClient(
            server_host=self.host,
            server_port=self.port
        )

        # Health check
        print("[*] Performing health check...")
        if not self.client.health_check():
            print("[-] Server health check failed!")
            return False

        print("[+] Server is reachable")
        return True

    def run_handshake(self):
        """Execute TLS handshake with the server."""
        print("\n" + "="*60)
        print("PHASE 1: TLS Handshake")
        print("="*60)

        print("\n[*] Initiating TLS handshake...")
        print("[*] Selecting vulnerable cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA")
        print("[*] This cipher suite uses RSA with PKCS#1 v1.5 padding")

        try:
            success = self.client.perform_handshake()
            if success:
                print("\n[+] TLS Handshake completed successfully!")
                print("[+] Server public key obtained")
                print("[+] Encrypted premaster secret sent")
                return True
            else:
                print("\n[-] TLS Handshake failed!")
                return False
        except Exception as e:
            print(f"\n[-] Handshake error: {e}")
            return False

    def run_attack(self):
        """Execute the Bleichenbacher attack."""
        print("\n" + "="*60)
        print("PHASE 2: Bleichenbacher Padding Oracle Attack")
        print("="*60)

        print("\n[*] Starting Bleichenbacher Attack...")
        print("[*] Attack Overview:")
        print("    1. Capture encrypted premaster secret")
        print("    2. Generate modified ciphertexts")
        print("    3. Use server as padding oracle")
        print("    4. Iteratively narrow solution space")
        print("    5. Recover plaintext")

        # Simulate attack execution
        try:
            # In a real implementation, we would:
            # 1. Capture the encrypted premaster secret
            # 2. Run the attack algorithm
            target_ciphertext = b"CAPTURED_ENCRYPTED_PREMASTER_SECRET"

            print(f"\n[*] Target ciphertext: {target_ciphertext[:20]}...")
            print("[*] Beginning oracle queries...")

            # Execute attack
            plaintext = self.client.execute_bleichenbacher_attack(
                target_ciphertext)

            if plaintext:
                print(f"\n[+] Attack successful!")
                print(f"[+] Recovered plaintext: {plaintext}")
                return True
            else:
                print(
                    "\n[!] Attack simulation complete (methods not fully implemented)")
                print(
                    "[!] In a real attack scenario, this would decrypt the premaster secret")
                return True

        except Exception as e:
            print(f"\n[-] Attack error: {e}")
            return False

    def demonstrate_oracle_queries(self):
        """Demonstrate how the padding oracle works."""
        print("\n" + "="*60)
        print("DEMONSTRATION: Padding Oracle Queries")
        print("="*60)

        print("\n[*] The Bleichenbacher attack works by:")
        print("    - Sending modified ciphertexts to the server")
        print("    - Observing server responses to determine padding validity")
        print("    - Using this information to narrow down the plaintext")

        print("\n[*] Simulating oracle queries...")

        # Demonstrate a few oracle queries
        test_ciphertexts = [
            b"TEST_MODIFIED_CIPHERTEXT_1",
            b"TEST_MODIFIED_CIPHERTEXT_2",
            b"TEST_MODIFIED_CIPHERTEXT_3"
        ]

        for i, ct in enumerate(test_ciphertexts, 1):
            print(f"\n[*] Query {i}: Testing ciphertext {ct[:15]}...")
            try:
                result = self.client.padding_oracle_query(ct)
                print(
                    f"    Response: {'Valid padding' if result else 'Invalid padding'}")
            except Exception as e:
                print(f"    Error: {e}")

        print("\n[*] Oracle query demonstration complete")

    def run_demo(self):
        """Execute the complete demo."""
        print("\n" + "="*60)
        print("Bleichenbacher Attack Demonstration")
        print("="*60)
        print("\nThis demo simulates a Bleichenbacher padding oracle attack")
        print("against a TLS server using RSA with PKCS#1 v1.5 padding.")
        print("\nPress Ctrl+C to stop at any time.")
        print("="*60 + "\n")

        try:
            # Start server
            self.start_server()

            # Initialize client
            if not self.start_client():
                print("\n[-] Failed to initialize client")
                return

            # Perform handshake
            if not self.run_handshake():
                print("\n[-] Failed to complete handshake")
                return

            # Demonstrate oracle queries
            self.demonstrate_oracle_queries()

            # Run attack
            self.run_attack()

            # Summary
            print("\n" + "="*60)
            print("DEMO SUMMARY")
            print("="*60)
            print("\n[+] Demo completed successfully!")
            print("\nKey Takeaways:")
            print("  - TLS with RSA PKCS#1 v1.5 is vulnerable to Bleichenbacher attack")
            print("  - Server responses leak information about padding validity")
            print("  - This allows an attacker to decrypt ciphertexts")
            print("  - Mitigation: Use TLS 1.3 or RSA-OAEP padding")
            print("\n" + "="*60 + "\n")

        except KeyboardInterrupt:
            print("\n\n[!] Demo interrupted by user")
        except Exception as e:
            print(f"\n[-] Demo error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.cleanup()

    def cleanup(self):
        """Clean up resources and stop the server."""
        print("\n[*] Cleaning up...")

        if self.client and self.client.session:
            self.client.session.close()
            print("[+] Client session closed")

        if self.server_thread and self.server_thread.is_alive():
            print("[*] Stopping server...")
            # Note: Flask's development server doesn't have a clean shutdown method
            # In production, you would use a production WSGI server with proper shutdown
            self.running = False
            print("[+] Server thread will terminate")

        print("[+] Cleanup complete")


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print("\n\n[!] Received interrupt signal")
    sys.exit(0)


def main():
    """Main entry point."""
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Parse command line arguments (optional)
    import argparse
    parser = argparse.ArgumentParser(
        description='Bleichenbacher Attack Demo'
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='Server host address (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='Server port number (default: 5000)'
    )

    args = parser.parse_args()

    # Run demo
    demo = AttackDemo(host=args.host, port=args.port)
    demo.run_demo()


if __name__ == "__main__":
    main()
