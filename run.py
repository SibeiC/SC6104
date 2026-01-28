#!/usr/bin/env python3
"""
Bleichenbacher Attack Demo
Demonstrates TLS server with Bleichenbacher padding oracle attack.
"""

import threading
import time
import sys
import signal
import logging
import argparse
import traceback
from typing import Optional

from server.server import TLSServer
from client.attack import BleichenbacherClient


class Colors:
    """
    ANSI color codes for terminal output.
    """
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


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

    def start_server(self):
        """Start the TLS server in a separate thread."""
        print(f"{Colors.CYAN}[*] Initializing TLS Server...{Colors.END}")

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
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        # Start server in daemon thread
        self.server_thread = threading.Thread(
            target=self.server.run,
            kwargs={'debug': False},
            daemon=True
        )
        self.server_thread.start()

        # Wait for server to be ready
        print(
            f"{Colors.CYAN}[*] Starting server on {self.host}:{self.port}...{Colors.END}")
        time.sleep(2)  # Give server time to start

        print(f"{Colors.GREEN}[+] Server is running{Colors.END}")

    def start_client(self):
        """Initialize and start the attack client."""
        print(
            f"\n{Colors.CYAN}[*] Initializing Bleichenbacher Attack Client...{Colors.END}")

        self.client = BleichenbacherClient(
            server_host=self.host,
            server_port=self.port
        )

        # Health check
        print(f"{Colors.CYAN}[*] Performing health check...{Colors.END}")
        if not self.client.health_check():
            print(f"{Colors.RED}[-] Server health check failed!{Colors.END}")
            return False

        print(f"{Colors.GREEN}[+] Server is reachable{Colors.END}")
        return True

    def run_attack(self):
        """Execute the Bleichenbacher attack."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
        print(
            f"{Colors.BOLD}{Colors.BLUE}Bleichenbacher Padding Oracle Attack{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")

        print(
            f"\n{Colors.CYAN}[*] Starting Bleichenbacher Attack...{Colors.END}")
        print(f"{Colors.CYAN}[*] Attack Overview:{Colors.END}")
        print(f"{Colors.CYAN}    1. Capture encrypted premaster secret{Colors.END}")
        print(f"{Colors.CYAN}    2. Generate modified ciphertexts{Colors.END}")
        print(f"{Colors.CYAN}    3. Use server as padding oracle{Colors.END}")
        print(f"{Colors.CYAN}    4. Iteratively narrow solution space{Colors.END}")
        print(f"{Colors.CYAN}    5. Recover plaintext{Colors.END}")

        # Simulate attack execution
        try:
            # In a real implementation, we would:
            # 1. Capture the encrypted premaster secret
            # 2. Run the attack algorithm
            target_ciphertext = b"CAPTURED_ENCRYPTED_PREMASTER_SECRET"

            print(
                f"\n{Colors.CYAN}[*] Target ciphertext: {target_ciphertext[:20]}...{Colors.END}")
            print(f"{Colors.CYAN}[*] Beginning oracle queries...{Colors.END}")

            # Execute attack
            plaintext = self.client.execute_bleichenbacher_attack(
                target_ciphertext)

            if plaintext:
                print(f"\n{Colors.GREEN}[+] Attack successful!{Colors.END}")
                print(
                    f"{Colors.GREEN}[+] Recovered plaintext: {plaintext}{Colors.END}")
                return True
            else:
                print(
                    f"\n{Colors.YELLOW}[!] Attack simulation complete (methods not fully implemented){Colors.END}")
                print(
                    f"{Colors.YELLOW}[!] In a real attack scenario, this would decrypt the premaster secret{Colors.END}")
                return True

        except Exception as e:
            print(f"\n{Colors.RED}[-] Attack error: {e}{Colors.END}")
            return False

    def run_demo(self):
        """Execute the complete demo."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
        print(
            f"{Colors.BOLD}{Colors.BLUE}Bleichenbacher Attack Demonstration{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
        print(
            f"\n{Colors.CYAN}This demo simulates a Bleichenbacher padding oracle attack{Colors.END}")
        print(
            f"{Colors.CYAN}against a TLS server using RSA with PKCS#1 v1.5 padding.{Colors.END}")
        print(f"\n{Colors.YELLOW}Press Ctrl+C to stop at any time.{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}\n")

        try:
            # Start server
            self.start_server()

            # Initialize client
            if not self.start_client():
                print(
                    f"\n{Colors.RED}[-] Failed to initialize client{Colors.END}")
                return

            # Run attack
            self.run_attack()

            # Summary
            print(f"\n{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
            print(f"{Colors.BOLD}{Colors.BLUE}DEMO SUMMARY{Colors.END}")
            print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
            print(
                f"\n{Colors.GREEN}[+] Demo completed successfully!{Colors.END}")
            print(f"\n{Colors.BOLD}Key Takeaways:{Colors.END}")
            print(
                f"{Colors.CYAN}  - TLS with RSA PKCS#1 v1.5 is vulnerable to Bleichenbacher attack{Colors.END}")
            print(
                f"{Colors.CYAN}  - Server responses leak information about padding validity{Colors.END}")
            print(
                f"{Colors.CYAN}  - This allows an attacker to decrypt ciphertexts{Colors.END}")
            print(
                f"{Colors.CYAN}  - Mitigation: Use TLS 1.3 or RSA-OAEP padding{Colors.END}")
            print(f"\n{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}\n")

        except KeyboardInterrupt:
            print(
                f"\n\n{Colors.YELLOW}[!] Demo interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[-] Demo error: {e}{Colors.END}")
            traceback.print_exc()


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print(f"\n\n{Colors.YELLOW}[!] Received interrupt signal{Colors.END}")
    sys.exit(0)


def main():
    """Main entry point."""
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Parse command line arguments (optional)
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
