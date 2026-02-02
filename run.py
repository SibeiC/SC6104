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

    def __init__(self, host: str = "localhost", port: int = 7265,
                 private_key_file: str = None, public_key_file: str = None,
                 debug: bool = False, secret_message: str = "Secret Message",
                 key_size: int = 1024):
        """
        Initialize the demo.

        Args:
            host: Server host address
            port: Server port number
            private_key_file: Path to private key file (optional)
            public_key_file: Path to public key file (optional)
            debug: Enable debug mode (saves keys to files)
            secret_message: Message to encrypt for attack demo
            key_size: RSA key size in bits (default: 1024)
        """
        self.host = host
        self.port = port
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file
        self.debug = debug
        self.secret_message = secret_message
        self.key_size = key_size
        self.server: Optional[TLSServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.client: Optional[BleichenbacherClient] = None

    def start_server(self):
        """Start the TLS server in a separate thread."""
        print(f"{Colors.CYAN}[*] Initializing TLS Server...{Colors.END}")

        # Create server instance with key file support
        # Keys will be auto-generated if files are not provided
        self.server = TLSServer(
            port=self.port,
            private_key_file=self.private_key_file,
            public_key_file=self.public_key_file,
            debug=self.debug,
            secret_message=self.secret_message,
            key_size=self.key_size
        )

        # Disable Flask's default logging for cleaner output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        # Start server in daemon thread
        self.server_thread = threading.Thread(
            target=self.server.run,
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

        # Simulate attack execution
        try:
            # Step 1: Perform handshake to get server's public key
            print(
                f"\n{Colors.CYAN}[*] Performing TLS handshake...{Colors.END}")
            print(
                f"{Colors.CYAN}[*] A minimal TLS handshake is simulated for client to retrieve server's public key{Colors.END}")
            if not self.client.perform_handshake():
                print(f"{Colors.RED}[-] Handshake failed!{Colors.END}")
                return
            print(f"{Colors.GREEN}[+] Handshake successful{Colors.END}")

            # Step 2: Capture an encrypted message from the server
            print(
                f"\n{Colors.CYAN}[*] Simulating intercepting an encrypted message...{Colors.END}")
            target_ciphertext = self.client.simulate_captured_message()
            print(
                f"{Colors.GREEN}[+] Captured {len(target_ciphertext)} bytes{Colors.END}")
            print(
                f"{Colors.CYAN}[*] Target ciphertext (hex): {target_ciphertext.hex()}{Colors.END}")
            print(f"{Colors.CYAN}[*] Beginning oracle queries...{Colors.END}")

            # Execute attack
            plaintext = self.client.execute_bleichenbacher_attack(
                target_ciphertext)

            if plaintext:
                print(f"\n{Colors.GREEN}[+] Attack successful!{Colors.END}")
                print(
                    f"{Colors.GREEN}[+] Recovered plaintext: {plaintext}{Colors.END}")
            else:
                print(
                    f"\n{Colors.YELLOW}[!] Attack simulation failed{Colors.END}")

        except Exception as e:
            print(f"\n{Colors.RED}[-] Attack error: {e}{Colors.END}")

    def run_demo(self):
        """Execute the complete demo."""
        print(f"\n{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
        print(
            f"{Colors.BOLD}{Colors.BLUE}Bleichenbacher Attack Demonstration{Colors.END}")
        print(f"{Colors.BOLD}{Colors.BLUE}" + "="*60 + f"{Colors.END}")
        print("\n")
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

    # Get message from user for encryption
    print(f"{Colors.BOLD}{Colors.BLUE}Bleichenbacher Attack Demo{Colors.END}")
    print(f"{Colors.CYAN}Enter a message to encrypt (or press Enter for default):  {Colors.END}", end="")
    user_message = input().strip()
    if not user_message:
        user_message = "I am Iron Man"
        print(f"{Colors.YELLOW}Using default message: '{user_message}'{Colors.END}")
    else:
        print(f"{Colors.GREEN}Using your message: '{user_message}'{Colors.END}")
    print()

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Bleichenbacher Attack Demo',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with auto-generated keys (default 1024-bit)
  python run.py
  
  # Run with 512-bit keys for faster in-class demo
  python run.py --key-size 512
  
  # Run with custom keys from files
  python run.py --private-key server_private_key.pem --public-key server_public_key.pem
  
  # Run in debug mode (saves generated keys to files)
  python run.py --debug
        """
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='Server host address (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=7265,
        help='Server port number (default: 7265)'
    )
    parser.add_argument(
        '--private-key',
        dest='private_key_file',
        help='Path to armored private key file (PEM format)'
    )
    parser.add_argument(
        '--public-key',
        dest='public_key_file',
        help='Path to armored public key file (PEM format)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode (saves generated keys and log to files)'
    )
    parser.add_argument(
        '--key-size',
        type=int,
        default=1024,
        help='RSA key size in bits (default: 1024, use 512 for faster in-class demo)'
    )
    args = parser.parse_args()

    # Run demo
    demo = AttackDemo(
        host=args.host,
        port=args.port,
        private_key_file=args.private_key_file,
        public_key_file=args.public_key_file,
        debug=args.debug,
        secret_message=user_message,
        key_size=args.key_size
    )
    demo.run_demo()


if __name__ == "__main__":
    main()
