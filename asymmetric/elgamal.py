"""
asymmetric/elgamal.py
---------------------
ElGamal Public-Key Encryption
Based on the Diffie-Hellman problem over a cyclic group.

Key Generation:
  - Public params: large prime p, generator g
  - Private key: x (random integer)
  - Public key:  h = g^x mod p

Encryption of message m:
  - Choose random k
  - C1 = g^k mod p
  - C2 = m * h^k mod p
  - Ciphertext: (C1, C2)

Decryption:
  - s = C1^x mod p  (shared secret)
  - m = C2 * s^(-1) mod p
"""

import os
from utils.math_utils import mod_inverse
from utils.primes import generate_safe_prime, find_primitive_root
from utils.converter import bytes_to_int, int_to_bytes


class ElGamal:
    """
    ElGamal cryptosystem over a prime-order group.
    
    Works on integers. For text, the message is split into chunks
    smaller than p.
    """

    def __init__(self, bits: int = 256):
        """Generate a new ElGamal keypair."""
        print(f"Generating {bits}-bit ElGamal parameters (may take a moment)...")
        self.p = generate_safe_prime(bits)
        self.g = find_primitive_root(self.p)

        # Private key: random x in [2, p-2]
        self.x = int.from_bytes(os.urandom(bits // 8), 'big') % (self.p - 2) + 2
        # Public key: h = g^x mod p
        self.h = pow(self.g, self.x, self.p)

        print(f"p  = {hex(self.p)[:18]}...")
        print(f"g  = {self.g}")
        print(f"h  = {hex(self.h)[:18]}...  (public)")

    @property
    def public_key(self) -> tuple[int, int, int]:
        """Returns (p, g, h)."""
        return self.p, self.g, self.h

    @property
    def private_key(self) -> tuple[int, int, int, int]:
        """Returns (p, g, h, x)."""
        return self.p, self.g, self.h, self.x

    def encrypt_int(self, m: int) -> tuple[int, int]:
        """
        Encrypt an integer m < p.
        Returns (C1, C2).
        """
        if m >= self.p:
            raise ValueError(f"Message {m} must be < p")
        k = int.from_bytes(os.urandom(len(hex(self.p)) // 2), 'big') % (self.p - 2) + 2
        C1 = pow(self.g, k, self.p)
        C2 = (m * pow(self.h, k, self.p)) % self.p
        return C1, C2

    def decrypt_int(self, C1: int, C2: int) -> int:
        """Decrypt ciphertext (C1, C2) back to integer m."""
        s = pow(C1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        return (C2 * s_inv) % self.p

    def encrypt_bytes(self, data: bytes) -> list[tuple[int, int]]:
        """Encrypt arbitrary bytes by splitting into chunks."""
        chunk_size = (self.p.bit_length() - 1) // 8  # Max bytes per chunk < p
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        return [self.encrypt_int(bytes_to_int(chunk)) for chunk in chunks]

    def decrypt_bytes(self, ciphertext_list: list[tuple[int, int]], original_len: int) -> bytes:
        """Decrypt list of (C1, C2) pairs back to bytes."""
        parts = []
        chunk_size = (self.p.bit_length() - 1) // 8
        for i, (C1, C2) in enumerate(ciphertext_list):
            m = self.decrypt_int(C1, C2)
            # Last chunk may be shorter
            if i == len(ciphertext_list) - 1:
                last_size = original_len % chunk_size or chunk_size
                parts.append(int_to_bytes(m, last_size))
            else:
                parts.append(int_to_bytes(m, chunk_size))
        return b''.join(parts)

    def encrypt_text(self, plaintext: str) -> tuple[list[tuple[int, int]], int]:
        data = plaintext.encode('utf-8')
        return self.encrypt_bytes(data), len(data)

    def decrypt_text(self, ciphertext_list: list, original_len: int) -> str:
        return self.decrypt_bytes(ciphertext_list, original_len).decode('utf-8')


if __name__ == "__main__":
    eg = ElGamal(bits=256)
    msg = "Hello ElGamal!"
    ct, length = eg.encrypt_text(msg)
    dec = eg.decrypt_text(ct, length)
    print(f"\nPlaintext  : {msg}")
    print(f"Ciphertext : {[(hex(c1)[:10], hex(c2)[:10]) for c1, c2 in ct]}")
    print(f"Decrypted  : {dec}")
