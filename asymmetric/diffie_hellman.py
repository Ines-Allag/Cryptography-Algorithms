"""
asymmetric/diffie_hellman.py
-----------------------------
Diffie-Hellman Key Exchange — allows two parties to establish a shared
secret over an insecure channel without transmitting the secret itself.

Protocol:
  Public params: large prime p, generator g (primitive root mod p)
  Alice: private a → public A = g^a mod p
  Bob:   private b → public B = g^b mod p
  Shared secret: s = B^a mod p = A^b mod p = g^(ab) mod p

Uses 256-bit safe primes for correctness; 2048-bit recommended for real use.
"""

import os
import hashlib
from utils.primes import generate_safe_prime, find_primitive_root


# Standard 2048-bit DH parameters (RFC 3526 Group 14) — faster than generating
MODP_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
MODP_2048_G = 2


class DHParty:
    """
    Represents one party in a Diffie-Hellman key exchange.
    
    Usage:
        alice = DHParty()
        bob   = DHParty(p=alice.p, g=alice.g)  # Share same params
        
        # Exchange public keys
        shared_alice = alice.compute_shared_secret(bob.public_key)
        shared_bob   = bob.compute_shared_secret(alice.public_key)
        assert shared_alice == shared_bob
    """

    def __init__(self, p: int = None, g: int = None, key_bits: int = 256):
        self.p = p or MODP_2048_P
        self.g = g or MODP_2048_G

        # Generate private key: random integer in [2, p-2]
        self._private_key = int.from_bytes(os.urandom(key_bits // 8), 'big') % (self.p - 2) + 2
        # Compute public key: A = g^a mod p
        self.public_key = pow(self.g, self._private_key, self.p)

    def compute_shared_secret(self, other_public_key: int) -> int:
        """Compute shared secret: s = other_pub^private mod p."""
        return pow(other_public_key, self._private_key, self.p)

    def derive_aes_key(self, other_public_key: int, key_bits: int = 256) -> bytes:
        """
        Derive a symmetric AES key from the shared secret using SHA-256/512.
        This is the standard way to use DH output.
        """
        secret = self.compute_shared_secret(other_public_key)
        secret_bytes = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
        if key_bits == 128:
            return hashlib.sha256(secret_bytes).digest()[:16]
        elif key_bits == 256:
            return hashlib.sha256(secret_bytes).digest()
        elif key_bits == 512:
            return hashlib.sha512(secret_bytes).digest()
        raise ValueError(f"Unsupported key_bits: {key_bits}")


def generate_dh_params(bits: int = 256) -> tuple[int, int]:
    """Generate fresh safe prime p and generator g. Slow for large bits."""
    p = generate_safe_prime(bits)
    g = find_primitive_root(p)
    return p, g


if __name__ == "__main__":
    print("=== Diffie-Hellman Key Exchange (2048-bit MODP Group) ===\n")

    alice = DHParty()
    bob = DHParty(p=alice.p, g=alice.g)

    print(f"Alice public key (first 64 hex): {hex(alice.public_key)[:66]}...")
    print(f"Bob   public key (first 64 hex): {hex(bob.public_key)[:66]}...")

    # Exchange public keys and derive AES keys
    aes_key_alice = alice.derive_aes_key(bob.public_key)
    aes_key_bob   = bob.derive_aes_key(alice.public_key)

    print(f"\nAlice AES key: {aes_key_alice.hex()}")
    print(f"Bob   AES key: {aes_key_bob.hex()}")
    print(f"Keys match   : {aes_key_alice == aes_key_bob}")
