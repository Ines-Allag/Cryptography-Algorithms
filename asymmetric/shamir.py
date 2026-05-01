"""
asymmetric/shamir.py
---------------------
Shamir's Secret Sharing (SSS)

Split a secret into n shares such that any k of them can reconstruct
the original secret (k-of-n threshold scheme).

Algorithm:
  1. Choose a random polynomial f(x) of degree k-1
     where f(0) = secret
  2. Generate n shares: (i, f(i)) for i = 1..n
  3. Reconstruct with Lagrange interpolation over GF(p)

Uses a large prime p > secret for the finite field.
"""

import secrets
from utils.math_utils import mod_inverse
from utils.primes import generate_prime

# Default field prime (larger than any secret we'll share)
DEFAULT_PRIME = generate_prime(256)


def _evaluate_polynomial(coefficients: list[int], x: int, prime: int) -> int:
    """Evaluate polynomial at x using Horner's method."""
    result = 0
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % prime
    return result


def split_secret(secret: int, n: int, k: int, prime: int = None) -> list[tuple[int, int]]:
    """
    Split `secret` into `n` shares with threshold `k`.
    
    Args:
        secret: The integer secret to split (must be < prime)
        n: Total number of shares to generate
        k: Minimum shares needed to reconstruct (threshold)
        prime: Field prime (auto-generated if None)
    
    Returns:
        List of (x, y) share tuples
    """
    if prime is None:
        prime = DEFAULT_PRIME
    if secret >= prime:
        raise ValueError("Secret must be less than the prime")
    if k > n:
        raise ValueError("Threshold k must be <= n")

    # Random polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    coefficients = [secret] + [secrets.randbelow(prime) for _ in range(k - 1)]

    shares = [(i, _evaluate_polynomial(coefficients, i, prime)) for i in range(1, n + 1)]
    return shares


def reconstruct_secret(shares: list[tuple[int, int]], prime: int = None) -> int:
    """
    Reconstruct the secret from at least k shares using Lagrange interpolation.
    
    Args:
        shares: List of (x, y) share tuples (at least k of them)
        prime: The same field prime used during splitting
    
    Returns:
        The original secret integer
    """
    if prime is None:
        prime = DEFAULT_PRIME

    secret = 0
    for i, (xi, yi) in enumerate(shares):
        # Compute Lagrange basis polynomial L_i(0)
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (-xj)) % prime
                denominator = (denominator * (xi - xj)) % prime
        lagrange = (yi * numerator * mod_inverse(denominator, prime)) % prime
        secret = (secret + lagrange) % prime

    return secret


# ── Byte/String helpers ───────────────────────────────────────────────────────

def split_secret_bytes(secret_bytes: bytes, n: int, k: int) -> tuple[list, int]:
    """Split a byte string as a secret. Returns (shares, prime)."""
    prime = generate_prime(len(secret_bytes) * 8 + 8)
    secret_int = int.from_bytes(secret_bytes, 'big')
    shares = split_secret(secret_int, n, k, prime)
    return shares, prime


def reconstruct_secret_bytes(shares: list, prime: int, byte_len: int) -> bytes:
    """Reconstruct bytes from shares."""
    secret_int = reconstruct_secret(shares, prime)
    return secret_int.to_bytes(byte_len, 'big')


def split_text(secret_text: str, n: int, k: int) -> tuple[list, int, int]:
    """Split a text string. Returns (shares, prime, original_byte_length)."""
    data = secret_text.encode('utf-8')
    shares, prime = split_secret_bytes(data, n, k)
    return shares, prime, len(data)


def reconstruct_text(shares: list, prime: int, byte_len: int) -> str:
    return reconstruct_secret_bytes(shares, prime, byte_len).decode('utf-8')


if __name__ == "__main__":
    print("=== Shamir's Secret Sharing ===")
    secret_text = "My private key is: 0xDEADBEEF"
    n, k = 5, 3  # 5 shares, any 3 can reconstruct

    shares, prime, byte_len = split_text(secret_text, n=n, k=k)
    print(f"Secret    : {secret_text}")
    print(f"Shares ({n}, threshold {k}):")
    for i, share in enumerate(shares):
        print(f"  Share {i+1}: ({share[0]}, {hex(share[1])[:20]}...)")

    # Use only 3 of the 5 shares
    subset = [shares[0], shares[2], shares[4]]
    recovered = reconstruct_text(subset, prime, byte_len)
    print(f"\nRecovered : {recovered}")
    print(f"Match     : {recovered == secret_text}")
