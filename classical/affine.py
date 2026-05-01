"""
classical/affine.py
-------------------
Affine Cipher: E(x) = (a*x + b) mod 26
Key: (a, b) where gcd(a, 26) = 1
"""

from utils.math_utils import gcd, mod_inverse

ALPHABET_SIZE = 26


def _validate_key(a: int) -> None:
    if gcd(a, ALPHABET_SIZE) != 1:
        raise ValueError(f"Key 'a={a}' is invalid: gcd({a}, 26) must be 1. "
                         f"Valid values: 1,3,5,7,9,11,15,17,19,21,23,25")


def encrypt(plaintext: str, a: int, b: int) -> str:
    """
    Encrypt plaintext using affine cipher.
    E(x) = (a*x + b) mod 26
    """
    _validate_key(a)
    result = []
    for ch in plaintext.upper():
        if ch.isalpha():
            x = ord(ch) - ord('A')
            result.append(chr((a * x + b) % ALPHABET_SIZE + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext: str, a: int, b: int) -> str:
    """
    Decrypt ciphertext using affine cipher.
    D(y) = a_inv * (y - b) mod 26
    """
    _validate_key(a)
    a_inv = mod_inverse(a, ALPHABET_SIZE)
    result = []
    for ch in ciphertext.upper():
        if ch.isalpha():
            y = ord(ch) - ord('A')
            result.append(chr((a_inv * (y - b)) % ALPHABET_SIZE + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


if __name__ == "__main__":
    a, b = 7, 3
    msg = "Hello World"
    enc = encrypt(msg, a, b)
    dec = decrypt(enc, a, b)
    print(f"Plaintext : {msg}")
    print(f"Encrypted : {enc}")
    print(f"Decrypted : {dec}")
