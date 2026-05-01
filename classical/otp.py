"""
classical/otp.py
----------------
One-Time Pad (OTP / Masque Jetable)

Theoretically unbreakable when used correctly:
  - Key must be truly random
  - Key must be at least as long as the plaintext
  - Key must never be reused
  - Key must be kept secret

C = P XOR K
P = C XOR K
"""

import os
import secrets
from utils.converter import xor_bytes


def generate_key(length: int) -> bytes:
    """Generate a cryptographically secure random key of `length` bytes."""
    return secrets.token_bytes(length)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext bytes with OTP key.
    Both must be the same length.
    """
    if len(key) < len(plaintext):
        raise ValueError(f"Key ({len(key)} bytes) must be >= plaintext ({len(plaintext)} bytes)")
    return xor_bytes(plaintext, key[:len(plaintext)])


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext bytes with OTP key.
    XOR is its own inverse: same operation as encrypt.
    """
    return encrypt(ciphertext, key)  # XOR is symmetric


def encrypt_text(plaintext: str, key: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt a text string. Generates key automatically if not provided.
    Returns (ciphertext_bytes, key_bytes).
    """
    data = plaintext.encode('utf-8')
    if key is None:
        key = generate_key(len(data))
    ct = encrypt(data, key)
    return ct, key


def decrypt_text(ciphertext: bytes, key: bytes) -> str:
    """Decrypt bytes back to text."""
    return decrypt(ciphertext, key).decode('utf-8')


if __name__ == "__main__":
    msg = "TOP SECRET MESSAGE"
    ct, key = encrypt_text(msg)
    dec = decrypt_text(ct, key)

    print(f"Plaintext  : {msg}")
    print(f"Key (hex)  : {key.hex()}")
    print(f"Cipher(hex): {ct.hex()}")
    print(f"Decrypted  : {dec}")
    print(f"\n⚠ Key used exactly once. NEVER reuse OTP keys.")
