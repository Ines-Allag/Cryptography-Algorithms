"""
modern/rc4.py
-------------
RC4 Stream Cipher (Rivest Cipher 4)
A variable key-size stream cipher. Note: RC4 is considered weak for modern
use due to biases in the keystream — included here for educational purposes.
"""


def _ksa(key: bytes) -> list[int]:
    """Key Scheduling Algorithm (KSA)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def _prga(S: list[int], length: int):
    """Pseudo-Random Generation Algorithm (PRGA). Yields keystream bytes."""
    i = j = 0
    S = S[:]  # Don't mutate original
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) % 256]


def keystream(key: bytes, length: int) -> bytes:
    """Generate `length` bytes of RC4 keystream from `key`."""
    S = _ksa(key)
    return bytes(_prga(S, length))


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext bytes with RC4.
    C = P XOR KS  where KS = keystream
    """
    ks = keystream(key, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext bytes with RC4.
    XOR is symmetric: same as encrypt.
    """
    return encrypt(ciphertext, key)


def encrypt_text(plaintext: str, key: str) -> bytes:
    return encrypt(plaintext.encode('utf-8'), key.encode('utf-8'))


def decrypt_text(ciphertext: bytes, key: str) -> str:
    return decrypt(ciphertext, key.encode('utf-8')).decode('utf-8')


if __name__ == "__main__":
    key = "SecretKey"
    msg = "Hello, RC4!"
    ct = encrypt_text(msg, key)
    dec = decrypt_text(ct, key)
    print(f"Key       : {key}")
    print(f"Plaintext : {msg}")
    print(f"Encrypted : {ct.hex()}")
    print(f"Decrypted : {dec}")
    print("\n⚠ RC4 is deprecated for security use. Use AES instead.")
