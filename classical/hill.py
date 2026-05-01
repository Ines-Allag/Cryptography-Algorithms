"""
classical/hill.py
-----------------
Hill Cipher — polygraphic substitution using linear algebra mod 26.
Key: an n×n invertible matrix mod 26.
"""

import numpy as np
from utils.math_utils import mod_inverse

ALPHABET_SIZE = 26


def _matrix_mod_inverse(matrix: np.ndarray, mod: int) -> np.ndarray:
    """Compute the modular inverse of a matrix using the adjugate method."""
    det = int(round(np.linalg.det(matrix))) % mod
    det_inv = mod_inverse(det, mod)

    # Adjugate (adjoint) = cofactor matrix transposed
    n = matrix.shape[0]
    adjugate = np.zeros((n, n), dtype=int)

    for i in range(n):
        for j in range(n):
            # Minor matrix
            minor = np.delete(np.delete(matrix, i, axis=0), j, axis=1)
            cofactor = int(round(np.linalg.det(minor))) * ((-1) ** (i + j))
            adjugate[j][i] = cofactor  # Transpose here

    return (det_inv * adjugate) % mod


def _text_to_vectors(text: str, n: int) -> list[np.ndarray]:
    """Convert text to list of column vectors of size n (padded with 'X' if needed)."""
    text = ''.join(c for c in text.upper() if c.isalpha())
    # Pad to multiple of n
    while len(text) % n != 0:
        text += 'X'
    vectors = []
    for i in range(0, len(text), n):
        chunk = text[i:i + n]
        vec = np.array([ord(c) - ord('A') for c in chunk], dtype=int)
        vectors.append(vec)
    return vectors


def encrypt(plaintext: str, key_matrix: list[list[int]]) -> str:
    """
    Encrypt plaintext using Hill cipher.
    C = K * P mod 26  (column vector multiplication)
    """
    K = np.array(key_matrix, dtype=int)
    n = K.shape[0]
    vectors = _text_to_vectors(plaintext, n)
    ciphertext = []

    for vec in vectors:
        enc_vec = (K @ vec) % ALPHABET_SIZE
        ciphertext.extend(chr(v + ord('A')) for v in enc_vec)

    return ''.join(ciphertext)


def decrypt(ciphertext: str, key_matrix: list[list[int]]) -> str:
    """
    Decrypt ciphertext using Hill cipher.
    P = K_inv * C mod 26
    """
    K = np.array(key_matrix, dtype=int)
    K_inv = _matrix_mod_inverse(K, ALPHABET_SIZE)
    n = K.shape[0]
    vectors = _text_to_vectors(ciphertext, n)
    plaintext = []

    for vec in vectors:
        dec_vec = (K_inv @ vec) % ALPHABET_SIZE
        plaintext.extend(chr(int(v) + ord('A')) for v in dec_vec)

    return ''.join(plaintext)


# Standard 2×2 example key
# det([[3,3],[2,5]]) = 15-6 = 9, gcd(9,26)=1 ✓
DEFAULT_KEY_2x2 = [[3, 3], [2, 5]]
DEFAULT_KEY_3x3 = [[2, 4, 5], [9, 2, 1], [3, 17, 7]]


if __name__ == "__main__":
    msg = "ACT"
    key = DEFAULT_KEY_2x2
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    print(f"Plaintext : {msg}")
    print(f"Key matrix: {key}")
    print(f"Encrypted : {enc}")
    print(f"Decrypted : {dec}")
