"""
classical/vigenere.py
---------------------
Vigenère Cipher — polyalphabetic substitution.
E(m_i) = (m_i + k_{i mod len(k)}) mod 26
"""


def _clean(text: str) -> str:
    return ''.join(c.upper() for c in text if c.isalpha())


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt using Vigenère cipher."""
    key = _clean(key)
    result = []
    k_idx = 0
    for ch in plaintext.upper():
        if ch.isalpha():
            shift = ord(key[k_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            k_idx += 1
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt using Vigenère cipher."""
    key = _clean(key)
    result = []
    k_idx = 0
    for ch in ciphertext.upper():
        if ch.isalpha():
            shift = ord(key[k_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            k_idx += 1
        else:
            result.append(ch)
    return ''.join(result)


def brute_force(ciphertext: str, max_key_len: int = 6) -> list[tuple[str, str]]:
    """
    Attempt brute-force for short keys (educational only).
    Returns list of (key, decrypted_text) for all keys up to max_key_len.
    """
    from itertools import product
    results = []
    for length in range(1, max_key_len + 1):
        for key_tuple in product('ABCDEFGHIJKLMNOPQRSTUVWXYZ', repeat=length):
            key = ''.join(key_tuple)
            dec = decrypt(ciphertext, key)
            results.append((key, dec))
    return results


if __name__ == "__main__":
    key = "LEMON"
    msg = "ATTACKATDAWN"
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    print(f"Key       : {key}")
    print(f"Plaintext : {msg}")
    print(f"Encrypted : {enc}")
    print(f"Decrypted : {dec}")
