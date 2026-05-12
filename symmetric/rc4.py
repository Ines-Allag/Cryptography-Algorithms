"""
symmetric/rc4.py
----------------
RC4 Stream Cipher — implémentation pure Python
"""

def encrypt_text(plaintext: str, key: str) -> bytes:
    key_bytes = key.encode('utf-8')
    data = plaintext.encode('utf-8')
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

def decrypt_text(ciphertext: bytes, key: str) -> str:
    return encrypt_text(ciphertext.decode('latin-1'), key).decode('latin-1')