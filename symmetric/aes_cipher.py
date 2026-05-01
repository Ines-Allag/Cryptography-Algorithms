"""
modern/aes_cipher.py
---------------------
AES (Advanced Encryption Standard) — 128/192/256-bit keys
Using pycryptodome for a standards-compliant implementation.
Supports: ECB, CBC (with IV), GCM (authenticated encryption)

AES block size: 128 bits (16 bytes)
Key sizes: 128, 192, or 256 bits (16, 24, 32 bytes)
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ── Modes ────────────────────────────────────────────────────────────────────

class AESCipher:
    """
    AES cipher wrapper supporting CBC and GCM modes.
    
    Usage:
        cipher = AESCipher(key_size=256)
        key = cipher.generate_key()
        ct, iv = cipher.encrypt_cbc(b"Hello World", key)
        pt = cipher.decrypt_cbc(ct, key, iv)
    """

    BLOCK_SIZE = 16  # AES always uses 128-bit blocks

    def __init__(self, key_size: int = 256):
        if key_size not in (128, 192, 256):
            raise ValueError("AES key size must be 128, 192, or 256 bits")
        self.key_size = key_size
        self.key_bytes = key_size // 8

    def generate_key(self) -> bytes:
        """Generate a random AES key."""
        return os.urandom(self.key_bytes)

    # ── ECB Mode (no IV — not recommended for real use) ────────────────────

    def encrypt_ecb(self, plaintext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, self.BLOCK_SIZE))

    def decrypt_ecb(self, ciphertext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)

    # ── CBC Mode (recommended for block encryption) ────────────────────────

    def encrypt_cbc(self, plaintext: bytes, key: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
        """Returns (ciphertext, iv)."""
        iv = iv or os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plaintext, self.BLOCK_SIZE)), iv

    def decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)

    # ── GCM Mode (authenticated encryption — recommended for secure comms) ─

    def encrypt_gcm(self, plaintext: bytes, key: bytes,
                    nonce: bytes = None, aad: bytes = None) -> tuple[bytes, bytes, bytes]:
        """
        GCM authenticated encryption.
        Returns (ciphertext, nonce, auth_tag).
        aad = Additional Authenticated Data (optional, not encrypted but authenticated).
        """
        nonce = nonce or os.urandom(16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct, nonce, tag

    def decrypt_gcm(self, ciphertext: bytes, key: bytes,
                    nonce: bytes, tag: bytes, aad: bytes = None) -> bytes:
        """
        GCM authenticated decryption. Raises ValueError if authentication fails.
        """
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)


# ── Convenience functions ─────────────────────────────────────────────────

def encrypt_text(plaintext: str, key: bytes = None, mode: str = "GCM") -> dict:
    """
    Encrypt a text string with AES-256.
    Returns a dict with all necessary data to decrypt.
    """
    aes = AESCipher(256)
    key = key or aes.generate_key()
    data = plaintext.encode('utf-8')

    if mode == "GCM":
        ct, nonce, tag = aes.encrypt_gcm(data, key)
        return {"ciphertext": ct, "key": key, "nonce": nonce, "tag": tag, "mode": "GCM"}
    elif mode == "CBC":
        ct, iv = aes.encrypt_cbc(data, key)
        return {"ciphertext": ct, "key": key, "iv": iv, "mode": "CBC"}
    else:
        raise ValueError(f"Unknown mode: {mode}")


def decrypt_text(params: dict) -> str:
    aes = AESCipher(256)
    mode = params["mode"]
    if mode == "GCM":
        pt = aes.decrypt_gcm(params["ciphertext"], params["key"],
                              params["nonce"], params["tag"])
    elif mode == "CBC":
        pt = aes.decrypt_cbc(params["ciphertext"], params["key"], params["iv"])
    else:
        raise ValueError(f"Unknown mode: {mode}")
    return pt.decode('utf-8')


if __name__ == "__main__":
    msg = "Confidential AES message — 256-bit key!"
    print("=== AES-256-GCM ===")
    params = encrypt_text(msg, mode="GCM")
    dec = decrypt_text(params)
    print(f"Plaintext  : {msg}")
    print(f"Key (hex)  : {params['key'].hex()}")
    print(f"Nonce(hex) : {params['nonce'].hex()}")
    print(f"Tag  (hex) : {params['tag'].hex()}")
    print(f"CT   (hex) : {params['ciphertext'].hex()}")
    print(f"Decrypted  : {dec}")

    print("\n=== AES-256-CBC ===")
    params2 = encrypt_text(msg, mode="CBC")
    dec2 = decrypt_text(params2)
    print(f"IV   (hex) : {params2['iv'].hex()}")
    print(f"CT   (hex) : {params2['ciphertext'].hex()}")
    print(f"Decrypted  : {dec2}")
