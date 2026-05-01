"""
modern/des_cipher.py
---------------------
DES and Triple-DES (3DES / TDEA)
Using pycryptodome. DES uses 56-bit effective key (64-bit with parity).
3DES uses 112 or 168 bits. Both are obsolete for new systems.

Note: DES is broken (56-bit key brute-forceable). Use AES in production.
"""

import os
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 8  # DES block = 64 bits


# ── DES ──────────────────────────────────────────────────────────────────────

def des_generate_key() -> bytes:
    """Generate a random 8-byte DES key."""
    return DES.adjust_key_parity(os.urandom(8))


def des_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """DES-CBC encryption. Returns (ciphertext, iv)."""
    iv = iv or os.urandom(BLOCK_SIZE)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE)), iv


def des_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """DES-CBC decryption."""
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


# ── Triple DES ────────────────────────────────────────────────────────────────

def tdes_generate_key(key_size: int = 24) -> bytes:
    """
    Generate a 3DES key.
    key_size=16 → 2-key 3DES (112-bit security)
    key_size=24 → 3-key 3DES (168-bit security)
    """
    if key_size not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes")
    return DES3.adjust_key_parity(os.urandom(key_size))


def tdes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """Triple-DES CBC encryption. Returns (ciphertext, iv)."""
    iv = iv or os.urandom(BLOCK_SIZE)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE)), iv


def tdes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Triple-DES CBC decryption."""
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


# ── Convenience ───────────────────────────────────────────────────────────────

def encrypt_text(plaintext: str, use_3des: bool = True) -> dict:
    data = plaintext.encode('utf-8')
    if use_3des:
        key = tdes_generate_key()
        ct, iv = tdes_encrypt_cbc(data, key)
        return {"ciphertext": ct, "key": key, "iv": iv, "algorithm": "3DES"}
    else:
        key = des_generate_key()
        ct, iv = des_encrypt_cbc(data, key)
        return {"ciphertext": ct, "key": key, "iv": iv, "algorithm": "DES"}


def decrypt_text(params: dict) -> str:
    algo = params["algorithm"]
    if algo == "3DES":
        pt = tdes_decrypt_cbc(params["ciphertext"], params["key"], params["iv"])
    else:
        pt = des_decrypt_cbc(params["ciphertext"], params["key"], params["iv"])
    return pt.decode('utf-8')


if __name__ == "__main__":
    msg = "DES / 3DES message"
    for use_3des in [False, True]:
        params = encrypt_text(msg, use_3des=use_3des)
        dec = decrypt_text(params)
        algo = params["algorithm"]
        print(f"=== {algo} ===")
        print(f"Key (hex): {params['key'].hex()}")
        print(f"IV  (hex): {params['iv'].hex()}")
        print(f"CT  (hex): {params['ciphertext'].hex()}")
        print(f"Decrypted: {dec}\n")
    print("⚠ DES/3DES are deprecated. Prefer AES-256.")
