"""
asymmetric/rsa_cipher.py
------------------------
RSA Encryption/Decryption using large keys (2048-bit default, up to 4096+).
Supports OAEP padding (secure) and raw textbook RSA (educational).

RSA Key generation:
  1. Choose two large primes p, q
  2. n = p * q
  3. λ(n) = lcm(p-1, q-1)   [Carmichael's totient]
  4. e = 65537              [standard public exponent]
  5. d = e^(-1) mod λ(n)    [private exponent]

Public key:  (e, n)
Private key: (d, n)
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256


# ── Key Generation ────────────────────────────────────────────────────────────

def generate_keypair(bits: int = 2048) -> tuple:
    """
    Generate RSA keypair.
    Returns (private_key, public_key) as PyCryptodome RsaKey objects.
    """
    key = RSA.generate(bits)
    return key, key.publickey()


def export_keys(private_key, public_key) -> tuple[str, str]:
    """Export keys as PEM strings."""
    return private_key.export_key().decode(), public_key.export_key().decode()


def import_private_key(pem: str):
    return RSA.import_key(pem)


def import_public_key(pem: str):
    return RSA.import_key(pem)


# ── OAEP Encryption (secure, recommended) ────────────────────────────────────

def encrypt_oaep(plaintext: bytes, public_key) -> bytes:
    """Encrypt with RSA-OAEP (PKCS#1 v2.1). Secure standard padding."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def decrypt_oaep(ciphertext: bytes, private_key) -> bytes:
    """Decrypt with RSA-OAEP."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


# ── Textbook RSA (educational — NO PADDING, do NOT use in production) ─────────

def textbook_encrypt(m: int, e: int, n: int) -> int:
    """C = m^e mod n  — raw RSA, no padding."""
    return pow(m, e, n)


def textbook_decrypt(c: int, d: int, n: int) -> int:
    """M = c^d mod n  — raw RSA, no padding."""
    return pow(c, d, n)


# ── Digital Signatures (RSA-PSS) ──────────────────────────────────────────────

def sign(message: bytes, private_key) -> bytes:
    """Sign a message with RSA-PSS using SHA-256."""
    h = SHA256.new(message)
    signature = pss.new(private_key).sign(h)
    return signature


def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    """Verify RSA-PSS signature. Returns True if valid."""
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# ── Convenience ───────────────────────────────────────────────────────────────

def encrypt_text(plaintext: str, public_key=None, bits: int = 2048) -> dict:
    """Encrypt a text string. Generates keys if none provided."""
    priv, pub = generate_keypair(bits)
    if public_key is None:
        public_key = pub
    ct = encrypt_oaep(plaintext.encode('utf-8'), public_key)
    return {"ciphertext": ct, "private_key": priv, "public_key": pub}


def decrypt_text(ciphertext: bytes, private_key) -> str:
    return decrypt_oaep(ciphertext, private_key).decode('utf-8')


if __name__ == "__main__":
    print("Generating 2048-bit RSA keypair...")
    priv, pub = generate_keypair(2048)
    print(f"Public key n (first 64 hex): {hex(pub.n)[:66]}...")

    msg = "RSA-OAEP encrypted message"
    ct = encrypt_oaep(msg.encode(), pub)
    pt = decrypt_oaep(ct, priv).decode()
    print(f"\nPlaintext  : {msg}")
    print(f"CT   (hex) : {ct.hex()[:64]}...")
    print(f"Decrypted  : {pt}")

    sig = sign(msg.encode(), priv)
    valid = verify_signature(msg.encode(), sig, pub)
    print(f"\nSignature valid: {valid}")
