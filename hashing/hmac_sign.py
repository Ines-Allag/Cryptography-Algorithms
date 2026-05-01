"""
hashing/hmac_sign.py
---------------------
HMAC (Hash-based Message Authentication Code) + Digital Signatures

HMAC: Provides both integrity and authentication.
  HMAC(K, m) = H((K XOR opad) || H((K XOR ipad) || m))

Digital Signatures (RSA-PSS & ECDSA):
  - Sign:   sig = Sign(private_key, hash(message))
  - Verify: bool = Verify(public_key, hash(message), sig)
"""

import hmac
import hashlib
import os
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss, DSS
from Crypto.Hash import SHA256


# ── HMAC ─────────────────────────────────────────────────────────────────────

def hmac_sha256(key: bytes, message: bytes | str) -> str:
    """Compute HMAC-SHA256 and return hex digest."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hmac_sha512(key: bytes, message: bytes | str) -> str:
    """Compute HMAC-SHA512 and return hex digest."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hmac.new(key, message, hashlib.sha512).hexdigest()


def hmac_verify(key: bytes, message: bytes | str, expected_mac: str,
                algorithm: str = "sha256") -> bool:
    """
    Verify HMAC in constant time (prevents timing attacks).
    Returns True if MAC matches.
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    if algorithm == "sha256":
        computed = hmac.new(key, message, hashlib.sha256).hexdigest()
    elif algorithm == "sha512":
        computed = hmac.new(key, message, hashlib.sha512).hexdigest()
    else:
        raise ValueError(f"Unknown HMAC algorithm: {algorithm}")
    return hmac.compare_digest(computed, expected_mac)


def generate_hmac_key(bits: int = 256) -> bytes:
    """Generate a random HMAC key."""
    return os.urandom(bits // 8)


# ── RSA Digital Signature (PSS) ───────────────────────────────────────────────

class RSASigner:
    def __init__(self, bits: int = 2048):
        print(f"Generating {bits}-bit RSA signing key...")
        self._key = RSA.generate(bits)

    @property
    def public_key(self):
        return self._key.publickey()

    def sign(self, message: bytes | str) -> bytes:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = SHA256.new(message)
        return pss.new(self._key).sign(h)

    def verify(self, message: bytes | str, signature: bytes) -> bool:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = SHA256.new(message)
        try:
            pss.new(self.public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


# ── ECDSA Digital Signature ───────────────────────────────────────────────────

class ECDSASigner:
    """
    ECDSA (Elliptic Curve Digital Signature Algorithm) over P-256.
    Smaller keys, faster signing than RSA.
    """

    def __init__(self, curve: str = "P-256"):
        self._key = ECC.generate(curve=curve)

    @property
    def public_key(self):
        return self._key.public_key()

    def sign(self, message: bytes | str) -> bytes:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = SHA256.new(message)
        signer = DSS.new(self._key, 'fips-186-3')
        return signer.sign(h)

    def verify(self, message: bytes | str, signature: bytes) -> bool:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = SHA256.new(message)
        verifier = DSS.new(self.public_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


if __name__ == "__main__":
    # HMAC demo
    key = generate_hmac_key()
    msg = "Authenticated message"
    mac = hmac_sha256(key, msg)
    valid = hmac_verify(key, msg, mac)
    print(f"=== HMAC-SHA256 ===")
    print(f"Message : {msg}")
    print(f"MAC     : {mac}")
    print(f"Valid   : {valid}")

    # RSA Signature demo
    print("\n=== RSA-PSS Signature ===")
    signer = RSASigner(2048)
    sig = signer.sign(msg)
    print(f"Signature valid: {signer.verify(msg, sig)}")
    print(f"Tampered valid : {signer.verify(msg + '!', sig)}")

    # ECDSA demo
    print("\n=== ECDSA (P-256) Signature ===")
    ec_signer = ECDSASigner()
    ec_sig = ec_signer.sign(msg)
    print(f"Signature valid: {ec_signer.verify(msg, ec_sig)}")
