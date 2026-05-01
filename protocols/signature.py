"""
protocols/signature.py
-----------------------
Digital Signature Schemes:
  1. RSA-PSS  — RSA with Probabilistic Signature Scheme
  2. ECDSA    — Elliptic Curve Digital Signature Algorithm (P-256, P-384)
  3. EdDSA    — Edwards-curve Digital Signature Algorithm (Ed25519)

A digital signature provides:
  - Authentication: only the private key holder could have signed
  - Integrity: any change to the message invalidates the signature
  - Non-repudiation: signer cannot deny having signed
"""

import os
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pss, DSS
from Crypto.Hash import SHA256, SHA384, SHA512


# ── RSA-PSS ───────────────────────────────────────────────────────────────────

class RSASignature:
    """RSA-PSS digital signature scheme."""

    def __init__(self, bits: int = 2048):
        self._private_key = RSA.generate(bits)
        self._public_key = self._private_key.publickey()

    @property
    def public_key(self):
        return self._public_key

    def sign(self, message: bytes | str, hash_algo: str = "SHA256") -> bytes:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = _hash(message, hash_algo)
        return pss.new(self._private_key).sign(h)

    @staticmethod
    def verify(message: bytes | str, signature: bytes, public_key,
               hash_algo: str = "SHA256") -> bool:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = _hash(message, hash_algo)
        try:
            pss.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def export_public_pem(self) -> str:
        return self._public_key.export_key().decode()

    def export_private_pem(self) -> str:
        return self._private_key.export_key().decode()


# ── ECDSA ─────────────────────────────────────────────────────────────────────

class ECDSASignature:
    """ECDSA over standard NIST curves (P-256, P-384, P-521)."""

    CURVES = {"P-256", "P-384", "P-521"}

    def __init__(self, curve: str = "P-256"):
        if curve not in self.CURVES:
            raise ValueError(f"Curve must be one of {self.CURVES}")
        self._private_key = ECC.generate(curve=curve)
        self._public_key = self._private_key.public_key()
        self.curve = curve

    @property
    def public_key(self):
        return self._public_key

    def sign(self, message: bytes | str, hash_algo: str = "SHA256") -> bytes:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = _hash(message, hash_algo)
        signer = DSS.new(self._private_key, 'fips-186-3')
        return signer.sign(h)

    @staticmethod
    def verify(message: bytes | str, signature: bytes, public_key,
               hash_algo: str = "SHA256") -> bool:
        if isinstance(message, str):
            message = message.encode('utf-8')
        h = _hash(message, hash_algo)
        verifier = DSS.new(public_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


# ── EdDSA (Ed25519) ───────────────────────────────────────────────────────────

class EdDSASignature:
    """EdDSA over Ed25519. Fast, secure, deterministic."""

    def __init__(self):
        self._private_key = ECC.generate(curve="Ed25519")
        self._public_key = self._private_key.public_key()

    @property
    def public_key(self):
        return self._public_key

    def sign(self, message: bytes | str) -> bytes:
        if isinstance(message, str):
            message = message.encode('utf-8')
        signer = DSS.new(self._private_key, 'rfc8032')
        h = SHA512.new(message)
        return signer.sign(h)

    @staticmethod
    def verify(message: bytes | str, signature: bytes, public_key) -> bool:
        if isinstance(message, str):
            message = message.encode('utf-8')
        verifier = DSS.new(public_key, 'rfc8032')
        h = SHA512.new(message)
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hash(data: bytes, algo: str):
    algos = {"SHA256": SHA256, "SHA384": SHA384, "SHA512": SHA512}
    if algo not in algos:
        raise ValueError(f"Hash algo must be one of {list(algos.keys())}")
    return algos[algo].new(data)


if __name__ == "__main__":
    msg = "Sign this important document"

    print("=== RSA-PSS ===")
    rsa_sig = RSASignature(2048)
    sig = rsa_sig.sign(msg)
    print(f"Valid  : {RSASignature.verify(msg, sig, rsa_sig.public_key)}")
    print(f"Tamper : {RSASignature.verify(msg + 'X', sig, rsa_sig.public_key)}")

    print("\n=== ECDSA (P-256) ===")
    ec_sig = ECDSASignature("P-256")
    sig = ec_sig.sign(msg)
    print(f"Valid  : {ECDSASignature.verify(msg, sig, ec_sig.public_key)}")

    print("\n=== EdDSA (Ed25519) ===")
    ed_sig = EdDSASignature()
    sig = ed_sig.sign(msg)
    print(f"Valid  : {EdDSASignature.verify(msg, sig, ed_sig.public_key)}")
