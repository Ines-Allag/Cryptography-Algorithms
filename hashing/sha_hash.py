"""
hashing/sha_hash.py
-------------------
Hashing algorithms: MD5, SHA-1, SHA-256, SHA-512
Using Python's built-in hashlib for standards-compliant implementations.

Note:
  MD5  → 128-bit digest. BROKEN for security. OK for checksums.
  SHA-1 → 160-bit digest. DEPRECATED for security.
  SHA-256 → 256-bit. Secure, widely used (Bitcoin, TLS, etc.)
  SHA-512 → 512-bit. Stronger, slower.
  SHA-3   → Alternative design to SHA-2.
"""

import hashlib
from utils.converter import bytes_to_hex


# ── Core hash functions ───────────────────────────────────────────────────────

def md5(data: bytes | str) -> str:
    """Return MD5 hex digest. ⚠ Not collision-resistant."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def sha1(data: bytes | str) -> str:
    """Return SHA-1 hex digest. ⚠ Deprecated for new applications."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha1(data).hexdigest()


def sha256(data: bytes | str) -> str:
    """Return SHA-256 hex digest. Recommended for general use."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha512(data: bytes | str) -> str:
    """Return SHA-512 hex digest."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha512(data).hexdigest()


def sha3_256(data: bytes | str) -> str:
    """Return SHA-3 (256-bit) hex digest."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha3_256(data).hexdigest()


def sha3_512(data: bytes | str) -> str:
    """Return SHA-3 (512-bit) hex digest."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha3_512(data).hexdigest()


def hash_all(data: str) -> dict[str, str]:
    """Return all hash digests for a given string."""
    return {
        "MD5":      md5(data),
        "SHA-1":    sha1(data),
        "SHA-256":  sha256(data),
        "SHA-512":  sha512(data),
        "SHA3-256": sha3_256(data),
        "SHA3-512": sha3_512(data),
    }


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Hash a file incrementally (memory-efficient for large files)."""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    msg = "Hello, World!"
    print(f"Input: \"{msg}\"\n")
    results = hash_all(msg)
    for algo, digest in results.items():
        print(f"{algo:<10}: {digest}")
