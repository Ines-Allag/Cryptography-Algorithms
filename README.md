# 🔐 CryptoLab — Cipher Suite

An educational cryptography toolkit built in Python, covering classical ciphers, modern symmetric encryption, asymmetric / public-key cryptography, hashing, digital signatures, and advanced protocols — all from a single interactive CLI.

Built with **256-bit+ keys** throughout and backed by `pycryptodome` and `sympy`.

---

## Features

| Category | Algorithms |
|---|---|
| Classical | Affine, Hill, Playfair, Vigenère, One-Time Pad, Frequency Analysis + IC |
| Modern Symmetric | AES (128/192/256-bit, CBC & GCM), DES / 3DES, RC4 |
| Asymmetric | RSA-OAEP (2048-bit), Diffie-Hellman (2048-bit MODP), ElGamal, Shamir's Secret Sharing |
| Hashing | MD5, SHA-1, SHA-256, SHA-512, SHA3-256, SHA3-512 |
| Authentication | HMAC-SHA256, HMAC-SHA512 |
| Protocols | Digital Signatures (RSA-PSS, ECDSA P-256/P-384, EdDSA Ed25519), Paillier Homomorphic Encryption |

---

## Project Structure

```
cryptolab/
├── main.py                  # Interactive CLI entry point
├── requirements.txt
├── README.md
├── .gitignore
│
├── classical/               # Classical ciphers
│   ├── affine.py
│   ├── hill.py
│   ├── playfair.py
│   ├── vigenere.py
│   ├── otp.py
│   └── frequency.py
│
├── modern/                  # Modern symmetric ciphers
│   ├── aes_cipher.py
│   ├── des_cipher.py
│   └── rc4.py
│
├── asymmetric/              # Public-key cryptography
│   ├── rsa_cipher.py
│   ├── diffie_hellman.py
│   ├── elgamal.py
│   └── shamir.py
│
├── hashing/                 # Hash functions & HMAC
│   ├── sha_hash.py
│   └── hmac_sign.py
│
├── protocols/               # Advanced schemes
│   ├── signature.py
│   └── homomorphic.py
│
└── utils/                   # Shared math & conversion helpers
    ├── converter.py
    ├── math_utils.py
    └── primes.py
```

---

## Installation

**Requirements:** Python 3.11+

```bash
git clone https://github.com/your-username/cryptolab.git
cd cryptolab
pip install -r requirements.txt
```

---

## Usage

```bash
python main.py
```

You will be presented with a menu. Select an algorithm by number, then choose whether to **encrypt** or **decrypt**. The CLI will prompt you for the required inputs (key, IV, nonce, etc.) depending on your choice.


---

## Algorithm Notes

### Classical Ciphers
- **Affine** — `E(x) = (ax + b) mod 26`, requires `gcd(a, 26) = 1`
- **Hill** — matrix multiplication mod 26 over n-grams
- **Playfair** — digraph substitution using a 5×5 key square (I=J)
- **Vigenère** — polyalphabetic substitution, key repeated cyclically
- **OTP** — XOR with a truly random key; theoretically unbreakable if key is never reused
- **Frequency Analysis** — letter frequency + Index of Coincidence to identify and attack ciphers

### Modern Symmetric
- **AES** — 128/192/256-bit keys; CBC (with IV) and GCM (authenticated encryption with nonce + tag)
- **DES / 3DES** — CBC mode; included for historical study only — broken/deprecated
- **RC4** — stream cipher; included for educational purposes only — do not use in production

### Asymmetric / Public-Key
- **RSA** — 2048-bit keys, OAEP padding (secure), textbook mode (educational)
- **Diffie-Hellman** — 2048-bit MODP Group 14 (RFC 3526); derives shared AES key via SHA-256
- **ElGamal** — 256-bit safe prime; based on the discrete logarithm problem
- **Shamir's Secret Sharing** — k-of-n threshold scheme over GF(p) via Lagrange interpolation

### Hashing
- **SHA-256 / SHA-512** — recommended for all new applications
- **SHA3-256 / SHA3-512** — Keccak-based alternative to SHA-2
- **MD5 / SHA-1** — included for completeness; cryptographically broken, do not use for security

### Protocols
- **Digital Signatures** — RSA-PSS (SHA-256), ECDSA (P-256/P-384), EdDSA (Ed25519)
- **HMAC** — keyed MAC providing both integrity and authentication; constant-time verification to prevent timing attacks
- **Paillier Homomorphic Encryption** — supports addition and scalar multiplication on ciphertexts without decrypting

---


## Dependencies

```
pycryptodome >= 3.20.0   # AES, DES, RSA, ECC, signatures
sympy        >= 1.12     # Large prime generation (Miller-Rabin, safe primes)
numpy                    # Hill cipher matrix operations
```

---
