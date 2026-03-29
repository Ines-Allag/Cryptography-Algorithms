# 🔐 Cryptography Algorithms

A collection of classical and modern cryptographic algorithms implemented for learning purposes.

---

## 📁 Structure

```
cryptography-algorithms/
├── classical/        # Caesar, Vigenère, Playfair, Hill, Affine...
├── modern/
│   ├── symmetric/    # AES, DES, 3DES
│   ├── asymmetric/   # RSA, ElGamal, Diffie-Hellman
│   └── hashing/      # MD5, SHA-1, SHA-256, SHA-512
└── tests/
```

---

## 🚀 Usage

```bash
pip install -r requirements.txt
python classical/caesar.py --mode encrypt --key 3 --text "HELLO"
python modern/symmetric/aes.py --mode encrypt --key "mysecretkey12345" --text "data"
```


