"""
main.py
--------
CryptoLab Interactive CLI
Demonstrates all implemented cryptographic algorithms.
"""

import sys
import os

# Make sure relative imports work
sys.path.insert(0, os.path.dirname(__file__))

# ─────────────────────────────────────────────────────────────────────────────
MENU = """
╔══════════════════════════════════════════════════════╗
║              🔐 CRYPTOLAB — CIPHER SUITE             ║
╠══════════════════════════════════════════════════════╣
║  CLASSICAL CIPHERS                                   ║
║    1.  Affine Cipher                                 ║
║    2.  Hill Cipher                                   ║
║    3.  Playfair Cipher                               ║
║    4.  Vigenère Cipher                               ║
║    5.  One-Time Pad (OTP / Masque Jetable)           ║
║    6.  Frequency Analysis + Indice de Coïncidence    ║
║                                                      ║
║  MODERN SYMMETRIC                                    ║
║    7.  RC4 Stream Cipher                             ║
║    8.  AES (128 / 192 / 256-bit)                     ║
║    9.  DES / Triple-DES                              ║
║                                                      ║
║  ASYMMETRIC / PUBLIC-KEY                             ║
║   10.  RSA (2048-bit, OAEP)                          ║
║   11.  Diffie-Hellman Key Exchange                   ║
║   12.  ElGamal Encryption                            ║
║   13.  Shamir's Secret Sharing                       ║
║                                                      ║
║  HASHING                                             ║
║   14.  MD5 / SHA-1 / SHA-256 / SHA-512               ║
║   15.  HMAC-SHA256                                   ║
║                                                      ║
║  PROTOCOLS                                           ║
║   16.  Digital Signatures (RSA-PSS / ECDSA / EdDSA) ║
║   17.  Homomorphic Encryption (Paillier)             ║
║                                                      ║
║    0.  Exit                                          ║
╚══════════════════════════════════════════════════════╝
"""


def separator(title=""):
    w = 54
    if title:
        print(f"\n{'─' * 4} {title} {'─' * (w - len(title) - 6)}")
    else:
        print("─" * w)


def get_input(prompt, default=None):
    val = input(f"  {prompt}: ").strip()
    return val if val else default


def demo_affine():
    separator("AFFINE CIPHER")
    from classical.affine import encrypt, decrypt
    msg = get_input("Plaintext", "HELLO WORLD")
    a = int(get_input("Key a (must be coprime with 26)", "7"))
    b = int(get_input("Key b", "3"))
    enc = encrypt(msg, a, b)
    dec = decrypt(enc, a, b)
    print(f"\n  Encrypted : {enc}")
    print(f"  Decrypted : {dec}")


def demo_hill():
    separator("HILL CIPHER")
    from classical.hill import encrypt, decrypt, DEFAULT_KEY_2x2
    msg = get_input("Plaintext", "ACT")
    print(f"  Using default 2×2 key: {DEFAULT_KEY_2x2}")
    enc = encrypt(msg, DEFAULT_KEY_2x2)
    dec = decrypt(enc, DEFAULT_KEY_2x2)
    print(f"\n  Encrypted : {enc}")
    print(f"  Decrypted : {dec}")


def demo_playfair():
    separator("PLAYFAIR CIPHER")
    from classical.playfair import encrypt, decrypt
    key = get_input("Keyword", "MONARCHY")
    msg = get_input("Plaintext", "INSTRUMENTS")
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    print(f"\n  Encrypted : {enc}")
    print(f"  Decrypted : {dec}")


def demo_vigenere():
    separator("VIGENÈRE CIPHER")
    from classical.vigenere import encrypt, decrypt
    key = get_input("Key", "LEMON")
    msg = get_input("Plaintext", "ATTACKATDAWN")
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    print(f"\n  Encrypted : {enc}")
    print(f"  Decrypted : {dec}")


def demo_otp():
    separator("ONE-TIME PAD")
    from classical.otp import encrypt_text, decrypt_text
    msg = get_input("Plaintext", "Top secret message")
    ct, key = encrypt_text(msg)
    dec = decrypt_text(ct, key)
    print(f"\n  Key (hex)   : {key.hex()}")
    print(f"  Cipher(hex) : {ct.hex()}")
    print(f"  Decrypted   : {dec}")
    print(f"  ⚠ Key used once — NEVER reuse OTP keys!")


def demo_frequency():
    separator("FREQUENCY ANALYSIS")
    from classical.frequency import print_frequency_analysis, index_of_coincidence
    msg = get_input("Text to analyse", "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
    print_frequency_analysis(msg)


def demo_rc4():
    separator("RC4 STREAM CIPHER")
    from symmetric.rc4 import encrypt_text, decrypt_text
    key = get_input("Key", "SecretKey")
    msg = get_input("Plaintext", "Hello, RC4!")
    ct = encrypt_text(msg, key)
    dec = decrypt_text(ct, key)
    print(f"\n  Encrypted (hex) : {ct.hex()}")
    print(f"  Decrypted       : {dec}")
    print(f"  ⚠ RC4 is deprecated. Use AES in production.")


def demo_aes():
    separator("AES CIPHER")
    from symmetric.aes_cipher import encrypt_text, decrypt_text
    msg = get_input("Plaintext", "AES-256 encrypted message!")
    mode = get_input("Mode (GCM/CBC)", "GCM").upper()
    params = encrypt_text(msg, mode=mode)
    dec = decrypt_text(params)
    print(f"\n  Key  (hex) : {params['key'].hex()}")
    print(f"  CT   (hex) : {params['ciphertext'].hex()}")
    print(f"  Decrypted  : {dec}")


def demo_des():
    separator("DES / 3DES")
    from symmetric.des_cipher import encrypt_text, decrypt_text
    msg = get_input("Plaintext", "DES example message")
    use_3des = get_input("Use 3DES? (y/n)", "y").lower() == "y"
    params = encrypt_text(msg, use_3des=use_3des)
    dec = decrypt_text(params)
    print(f"\n  Algorithm  : {params['algorithm']}")
    print(f"  Key  (hex) : {params['key'].hex()}")
    print(f"  CT   (hex) : {params['ciphertext'].hex()}")
    print(f"  Decrypted  : {dec}")


def demo_rsa():
    separator("RSA (2048-bit)")
    from asymmetric.rsa_cipher import generate_keypair, encrypt_oaep, decrypt_oaep
    print("  Generating 2048-bit RSA keypair...")
    priv, pub = generate_keypair(2048)
    msg = get_input("Plaintext", "RSA secret message")
    ct = encrypt_oaep(msg.encode(), pub)
    pt = decrypt_oaep(ct, priv).decode()
    print(f"\n  CT   (hex) : {ct.hex()[:64]}...")
    print(f"  Decrypted  : {pt}")


def demo_dh():
    separator("DIFFIE-HELLMAN")
    from asymmetric.diffie_hellman import DHParty
    print("  Simulating Alice ↔ Bob key exchange (2048-bit MODP)...")
    alice = DHParty()
    bob = DHParty(p=alice.p, g=alice.g)
    aes_alice = alice.derive_aes_key(bob.public_key)
    aes_bob = bob.derive_aes_key(alice.public_key)
    print(f"\n  Alice AES key : {aes_alice.hex()}")
    print(f"  Bob   AES key : {aes_bob.hex()}")
    print(f"  Keys match    : {aes_alice == aes_bob} ✓")


def demo_elgamal():
    separator("ELGAMAL")
    from asymmetric.elgamal import ElGamal
    eg = ElGamal(bits=256)
    msg = get_input("Plaintext", "ElGamal message")
    ct, length = eg.encrypt_text(msg)
    dec = eg.decrypt_text(ct, length)
    print(f"\n  Decrypted : {dec}")


def demo_shamir():
    separator("SHAMIR'S SECRET SHARING")
    from asymmetric.shamir import split_text, reconstruct_text
    secret = get_input("Secret", "Password123!")
    n = int(get_input("Total shares (n)", "5"))
    k = int(get_input("Threshold (k)", "3"))
    shares, prime, byte_len = split_text(secret, n=n, k=k)
    print(f"\n  {n} shares generated. Using shares 1, 3, {n} to reconstruct:")
    subset = [shares[0], shares[2], shares[n - 1]]
    recovered = reconstruct_text(subset, prime, byte_len)
    print(f"  Recovered : {recovered}")
    print(f"  Match     : {recovered == secret} ✓")


def demo_hashing():
    separator("HASHING — MD5 / SHA")
    from hashing.sha_hash import hash_all
    msg = get_input("Text to hash", "Hello, World!")
    results = hash_all(msg)
    print()
    for algo, digest in results.items():
        print(f"  {algo:<10}: {digest}")


def demo_hmac():
    separator("HMAC-SHA256")
    from hashing.hmac_sign import generate_hmac_key, hmac_sha256, hmac_verify
    key = generate_hmac_key()
    msg = get_input("Message", "Authenticate this")
    mac = hmac_sha256(key, msg)
    valid = hmac_verify(key, msg, mac)
    print(f"\n  Key (hex) : {key.hex()}")
    print(f"  MAC       : {mac}")
    print(f"  Valid     : {valid} ✓")


def demo_signatures():
    separator("DIGITAL SIGNATURES")
    from protocols.signature import RSASignature, ECDSASignature
    msg = get_input("Message to sign", "Sign this document")

    print("\n  RSA-PSS (2048-bit):")
    rsa = RSASignature(2048)
    sig = rsa.sign(msg)
    print(f"  Valid  : {RSASignature.verify(msg, sig, rsa.public_key)} ✓")
    print(f"  Tamper : {RSASignature.verify(msg + 'X', sig, rsa.public_key)} ✗")

    print("\n  ECDSA (P-256):")
    ec = ECDSASignature("P-256")
    sig = ec.sign(msg)
    print(f"  Valid  : {ECDSASignature.verify(msg, sig, ec.public_key)} ✓")


def demo_homomorphic():
    separator("PAILLIER HOMOMORPHIC ENCRYPTION")
    from protocols.homomorphic import Paillier
    p = Paillier(bits=256)
    a = int(get_input("Value a", "42"))
    b = int(get_input("Value b", "17"))
    ca = p.encrypt(a)
    cb = p.encrypt(b)
    c_sum = p.add_ciphertexts(ca, cb)
    result = p.decrypt(c_sum)
    print(f"\n  Enc({a}) + Enc({b}) decrypts to: {result}  (expected {a+b})")
    k = 5
    c_mul = p.multiply_by_scalar(ca, k)
    print(f"  Enc({a}) * {k} decrypts to:    {p.decrypt(c_mul)}  (expected {a*k})")


HANDLERS = {
    "1": demo_affine,
    "2": demo_hill,
    "3": demo_playfair,
    "4": demo_vigenere,
    "5": demo_otp,
    "6": demo_frequency,
    "7": demo_rc4,
    "8": demo_aes,
    "9": demo_des,
    "10": demo_rsa,
    "11": demo_dh,
    "12": demo_elgamal,
    "13": demo_shamir,
    "14": demo_hashing,
    "15": demo_hmac,
    "16": demo_signatures,
    "17": demo_homomorphic,
}


def main():
    print(MENU)
    while True:
        choice = input("\n  Select [0-17]: ").strip()
        if choice == "0":
            print("  Goodbye! 🔐")
            break
        handler = HANDLERS.get(choice)
        if handler:
            try:
                handler()
            except Exception as e:
                print(f"\n  ❌ Error: {e}")
                import traceback
                traceback.print_exc()
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    main()
