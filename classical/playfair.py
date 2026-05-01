"""
classical/playfair.py
---------------------
Playfair Cipher — digraph substitution using a 5×5 key square.
I and J are treated as the same letter.
"""


def _build_square(key: str) -> list[list[str]]:
    """Build the 5×5 Playfair key square from a keyword."""
    key = key.upper().replace('J', 'I')
    seen = []
    for c in key:
        if c.isalpha() and c not in seen:
            seen.append(c)
    for c in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.append(c)
    return [seen[i * 5:(i + 1) * 5] for i in range(5)]


def _find_position(square: list[list[str]], letter: str) -> tuple[int, int]:
    for r, row in enumerate(square):
        if letter in row:
            return r, row.index(letter)
    raise ValueError(f"Letter '{letter}' not found in square")


def _prepare_text(text: str) -> str:
    """Prepare plaintext: uppercase, remove non-alpha, replace J→I, insert X between doubles."""
    text = text.upper().replace('J', 'I')
    text = ''.join(c for c in text if c.isalpha())
    result = []
    i = 0
    while i < len(text):
        result.append(text[i])
        if i + 1 < len(text):
            if text[i] == text[i + 1]:
                result.append('X')  # Insert filler
            else:
                result.append(text[i + 1])
                i += 1
        i += 1
    if len(result) % 2 != 0:
        result.append('X')  # Pad if odd length
    return ''.join(result)


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt using Playfair cipher."""
    square = _build_square(key)
    text = _prepare_text(plaintext)
    ciphertext = []

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        r1, c1 = _find_position(square, a)
        r2, c2 = _find_position(square, b)

        if r1 == r2:                          # Same row → shift right
            ciphertext += [square[r1][(c1 + 1) % 5], square[r2][(c2 + 1) % 5]]
        elif c1 == c2:                         # Same column → shift down
            ciphertext += [square[(r1 + 1) % 5][c1], square[(r2 + 1) % 5][c2]]
        else:                                  # Rectangle → swap columns
            ciphertext += [square[r1][c2], square[r2][c1]]

    return ''.join(ciphertext)


def decrypt(ciphertext: str, key: str) -> str:
    """Decrypt using Playfair cipher."""
    square = _build_square(key)
    ciphertext = ciphertext.upper()
    plaintext = []

    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        r1, c1 = _find_position(square, a)
        r2, c2 = _find_position(square, b)

        if r1 == r2:                          # Same row → shift left
            plaintext += [square[r1][(c1 - 1) % 5], square[r2][(c2 - 1) % 5]]
        elif c1 == c2:                         # Same column → shift up
            plaintext += [square[(r1 - 1) % 5][c1], square[(r2 - 1) % 5][c2]]
        else:                                  # Rectangle → swap columns
            plaintext += [square[r1][c2], square[r2][c1]]

    return ''.join(plaintext)


if __name__ == "__main__":
    key = "MONARCHY"
    msg = "INSTRUMENTS"
    enc = encrypt(msg, key)
    dec = decrypt(enc, key)
    print(f"Key       : {key}")
    print(f"Plaintext : {msg}")
    print(f"Encrypted : {enc}")
    print(f"Decrypted : {dec}")
