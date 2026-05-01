"""
classical/frequency.py
-----------------------
Frequency Analysis & Index of Coincidence (IC / Indice de Coïncidence)

Used to:
- Analyse letter frequencies in a ciphertext
- Estimate key length for polyalphabetic ciphers (Vigenère)
- Distinguish monoalphabetic from polyalphabetic ciphers
"""

from collections import Counter

# Expected English letter frequencies (%)
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
}

# Theoretical IC for English (~0.065) vs random (~0.038)
IC_ENGLISH = 0.065
IC_RANDOM  = 0.038


def letter_frequencies(text: str) -> dict[str, float]:
    """Return letter frequency (%) for alphabetic characters only."""
    text = text.upper()
    letters = [c for c in text if c.isalpha()]
    total = len(letters)
    if total == 0:
        return {}
    counts = Counter(letters)
    return {chr(i + ord('A')): counts.get(chr(i + ord('A')), 0) / total * 100
            for i in range(26)}


def index_of_coincidence(text: str) -> float:
    """
    Compute the Index of Coincidence (IC).
    IC = Σ f_i*(f_i - 1) / N*(N-1)
    where f_i = frequency of letter i, N = total letters.
    
    English text IC ≈ 0.065
    Random text  IC ≈ 0.038
    """
    text = text.upper()
    letters = [c for c in text if c.isalpha()]
    n = len(letters)
    if n <= 1:
        return 0.0
    counts = Counter(letters)
    numerator = sum(f * (f - 1) for f in counts.values())
    return numerator / (n * (n - 1))


def estimate_vigenere_key_length(ciphertext: str, max_key_len: int = 20) -> list[tuple[int, float]]:
    """
    Estimate Vigenère key length using IC.
    Split the text into `k` subsequences and average their ICs.
    The key length where average IC is closest to English IC (0.065) is likely correct.
    Returns sorted list of (key_length, avg_ic).
    """
    text = ''.join(c for c in ciphertext.upper() if c.isalpha())
    results = []
    for k in range(1, max_key_len + 1):
        subsequences = [text[i::k] for i in range(k)]
        ics = [index_of_coincidence(s) for s in subsequences if len(s) > 1]
        avg_ic = sum(ics) / len(ics) if ics else 0
        results.append((k, avg_ic))
    # Sort by proximity to English IC
    results.sort(key=lambda x: abs(x[1] - IC_ENGLISH))
    return results


def chi_squared_score(observed_freq: dict[str, float]) -> float:
    """
    Chi-squared distance between observed and English frequencies.
    Lower = more English-like (used in brute-force decryption).
    """
    return sum(
        (observed_freq.get(c, 0) - ENGLISH_FREQ[c]) ** 2 / ENGLISH_FREQ[c]
        for c in ENGLISH_FREQ
    )


def print_frequency_analysis(text: str) -> None:
    """Pretty-print a full frequency analysis report."""
    freqs = letter_frequencies(text)
    ic = index_of_coincidence(text)

    print("=" * 50)
    print("FREQUENCY ANALYSIS REPORT")
    print("=" * 50)
    print(f"Text length (letters): {sum(1 for c in text if c.isalpha())}")
    print(f"Index of Coincidence : {ic:.4f}  (English≈0.065, Random≈0.038)")
    print("-" * 50)
    print(f"{'Letter':<8} {'Observed%':>10} {'English%':>10} {'Diff':>8}")
    print("-" * 50)
    for letter in sorted(freqs, key=lambda x: freqs[x], reverse=True):
        obs = freqs[letter]
        exp = ENGLISH_FREQ[letter]
        print(f"  {letter:<6} {obs:>10.2f} {exp:>10.2f} {obs-exp:>+8.2f}")
    print("=" * 50)


if __name__ == "__main__":
    sample = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    print_frequency_analysis(sample)
    print(f"\nIC = {index_of_coincidence(sample):.4f}")
    print("\nEstimated Vigenère key lengths:")
    for klen, ic in estimate_vigenere_key_length(sample * 3)[:5]:
        print(f"  Key length {klen}: IC = {ic:.4f}")
