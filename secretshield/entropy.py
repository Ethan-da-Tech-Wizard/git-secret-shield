"""
===============================================================================
SecretShield - Shannon Entropy Calculation Engine
===============================================================================

This module implements Shannon Information Entropy analysis to detect high-entropy
randomized strings (e.g., cryptographic keys, database passwords, high-randomness
API tokens) that lack static recognizable signature prefixes.

Mathematical Theory:
--------------------
Claude Shannon defined Information Entropy in his landmark 1948 paper
"A Mathematical Theory of Communication". For a discrete random variable X
taking values in an alphabet with probabilities p(x_i):

    H(X) = - SUM_{i=1}^{n} p(x_i) * log2( p(x_i) )

Where:
  - n is the count of distinct symbols observed in the string.
  - p(x_i) is the empirical probability (relative frequency) of character x_i.
  - log2 is the base-2 logarithm, expressing entropy in bits per symbol.
  - H(X) measures the average amount of "surprise" or uncertainty per character.

Alphabet Theoretical Bounds:
  - Base16 (Hexadecimal: 0-9, a-f): Alphabet size 16 -> max entropy = log2(16) = 4.0 bits/char.
  - Base64 (A-Z, a-z, 0-9, +, /): Alphabet size 64 -> max entropy = log2(64) = 6.0 bits/char.
  - Printable ASCII (95 chars): Alphabet size 95 -> max entropy = log2(95) ≈ 6.57 bits/char.

By dynamically detecting the character set of a candidate token, we can calibrate
the detection threshold to avoid catastrophic false positives on natural text
while aggressively detecting machine-generated randomness.
"""

from __future__ import annotations

import math
import re
from typing import Dict, List, Tuple


# Pre-compiled regular expressions for character set classification
# Used to classify candidate tokens into hex, base64, or generic ASCII sets.
RE_HEXADECIMAL = re.compile(r"^[0-9a-fA-F]+$")
RE_BASE64 = re.compile(r"^[0-9a-zA-Z+/=_-]+$")

# Candidate token extractor: extracts continuous alphanumeric and symbol sequences
# that have typical token lengths (16 to 128 characters).
RE_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-\$]{16,128}")

# UUID pattern filter: standard UUIDs (RFC 4122) are frequently high entropy but
# are almost universally public identifiers rather than cryptographic secrets.
RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

# Common safe identifier patterns (e.g. SHA-256 commit hashes, git object IDs,
# known benign placeholder tokens like 'example', 'placeholder', 'dummy').
BENIGN_KEYWORD_SUBSTRINGS = (
    "example",
    "placeholder",
    "dummy",
    "changeme",
    "your_key_here",
    "insert_token",
    "00000000",
    "11111111",
    "abcdef",
)


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of an input string in bits per character.

    Steps:
      1. Handle boundary cases (empty string -> 0.0 bits).
      2. Count the frequency of each unique character in the string.
      3. Compute empirical probability p = count / total_length for each symbol.
      4. Sum -p * log2(p) for all unique symbols.

    Args:
        data: The input string whose informational entropy will be measured.

    Returns:
        A float representing the entropy in bits (0.0 to ~6.57 for printable ASCII).

    Examples:
        >>> calculate_shannon_entropy("AAAAAAA")  # Zero uncertainty
        0.0
        >>> calculate_shannon_entropy("0123456789abcdef")  # Hex alphabet uniform
        4.0
    """
    # Guard against empty strings to prevent division by zero
    if not data:
        return 0.0

    length: int = len(data)

    # Step 1: Count frequency of each distinct character
    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    # Step 2: Sum the Shannon entropy formula: H(X) = -sum(p(x) * log2(p(x)))
    entropy: float = 0.0
    for count in frequencies.values():
        probability: float = count / length
        # Mathematical identity: p * log2(p)
        # Note: 0 < probability <= 1.0, so log2(probability) is <= 0.
        entropy -= probability * math.log2(probability)

    return entropy


def character_frequency_distribution(data: str) -> Dict[str, float]:
    """
    Compute the relative empirical probability distribution of characters.

    Useful for diagnostics, debugging false positives, and analyzing symbol
    uniformity within candidate secret strings.

    Args:
        data: The string to analyze.

    Returns:
        A dictionary mapping each distinct character to its probability (0.0 to 1.0).
    """
    if not data:
        return {}

    total_len = len(data)
    distribution: Dict[str, float] = {}

    for char in data:
        distribution[char] = distribution.get(char, 0.0) + (1.0 / total_len)

    return distribution


def is_high_entropy(
    candidate: str,
    hex_threshold: float = 3.2,
    base64_threshold: float = 4.6,
    generic_threshold: float = 4.3,
    min_length: int = 20,
) -> Tuple[bool, str, float]:
    """
    Determine if a candidate token exhibits statistically suspicious entropy.

    Different character sets possess different theoretical maximum entropies:
      - Hexadecimal strings cap at 4.0 bits/char. A hex string above 3.2 bits
        is uniformly distributed and indicative of a 128-bit, 256-bit or 512-bit
        cryptographic hash, private key, or secret salt.
      - Base64 strings cap at 6.0 bits/char. Natural text encoded in base64
        rarely exceeds 4.0 bits, while high-randomness tokens exceed 4.6 bits.
      - Generic alphanumeric passwords/tokens with mixed symbols exceed 4.3 bits.

    Filters are applied to reject common false positives:
      - Length checks (< min_length characters).
      - Standard RFC 4122 UUIDs.
      - Known placeholder substrings ('dummy', 'example', 'your_key_here').
      - Monotonous repeated characters ('aaaaa...', '12345...').

    Args:
        candidate: The raw candidate string to test.
        hex_threshold: Minimum bits/char for hexadecimal candidates.
        base64_threshold: Minimum bits/char for base64 candidates.
        generic_threshold: Minimum bits/char for general strings.
        min_length: Minimum character length required before testing entropy.

    Returns:
        A tuple of (is_secret: bool, charset_type: str, measured_entropy: float).
    """
    # Reject strings shorter than our minimum meaningful secret length
    if len(candidate) < min_length:
        return False, "too_short", 0.0

    # Clean candidate of surrounding quotes or whitespace
    clean_candidate = candidate.strip("\"'` ,;")

    if len(clean_candidate) < min_length:
        return False, "too_short", 0.0

    # Filter out standard RFC 4122 UUIDs (e.g. 550e8400-e29b-41d4-a716-446655440000)
    if RE_UUID.match(clean_candidate):
        return False, "uuid_identifier", 0.0

    # Filter out dummy/placeholder credentials commonly found in documentation & tests
    lower_cand = clean_candidate.lower()
    for benign in BENIGN_KEYWORD_SUBSTRINGS:
        if benign in lower_cand:
            return False, "benign_placeholder", 0.0

    # Calculate actual Shannon entropy
    entropy = calculate_shannon_entropy(clean_candidate)

    # Classify character set and evaluate against tailored thresholds
    if RE_HEXADECIMAL.match(clean_candidate):
        # Hexadecimal space: 16 possible symbols (0-9, a-f)
        if entropy >= hex_threshold:
            return True, "high_entropy_hex", entropy
        return False, "low_entropy_hex", entropy

    if RE_BASE64.match(clean_candidate):
        # Base64 space: 64 possible symbols
        if entropy >= base64_threshold:
            return True, "high_entropy_base64", entropy
        return False, "low_entropy_base64", entropy

    # Generic mixed ASCII space
    if entropy >= generic_threshold:
        return True, "high_entropy_generic", entropy

    return False, "low_entropy_generic", entropy


def extract_potential_tokens(
    line: str,
    min_len: int = 20,
    max_len: int = 120,
) -> List[str]:
    """
    Extract candidate credential token strings from an arbitrary line of code or text.

    Finds contiguous sequences of non-whitespace characters that match token length
    boundaries and are not typical code keywords or URLs.

    Args:
        line: The text line to inspect.
        min_len: Minimum token length.
        max_len: Maximum token length.

    Returns:
        A list of candidate token strings suitable for entropy analysis.
    """
    candidates: List[str] = []

    # Use candidate regex to find long unbroken alphanumeric/symbol sequences
    for match in RE_CANDIDATE_TOKEN.finditer(line):
        token = match.group(0).strip("\"'`;,()")
        if min_len <= len(token) <= max_len:
            # Skip obvious URL hosts or protocol prefixes
            if token.startswith(("http://", "https://", "ftp://")):
                continue
            candidates.append(token)

    return candidates
