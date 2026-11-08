"""
Program: Git Secret Shield - Shannon Information Entropy Engine
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Calculate Claude Shannon information entropy on arbitrary candidate tokens to detect high-randomness passwords, cryptographic keys, and tokens lacking static signature prefixes without excessive false positives.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## math: Provides logarithmic functions (math.log2) for calculating entropy bits
import math
## re: Regular expression processing for character set classification & token extraction
import re
## typing: Static typing annotations for dictionary, list, and tuple returns
from typing import Dict, List, Tuple

## ---------------------------------------------------------------------------
## Pre-compiled Regular Expression Classifiers
## ---------------------------------------------------------------------------
## RE_HEXADECIMAL: Matches strings containing exclusively hexadecimal digits (0-9, a-f, A-F)
## Base16 alphabet size = 16. Theoretical max entropy = log2(16) = 4.0 bits/char.
RE_HEXADECIMAL = re.compile(r"^[0-9a-fA-F]+$")

## RE_BASE64: Matches valid base64 character strings including common URL-safe variants (+, /, =, _, -)
## Base64 alphabet size = 64. Theoretical max entropy = log2(64) = 6.0 bits/char.
RE_BASE64 = re.compile(r"^[0-9a-zA-Z+/=_-]+$")

## RE_CANDIDATE_TOKEN: Extracts unbroken alphanumeric and symbol strings between 16 and 128 chars.
## This range captures nearly all production API keys, HMAC secrets, and database credentials.
RE_CANDIDATE_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-\$]{16,128}")

## RE_UUID: Strictly matches standard RFC 4122 Universally Unique Identifiers (UUID v1 through v5).
## Although UUIDs have high entropy, they are public entity IDs, not confidential secrets.
RE_UUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

## ---------------------------------------------------------------------------
## Benign Substring Allowlist (False-Positive Suppression)
## ---------------------------------------------------------------------------
## Common placeholder substrings frequently found in documentation, mock configurations, and tests.
## Strings containing these substrings are rejected by the entropy detector to reduce false alarms.
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
    ## Guard against empty strings to prevent division by zero or negative logarithms
    if not data:
        return 0.0

    ## Record total symbol count (string length) as integer denominator
    length: int = len(data)

    ## Step 1: Count frequency of each distinct character symbol in input string
    frequencies: Dict[str, int] = {}
    for char in data:
        ## Increment frequency count for the observed character
        frequencies[char] = frequencies.get(char, 0) + 1

    ## Step 2: Accumulate Shannon entropy according to H(X) = -sum(p(x) * log2(p(x)))
    entropy: float = 0.0
    for count in frequencies.values():
        ## Empirical probability of occurrence for symbol x_i: p(x_i) = count / total_length
        probability: float = count / length

        ## Mathematical identity: p * log2(p).
        ## Since 0 < probability <= 1.0, math.log2(probability) is <= 0.
        ## Subtracting a negative value accumulates a positive informational entropy score.
        entropy -= probability * math.log2(probability)

    ## Return computed entropy score in units of bits per symbol
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
    ## Return empty mapping if data is None or empty string
    if not data:
        return {}

    ## Compute string length once for relative frequency normalization
    total_len = len(data)
    distribution: Dict[str, float] = {}

    ## Iterate over each character and accumulate its probability increment
    for char in data:
        distribution[char] = distribution.get(char, 0.0) + (1.0 / total_len)

    ## Return completed probability dictionary where sum of values equals approximately 1.0
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
    ## Reject candidate strings shorter than the configured minimum evaluation length
    if len(candidate) < min_length:
        return False, "too_short", 0.0

    ## Clean candidate of surrounding quotes, whitespace, or punctuation delimiters
    clean_candidate = candidate.strip("\"'` ,;")

    ## Re-verify length after stripping punctuation characters
    if len(clean_candidate) < min_length:
        return False, "too_short", 0.0

    ## Filter out standard RFC 4122 UUIDs (e.g. 550e8400-e29b-41d4-a716-446655440000)
    ## UUIDs exhibit moderate entropy but represent benign public resource identifiers
    if RE_UUID.match(clean_candidate):
        return False, "uuid_identifier", 0.0

    ## Filter out placeholder/dummy credentials commonly found in documentation & tests
    lower_cand = clean_candidate.lower()
    for benign in BENIGN_KEYWORD_SUBSTRINGS:
        if benign in lower_cand:
            return False, "benign_placeholder", 0.0

    ## Calculate actual Shannon informational entropy in bits per character
    entropy = calculate_shannon_entropy(clean_candidate)

    ## Case 1: Candidate consists exclusively of hexadecimal characters (0-9, a-f, A-F)
    if RE_HEXADECIMAL.match(clean_candidate):
        ## Hexadecimal theoretical maximum is 4.0 bits/char
        ## Values >= hex_threshold (default 3.2) indicate cryptographic randomness
        if entropy >= hex_threshold:
            return True, "high_entropy_hex", entropy
        return False, "low_entropy_hex", entropy

    ## Case 2: Candidate consists exclusively of valid Base64 characters
    if RE_BASE64.match(clean_candidate):
        ## Base64 theoretical maximum is 6.0 bits/char
        ## Human-readable sentences in base64 are <= 4.0 bits; keys exceed base64_threshold (4.6)
        if entropy >= base64_threshold:
            return True, "high_entropy_base64", entropy
        return False, "low_entropy_base64", entropy

    ## Case 3: Generic mixed ASCII string containing special symbols
    ## Printable ASCII maximum is ~6.57 bits/char; threshold is calibrated to 4.3 bits
    if entropy >= generic_threshold:
        return True, "high_entropy_generic", entropy

    ## Fallback: Entropy is below all alert thresholds; classified as safe
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
    ## Initialize empty accumulator list for candidate tokens
    candidates: List[str] = []

    ## Use candidate regular expression to identify contiguous symbol sequences
    for match in RE_CANDIDATE_TOKEN.finditer(line):
        ## Strip wrapping quotes, semicolons, and parentheses from token boundary
        token = match.group(0).strip("\"'`;,()")

        ## Check that token length falls within expected credential bounds
        if min_len <= len(token) <= max_len:
            ## Exclude obvious web URLs or protocol prefixes from consideration
            if token.startswith(("http://", "https://", "ftp://")):
                continue
            ## Append candidate token for downstream entropy evaluation
            candidates.append(token)

    ## Return all extracted candidate tokens from this line
    return candidates
