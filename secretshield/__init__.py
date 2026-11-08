"""
===============================================================================
SecretShield - Zero-Dependency Secret Detection & Git Hook Guardian
===============================================================================

SecretShield is a pure Python 3 standard library offline secret detection engine,
git pre-commit hook guardian, and environment sanitizer.

Core Features:
  - Shannon Information Entropy analysis for randomized API keys, tokens, and hashes.
  - Curated non-backtracking regular expression signatures for 35+ credential types.
  - Fast POSIX git pre-commit hook integration protecting repositories locally.
  - Configuration sanitizer and automated file redactor.
  - JSON and Markdown security audit receipt generation.

Author: Ethan Kilmer <ethan@twu.software>
License: MIT
"""

from __future__ import annotations

from secretshield.entropy import (
    calculate_shannon_entropy,
    character_frequency_distribution,
    extract_potential_tokens,
    is_high_entropy,
)
from secretshield.hook import (
    find_git_root,
    install_pre_commit_hook,
    uninstall_pre_commit_hook,
)
from secretshield.patterns import (
    SCANNER_PATTERNS,
    SecretPattern,
    find_pattern_by_id,
)
from secretshield.redactor import redact_file, redact_text
from secretshield.report import generate_json_report, generate_markdown_report
from secretshield.scanner import (
    DEFAULT_IGNORED_DIRS,
    DEFAULT_IGNORED_EXTENSIONS,
    ScanFinding,
    SecretScanner,
    mask_secret,
)

__version__ = "1.0.0"
__author__ = "Ethan Kilmer"
__all__ = [
    "calculate_shannon_entropy",
    "character_frequency_distribution",
    "extract_potential_tokens",
    "is_high_entropy",
    "find_git_root",
    "install_pre_commit_hook",
    "uninstall_pre_commit_hook",
    "SCANNER_PATTERNS",
    "SecretPattern",
    "find_pattern_by_id",
    "redact_file",
    "redact_text",
    "generate_json_report",
    "generate_markdown_report",
    "DEFAULT_IGNORED_DIRS",
    "DEFAULT_IGNORED_EXTENSIONS",
    "ScanFinding",
    "SecretScanner",
    "mask_secret",
    "__version__",
    "__author__",
]
