"""
Program: Git Secret Shield - Package Initialization & Public API
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Expose clean public API symbols for the Git Secret Shield zero-dependency security toolkit, defining version metadata and convenient imports for scanner, entropy, hook, redactor, and report generation modules.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Imports: Mathematical Shannon entropy analysis functions
## ---------------------------------------------------------------------------
## calculate_shannon_entropy: Computes informational entropy in bits/char.
## character_frequency_distribution: Probability distribution of character occurrences.
## extract_potential_tokens: Identifies candidate token strings from raw text lines.
## is_high_entropy: Calibrated threshold evaluator for hex/base64/generic tokens.
from secretshield.entropy import (
    calculate_shannon_entropy,
    character_frequency_distribution,
    extract_potential_tokens,
    is_high_entropy,
)

## ---------------------------------------------------------------------------
## Imports: Git pre-commit hook integration and lifecycle utilities
## ---------------------------------------------------------------------------
## find_git_root: Locates the parent repository root containing .git directory.
## install_pre_commit_hook: Installs or updates the POSIX pre-commit hook script.
## uninstall_pre_commit_hook: Safely removes the pre-commit hook if managed by SecretShield.
from secretshield.hook import (
    find_git_root,
    install_pre_commit_hook,
    uninstall_pre_commit_hook,
)

## ---------------------------------------------------------------------------
## Imports: Curated regex signature models and registries
## ---------------------------------------------------------------------------
## SCANNER_PATTERNS: Curated list of 35+ non-backtracking regex secret patterns.
## SecretPattern: Immutable dataclass container representing an individual pattern.
## find_pattern_by_id: Fast lookup utility matching pattern ID strings.
from secretshield.patterns import (
    SCANNER_PATTERNS,
    SecretPattern,
    find_pattern_by_id,
)

## ---------------------------------------------------------------------------
## Imports: File and in-memory credential sanitization and redaction
## ---------------------------------------------------------------------------
## redact_file: Reads a file, replaces credentials with placeholders, and saves backups.
## redact_text: Sanitizes raw multi-line strings directly in memory.
from secretshield.redactor import redact_file, redact_text

## ---------------------------------------------------------------------------
## Imports: Security audit receipt formatters (JSON and Markdown)
## ---------------------------------------------------------------------------
## generate_json_report: Constructs structured JSON audit receipt for CI/CD pipelines.
## generate_markdown_report: Generates human-readable Markdown summary with remediation advice.
from secretshield.report import generate_json_report, generate_markdown_report

## ---------------------------------------------------------------------------
## Imports: Core recursive scanner engine and finding data structures
## ---------------------------------------------------------------------------
## DEFAULT_IGNORED_DIRS: Common dependency and build directories ignored by default.
## DEFAULT_IGNORED_EXTENSIONS: File extensions skipped to avoid scanning binary files.
## ScanFinding: Dataclass recording a detected secret match or entropy violation.
## SecretScanner: Main scanner orchestrator evaluating files, directories, and git index.
## mask_secret: Security utility that redacts sensitive inner characters of a token.
from secretshield.scanner import (
    DEFAULT_IGNORED_DIRS,
    DEFAULT_IGNORED_EXTENSIONS,
    ScanFinding,
    SecretScanner,
    mask_secret,
)

## ---------------------------------------------------------------------------
## Package Metadata Constants
## ---------------------------------------------------------------------------
## Package semantic version identifier
__version__ = "1.0.0"

## Primary author and project maintainer
__author__ = "Ethan Kilmer"

## ---------------------------------------------------------------------------
## Public API Symbol Export Manifest (__all__)
## ---------------------------------------------------------------------------
## Explicit declaration of all public symbols exported by the secretshield package.
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
