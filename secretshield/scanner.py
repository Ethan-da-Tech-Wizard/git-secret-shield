"""
===============================================================================
SecretShield - Recursive Secret & Entropy Scanner Engine
===============================================================================

This module provides the core scanning engine that processes individual files,
directory trees, and git staged changes to uncover hardcoded secrets.

Key Architectural Capabilities:
--------------------------------
1. Dual-Engine Detection Pipeline:
   - Stage 1: Deterministic signature matching against curated regex patterns
     (35+ vendor and credential formats).
   - Stage 2: Information-theoretic Shannon entropy analysis for unknown,
     randomized keys, tokens, and cryptographic seeds.

2. Fast Binary & False-Positive Elimination:
   - Immediate rejection of binary files (zero-byte probing within initial block).
   - Exclusion of dependency trees (`node_modules`, `.venv`), source control
     metadata (`.git`), build artifacts, and package manager lockfiles.

3. Git Staged Pre-Commit Optimization:
   - Parses `git diff --cached --unified=0` to inspect exclusively modified
     or newly inserted lines prior to commit finalization.
   - Prevents blocking commits due to legacy secrets already present elsewhere
     in existing repository history.

4. Safe Secret Masking:
   - Findings redact all sensitive characters by default (e.g. `AKIA************`),
     preventing accidental leakage into logs, dashboards, or CI console transcripts.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Generator, Iterable, List, Optional, Set, Tuple

from secretshield.entropy import extract_potential_tokens, is_high_entropy
from secretshield.patterns import SCANNER_PATTERNS, SecretPattern


# Ignored directory names (dependency trees, build artifacts, venvs)
DEFAULT_IGNORED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".tox",
    ".idea",
    ".vscode",
}

# Ignored binary and media file extensions
DEFAULT_IGNORED_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".bz2", ".xz",
    ".exe", ".bin", ".so", ".dylib", ".dll", ".o", ".a",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".pyd",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".iso", ".dmg", ".qcow2",
}

# Lockfiles that contain thousands of non-secret cryptographic package hashes
DEFAULT_IGNORED_FILENAMES: Set[str] = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
}


def mask_secret(secret: str, visible_start: int = 4, visible_end: int = 4) -> str:
    """
    Safely mask a detected secret string for terminal output and reports.

    Example:
      'AKIA1234567890ABCDEF' -> 'AKIA************CDEF'

    Args:
        secret: The plaintext secret string.
        visible_start: Number of leading characters to keep visible.
        visible_end: Number of trailing characters to keep visible.

    Returns:
        The masked secret string.
    """
    length = len(secret)
    if length <= (visible_start + visible_end):
        # String too short for partial masking; mask completely
        return "*" * length

    mask_len = length - (visible_start + visible_end)
    return secret[:visible_start] + ("*" * mask_len) + secret[-visible_end:]


def is_binary_file(path: Path, block_size: int = 1024) -> bool:
    """
    Check if a file contains binary content by probing the first block for null bytes.

    Standard POSIX convention: text files rarely contain ASCII NUL (\x00),
    whereas compiled binaries, images, and archives contain null bytes.

    Args:
        path: Path to the file.
        block_size: Number of bytes to inspect from the head of the file.

    Returns:
        True if the file is detected as binary, False otherwise.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(block_size)
            return b"\x00" in chunk
    except (OSError, PermissionError):
        # If unreadable, treat as non-text to avoid scanner crashes
        return True


@dataclass
class ScanFinding:
    """
    Record of a detected secret or high-entropy credential.

    Attributes:
        file_path: Relative or absolute path where secret was found.
        line_number: 1-based line number.
        pattern_name: Identifier of the matched signature or 'High Entropy Candidate'.
        pattern_id: Machine-readable signature id.
        severity: Severity level ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence: Signal confidence rating ('HIGH', 'MEDIUM', 'LOW').
        secret_preview: Masked representation of the secret.
        remediation: Specific advice to revoke and rotate the secret.
        detection_type: Either 'signature' or 'entropy'.
        entropy_score: Measured bits/character if entropy analysis was executed.
        raw_secret: Plaintext value (retained in-memory only for optional redaction).
    """
    file_path: str
    line_number: int
    pattern_name: str
    pattern_id: str
    severity: str
    confidence: str
    secret_preview: str
    remediation: str
    detection_type: str = "signature"
    entropy_score: Optional[float] = None
    raw_secret: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        """Convert finding to a JSON-serializable dictionary without exposing raw secrets."""
        data = asdict(self)
        # Never serialize raw plaintext secret to dictionary outputs
        data.pop("raw_secret", None)
        return data


class SecretScanner:
    """
    Core secret scanner engine that traverses paths, inspects lines,
    evaluates regex signatures, and calculates Shannon entropy.
    """

    def __init__(
        self,
        patterns: Optional[List[SecretPattern]] = None,
        check_entropy: bool = True,
        entropy_min_length: int = 20,
        ignored_dirs: Optional[Set[str]] = None,
        ignored_extensions: Optional[Set[str]] = None,
        ignored_files: Optional[Set[str]] = None,
    ) -> None:
        """
        Initialize the scanner with configurable pattern rules and filters.

        Args:
            patterns: List of SecretPattern objects to evaluate (defaults to SCANNER_PATTERNS).
            check_entropy: Whether to execute Shannon entropy analysis on candidate tokens.
            entropy_min_length: Minimum string length to subject to entropy evaluation.
            ignored_dirs: Set of directory names to skip during recursive traversal.
            ignored_extensions: Set of file extensions to skip.
            ignored_files: Set of exact filenames to skip.
        """
        self.patterns = patterns if patterns is not None else SCANNER_PATTERNS
        self.check_entropy = check_entropy
        self.entropy_min_length = entropy_min_length
        self.ignored_dirs = ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS
        self.ignored_extensions = (
            ignored_extensions if ignored_extensions is not None else DEFAULT_IGNORED_EXTENSIONS
        )
        self.ignored_files = (
            ignored_files if ignored_files is not None else DEFAULT_IGNORED_FILENAMES
        )

    def should_scan_file(self, path: Path) -> bool:
        """
        Determine if a file path is eligible for scanning.

        Checks:
          - File existence and regular file type.
          - File extension exclusions.
          - Filename exclusions (e.g. lockfiles).
          - Path segments against ignored directories.
          - Binary content detection.

        Args:
            path: Path to the target file.

        Returns:
            True if file should be scanned, False if skipped.
        """
        if not path.is_file():
            return False

        # Check ignored filenames (e.g., package-lock.json)
        if path.name in self.ignored_files:
            return False

        # Check file extension
        if path.suffix.lower() in self.ignored_extensions:
            return False

        # Check if any parent folder is in the ignored list
        for part in path.parts:
            if part in self.ignored_dirs:
                return False

        # Check for binary file structure
        if is_binary_file(path):
            return False

        return True

    def scan_line(
        self,
        line: str,
        line_number: int,
        file_path: str,
    ) -> List[ScanFinding]:
        """
        Scan a single line of text for signature pattern matches and entropy anomalies.

        Args:
            line: The text line content.
            line_number: The line number in the source file.
            file_path: Human-readable file path identifier.

        Returns:
            List of ScanFinding records identified on this line.
        """
        findings: List[ScanFinding] = []
        matched_spans: Set[Tuple[int, int]] = set()

        # Phase 1: Curated Signature Pattern Matching
        for pattern in self.patterns:
            for match in pattern.regex.finditer(line):
                # If pattern has a capturing group, use group 1; otherwise entire match
                secret_text = match.group(1) if match.lastindex else match.group(0)

                # Record matched character span to avoid redundant entropy alert
                matched_spans.add(match.span())

                finding = ScanFinding(
                    file_path=file_path,
                    line_number=line_number,
                    pattern_name=pattern.name,
                    pattern_id=pattern.id,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    secret_preview=mask_secret(secret_text),
                    remediation=pattern.remediation,
                    detection_type="signature",
                    raw_secret=secret_text,
                )
                findings.append(finding)

        # Phase 2: Shannon Entropy Analysis (if enabled)
        if self.check_entropy:
            candidates = extract_potential_tokens(line, min_len=self.entropy_min_length)
            for candidate in candidates:
                # Check if candidate token overlaps with an already-flagged signature match
                token_start = line.find(candidate)
                if token_start != -1:
                    token_span = (token_start, token_start + len(candidate))
                    if any(
                        s[0] <= token_span[0] and s[1] >= token_span[1]
                        for s in matched_spans
                    ):
                        # Already matched by a high-confidence signature
                        continue

                is_suspicious, charset_type, entropy = is_high_entropy(
                    candidate,
                    min_length=self.entropy_min_length,
                )

                if is_suspicious:
                    finding = ScanFinding(
                        file_path=file_path,
                        line_number=line_number,
                        pattern_name=f"High Shannon Entropy Token ({charset_type})",
                        pattern_id=f"entropy_{charset_type}",
                        severity="HIGH",
                        confidence="MEDIUM",
                        secret_preview=mask_secret(candidate),
                        remediation=(
                            "Detected token with statistically high information entropy. "
                            "Verify if this string represents an unencrypted API secret or private key. "
                            "Extract into an environment variable if confidential."
                        ),
                        detection_type="entropy",
                        entropy_score=round(entropy, 3),
                        raw_secret=candidate,
                    )
                    findings.append(finding)

        return findings

    def scan_text(self, text: str, source_name: str = "<memory>") -> List[ScanFinding]:
        """
        Scan a block of multi-line text directly in memory.

        Args:
            text: String content to scan.
            source_name: Virtual source label for reporting.

        Returns:
            List of ScanFinding records.
        """
        findings: List[ScanFinding] = []
        for line_idx, line in enumerate(text.splitlines(), start=1):
            findings.extend(self.scan_line(line, line_idx, source_name))
        return findings

    def scan_file(self, path: Path) -> List[ScanFinding]:
        """
        Scan a single file from disk.

        Args:
            path: Target file path.

        Returns:
            List of ScanFinding records.
        """
        if not self.should_scan_file(path):
            return []

        findings: List[ScanFinding] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line_idx, line in enumerate(f, start=1):
                    line_findings = self.scan_line(line, line_idx, str(path))
                    findings.extend(line_findings)
        except (OSError, PermissionError):
            # Gracefully handle file read exceptions
            return []

        return findings

    def scan_directory(
        self,
        directory: Path,
        recursive: bool = True,
    ) -> List[ScanFinding]:
        """
        Recursively scan a directory tree for secrets.

        Args:
            directory: Root directory path to scan.
            recursive: Whether to traverse child subdirectories.

        Returns:
            List of all ScanFinding records across all scanned files.
        """
        all_findings: List[ScanFinding] = []

        if not directory.exists() or not directory.is_dir():
            return []

        if recursive:
            for root, dirs, files in os.walk(directory):
                # In-place modify dirs to prune ignored subdirectories during os.walk
                dirs[:] = [d for d in dirs if d not in self.ignored_dirs]

                root_path = Path(root)
                for file_name in files:
                    file_path = root_path / file_name
                    if self.should_scan_file(file_path):
                        all_findings.extend(self.scan_file(file_path))
        else:
            for item in directory.iterdir():
                if item.is_file() and self.should_scan_file(item):
                    all_findings.extend(self.scan_file(item))

        return all_findings

    def scan_git_staged(self, repo_path: Optional[Path] = None) -> List[ScanFinding]:
        """
        Inspect git staged changes using `git diff --cached --unified=0`.

        Only newly added or altered lines (`+`) in the git staging area are scanned.
        This provides instantaneous pre-commit hook feedback and prevents
        nuisance alerts on untouched legacy code.

        Args:
            repo_path: Root of the git repository (defaults to current working directory).

        Returns:
            List of ScanFinding records detected in staged additions.
        """
        target_dir = repo_path or Path.cwd()

        # Run git diff --cached to get raw staged patch
        try:
            cmd = ["git", "diff", "--cached", "--unified=0", "--no-color"]
            result = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                # Git command failed (e.g. not a git repository)
                return []
        except (FileNotFoundError, OSError):
            # git executable not available in environment PATH
            return []

        findings: List[ScanFinding] = []
        current_file: Optional[str] = None
        current_line_num: int = 1

        for line in result.stdout.splitlines():
            # Header line: '+++ b/path/to/file.py'
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue
            elif line.startswith("+++ /dev/null"):
                current_file = None
                continue

            # Chunk header: '@@ -old,count +new,count @@'
            if line.startswith("@@"):
                parts = line.split()
                for part in parts:
                    if part.startswith("+"):
                        # Extract starting line number: e.g. '+42,5' or '+42'
                        num_str = part[1:].split(",")[0]
                        try:
                            current_line_num = int(num_str)
                        except ValueError:
                            current_line_num = 1
                continue

            # Added line: begins with '+' and not '+++'
            if line.startswith("+") and not line.startswith("+++"):
                if current_file:
                    target_file_path = target_dir / current_file
                    # Skip if the file matches an ignored pattern or is binary
                    if self.should_scan_file(target_file_path):
                        added_text = line[1:]  # strip leading '+'
                        line_findings = self.scan_line(
                            added_text,
                            current_line_num,
                            current_file,
                        )
                        findings.extend(line_findings)
                current_line_num += 1

        return findings
