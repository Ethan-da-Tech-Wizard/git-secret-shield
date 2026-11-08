"""
Program: Git Secret Shield - Recursive Secret & Entropy Scanner Engine
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Recursively inspect files, directories, text streams, and Git staged patches using two-phase detection (deterministic regex signatures plus Shannon entropy analysis) with binary exclusion and safe secret masking.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## os: Directory traversal (os.walk) and path handling
import os
## subprocess: Executes git commands (`git diff --cached`) for staged hook scanning
import subprocess
## dataclasses: Data container models for findings (asdict converts dataclass to dict)
from dataclasses import asdict, dataclass
## pathlib.Path: Object-oriented filesystem path navigation
from pathlib import Path
## typing: Static typing annotations for collections and generator returns
from typing import Dict, Generator, Iterable, List, Optional, Set, Tuple

## ---------------------------------------------------------------------------
## Internal Imports
## ---------------------------------------------------------------------------
## extract_potential_tokens, is_high_entropy: Entropy evaluation utilities
from secretshield.entropy import extract_potential_tokens, is_high_entropy
## SCANNER_PATTERNS, SecretPattern: Curated signature pattern definitions
from secretshield.patterns import SCANNER_PATTERNS, SecretPattern

## ---------------------------------------------------------------------------
## Scanner Exclusion Sets
## ---------------------------------------------------------------------------
## Directories excluded during recursive traversal (dependency caches, venvs, IDEs)
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

## File extensions skipped to avoid processing binary media, fonts, and compiled artifacts
DEFAULT_IGNORED_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".bz2", ".xz",
    ".exe", ".bin", ".so", ".dylib", ".dll", ".o", ".a",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".pyd",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".iso", ".dmg", ".qcow2",
}

## Dependency lockfiles containing thousands of non-secret cryptographic checksums
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
    ## Calculate total secret length
    length = len(secret)

    ## If secret is too short to show leading and trailing characters safely, mask entirely
    if length <= (visible_start + visible_end):
        return "*" * length

    ## Compute number of asterisks needed for the middle redaction span
    mask_len = length - (visible_start + visible_end)

    ## Return composite string: unmasked prefix + masked asterisks + unmasked suffix
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
    ## Open file in binary read mode to inspect initial chunk
    try:
        with open(path, "rb") as f:
            chunk = f.read(block_size)
            ## Check for presence of null byte (b'\x00')
            return b"\x00" in chunk
    except (OSError, PermissionError):
        ## If file cannot be read, treat as non-text to avoid crashing the scanner
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
        ## Convert dataclass fields to standard dictionary
        data = asdict(self)
        ## Strictly purge raw plaintext secret from serialized representation
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
        ## Assign signature patterns; default to full built-in pattern suite
        self.patterns = patterns if patterns is not None else SCANNER_PATTERNS
        ## Boolean flag controlling secondary Shannon entropy analysis
        self.check_entropy = check_entropy
        ## Minimum character length threshold before evaluating candidate token entropy
        self.entropy_min_length = entropy_min_length
        ## Directory exclusion set
        self.ignored_dirs = ignored_dirs if ignored_dirs is not None else DEFAULT_IGNORED_DIRS
        ## File extension exclusion set
        self.ignored_extensions = (
            ignored_extensions if ignored_extensions is not None else DEFAULT_IGNORED_EXTENSIONS
        )
        ## Specific filename exclusion set (lockfiles)
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
        ## Verify file exists and is a regular file (not directory or socket)
        if not path.is_file():
            return False

        ## Check if filename matches ignored lockfile list (e.g. package-lock.json)
        if path.name in self.ignored_files:
            return False

        ## Check if file extension matches binary or media exclusions (.png, .zip, etc.)
        if path.suffix.lower() in self.ignored_extensions:
            return False

        ## Check if any folder component along the path is in the ignored set
        for part in path.parts:
            if part in self.ignored_dirs:
                return False

        ## Probe file contents for binary null bytes
        if is_binary_file(path):
            return False

        ## File passed all exclusion checks; eligible for secret scanning
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
        ## Findings accumulator for this line
        findings: List[ScanFinding] = []
        ## Track character start/end spans of confirmed signature matches to suppress redundant entropy alerts
        matched_spans: Set[Tuple[int, int]] = set()

        ## ---------------------------------------------------------------------
        ## Phase 1: Curated Signature Pattern Matching
        ## ---------------------------------------------------------------------
        for pattern in self.patterns:
            ## Evaluate regular expression across the line
            for match in pattern.regex.finditer(line):
                ## Extract captured group 1 if defined; otherwise full matched string
                secret_text = match.group(1) if match.lastindex else match.group(0)

                ## Store span indices for overlap checking
                matched_spans.add(match.span())

                ## Construct signature detection finding record
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

        ## ---------------------------------------------------------------------
        ## Phase 2: Shannon Entropy Analysis (if enabled)
        ## ---------------------------------------------------------------------
        if self.check_entropy:
            ## Extract contiguous candidate token strings meeting minimum length
            candidates = extract_potential_tokens(line, min_len=self.entropy_min_length)
            for candidate in candidates:
                ## Determine token position in line to check for overlap with Phase 1 matches
                token_start = line.find(candidate)
                if token_start != -1:
                    token_span = (token_start, token_start + len(candidate))
                    ## If candidate overlaps with a high-confidence signature match, skip it
                    if any(
                        s[0] <= token_span[0] and s[1] >= token_span[1]
                        for s in matched_spans
                    ):
                        continue

                ## Evaluate candidate token entropy against calibrated thresholds
                is_suspicious, charset_type, entropy = is_high_entropy(
                    candidate,
                    min_length=self.entropy_min_length,
                )

                ## If entropy exceeds the character set threshold, record an alert
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

        ## Return all detected findings for this line
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
        ## Iterate over lines with 1-based indexing
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
        ## Verify file meets scanning criteria
        if not self.should_scan_file(path):
            return []

        findings: List[ScanFinding] = []
        try:
            ## Open text file with UTF-8 decoding and replacement for non-decodable bytes
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line_idx, line in enumerate(f, start=1):
                    line_findings = self.scan_line(line, line_idx, str(path))
                    findings.extend(line_findings)
        except (OSError, PermissionError):
            ## Silently ignore unreadable or permission-restricted files
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

        ## Validate directory existence
        if not directory.exists() or not directory.is_dir():
            return []

        if recursive:
            ## Walk directory tree recursively
            for root, dirs, files in os.walk(directory):
                ## In-place prune ignored directories from traversal list
                dirs[:] = [d for d in dirs if d not in self.ignored_dirs]

                root_path = Path(root)
                for file_name in files:
                    file_path = root_path / file_name
                    if self.should_scan_file(file_path):
                        all_findings.extend(self.scan_file(file_path))
        else:
            ## Non-recursive shallow scan of immediate directory files
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
        ## Default to current working directory if repo_path not explicitly specified
        target_dir = repo_path or Path.cwd()

        ## Execute git diff against cached staging index
        try:
            cmd = ["git", "diff", "--cached", "--unified=0", "--no-color"]
            result = subprocess.run(
                cmd,
                cwd=target_dir,
                capture_output=True,
                text=True,
                check=False,
            )
            ## Return empty list if git diff exited with error (e.g. non-git directory)
            if result.returncode != 0:
                return []
        except (FileNotFoundError, OSError):
            ## Git binary not found on PATH
            return []

        findings: List[ScanFinding] = []
        current_file: Optional[str] = None
        current_line_num: int = 1

        ## Parse standard unified diff output stream
        for line in result.stdout.splitlines():
            ## File target header: '+++ b/path/to/file.py'
            if line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue
            ## File deletion header: '+++ /dev/null'
            elif line.startswith("+++ /dev/null"):
                current_file = None
                continue

            ## Chunk range indicator: '@@ -old,count +new,count @@'
            if line.startswith("@@"):
                parts = line.split()
                for part in parts:
                    if part.startswith("+"):
                        ## Extract newly added line number
                        num_str = part[1:].split(",")[0]
                        try:
                            current_line_num = int(num_str)
                        except ValueError:
                            current_line_num = 1
                continue

            ## Added content line (starts with '+' but not '+++')
            if line.startswith("+") and not line.startswith("+++"):
                if current_file:
                    target_file_path = target_dir / current_file
                    ## Verify file is not excluded (e.g. not lockfile or binary)
                    if self.should_scan_file(target_file_path):
                        added_text = line[1:]  ## Strip leading '+' diff marker
                        line_findings = self.scan_line(
                            added_text,
                            current_line_num,
                            current_file,
                        )
                        findings.extend(line_findings)
                ## Increment line counter for next line in this hunk
                current_line_num += 1

        return findings
