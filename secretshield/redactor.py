"""
Program: Git Secret Shield - File Sanitizer & Credential Redactor
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Sanitize sensitive environment files and text configurations in-place or to new destination files with automatic backup preservation and standardized redaction placeholders.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## shutil: High-level filesystem operations (copy2 preserves file timestamps and metadata)
import shutil
## pathlib.Path: Object-oriented filesystem path handling
from pathlib import Path
## typing: Static type definitions for return values and optional parameters
from typing import List, Optional, Tuple

## ---------------------------------------------------------------------------
## Internal Imports
## ---------------------------------------------------------------------------
## SecretScanner: Engine used to identify leaked secrets within input text
from secretshield.scanner import SecretScanner


def redact_text(
    content: str,
    scanner: Optional[SecretScanner] = None,
    replacement_format: str = "[REDACTED_{pattern_id}]",
) -> Tuple[str, int]:
    """
    Scan a string for secrets and replace all detected occurrences.

    Args:
        content: The input text to sanitize.
        scanner: Optional SecretScanner instance.
        replacement_format: Template format string using finding attributes.

    Returns:
        Tuple of (sanitized_text: str, redaction_count: int).
    """
    ## Default to signature-only scanner if no explicit scanner instance provided
    ## Entropy scanning is disabled by default during text redaction to prevent accidental
    ## disruption of legitimate high-entropy non-secret variable values.
    if scanner is None:
        scanner = SecretScanner(check_entropy=False)

    ## Execute scan against memory text
    findings = scanner.scan_text(content)
    if not findings:
        return content, 0

    ## Initialize working content and replacement counter
    redacted_content = content
    count = 0

    ## Filter out findings lacking raw secret representations
    valid_findings = [f for f in findings if f.raw_secret]

    ## Sort findings by raw_secret length in descending order.
    ## This is a critical algorithmic safety step: replacing longer composite secrets first
    ## prevents shorter overlapping substrings from destroying string replacement boundaries.
    valid_findings.sort(key=lambda f: len(f.raw_secret or ""), reverse=True)

    ## Maintain set of already sanitized raw secret strings to prevent redundant replacements
    seen_secrets = set()
    for finding in valid_findings:
        raw = finding.raw_secret
        ## Skip empty or already-processed secret tokens
        if not raw or raw in seen_secrets:
            continue
        seen_secrets.add(raw)

        ## Construct standardized replacement placeholder string
        replacement = replacement_format.format(
            pattern_id=finding.pattern_id.upper(),
            severity=finding.severity,
            name=finding.pattern_name.replace(" ", "_").upper(),
        )

        ## Replace all occurrences of the raw secret token in the content
        if raw in redacted_content:
            redacted_content = redacted_content.replace(raw, replacement)
            count += 1

    ## Return sanitized text block and count of replaced credentials
    return redacted_content, count


def redact_file(
    file_path: Path,
    output_path: Optional[Path] = None,
    in_place: bool = False,
    create_backup: bool = True,
    scanner: Optional[SecretScanner] = None,
) -> Tuple[bool, int, str]:
    """
    Sanitize and redact secrets directly from a file.

    Args:
        file_path: Target file to redact.
        output_path: Destination path for redacted file (if not in_place).
        in_place: If True, overwrite the target file.
        create_backup: If in_place is True, write an untouched copy to `<file>.bak`.
        scanner: Optional SecretScanner instance.

    Returns:
        Tuple of (success: bool, count_redacted: int, message: str).
    """
    ## Verify target path is a valid existing regular file
    if not file_path.is_file():
        return False, 0, f"File does not exist: {file_path}"

    ## Read file contents safely using UTF-8 encoding with character replacement fallback
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        return False, 0, f"Failed to read file '{file_path}': {err}"

    ## Execute string redaction pipeline
    sanitized, count = redact_text(content, scanner=scanner)

    ## If no secrets were detected, leave file untouched and return early
    if count == 0:
        return True, 0, f"No secrets detected in '{file_path}'."

    ## Determine output destination path based on execution arguments
    dest = file_path if in_place else (output_path or file_path.with_suffix(file_path.suffix + ".redacted"))

    ## Create an untouched .bak backup copy if in-place modification is requested
    if in_place and create_backup:
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        try:
            shutil.copy2(file_path, backup_path)
        except OSError as err:
            return False, 0, f"Failed to create backup at '{backup_path}': {err}"

    ## Write sanitized content to destination file
    try:
        dest.write_text(sanitized, encoding="utf-8")
    except OSError as err:
        return False, 0, f"Failed to write redacted output to '{dest}': {err}"

    ## Return successful completion receipt
    return True, count, f"Successfully redacted {count} secret(s) -> '{dest}'."
