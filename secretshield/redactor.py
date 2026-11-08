"""
===============================================================================
SecretShield - Configuration Sanitizer & Secret Redactor Engine
===============================================================================

This module provides automated redaction and environment sanitization to neutralize
leaked credentials in configuration files (`.env`, YAML, JSON, config files).

Security Rationale:
-------------------
Developers often clone repositories or work with sample environment configurations
where sensitive API keys, database credentials, or tokens are accidentally pasted.
The Redactor provides:
  1. Safe in-place or copy-based file sanitization.
  2. Automatic generation of `.bak` backups before modifying any source file.
  3. Context-aware replacement that preserves variable names, structure,
     and whitespace while replacing the secret value with a safe placeholder.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional, Tuple

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
    if scanner is None:
        scanner = SecretScanner(check_entropy=False)

    findings = scanner.scan_text(content)
    if not findings:
        return content, 0

    redacted_content = content
    count = 0

    # Sort findings by raw_secret length descending to avoid partial substring collisions
    valid_findings = [f for f in findings if f.raw_secret]
    valid_findings.sort(key=lambda f: len(f.raw_secret or ""), reverse=True)

    seen_secrets = set()
    for finding in valid_findings:
        raw = finding.raw_secret
        if not raw or raw in seen_secrets:
            continue
        seen_secrets.add(raw)

        replacement = replacement_format.format(
            pattern_id=finding.pattern_id.upper(),
            severity=finding.severity,
            name=finding.pattern_name.replace(" ", "_").upper(),
        )
        if raw in redacted_content:
            redacted_content = redacted_content.replace(raw, replacement)
            count += 1

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
    if not file_path.is_file():
        return False, 0, f"File does not exist: {file_path}"

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as err:
        return False, 0, f"Failed to read file '{file_path}': {err}"

    sanitized, count = redact_text(content, scanner=scanner)

    if count == 0:
        return True, 0, f"No secrets detected in '{file_path}'."

    dest = file_path if in_place else (output_path or file_path.with_suffix(file_path.suffix + ".redacted"))

    if in_place and create_backup:
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        try:
            shutil.copy2(file_path, backup_path)
        except OSError as err:
            return False, 0, f"Failed to create backup at '{backup_path}': {err}"

    try:
        dest.write_text(sanitized, encoding="utf-8")
    except OSError as err:
        return False, 0, f"Failed to write redacted output to '{dest}': {err}"

    return True, count, f"Successfully redacted {count} secret(s) -> '{dest}'."
