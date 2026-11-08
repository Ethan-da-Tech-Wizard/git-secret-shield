"""
Program: Git Secret Shield - Security Audit Receipt & Report Generator
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Transform detected credential findings into structured, machine-readable JSON receipts for CI/CD pipelines and executive GitHub-flavored Markdown summaries with remediation instructions.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## json: Serializes structured dictionary records into formatted JSON receipts
import json
## datetime: Generates ISO-8601 timestamps and human-readable audit timestamps
from datetime import datetime, timezone
## typing: Static typing annotations for dictionary structures and finding lists
from typing import Any, Dict, List

## ---------------------------------------------------------------------------
## Internal Imports
## ---------------------------------------------------------------------------
## ScanFinding: Data model for individual security violation records
from secretshield.scanner import ScanFinding


def generate_json_report(
    findings: List[ScanFinding],
    metadata: Dict[str, Any],
) -> str:
    """
    Generate a structured JSON security audit receipt.

    Args:
        findings: List of identified ScanFinding instances.
        metadata: Execution context dictionary (target path, timestamp, duration).

    Returns:
        Formatted JSON string.
    """
    ## Initialize severity tally mapping with zero counts for all supported levels
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    ## Tally findings across severity classifications
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    ## Construct structured audit dictionary payload
    report_payload = {
        "tool": "git-secret-shield",
        "version": "1.0.0",
        ## Use timezone-aware UTC ISO timestamp for reproducible machine receipts
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            ## Count findings by detection engine phase
            "signature_detections": sum(1 for f in findings if f.detection_type == "signature"),
            "entropy_detections": sum(1 for f in findings if f.detection_type == "entropy"),
        },
        ## Convert each finding to dictionary form; to_dict() guarantees raw secrets are excluded
        "findings": [f.to_dict() for f in findings],
    }

    ## Return indented JSON string suitable for archiving or piping into SIEM tools
    return json.dumps(report_payload, indent=2)


def generate_markdown_report(
    findings: List[ScanFinding],
    metadata: Dict[str, Any],
) -> str:
    """
    Generate an executive Markdown security audit report.

    Args:
        findings: List of identified ScanFinding instances.
        metadata: Execution context dictionary.

    Returns:
        GitHub-flavored Markdown report string.
    """
    ## Format UTC timestamp in human-readable notation
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    ## Extract scan target description from metadata or default to generic label
    target = metadata.get("target", "Repository / Worktree")

    ## Tally findings by severity tier
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    ## Build document header and executive summary table
    lines = [
        "# 🛡️ Git Secret Shield - Security Audit Report",
        "",
        f"- **Generated:** `{timestamp}`",
        f"- **Scan Target:** `{target}`",
        f"- **Total Violations Found:** `{len(findings)}`",
        "",
        "## Summary by Severity",
        "",
        "| Severity | Findings Count | Risk Level |",
        "| :--- | :--- | :--- |",
        f"| **CRITICAL** | `{severity_counts['CRITICAL']}` | Immediate Account Takeover Risk |",
        f"| **HIGH** | `{severity_counts['HIGH']}` | Unauthorized Service / API Access |",
        f"| **MEDIUM** | `{severity_counts['MEDIUM']}` | Metadata / Reconnaissance Exposure |",
        f"| **LOW** | `{severity_counts['LOW']}` | Low-confidence / Information Leak |",
        "",
    ]

    ## Handle clean audit case (no findings detected)
    if not findings:
        lines.extend([
            "## Audit Result: PASSED ✅",
            "",
            "> No hardcoded secrets, API tokens, or high-entropy credentials were detected.",
            "",
        ])
        return "\n".join(lines)

    ## Section: Detailed findings enumeration with specific remediation instructions
    lines.extend([
        "## Detailed Findings & Remediation Plan",
        "",
    ])

    ## Iterate over each detected violation and construct markdown item
    for idx, f in enumerate(findings, start=1):
        lines.extend([
            f"### {idx}. [{f.severity}] {f.pattern_name}",
            "",
            f"- **Location:** `{f.file_path}:{f.line_number}`",
            f"- **Detection Type:** `{f.detection_type.capitalize()}`",
            f"- **Pattern ID:** `{f.pattern_id}`",
            f"- **Masked Preview:** `{f.secret_preview}`",
        ])

        ## Include calculated Shannon entropy score if violation was found via entropy engine
        if f.entropy_score is not None:
            lines.append(f"- **Shannon Entropy Score:** `{f.entropy_score:.3f} bits/symbol`")

        lines.extend([
            f"- **Remediation Action:** {f.remediation}",
            "",
        ])

    ## Concluding recommendations and policy guardrails
    lines.extend([
        "---",
        "### Prevention & Policy Recommendations",
        "1. Install the pre-commit hook locally: `python3 -m secretshield install-hook`",
        "2. Add `.env` and credential files to `.gitignore`.",
        "3. Invalidate compromised keys immediately in their respective provider consoles.",
        "",
        "*Report compiled by [Git Secret Shield](https://github.com/Ethan-da-Tech-Wizard/git-secret-shield).*",
    ])

    ## Join all lines into unified Markdown string
    return "\n".join(lines)
