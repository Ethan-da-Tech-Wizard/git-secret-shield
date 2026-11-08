"""
===============================================================================
SecretShield - Security Audit Receipt & Report Generator
===============================================================================

This module formats scan findings into structured JSON or human-readable Markdown
security audit receipts.

Receipt Design Principles:
--------------------------
1. Machine-Readable Interoperability (JSON):
   - Strict schema compliant with DevSecOps CI/CD pipelines, security dashboards,
     and SIEM ingestion.
   - Contains zero raw plaintext secrets; all previews are strictly masked.

2. Actionable Remediation (Markdown):
   - Grouped by severity (CRITICAL -> HIGH -> MEDIUM -> LOW).
   - Specifies exact line numbers, pattern identification, and step-by-step
     credential rotation procedures.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

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
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    report_payload = {
        "tool": "git-secret-shield",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata,
        "summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "signature_detections": sum(1 for f in findings if f.detection_type == "signature"),
            "entropy_detections": sum(1 for f in findings if f.detection_type == "entropy"),
        },
        "findings": [f.to_dict() for f in findings],
    }

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
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target = metadata.get("target", "Repository / Worktree")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

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

    if not findings:
        lines.extend([
            "## Audit Result: PASSED ✅",
            "",
            "> No hardcoded secrets, API tokens, or high-entropy credentials were detected.",
            "",
        ])
        return "\n".join(lines)

    lines.extend([
        "## Detailed Findings & Remediation Plan",
        "",
    ])

    for idx, f in enumerate(findings, start=1):
        lines.extend([
            f"### {idx}. [{f.severity}] {f.pattern_name}",
            "",
            f"- **Location:** `{f.file_path}:{f.line_number}`",
            f"- **Detection Type:** `{f.detection_type.capitalize()}`",
            f"- **Pattern ID:** `{f.pattern_id}`",
            f"- **Masked Preview:** `{f.secret_preview}`",
        ])
        if f.entropy_score is not None:
            lines.append(f"- **Shannon Entropy Score:** `{f.entropy_score:.3f} bits/symbol`")

        lines.extend([
            f"- **Remediation Action:** {f.remediation}",
            "",
        ])

    lines.extend([
        "---",
        "### Prevention & Policy Recommendations",
        "1. Install the pre-commit hook locally: `python3 -m secretshield install-hook`",
        "2. Add `.env` and credential files to `.gitignore`.",
        "3. Invalidate compromised keys immediately in their respective provider consoles.",
        "",
        "*Report compiled by [Git Secret Shield](https://github.com/Ethan-da-Tech-Wizard/git-secret-shield).*",
    ])

    return "\n".join(lines)
