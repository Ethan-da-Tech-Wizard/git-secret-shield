"""
===============================================================================
SecretShield - Command-Line Interface (CLI) Dispatcher
===============================================================================

This module provides the terminal interface and subcommands for Git Secret Shield:
  - `scan`: Audit files, directories, or git staged changes.
  - `install-hook`: Register pre-commit hook into local .git.
  - `uninstall-hook`: Remove pre-commit hook.
  - `redact`: Sanitize files (.env, configs) by replacing secrets with placeholders.
  - `patterns`: Enumerate all built-in detection signatures.
  - `report`: Produce standalone Markdown or JSON security audit receipts.

POSIX & DevSecOps Compliance:
  - Returns exit code 0 on clean scan; exit code 1 when `--fail-on-findings`
    is requested and secrets are uncovered.
  - Automatically respects `NO_COLOR` environment variable (https://no-color.org)
    and terminal TTY capabilities.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from secretshield.entropy import is_high_entropy
from secretshield.hook import install_pre_commit_hook, uninstall_pre_commit_hook
from secretshield.patterns import SCANNER_PATTERNS
from secretshield.redactor import redact_file
from secretshield.report import generate_json_report, generate_markdown_report
from secretshield.scanner import ScanFinding, SecretScanner


# ANSI Color formatting codes for terminal UX
class TermColor:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


def _colorize(text: str, color_code: str) -> str:
    """Apply ANSI color if stdout is a TTY and NO_COLOR is not set."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"{color_code}{text}{TermColor.RESET}"


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute scanning workflow on files, directories, or git staged files."""
    start_time = time.time()
    scanner = SecretScanner(check_entropy=not args.no_entropy)

    target_path = Path(args.target).resolve()
    findings: List[ScanFinding] = []
    target_description = str(target_path)

    if args.staged:
        target_description = f"Git Staged Index ({target_path})"
        if not args.json and not args.markdown:
            print(_colorize(f"[SecretShield] Scanning git staged changes in {target_path}...", TermColor.CYAN))
        findings = scanner.scan_git_staged(target_path)
    elif target_path.is_file():
        if not args.json and not args.markdown:
            print(_colorize(f"[SecretShield] Scanning file: {target_path}...", TermColor.CYAN))
        findings = scanner.scan_file(target_path)
    elif target_path.is_dir():
        if not args.json and not args.markdown:
            print(_colorize(f"[SecretShield] Recursively scanning directory: {target_path}...", TermColor.CYAN))
        findings = scanner.scan_directory(target_path, recursive=not args.non_recursive)
    else:
        print(_colorize(f"[SecretShield] Error: Path '{target_path}' does not exist.", TermColor.RED), file=sys.stderr)
        return 2

    duration = round(time.time() - start_time, 3)
    metadata = {
        "target": target_description,
        "duration_seconds": duration,
        "entropy_enabled": not args.no_entropy,
    }

    # Format outputs according to requested flags
    if args.json:
        report_output = generate_json_report(findings, metadata)
        if args.output:
            Path(args.output).write_text(report_output, encoding="utf-8")
        else:
            print(report_output)
    elif args.markdown:
        report_output = generate_markdown_report(findings, metadata)
        if args.output:
            Path(args.output).write_text(report_output, encoding="utf-8")
        else:
            print(report_output)
    else:
        # Human-friendly terminal printer
        _print_terminal_findings(findings, duration, target_description)
        if args.output:
            Path(args.output).write_text(
                generate_markdown_report(findings, metadata),
                encoding="utf-8",
            )
            print(_colorize(f"[SecretShield] Saved markdown report -> {args.output}", TermColor.GREEN))

    if findings and args.fail_on_findings:
        return 1

    return 0


def _print_terminal_findings(findings: List[ScanFinding], duration: float, target: str) -> None:
    """Render colorized findings table to standard output."""
    print("=" * 72)
    print(_colorize("🛡️  GIT SECRET SHIELD - SCAN RESULTS", TermColor.BOLD))
    print("=" * 72)
    print(f"Target:   {target}")
    print(f"Duration: {duration}s")
    print(f"Findings: {len(findings)}")
    print("-" * 72)

    if not findings:
        print(_colorize("✅ Clean! No secrets or high-entropy credentials detected.", TermColor.GREEN))
        print("=" * 72)
        return

    for idx, f in enumerate(findings, start=1):
        color = TermColor.RED if f.severity in ("CRITICAL", "HIGH") else TermColor.YELLOW
        sev_tag = _colorize(f"[{f.severity}]", color)
        print(f"\n{idx}. {sev_tag} {TermColor.BOLD}{f.pattern_name}{TermColor.RESET}")
        print(f"   Location:  {f.file_path}:{f.line_number}")
        print(f"   Preview:   {_colorize(f.secret_preview, TermColor.YELLOW)}")
        if f.entropy_score is not None:
            print(f"   Entropy:   {f.entropy_score:.3f} bits/symbol")
        print(f"   Guidance:  {f.remediation}")

    print("\n" + "=" * 72)
    print(_colorize(f"🚨 ALERT: Found {len(findings)} potential secret(s)!", TermColor.RED + TermColor.BOLD))
    print("Do not commit these secrets to remote repositories.")
    print("=" * 72)


def cmd_install_hook(args: argparse.Namespace) -> int:
    """Install git pre-commit hook."""
    repo_path = Path(args.path).resolve()
    success, message = install_pre_commit_hook(repo_path, force=args.force)

    if success:
        print(_colorize(f"[SecretShield] [SUCCESS] {message}", TermColor.GREEN))
        return 0
    else:
        print(_colorize(f"[SecretShield] [ERROR] {message}", TermColor.RED), file=sys.stderr)
        return 1


def cmd_uninstall_hook(args: argparse.Namespace) -> int:
    """Remove git pre-commit hook."""
    repo_path = Path(args.path).resolve()
    success, message = uninstall_pre_commit_hook(repo_path)

    if success:
        print(_colorize(f"[SecretShield] [SUCCESS] {message}", TermColor.GREEN))
        return 0
    else:
        print(_colorize(f"[SecretShield] [ERROR] {message}", TermColor.RED), file=sys.stderr)
        return 1


def cmd_redact(args: argparse.Namespace) -> int:
    """Redact hardcoded secrets from a file."""
    file_path = Path(args.file).resolve()
    output_path = Path(args.output).resolve() if args.output else None

    success, count, msg = redact_file(
        file_path,
        output_path=output_path,
        in_place=args.in_place,
        create_backup=not args.no_backup,
    )

    if success:
        print(_colorize(f"[SecretShield] {msg}", TermColor.GREEN))
        return 0
    else:
        print(_colorize(f"[SecretShield] [ERROR] {msg}", TermColor.RED), file=sys.stderr)
        return 1


def cmd_patterns(args: argparse.Namespace) -> int:
    """Enumerate all built-in detection patterns."""
    print("=" * 78)
    print(_colorize("🛡️  GIT SECRET SHIELD - CURATED SIGNATURE PATTERNS", TermColor.BOLD))
    print("=" * 78)
    print(f"Total Patterns: {len(SCANNER_PATTERNS)}\n")

    for p in SCANNER_PATTERNS:
        sev_color = TermColor.RED if p.severity in ("CRITICAL", "HIGH") else TermColor.YELLOW
        print(f"- {_colorize(f'[{p.severity}]', sev_color)} {TermColor.BOLD}{p.name}{TermColor.RESET} (`{p.id}`)")
        print(f"  Description: {p.description}")
        print(f"  Remediation: {p.remediation}\n")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="secretshield",
        description="Zero-dependency offline secret detection engine and git pre-commit hook guardian.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Subcommand: scan
    scan_p = subparsers.add_parser("scan", help="Scan files, directories, or git staged files for secrets.")
    scan_p.add_argument("target", nargs="?", default=".", help="Target file or directory path (default: .)")
    scan_p.add_argument("--staged", action="store_true", help="Scan git staged changes only.")
    scan_p.add_argument("--no-entropy", action="store_true", help="Disable Shannon entropy detection.")
    scan_p.add_argument("--fail-on-findings", action="store_true", help="Exit with code 1 if any secrets are found.")
    scan_p.add_argument("--non-recursive", action="store_true", help="Do not recurse into subdirectories.")
    scan_p.add_argument("--json", action="store_true", help="Output results in JSON format.")
    scan_p.add_argument("--markdown", action="store_true", help="Output results in Markdown format.")
    scan_p.add_argument("-o", "--output", help="Save output report to specified file.")

    # Subcommand: install-hook
    install_p = subparsers.add_parser("install-hook", help="Install git pre-commit hook guardian.")
    install_p.add_argument("--path", default=".", help="Path inside target git repository (default: .)")
    install_p.add_argument("-f", "--force", action="store_true", help="Overwrite existing pre-commit hook.")

    # Subcommand: uninstall-hook
    uninstall_p = subparsers.add_parser("uninstall-hook", help="Remove git pre-commit hook.")
    uninstall_p.add_argument("--path", default=".", help="Path inside target git repository (default: .)")

    # Subcommand: redact
    redact_p = subparsers.add_parser("redact", help="Sanitize secrets from a file (.env, configs).")
    redact_p.add_argument("file", help="File to sanitize.")
    redact_p.add_argument("-i", "--in-place", action="store_true", help="Overwrite file in-place.")
    redact_p.add_argument("-o", "--output", help="Output destination file path.")
    redact_p.add_argument("--no-backup", action="store_true", help="Skip creating .bak backup when --in-place is used.")

    # Subcommand: patterns
    subparsers.add_parser("patterns", help="List all built-in secret signature patterns.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI application entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "install-hook":
        return cmd_install_hook(args)
    elif args.command == "uninstall-hook":
        return cmd_uninstall_hook(args)
    elif args.command == "redact":
        return cmd_redact(args)
    elif args.command == "patterns":
        return cmd_patterns(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
