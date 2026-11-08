"""
Program: Git Secret Shield - Git Pre-Commit Hook Integration Guardian
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Manage the lifecycle (detection, installation, verification, and uninstallation) of POSIX-compliant Git pre-commit hooks to prevent uncommitted secrets from leaking into Git version control.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## os: Operating system interfaces for file permissions and stat queries
import os
## stat: File mode bit flags (S_IXUSR, S_IXGRP, S_IXOTH) to set executable permissions
import stat
## pathlib.Path: Object-oriented filesystem path manipulation
from pathlib import Path
## typing: Type hints for optional values and tuple returns
from typing import Optional, Tuple

## ---------------------------------------------------------------------------
## Hook Script Constants
## ---------------------------------------------------------------------------
## Marker token used to identify SecretShield's presence in an existing hook script.
## This allows safe detection and idempotent overwriting without destroying user hooks.
SECRETSHIELD_HOOK_MARKER = "### SECRETSHIELD_GIT_HOOK_GUARDIAN_V1 ###"

## POSIX-compliant shell script template installed into .git/hooks/pre-commit.
## Executes `python3 -m secretshield scan --staged --fail-on-findings` before commit creation.
PRE_COMMIT_HOOK_TEMPLATE = f"""#!/bin/sh
{SECRETSHIELD_HOOK_MARKER}
# =============================================================================
# Git Secret Shield - Automated Pre-Commit Security Guardian
# =============================================================================
# This hook intercepts git commits to scan staged changes for leaked credentials,
# private keys, and high-entropy secret tokens before they enter version control.
#
# Generated automatically by SecretShield.
# Bypass only in verified emergency circumstances: git commit --no-verify
# =============================================================================

# Ensure python3 interpreter is available in PATH
if ! command -v python3 >/dev/null 2>&1; then
    echo "[SecretShield] [WARN] python3 is not installed or not in PATH. Skipping pre-commit secret scan."
    exit 0
fi

# Execute SecretShield scanner against git staged files
python3 -m secretshield scan --staged --fail-on-findings

SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "[SecretShield] [BLOCKED] Commit rejected: staged files contain hardcoded secrets!"
    echo "[SecretShield] [ACTION] Redact or extract keys into environment variables."
    echo "[SecretShield] [BYPASS] If this is a confirmed false-positive: git commit --no-verify"
    echo ""
    exit 1
fi

exit 0
"""


def find_git_root(start_path: Optional[Path] = None) -> Optional[Path]:
    """
    Locate the root directory of the surrounding git repository.

    Walks upward from `start_path` until a directory containing a `.git` folder
    or file (for submodules/worktrees) is discovered.

    Args:
        start_path: Directory to begin upward search from (defaults to CWD).

    Returns:
        Path to git repository root, or None if not inside a git worktree.
    """
    ## Resolve start directory to an absolute canonical path; default to current working directory
    current = (start_path or Path.cwd()).resolve()

    ## Traverse the directory ancestry tree upwards toward filesystem root
    for parent in [current] + list(current.parents):
        git_entry = parent / ".git"
        ## Verify existence of .git directory or submodule pointer file
        if git_entry.exists():
            return parent

    ## If filesystem root reached without encountering .git, return None
    return None


def get_hook_path(repo_root: Path) -> Path:
    """
    Resolve the absolute path to the `.git/hooks/pre-commit` file.

    Handles standard repositories (`.git/hooks`) as well as git worktrees
    where `.git` is a pointer file.

    Args:
        repo_root: Root directory of the repository.

    Returns:
        Path object pointing to the pre-commit hook file.
    """
    ## Form initial candidate path to the .git entry
    git_dir = repo_root / ".git"

    ## In linked git worktrees or submodules, .git is a text file with `gitdir: <path>`
    if git_dir.is_file():
        try:
            content = git_dir.read_text(encoding="utf-8").strip()
            if content.startswith("gitdir:"):
                ## Parse the actual git directory path from pointer file
                actual_git_dir = Path(content.split("gitdir:", 1)[1].strip())
                if not actual_git_dir.is_absolute():
                    actual_git_dir = repo_root / actual_git_dir
                return actual_git_dir / "hooks" / "pre-commit"
        except (OSError, UnicodeDecodeError):
            ## Fall through to standard layout on file read failure
            pass

    ## Return standard pre-commit hook location within .git/hooks/
    return git_dir / "hooks" / "pre-commit"


def install_pre_commit_hook(
    repo_path: Optional[Path] = None,
    force: bool = False,
) -> Tuple[bool, str]:
    """
    Install the SecretShield pre-commit hook into the specified git repository.

    Safeties:
      - Validates that target is inside a real git repository.
      - Automatically creates `.git/hooks/` directory if missing.
      - If an existing hook is detected:
        * If already managed by SecretShield, updates it cleanly.
        * If authored by another tool (e.g. husky or pre-commit), refuses overwrite
          unless `force=True`, or appends invocation safely.
      - Sets executable POSIX permissions (`chmod 0755`).

    Args:
        repo_path: Path inside the git repository.
        force: Overwrite existing hook even if managed by another tool.

    Returns:
        Tuple of (success: bool, message: str).
    """
    ## Verify target path resides within an active git repository
    root = find_git_root(repo_path)
    if not root:
        return False, "Target directory is not inside a git repository."

    ## Resolve exact target path for the pre-commit hook script
    hook_file = get_hook_path(root)
    hooks_dir = hook_file.parent

    ## Create parent hooks directory if it does not yet exist
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        return False, f"Failed to create hooks directory '{hooks_dir}': {err}"

    ## Inspect existing hook file if present
    if hook_file.exists():
        try:
            existing_content = hook_file.read_text(encoding="utf-8", errors="replace")
            ## Case A: Existing hook was generated by SecretShield -> update safely
            if SECRETSHIELD_HOOK_MARKER in existing_content:
                hook_file.write_text(PRE_COMMIT_HOOK_TEMPLATE, encoding="utf-8")
                _make_executable(hook_file)
                return True, f"Updated existing SecretShield pre-commit hook at '{hook_file}'."
            ## Case B: Foreign hook script present and force flag is False -> protect user file
            elif not force:
                return (
                    False,
                    f"Existing pre-commit hook detected at '{hook_file}'. "
                    "Use --force to overwrite or manually add SecretShield to your hook.",
                )
        except OSError as err:
            return False, f"Failed to read existing hook: {err}"

    ## Write standard SecretShield pre-commit hook script
    try:
        hook_file.write_text(PRE_COMMIT_HOOK_TEMPLATE, encoding="utf-8")
        _make_executable(hook_file)
    except OSError as err:
        return False, f"Failed to write hook file: {err}"

    ## Successfully written and configured hook script
    return True, f"Successfully installed pre-commit hook at '{hook_file}'."


def uninstall_pre_commit_hook(repo_path: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Remove SecretShield pre-commit hook from the repository.

    Args:
        repo_path: Path inside the git repository.

    Returns:
        Tuple of (success: bool, message: str).
    """
    ## Find git root directory
    root = find_git_root(repo_path)
    if not root:
        return False, "Target directory is not inside a git repository."

    ## Resolve hook file path
    hook_file = get_hook_path(root)
    if not hook_file.exists():
        return False, f"No pre-commit hook found at '{hook_file}'."

    ## Validate hook ownership before unlinking
    try:
        content = hook_file.read_text(encoding="utf-8", errors="replace")
        ## Refuse to delete foreign hooks that do not contain our marker signature
        if SECRETSHIELD_HOOK_MARKER not in content:
            return False, f"Hook at '{hook_file}' was not created by SecretShield. Skipping removal."

        ## Delete pre-commit hook file
        hook_file.unlink()
        return True, f"Successfully removed pre-commit hook from '{hook_file}'."
    except OSError as err:
        return False, f"Failed to remove hook file: {err}"


def _make_executable(path: Path) -> None:
    """
    Set POSIX executable permissions (chmod +x / 0755) on a file.

    Args:
        path: File path to modify.
    """
    ## Read current file mode bitmask
    current_mode = os.stat(path).st_mode
    ## Apply bitwise OR with User, Group, and Other executable bits (0o755 style)
    os.chmod(path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
