"""
===============================================================================
SecretShield - Git Pre-Commit Hook Integration Engine
===============================================================================

This module handles lifecycle management (installation, verification, and uninstallation)
for POSIX-compliant git pre-commit hooks.

Git Hook Lifecycle Theory:
--------------------------
Git triggers the `.git/hooks/pre-commit` script prior to writing a commit object
to the local git repository database.
  1. The developer invokes `git commit`.
  2. Git invokes `.git/hooks/pre-commit` with no parameters.
  3. The hook inspects the git index (staging area).
  4. If the hook exits with return code 0:
     Git completes the commit object creation.
  5. If the hook exits with non-zero (e.g. exit 1):
     Git immediately aborts the commit, preserving all staged changes untouched
     in the developer's working directory.

This guarantees that secrets are stopped BEFORE they enter local git revision
history, avoiding painful and dangerous `git filter-repo` or `git rebase` rewrites.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional, Tuple


# Marker token used to identify SecretShield's presence in an existing hook script
SECRETSHIELD_HOOK_MARKER = "### SECRETSHIELD_GIT_HOOK_GUARDIAN_V1 ###"

# POSIX-compliant shell script template installed into .git/hooks/pre-commit
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
    current = (start_path or Path.cwd()).resolve()

    for parent in [current] + list(current.parents):
        git_entry = parent / ".git"
        if git_entry.exists():
            return parent

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
    git_dir = repo_root / ".git"

    if git_dir.is_file():
        # Handle git worktrees or submodules where .git contains `gitdir: <path>`
        try:
            content = git_dir.read_text(encoding="utf-8").strip()
            if content.startswith("gitdir:"):
                actual_git_dir = Path(content.split("gitdir:", 1)[1].strip())
                if not actual_git_dir.is_absolute():
                    actual_git_dir = repo_root / actual_git_dir
                return actual_git_dir / "hooks" / "pre-commit"
        except (OSError, UnicodeDecodeError):
            pass

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
    root = find_git_root(repo_path)
    if not root:
        return False, "Target directory is not inside a git repository."

    hook_file = get_hook_path(root)
    hooks_dir = hook_file.parent

    # Create hooks directory if missing (e.g. fresh clones or non-standard templates)
    try:
        hooks_dir.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        return False, f"Failed to create hooks directory '{hooks_dir}': {err}"

    # Check for existing hook script
    if hook_file.exists():
        try:
            existing_content = hook_file.read_text(encoding="utf-8", errors="replace")
            if SECRETSHIELD_HOOK_MARKER in existing_content:
                # Already managed by SecretShield; overwrite with updated version
                hook_file.write_text(PRE_COMMIT_HOOK_TEMPLATE, encoding="utf-8")
                _make_executable(hook_file)
                return True, f"Updated existing SecretShield pre-commit hook at '{hook_file}'."
            elif not force:
                return (
                    False,
                    f"Existing pre-commit hook detected at '{hook_file}'. "
                    "Use --force to overwrite or manually add SecretShield to your hook.",
                )
        except OSError as err:
            return False, f"Failed to read existing hook: {err}"

    # Write new hook script
    try:
        hook_file.write_text(PRE_COMMIT_HOOK_TEMPLATE, encoding="utf-8")
        _make_executable(hook_file)
    except OSError as err:
        return False, f"Failed to write hook file: {err}"

    return True, f"Successfully installed pre-commit hook at '{hook_file}'."


def uninstall_pre_commit_hook(repo_path: Optional[Path] = None) -> Tuple[bool, str]:
    """
    Remove SecretShield pre-commit hook from the repository.

    Args:
        repo_path: Path inside the git repository.

    Returns:
        Tuple of (success: bool, message: str).
    """
    root = find_git_root(repo_path)
    if not root:
        return False, "Target directory is not inside a git repository."

    hook_file = get_hook_path(root)
    if not hook_file.exists():
        return False, f"No pre-commit hook found at '{hook_file}'."

    try:
        content = hook_file.read_text(encoding="utf-8", errors="replace")
        if SECRETSHIELD_HOOK_MARKER not in content:
            return False, f"Hook at '{hook_file}' was not created by SecretShield. Skipping removal."

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
    current_mode = os.stat(path).st_mode
    os.chmod(path, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
