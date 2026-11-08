"""
Program: Git Secret Shield - Exhaustive Unit & Integration Test Suite
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Comprehensively validate mathematical entropy accuracy, pattern matching precision, false-positive filtering, scanner traversal, git hook workflows, file redaction, and CLI behavior with 100% test pass rate.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## io: String buffer simulation
import io
## json: Validates JSON report serialization and parsing
import json
## math: Mathematical validations (math.log2) for entropy expectations
import math
## os: Filesystem permissions and access queries
import os
## shutil: Temporary directory cleanup
import shutil
## subprocess: Executes git commands inside isolated test repositories
import subprocess
## tempfile: Generates isolated scratch directories for unit test isolation
import tempfile
## unittest: Python standard library unit testing framework
import unittest
## pathlib.Path: Object-oriented path manipulation
from pathlib import Path

## ---------------------------------------------------------------------------
## Internal Imports: SecretShield API under test
## ---------------------------------------------------------------------------
from secretshield.cli import main
from secretshield.entropy import (
    calculate_shannon_entropy,
    character_frequency_distribution,
    extract_potential_tokens,
    is_high_entropy,
)
from secretshield.hook import (
    find_git_root,
    install_pre_commit_hook,
    uninstall_pre_commit_hook,
)
from secretshield.patterns import SCANNER_PATTERNS, find_pattern_by_id
from secretshield.redactor import redact_file, redact_text
from secretshield.report import generate_json_report, generate_markdown_report
from secretshield.scanner import (
    ScanFinding,
    SecretScanner,
    is_binary_file,
    mask_secret,
)


def _t(*parts: str) -> str:
    """
    Dynamically assemble test fixture strings from fragments.

    Prevents remote Git hosting providers (e.g. GitHub Push Protection) from
    incorrectly flagging unit test files containing synthetic test tokens.
    """
    ## Concatenate string fragments in memory
    return "".join(parts)


class TestShannonEntropy(unittest.TestCase):
    """Test suite validating Shannon Information Entropy mathematics."""

    def test_zero_entropy_for_repeated_characters(self):
        """A string of identical characters contains 0 bits of information entropy."""
        ## Empty string has zero uncertainty
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        ## Single character string has zero uncertainty
        self.assertEqual(calculate_shannon_entropy("A"), 0.0)
        ## Monotonous repeated string has zero uncertainty
        self.assertEqual(calculate_shannon_entropy("AAAAAAAAAAAAAAA"), 0.0)

    def test_maximum_entropy_for_uniform_alphabet(self):
        """
        A string with N distinct characters of length N has uniform probability 1/N.
        Theoretical entropy: H(X) = -N * (1/N) * log2(1/N) = log2(N).
        For 16 distinct hex symbols: log2(16) = 4.0 bits/char.
        """
        hex_alphabet = "0123456789abcdef"
        ## Theoretical maximum entropy for 16 equally likely symbols
        expected_entropy = math.log2(16)  ## exactly 4.0
        self.assertAlmostEqual(calculate_shannon_entropy(hex_alphabet), expected_entropy, places=5)

    def test_frequency_distribution_probabilities(self):
        """Probabilities in character frequency distribution must sum to 1.0."""
        text = "Hello World! This is SecretShield."
        dist = character_frequency_distribution(text)
        ## Total empirical probabilities must sum to 1.0
        self.assertAlmostEqual(sum(dist.values()), 1.0, places=5)
        ## Character keys must be present
        self.assertIn("H", dist)
        self.assertIn(" ", dist)

    def test_high_entropy_detection_hex(self):
        """Randomized hexadecimal hashes (e.g. 64-character SHA-256 / private key) exceed 3.5 bits."""
        ## Dynamically build synthetic 64-character hex hash
        random_hex = _t("4a8f9c2d1b7e6a0f", "5e3d8c1a9b2e7f4c", "6d0a8b3e5f1c9d2a", "7b4e8f0c3a5d1e6b")
        is_secret, charset, score = is_high_entropy(random_hex)
        ## Must be classified as a high-entropy secret
        self.assertTrue(is_secret)
        self.assertEqual(charset, "high_entropy_hex")
        self.assertGreater(score, 3.2)

    def test_high_entropy_detection_base64(self):
        """High-entropy base64 string must be flagged."""
        ## Dynamically construct high-randomness base64 token
        random_b64 = _t("Gk8v+J2mR9qZ3wL5", "pT7sY1xN0bC4eF8u", "A2dI6hK9mP3=")
        is_secret, charset, score = is_high_entropy(random_b64)
        ## Must be flagged as high-entropy base64
        self.assertTrue(is_secret)
        self.assertEqual(charset, "high_entropy_base64")
        self.assertGreater(score, 4.5)

    def test_false_positive_filter_uuid(self):
        """Standard RFC 4122 UUIDs must NOT be flagged as high-entropy secrets."""
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        is_secret, charset, score = is_high_entropy(uuid_str)
        ## Must be rejected by the false-positive filter
        self.assertFalse(is_secret)
        self.assertEqual(charset, "uuid_identifier")

    def test_false_positive_filter_placeholders(self):
        """Common documentation placeholders containing 'example' or 'dummy' must be ignored."""
        placeholder = "example_dummy_token_1234567890abcdef"
        is_secret, charset, _ = is_high_entropy(placeholder)
        ## Must be recognized as benign placeholder
        self.assertFalse(is_secret)
        self.assertEqual(charset, "benign_placeholder")

    def test_candidate_token_extractor(self):
        """Extract contiguous token candidates from arbitrary code lines."""
        line = "const API_KEY = 'c8b417e99214d026bcad34a2e584f107';"
        tokens = extract_potential_tokens(line)
        ## Extracted token list must isolate the 32-char hex string
        self.assertIn("c8b417e99214d026bcad34a2e584f107", tokens)


class TestSignaturePatterns(unittest.TestCase):
    """Test suite validating all curated regex signature patterns."""

    def test_registered_patterns_count(self):
        """Ensure library has at least 30 registered signature patterns."""
        self.assertGreaterEqual(len(SCANNER_PATTERNS), 30)

    def test_aws_access_key_detection(self):
        """Match valid AWS Access Key ID starting with AKIA."""
        pattern = find_pattern_by_id("aws_access_key_id")
        self.assertIsNotNone(pattern)
        token = _t("AKIA", "IOSFODNN7EXAMPLE")
        match = pattern.regex.search(f"export AWS_ACCESS_KEY_ID={token}")
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), token)

    def test_github_tokens(self):
        """Match various GitHub token formats (classic, fine-grained, OAuth)."""
        ## Classic PAT check
        classic = find_pattern_by_id("github_pat_classic")
        self.assertIsNotNone(classic.regex.search(_t("ghp_", "123456789012345678901234567890123456")))

        ## Fine-grained PAT check
        fine = find_pattern_by_id("github_pat_fine_grained")
        self.assertIsNotNone(
            fine.regex.search(
                _t("github_pat_", "11AAAAAAA0123456789012345678901234567890123456789012345678901234567890123456789012")
            )
        )

        ## OAuth access token check
        oauth = find_pattern_by_id("github_oauth_access_token")
        self.assertIsNotNone(oauth.regex.search(_t("gho_", "123456789012345678901234567890123456")))

    def test_slack_tokens_and_webhooks(self):
        """Match Slack bot, user, and incoming webhook URLs."""
        ## Slack bot token check
        bot = find_pattern_by_id("slack_bot_token")
        self.assertIsNotNone(bot.regex.search(_t("xoxb-", "123456789012-", "123456789012-", "abcdefghijklmnopqrstuvwx")))

        ## Slack user token check
        user = find_pattern_by_id("slack_user_token")
        self.assertIsNotNone(user.regex.search(_t("xoxp-", "123456789012-", "123456789012-", "abcdefghijklmnopqrstuvwx")))

        ## Slack webhook URL check
        webhook = find_pattern_by_id("slack_webhook_url")
        self.assertIsNotNone(
            webhook.regex.search(_t("https://hooks.", "slack.com/services/", "T12345678/B12345678/", "abcdefghijklmnopqrstuvwx"))
        )

    def test_ai_vendor_keys(self):
        """Match OpenAI, Anthropic, and Google Gemini API keys."""
        ## Standard OpenAI API key
        openai_std = find_pattern_by_id("openai_api_key")
        self.assertIsNotNone(openai_std.regex.search(_t("sk-", "1234567890abcdef1234567890abcdef1234567890abcdef")))

        ## Project-scoped OpenAI API key
        openai_proj = find_pattern_by_id("openai_project_api_key")
        self.assertIsNotNone(
            openai_proj.regex.search(
                _t("sk-proj-", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            )
        )

        ## Anthropic API key
        anthropic = find_pattern_by_id("anthropic_api_key")
        self.assertIsNotNone(
            anthropic.regex.search(
                _t("sk-ant-api03-", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            )
        )

        ## Google Gemini API key
        gemini = find_pattern_by_id("google_gemini_api_key")
        self.assertIsNotNone(gemini.regex.search(_t("AIza", "SyD-1234567890abcdef1234567890abcde")))

    def test_stripe_keys(self):
        """Match Stripe live secret keys and restricted keys."""
        ## Stripe live secret key
        live_key = find_pattern_by_id("stripe_secret_key")
        self.assertIsNotNone(live_key.regex.search(_t("sk_live_", "123456789012345678901234")))

        ## Stripe restricted key
        restricted_key = find_pattern_by_id("stripe_restricted_key")
        self.assertIsNotNone(restricted_key.regex.search(_t("rk_live_", "123456789012345678901234")))

    def test_private_key_headers(self):
        """Match unencrypted RSA, OpenSSH, and generic PKCS#8 private keys."""
        ## RSA PEM header
        rsa = find_pattern_by_id("rsa_private_key")
        self.assertIsNotNone(rsa.regex.search("-----BEGIN RSA PRIVATE KEY-----"))

        ## OpenSSH header
        ssh = find_pattern_by_id("openssh_private_key")
        self.assertIsNotNone(ssh.regex.search("-----BEGIN OPENSSH PRIVATE KEY-----"))

        ## PKCS#8 generic header
        pkcs8 = find_pattern_by_id("pkcs8_private_key")
        self.assertIsNotNone(pkcs8.regex.search("-----BEGIN PRIVATE KEY-----"))

    def test_jwt_tokens(self):
        """Match JSON Web Tokens (JWT)."""
        jwt_pat = find_pattern_by_id("jwt_token")
        test_jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        self.assertIsNotNone(jwt_pat.regex.search(test_jwt))

    def test_discord_and_telegram(self):
        """Match Discord bot token, webhook, and Telegram bot token."""
        ## Discord bot token
        discord_bot = find_pattern_by_id("discord_bot_token")
        self.assertIsNotNone(
            discord_bot.regex.search(_t("NzgxMjM0NTY3ODkwMTIzNDU2.", "GAB_CD.", "1234567890abcdefghijklmnopqrstuv"))
        )

        ## Discord webhook URL
        discord_hook = find_pattern_by_id("discord_webhook_url")
        self.assertIsNotNone(
            discord_hook.regex.search(
                _t("https://discord.com/api/webhooks/", "123456789012345678/", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01")
            )
        )

        ## Telegram bot token
        telegram = find_pattern_by_id("telegram_bot_token")
        self.assertIsNotNone(telegram.regex.search(_t("123456789:", "ABCdefGHIjklMNOpqrsTUVwxyz123456789")))

    def test_database_connection_uri(self):
        """Match PostgreSQL, MySQL, Redis, MongoDB connection strings containing passwords."""
        db_pat = find_pattern_by_id("database_connection_uri")
        uri = "postgres://db_user:s3cr3t_pass123@db.internal.net:5432/production"
        self.assertIsNotNone(db_pat.regex.search(uri))


class TestSecretScanner(unittest.TestCase):
    """Test suite validating file and directory scanning logic."""

    def setUp(self):
        ## Create clean isolated temporary scratch directory
        self.temp_dir = tempfile.mkdtemp(prefix="secretshield_test_")
        self.temp_path = Path(self.temp_dir)

    def tearDown(self):
        ## Recursively clean up temporary scratch directory
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_mask_secret_helper(self):
        """Verify secret masking hides confidential inner characters."""
        ## Standard length credential masking
        self.assertEqual(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIA************MPLE")
        ## Short credential complete masking
        self.assertEqual(mask_secret("short"), "*****")

    def test_binary_file_detection(self):
        """Scanner correctly flags binary files containing null bytes."""
        ## Binary file with null byte
        bin_file = self.temp_path / "sample.bin"
        bin_file.write_bytes(b"HELLO\x00WORLD\x00BINARY")
        self.assertTrue(is_binary_file(bin_file))

        ## Clean text file without null byte
        text_file = self.temp_path / "sample.txt"
        text_file.write_text("Hello clean text file without nulls", encoding="utf-8")
        self.assertFalse(is_binary_file(text_file))

    def test_scan_text_findings(self):
        """Scanner uncovers signature matches in raw string text."""
        scanner = SecretScanner(check_entropy=False)
        ghp_tok = _t("ghp_", "123456789012345678901234567890123456")
        text = f"const key = '{ghp_tok}';\n"
        findings = scanner.scan_text(text)
        ## Verify finding details
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_id, "github_pat_classic")
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertTrue(findings[0].secret_preview.startswith("ghp_"))
        self.assertTrue(findings[0].secret_preview.endswith("3456"))

    def test_recursive_directory_scan(self):
        """Scanner recursively traverses subdirectories and respects ignored directories."""
        sub = self.temp_path / "src"
        sub.mkdir()
        leaky_file = sub / "api.py"
        key_val = _t("AKIA", "1234567890ABCDEF")
        leaky_file.write_text(f"AWS_KEY = '{key_val}'\n", encoding="utf-8")

        ## Ignored node_modules directory with secret that must NOT be reported
        node_mod = self.temp_path / "node_modules"
        node_mod.mkdir()
        ignored_file = node_mod / "bundle.js"
        ign_val = _t("AKIA", "9999999999ABCDEF")
        ignored_file.write_text(f"AWS_KEY = '{ign_val}'\n", encoding="utf-8")

        scanner = SecretScanner(check_entropy=False)
        findings = scanner.scan_directory(self.temp_path)
        ## Only un-ignored source directory should have its findings returned
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file_path, str(leaky_file))


class TestGitHookIntegration(unittest.TestCase):
    """Test suite validating git pre-commit hook installer and execution."""

    def setUp(self):
        ## Initialize temporary test git repository
        self.repo_dir = tempfile.mkdtemp(prefix="secretshield_git_")
        self.repo_path = Path(self.repo_dir)
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo_path, check=True, capture_output=True)
        ## Configure dummy test author identity
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=self.repo_path, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repo_path, check=True)

    def tearDown(self):
        shutil.rmtree(self.repo_dir, ignore_errors=True)

    def test_find_git_root(self):
        """Locates git root from nested directory."""
        nested = self.repo_path / "a" / "b" / "c"
        nested.mkdir(parents=True)
        root = find_git_root(nested)
        self.assertEqual(root.resolve(), self.repo_path.resolve())

    def test_install_and_uninstall_hook(self):
        """Install pre-commit hook, verify permissions, and uninstall cleanly."""
        success, msg = install_pre_commit_hook(self.repo_path)
        self.assertTrue(success)
        hook_path = self.repo_path / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook_path.exists())
        ## Verify hook has executable bit set
        self.assertTrue(os.access(hook_path, os.X_OK))

        ## Idempotent re-installation test
        success_update, _ = install_pre_commit_hook(self.repo_path)
        self.assertTrue(success_update)

        ## Uninstallation test
        uninstalled, u_msg = uninstall_pre_commit_hook(self.repo_path)
        self.assertTrue(uninstalled)
        self.assertFalse(hook_path.exists())

    def test_git_staged_scanner_catches_staged_secret(self):
        """Pre-commit scanner inspects git staging area and catches added secrets."""
        test_file = self.repo_path / "config.py"
        stripe_tok = _t("sk_live_", "123456789012345678901234")
        test_file.write_text(f"STRIPE_KEY = '{stripe_tok}'\n", encoding="utf-8")
        subprocess.run(["git", "add", "config.py"], cwd=self.repo_path, check=True)

        scanner = SecretScanner(check_entropy=False)
        findings = scanner.scan_git_staged(self.repo_path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].pattern_id, "stripe_secret_key")


class TestRedactorAndReports(unittest.TestCase):
    """Test suite validating file sanitizer and audit reports."""

    def test_redact_text(self):
        """Redactor replaces secret with standardized placeholder."""
        ghp_tok = _t("ghp_", "123456789012345678901234567890123456")
        raw_text = f"API_KEY={ghp_tok}\nPORT=8080"
        redacted, count = redact_text(raw_text)
        self.assertEqual(count, 1)
        self.assertNotIn(ghp_tok, redacted)
        self.assertIn("[REDACTED_GITHUB_PAT_CLASSIC]", redacted)
        self.assertIn("PORT=8080", redacted)

    def test_redact_file_with_backup(self):
        """Redact file in-place and verify .bak preservation."""
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            sk_tok = _t("sk-", "1234567890abcdef1234567890abcdef1234567890abcdef")
            env_file.write_text(f"OPENAI_KEY={sk_tok}\n", encoding="utf-8")

            success, count, _ = redact_file(env_file, in_place=True, create_backup=True)
            self.assertTrue(success)
            self.assertEqual(count, 1)

            ## Check .bak existence and contents
            bak_file = Path(tmp) / ".env.bak"
            self.assertTrue(bak_file.exists())
            self.assertIn("1234567890abcdef", bak_file.read_text(encoding="utf-8"))

            ## Check sanitized original
            sanitized = env_file.read_text(encoding="utf-8")
            self.assertIn("[REDACTED_OPENAI_API_KEY]", sanitized)

    def test_report_generation_json_and_markdown(self):
        """Verify JSON and Markdown report outputs."""
        sample_finding = ScanFinding(
            file_path="src/app.py",
            line_number=42,
            pattern_name="AWS Access Key ID",
            pattern_id="aws_access_key_id",
            severity="CRITICAL",
            confidence="HIGH",
            secret_preview="AKIA************CDEF",
            remediation="Rotate AWS IAM key immediately.",
            detection_type="signature",
        )

        metadata = {"target": "unit_test_repo", "duration_seconds": 0.05}

        ## Test JSON schema
        json_report = generate_json_report([sample_finding], metadata)
        parsed = json.loads(json_report)
        self.assertEqual(parsed["summary"]["total_findings"], 1)
        self.assertEqual(parsed["summary"]["severity_breakdown"]["CRITICAL"], 1)

        ## Test Markdown
        md_report = generate_markdown_report([sample_finding], metadata)
        self.assertIn("# 🛡️ Git Secret Shield - Security Audit Report", md_report)
        self.assertIn("[CRITICAL] AWS Access Key ID", md_report)
        self.assertIn("src/app.py:42", md_report)


class TestCliIntegration(unittest.TestCase):
    """Test suite validating command-line argument parsing and invocation."""

    def test_cli_patterns_command(self):
        """CLI `patterns` subcommand lists all signatures without errors."""
        exit_code = main(["patterns"])
        self.assertEqual(exit_code, 0)

    def test_cli_clean_scan(self):
        """CLI `scan` returns 0 on empty directory."""
        with tempfile.TemporaryDirectory() as tmp:
            exit_code = main(["scan", tmp, "--fail-on-findings"])
            self.assertEqual(exit_code, 0)

    def test_cli_scan_fail_on_findings(self):
        """CLI `scan --fail-on-findings` exits with returncode 1 when secrets exist."""
        with tempfile.TemporaryDirectory() as tmp:
            bad_file = Path(tmp) / "secret.txt"
            ghp_tok = _t("ghp_", "123456789012345678901234567890123456")
            bad_file.write_text(f"export TOKEN={ghp_tok}\n")
            exit_code = main(["scan", tmp, "--fail-on-findings"])
            self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
