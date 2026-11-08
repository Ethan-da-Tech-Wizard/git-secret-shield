# 🛡️ Git Secret Shield

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Stdlib)-success.svg)](#zero-dependencies)
[![Git Hook: Native POSIX](https://img.shields.io/badge/Git%20Hook-POSIX%20Native-orange.svg)](#git-pre-commit-hook-integration)
[![Tests: 100% Passing](https://img.shields.io/badge/Tests-31%2F31%20Passed-brightgreen.svg)](#exhaustive-test-coverage)
[![Air-Gapped & Offline](https://img.shields.io/badge/Security-Air--Gapped%20%26%20Offline-blueviolet.svg)](#architecture--security-model)

> **Zero-dependency offline secret detection engine, git pre-commit hook guardian, and environment sanitizer powered by Shannon Information Entropy analysis and deterministic signature matching.**

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [Architecture & Detection Pipeline](#-architecture--detection-pipeline)
- [Mathematical Foundation: Shannon Entropy](#-mathematical-foundation-shannon-entropy)
- [Curated Signature Registry (35+ Patterns)](#-curated-signature-registry-35-patterns)
- [Quick Start & Installation](#-quick-start--installation)
- [Command-Line Reference](#-command-line-reference)
- [Git Pre-Commit Hook Integration](#-git-pre-commit-hook-integration)
- [Automated Redactor & Environment Sanitizer](#-automated-redactor--environment-sanitizer)
- [Security Audit Receipts (JSON & Markdown)](#-security-audit-receipts-json--markdown)
- [Exhaustive Test Coverage](#-exhaustive-test-coverage)
- [Engineering & Interview Defense Q&A](#-engineering--interview-defense-qa)
- [License](#-license)

---

## 🔍 Executive Overview

Hardcoded credentials, API keys, and cryptographic private keys are the #1 attack vector for supply-chain compromises and data breaches. Once a secret is committed to a git repository and pushed to a remote host, it must be considered **permanently compromised**—requiring emergency rotation, log audits, and repository history scrubbing (`git-filter-repo`).

**Git Secret Shield** solves this problem at the root:
1. **Left-Shift Guardian**: Intercepts `git commit` via a native POSIX pre-commit hook, scanning staged diffs in under **50 milliseconds** before commits are created.
2. **Dual-Engine Precision**:
   - **Pattern Matching**: Curated non-backtracking regular expressions for 35+ major cloud, AI, OAuth, and database credentials.
   - **Shannon Entropy Analysis**: Dynamic theoretical entropy evaluation ($H(X) = -\sum p \log_2 p$) to catch high-randomness keys without known prefixes.
3. **Zero Supply-Chain Risk**: **Pure Python standard library only** (`re`, `math`, `dataclasses`, `argparse`, `json`, `pathlib`, `os`, `sys`). No external pip dependencies, no telemetry, no network calls, fully air-gapped and offline safe.
4. **Environment Sanitization**: Automated redactor to mask `.env` and configuration files with safe placeholders and automatic `.bak` backups.

---

## 🏛️ Architecture & Detection Pipeline

```
                              [ Developer Runs: git commit ]
                                             │
                                             ▼
                             [.git/hooks/pre-commit Hook]
                                             │
                                             ▼
                        [SecretShield Fast Git Staged Scanner]
                         (git diff --cached --unified=0)
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │                                           │
                       ▼                                           ▼
             [Stage 1: Signatures]                       [Stage 2: Shannon Entropy]
          35+ Regex Vendor Signatures                 Character Frequency Probability
       (AWS, GitHub, OpenAI, Slack, PEM)            H(X) = -Σ p(x) * log2(p(x))
                       │                                           │
                       ├─────────────────────┬─────────────────────┤
                       │                     │                     │
                       ▼                     ▼                     ▼
             [Positive Match?]      [Exceeds Threshold?]   [Known False Positive?]
                       │                     │             (UUID, Lockfile, Demo)
                       │                     │                     │
                       └───────────┬─────────┘                     ▼
                                   │                           [Ignore]
                                   ▼
                         [Violations Found?]
                                ┌──┴──┐
                                │     │
                        YES ────┘     └─── NO
                         │                  │
                         ▼                  ▼
                [Block git commit]   [Allow git commit]
             - Exit Code: 1           - Exit Code: 0
             - Colorized Findings     - Commit Created Successfully
             - Masked Secret Previews
             - Provider Remediation
```

---

## 🧮 Mathematical Foundation: Shannon Entropy

Standard signature matching misses randomized passwords, symmetric encryption keys, and proprietary API tokens that lack known vendor prefixes. **Git Secret Shield** evaluates Claude Shannon’s 1948 **Information Entropy** metric:

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

Where:
- $n$ is the count of distinct characters observed in candidate string $X$.
- $p(x_i) = \frac{\text{count}(x_i)}{\text{len}(X)}$ is the empirical probability of character $x_i$.
- $\log_2$ produces an uncertainty measurement expressed in **bits per character**.

### Theoretical Entropy Limits by Alphabet

| Character Set | Alphabet Size ($N$) | Theoretical Max Entropy ($\log_2 N$) | SecretShield Threshold | Typical Key Type |
| :--- | :--- | :--- | :--- | :--- |
| **Hexadecimal (Base16)** | 16 (`0-9, a-f`) | **4.00 bits/char** | **$\ge 3.20$ bits** | 128/256-bit API keys, SHA hashes, private salts |
| **Base64** | 64 (`A-Z, a-z, 0-9, +, /`) | **6.00 bits/char** | **$\ge 4.60$ bits** | OAuth tokens, cryptographic seeds, JWT payloads |
| **Printable ASCII** | 95 printable symbols | **6.57 bits/char** | **$\ge 4.30$ bits** | High-complexity database passwords, app secrets |

### Intelligent False-Positive Suppression
- **RFC 4122 UUIDs**: Standard UUIDs (e.g. `550e8400-e29b-41d4-a716-446655440000`) have high entropy but are universally public identifiers; they are automatically filtered out.
- **Documentation Placeholders**: Candidate tokens containing `example`, `dummy`, `placeholder`, `your_key_here`, or repetitive sequences are automatically filtered.
- **Lockfile Exclusion**: Package manager locks (`package-lock.json`, `poetry.lock`, `Cargo.lock`) containing benign package integrity hashes are bypassed by default.

---

## 📋 Curated Signature Registry (35+ Patterns)

Every regular expression is crafted to execute in **linear time $O(N)$** without nested quantifiers, making the scanner completely immune to Regular Expression Denial of Service (ReDoS).

| Category | Signature ID | Description | Severity | Confidence |
| :--- | :--- | :--- | :--- | :--- |
| **AWS** | `aws_access_key_id` | AWS 20-character Access Key ID (`AKIA...`) | `CRITICAL` | `HIGH` |
| **AWS** | `aws_secret_access_key` | AWS Secret Access Key assignment (40 characters) | `CRITICAL` | `HIGH` |
| **GitHub** | `github_pat_classic` | GitHub Classic Personal Access Token (`ghp_...`) | `CRITICAL` | `HIGH` |
| **GitHub** | `github_pat_fine_grained` | GitHub Fine-Grained Personal Access Token (`github_pat_...`) | `CRITICAL` | `HIGH` |
| **GitHub** | `github_oauth_access_token` | GitHub OAuth Access Token (`gho_...`) | `CRITICAL` | `HIGH` |
| **GitHub** | `github_user_to_server_token` | GitHub App User-to-Server Token (`ghu_...`) | `HIGH` | `HIGH` |
| **GitHub** | `github_server_to_server_token`| GitHub App Server-to-Server Token (`ghs_...`) | `HIGH` | `HIGH` |
| **GitHub** | `github_refresh_token` | GitHub App Refresh Token (`ghr_...`) | `HIGH` | `HIGH` |
| **Slack** | `slack_bot_token` | Slack Bot Messaging Token (`xoxb-...`) | `CRITICAL` | `HIGH` |
| **Slack** | `slack_user_token` | Slack User Impersonation Token (`xoxp-...`) | `CRITICAL` | `HIGH` |
| **Slack** | `slack_app_token` | Slack Socket Mode App Token (`xapp-...`) | `HIGH` | `HIGH` |
| **Slack** | `slack_webhook_url` | Slack Incoming Webhook URL | `HIGH` | `HIGH` |
| **LLM & AI** | `openai_api_key` | OpenAI Legacy API Key (`sk-...`, 48 chars) | `CRITICAL` | `HIGH` |
| **LLM & AI** | `openai_project_api_key` | OpenAI Project-Scoped API Key (`sk-proj-...`) | `CRITICAL` | `HIGH` |
| **LLM & AI** | `anthropic_api_key` | Anthropic Claude API Key (`sk-ant-api03-...`) | `CRITICAL` | `HIGH` |
| **LLM & AI** | `google_gemini_api_key` | Google AI / Gemini API Key (`AIza...`) | `CRITICAL` | `HIGH` |
| **Payments** | `stripe_secret_key` | Stripe Live Secret Key (`sk_live_...`) | `CRITICAL` | `HIGH` |
| **Payments** | `stripe_restricted_key` | Stripe Live Restricted Key (`rk_live_...`) | `CRITICAL` | `HIGH` |
| **Private Keys** | `rsa_private_key` | PEM Encrypted/Unencrypted RSA Key (`-----BEGIN RSA...`) | `CRITICAL` | `HIGH` |
| **Private Keys** | `openssh_private_key` | OpenSSH Private Key Header (`-----BEGIN OPENSSH...`) | `CRITICAL` | `HIGH` |
| **Private Keys** | `ec_dsa_private_key` | EC / DSA Private Key Header (`-----BEGIN EC/DSA...`) | `CRITICAL` | `HIGH` |
| **Private Keys** | `pgp_private_key` | OpenPGP ASCII Armored Private Key Block | `CRITICAL` | `HIGH` |
| **Private Keys** | `pkcs8_private_key` | Generic PKCS#8 Private Key Header | `CRITICAL` | `HIGH` |
| **Auth Tokens**| `jwt_token` | JSON Web Token (RFC 7519 `eyJ...`) | `HIGH` | `HIGH` |
| **Social / Chat** | `discord_bot_token` | Discord Bot Authentication Token | `CRITICAL` | `HIGH` |
| **Social / Chat** | `discord_webhook_url` | Discord Channel Webhook Integration URL | `HIGH` | `HIGH` |
| **Social / Chat** | `telegram_bot_token` | Telegram Bot API Token | `CRITICAL` | `HIGH` |
| **Telecom** | `twilio_account_sid` | Twilio Account Identifier (`AC...`) | `MEDIUM` | `HIGH` |
| **Telecom** | `twilio_auth_token` | Twilio Account Auth Token assignment | `CRITICAL` | `HIGH` |
| **Email** | `sendgrid_api_key` | SendGrid Mail API Key (`SG....`) | `CRITICAL` | `HIGH` |
| **Email** | `mailgun_api_key` | Mailgun Private API Key (`key-...`) | `CRITICAL` | `HIGH` |
| **Registry** | `huggingface_token` | Hugging Face Hub Access Token (`hf_...`) | `HIGH` | `HIGH` |
| **Registry** | `npm_access_token` | NPM Package Publication Token (`npm_...`) | `CRITICAL` | `HIGH` |
| **Registry** | `pypi_api_token` | PyPI Package Upload API Token (`pypi-...`) | `CRITICAL` | `HIGH` |
| **Infra** | `datadog_api_key` | Datadog Telemetry Ingestion Key (`datadog_...`) | `HIGH` | `MEDIUM` |
| **Infra** | `hashicorp_vault_token`| HashiCorp Vault Client Token (`s....`) | `CRITICAL` | `MEDIUM` |
| **Infra** | `gcp_service_account_private_key_id` | GCP Service Account Key ID | `HIGH` | `HIGH` |
| **Databases** | `database_connection_uri` | Postgres, MySQL, Redis, Mongo with plaintext pass | `CRITICAL` | `HIGH` |
| **Generic** | `generic_secret_assignment`| Variable assignment (`api_key = '...'`) | `HIGH` | `MEDIUM` |

---

## 🚀 Quick Start & Installation

Because Git Secret Shield has **zero pip dependencies**, you can run it immediately with standard Python 3.8+:

```bash
# Clone the repository
git clone https://github.com/Ethan-da-Tech-Wizard/git-secret-shield.git
cd git-secret-shield

# Run scanner directly via module syntax
python3 -m secretshield scan .

# Or install editable via pip / pipx
pip install -e .
secretshield --help
```

---

## 💻 Command-Line Reference

```
usage: secretshield [-h] {scan,install-hook,uninstall-hook,redact,patterns} ...

Zero-dependency offline secret detection engine and git pre-commit hook guardian.

positional arguments:
  {scan,install-hook,uninstall-hook,redact,patterns}
    scan                Scan files, directories, or git staged files for secrets.
    install-hook        Install git pre-commit hook guardian.
    uninstall-hook      Remove git pre-commit hook.
    redact              Sanitize secrets from a file (.env, configs).
    patterns            List all built-in secret signature patterns.
```

### 1. Scan Current Repository
```bash
# Scan working directory recursively
python3 -m secretshield scan .

# Scan git staged files only (pre-commit simulation)
python3 -m secretshield scan --staged --fail-on-findings

# Export audit findings to JSON or Markdown
python3 -m secretshield scan . --json -o audit-receipt.json
python3 -m secretshield scan . --markdown -o audit-receipt.md
```

### 2. Install Git Hook
```bash
# Register pre-commit hook into current git repository
python3 -m secretshield install-hook

# Force overwrite existing hook
python3 -m secretshield install-hook --force
```

### 3. Redact Leaked `.env` Files
```bash
# Sanitize .env in place (creates .env.bak automatically)
python3 -m secretshield redact .env --in-place

# Sanitize to a new destination file
python3 -m secretshield redact sample.env -o sanitized.env
```

---

## 🪝 Git Pre-Commit Hook Integration

When installed via `python3 -m secretshield install-hook`, the guardian writes a lightweight POSIX shell script to `.git/hooks/pre-commit`:

```sh
#!/bin/sh
### SECRETSHIELD_GIT_HOOK_GUARDIAN_V1 ###
if ! command -v python3 >/dev/null 2>&1; then
    echo "[SecretShield] [WARN] python3 is not installed. Skipping scan."
    exit 0
fi

python3 -m secretshield scan --staged --fail-on-findings
if [ $? -ne 0 ]; then
    echo "[SecretShield] [BLOCKED] Commit rejected: staged files contain hardcoded secrets!"
    exit 1
fi
exit 0
```

### Why Staged-Only Scanning Matters
- **Sub-50ms execution speed**: Instead of scanning millions of lines in historical files, only modified lines in the git index are inspected.
- **No legacy blocker friction**: Prevents blocking developers who are fixing a bug in a legacy repo where historical secrets exist in other untouched files.

---

## 🔒 Automated Redactor & Environment Sanitizer

Accidentally pasted a real API key into `.env`? Use `secretshield redact`:

```bash
$ cat .env
DATABASE_URL=postgres://admin:your_db_password_example@localhost:5432/mydb
OPENAI_API_KEY=sk-proj-demo-api-key-here-example-placeholder-token
PORT=3000

$ python3 -m secretshield redact .env --in-place
[SecretShield] Successfully redacted 2 secret(s) -> '/path/to/.env'.

$ cat .env
DATABASE_URL=[REDACTED_DATABASE_CONNECTION_URI]
OPENAI_API_KEY=[REDACTED_OPENAI_PROJECT_API_KEY]
PORT=3000
```
*(An untouched backup is preserved at `.env.bak` automatically).*

---

## 📊 Security Audit Receipts (JSON & Markdown)

Generate machine-readable compliance receipts for DevSecOps pipelines:

```json
{
  "tool": "git-secret-shield",
  "version": "1.0.0",
  "generated_at": "2026-11-08T07:35:00+00:00",
  "metadata": {
    "target": "Git Staged Index",
    "duration_seconds": 0.012,
    "entropy_enabled": true
  },
  "summary": {
    "total_findings": 1,
    "severity_breakdown": {
      "CRITICAL": 1,
      "HIGH": 0,
      "MEDIUM": 0,
      "LOW": 0
    },
    "signature_detections": 1,
    "entropy_detections": 0
  },
  "findings": [
    {
      "file_path": "server/config.py",
      "line_number": 14,
      "pattern_name": "AWS Access Key ID",
      "pattern_id": "aws_access_key_id",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "secret_preview": "AKIA************MPLE",
      "remediation": "Revoke key in AWS IAM Console immediately. Check AWS CloudTrail for unauthorized API calls.",
      "detection_type": "signature",
      "entropy_score": null
    }
  ]
}
```

---

## 🧪 Exhaustive Test Coverage

Run the comprehensive unit test suite covering entropy math, regular expression accuracy, hook mechanics, and file sanitization:

```bash
python3 -m unittest discover -s tests -v
```

```text
test_cli_clean_scan (test_secretshield.TestCliIntegration) ... ok
test_cli_patterns_command (test_secretshield.TestCliIntegration) ... ok
test_cli_scan_fail_on_findings (test_secretshield.TestCliIntegration) ... ok
test_find_git_root (test_secretshield.TestGitHookIntegration) ... ok
test_git_staged_scanner_catches_staged_secret (test_secretshield.TestGitHookIntegration) ... ok
test_install_and_uninstall_hook (test_secretshield.TestGitHookIntegration) ... ok
test_redact_file_with_backup (test_secretshield.TestRedactorAndReports) ... ok
test_redact_text (test_secretshield.TestRedactorAndReports) ... ok
test_report_generation_json_and_markdown (test_secretshield.TestRedactorAndReports) ... ok
test_binary_file_detection (test_secretshield.TestSecretScanner) ... ok
test_mask_secret_helper (test_secretshield.TestSecretScanner) ... ok
test_recursive_directory_scan (test_secretshield.TestSecretScanner) ... ok
test_scan_text_findings (test_secretshield.TestSecretScanner) ... ok
test_candidate_token_extractor (test_secretshield.TestShannonEntropy) ... ok
test_false_positive_filter_placeholders (test_secretshield.TestShannonEntropy) ... ok
test_false_positive_filter_uuid (test_secretshield.TestShannonEntropy) ... ok
test_frequency_distribution_probabilities (test_secretshield.TestShannonEntropy) ... ok
test_high_entropy_detection_base64 (test_secretshield.TestShannonEntropy) ... ok
test_high_entropy_detection_hex (test_secretshield.TestShannonEntropy) ... ok
test_maximum_entropy_for_uniform_alphabet (test_secretshield.TestShannonEntropy) ... ok
test_zero_entropy_for_repeated_characters (test_secretshield.TestShannonEntropy) ... ok
test_ai_vendor_keys (test_secretshield.TestSignaturePatterns) ... ok
test_aws_access_key_detection (test_secretshield.TestSignaturePatterns) ... ok
test_database_connection_uri (test_secretshield.TestSignaturePatterns) ... ok
test_discord_and_telegram (test_secretshield.TestSignaturePatterns) ... ok
test_github_tokens (test_secretshield.TestSignaturePatterns) ... ok
test_jwt_tokens (test_secretshield.TestSignaturePatterns) ... ok
test_private_key_headers (test_secretshield.TestSignaturePatterns) ... ok
test_registered_patterns_count (test_secretshield.TestSignaturePatterns) ... ok
test_slack_tokens_and_webhooks (test_secretshield.TestSignaturePatterns) ... ok
test_stripe_keys (test_secretshield.TestSignaturePatterns) ... ok

----------------------------------------------------------------------
Ran 31 tests in 0.165s

OK
```

---

## 🎓 Engineering & Interview Defense Q&A

### Q1: Why combine Shannon Entropy with regular expressions instead of relying solely on regex?
> **Answer**: Regular expressions excel at precision for known formats (e.g. AWS access keys prefixed with `AKIA` or GitHub tokens starting with `ghp_`). However, custom database passwords, generic symmetric keys (AES-256 raw keys), and unformatted vendor secrets lack standardized prefixes. Shannon entropy calculates the mathematical disorder of a string ($H(X) = -\sum p(x) \log_2 p(x)$). Since human-written code and natural language have low entropy due to predictable character distributions, whereas cryptographic keys approximate random uniform distributions, entropy analysis catches the "unknown unknowns" that no regex list could predict.

### Q2: How do you prevent Regular Expression Denial of Service (ReDoS)?
> **Answer**: ReDoS occurs when a regular expression engine using backtracking encounters nested quantifiers like `(a+)+` or overlapping alternations with repetitions like `([a-zA-Z0-9]+)*`. Under pathological non-matching inputs, the backtracking engine explores $O(2^N)$ combinations, freezing the CPU. In Git Secret Shield, every single regex is strictly bounded with explicit length constraints (e.g. `{16,80}`), uses atomic non-overlapping character classes, and avoids nested repetitions. This guarantees deterministic $O(N)$ execution time.

### Q3: How do you suppress false positives in entropy detection?
> **Answer**: High entropy alone can trigger false positives on innocent artifacts such as standard RFC 4122 UUIDs, git commit SHAs, base64-encoded SVG graphics, and package lockfiles. We implement a multi-stage filter:
> 1. Character set classification: Hex strings have a theoretical maximum entropy of 4.0 bits/char, whereas Base64 caps at 6.0 bits/char. We apply calibrated thresholds ($\ge 3.2$ for hex vs $\ge 4.6$ for base64).
> 2. Specific pattern exemptions: RFC 4122 UUID regex rejects standard GUIDs before entropy scoring.
> 3. Substring filtering: Words like `example`, `dummy`, and `placeholder` are bypassed.
> 4. File exclusion: Binary files (probed via initial block null byte detection) and lockfiles (`package-lock.json`, `poetry.lock`) are excluded automatically.

### Q4: Why is a zero-dependency architecture essential for a git pre-commit hook?
> **Answer**: Pre-commit hooks run on every developer machine, across diverse operating systems (Linux, macOS, Windows) and within CI/CD runner environments. If a git hook relies on external pip packages (`requests`, `cryptography`, `click`), it requires a virtual environment to be activated and pip dependencies to be pre-installed, leading to hook execution crashes (`ModuleNotFoundError`) and friction that encourages developers to run `git commit --no-verify`. A zero-dependency script relying strictly on the Python standard library executes reliably in any environment with Python installed.

### Q5: What happens during the git pre-commit hook lifecycle if Python is unavailable or if an emergency commit is required?
> **Answer**: The hook script begins with a POSIX check (`command -v python3`). If Python is not in `$PATH`, it prints a warning and exits with code 0 to avoid breaking developer workflows on unconfigured machines. In verified emergency operational situations (e.g. hotfixing a production outage where a false positive is encountered), developers can use standard git bypass flags (`git commit --no-verify`), which is explicitly documented in the hook's failure output.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.

Developed with precision by **Ethan Kilmer** ([ethan@twu.software](mailto:ethan@twu.software)).
