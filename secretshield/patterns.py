"""
===============================================================================
SecretShield - Curated Secret Signature Patterns
===============================================================================

This module defines deterministic, high-accuracy signature patterns for identifying
known cryptographic secrets, OAuth tokens, cloud vendor credentials, and private keys.

Security & Performance Design Principles:
-----------------------------------------
1. Regular Expression Denial of Service (ReDoS) Defense:
   - All regex patterns are constructed strictly WITHOUT nested quantifiers
     (e.g., avoid `(a+)+` or `(.*)*`), which cause catastrophic backtracking O(2^N).
   - Patterns use bounded character classes and explicit length quantifiers,
     ensuring O(N) linear time evaluation with the standard library `re` engine.

2. High Signal-to-Noise Ratio (Low False Positives):
   - Strict vendor prefixes (e.g., `ghp_`, `AKIA`, `sk-ant-`, `SG.`) anchor matches.
   - For generic secret assignments, strict variable name lookbehinds and quote
     delimiters are enforced.

3. Defense-in-Depth Remediation Advice:
   - Each pattern specifies its exact severity (CRITICAL, HIGH, MEDIUM), confidence
     level, and specific remediation advice for credential rotation and revocation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class SecretPattern:
    """
    Data model representing a secret detection signature pattern.

    Attributes:
        id: Unique machine-readable identifier (e.g., 'aws_access_key_id').
        name: Human-readable display title.
        regex: Pre-compiled regular expression object.
        severity: Security severity rating ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        confidence: Signal confidence rating ('HIGH', 'MEDIUM', 'LOW').
        description: Technical explanation of the detected credential type.
        remediation: Step-by-step instructions for revoking and rotating the secret.
    """
    id: str
    name: str
    regex: re.Pattern
    severity: str
    confidence: str
    description: str
    remediation: str


# =============================================================================
# CURATED DETECTION PATTERNS (35+ SPECIFIC VENDOR & CREDENTIAL PATTERNS)
# =============================================================================

SCANNER_PATTERNS: List[SecretPattern] = [
    # -------------------------------------------------------------------------
    # 1. Amazon Web Services (AWS)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="aws_access_key_id",
        name="AWS Access Key ID",
        # AKIA prefix + 16 uppercase alphanumeric characters
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Identifies Amazon Web Services 20-character Access Key IDs starting with 'AKIA'.",
        remediation="Revoke key in AWS IAM Console immediately. Check AWS CloudTrail for unauthorized API calls."
    ),
    SecretPattern(
        id="aws_secret_access_key",
        name="AWS Secret Access Key Assignment",
        # Matches aws secret key variable assignment containing a 40-char base64-like string
        regex=re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key|aws_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        severity="CRITICAL",
        confidence="HIGH",
        description="Identifies AWS Secret Access Key string assignments (40 characters).",
        remediation="Revoke corresponding AWS IAM access key pair immediately and rotate."
    ),

    # -------------------------------------------------------------------------
    # 2. GitHub Tokens (All Flavors)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="github_pat_classic",
        name="GitHub Personal Access Token (Classic)",
        # 'ghp_' followed by 36 alphanumeric characters
        regex=re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="GitHub classic personal access token with standard 'ghp_' prefix.",
        remediation="Revoke in GitHub Settings -> Developer settings -> Personal access tokens."
    ),
    SecretPattern(
        id="github_pat_fine_grained",
        name="GitHub Fine-Grained Personal Access Token",
        # 'github_pat_' followed by 82 characters
        regex=re.compile(r"\b(github_pat_[0-9a-zA-Z_]{82})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="GitHub fine-grained repository access token.",
        remediation="Revoke in GitHub Settings -> Developer settings -> Personal access tokens (fine-grained)."
    ),
    SecretPattern(
        id="github_oauth_access_token",
        name="GitHub OAuth Access Token",
        # 'gho_' followed by 36 alphanumeric characters
        regex=re.compile(r"\b(gho_[0-9a-zA-Z]{36})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="GitHub OAuth application client access token.",
        remediation="Revoke token via GitHub OAuth application authorizations."
    ),
    SecretPattern(
        id="github_user_to_server_token",
        name="GitHub User-to-Server Token",
        # 'ghu_' followed by 36 alphanumeric characters
        regex=re.compile(r"\b(ghu_[0-9a-zA-Z]{36})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="GitHub App user-to-server token.",
        remediation="Revoke in GitHub App installations."
    ),
    SecretPattern(
        id="github_server_to_server_token",
        name="GitHub Server-to-Server Token",
        # 'ghs_' followed by 36 alphanumeric characters
        regex=re.compile(r"\b(ghs_[0-9a-zA-Z]{36})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="GitHub App server-to-server installation token.",
        remediation="Revoke through GitHub App API."
    ),
    SecretPattern(
        id="github_refresh_token",
        name="GitHub Refresh Token",
        # 'ghr_' followed by 36 alphanumeric characters
        regex=re.compile(r"\b(ghr_[0-9a-zA-Z]{36})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="GitHub App long-lived refresh token.",
        remediation="Revoke via OAuth token refresh endpoint."
    ),

    # -------------------------------------------------------------------------
    # 3. Slack Integration Tokens & Webhooks
    # -------------------------------------------------------------------------
    SecretPattern(
        id="slack_bot_token",
        name="Slack Bot Token",
        # 'xoxb-' + team id + user id + 24 char token
        regex=re.compile(r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Slack bot integration token with workspace messaging privileges.",
        remediation="Revoke token at api.slack.com/apps and reinstall bot."
    ),
    SecretPattern(
        id="slack_user_token",
        name="Slack User Token",
        # 'xoxp-' + team id + user id + 24 char token
        regex=re.compile(r"\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Slack user API token with full impersonation privileges.",
        remediation="Revoke token immediately at api.slack.com/apps."
    ),
    SecretPattern(
        id="slack_app_token",
        name="Slack App Token",
        # 'xapp-' format
        regex=re.compile(r"\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+)\b"),
        severity="HIGH",
        confidence="HIGH",
        description="Slack App-level token for socket mode and organizational operations.",
        remediation="Regenerate token in Slack App Settings -> Basic Information."
    ),
    SecretPattern(
        id="slack_webhook_url",
        name="Slack Incoming Webhook URL",
        # Slack incoming webhook URL
        regex=re.compile(
            r"(https://hooks\.slack\.com/services/T[0-9A-Z]{8,12}/B[0-9A-Z]{8,12}/[0-9A-Za-z]{24})"
        ),
        severity="HIGH",
        confidence="HIGH",
        description="Slack incoming webhook URL permitting unauthenticated channel messaging.",
        remediation="Delete webhook URL from Slack App incoming webhooks configuration."
    ),

    # -------------------------------------------------------------------------
    # 4. Large Language Model & AI API Keys (OpenAI, Anthropic, Google Gemini)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="openai_api_key",
        name="OpenAI API Key (Standard)",
        # 'sk-' followed by 48 alphanumeric characters
        regex=re.compile(r"\b(sk-[a-zA-Z0-9]{48})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Standard legacy OpenAI API authentication secret key.",
        remediation="Revoke immediately at platform.openai.com/api-keys."
    ),
    SecretPattern(
        id="openai_project_api_key",
        name="OpenAI Project-Scoped API Key",
        # 'sk-proj-' followed by project and secret strings
        regex=re.compile(r"\b(sk-proj-[a-zA-Z0-9_-]{48,128})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Modern OpenAI project-scoped API authorization key.",
        remediation="Revoke in OpenAI Dashboard -> Project Settings -> API Keys."
    ),
    SecretPattern(
        id="anthropic_api_key",
        name="Anthropic Claude API Key",
        # 'sk-ant-api03-' or similar prefix
        regex=re.compile(r"\b(sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{80,120})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Anthropic Claude API client authentication key.",
        remediation="Revoke immediately in Anthropic Console (console.anthropic.com)."
    ),
    SecretPattern(
        id="google_gemini_api_key",
        name="Google AI / Gemini API Key",
        # 'AIza' followed by 35 alphanumeric or dash/underscore characters
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Google Cloud API key (Gemini, Maps, Firebase, etc.).",
        remediation="Delete or restrict key in Google Cloud Console -> APIs & Services -> Credentials."
    ),

    # -------------------------------------------------------------------------
    # 5. Stripe Payment Processing Keys
    # -------------------------------------------------------------------------
    SecretPattern(
        id="stripe_secret_key",
        name="Stripe Live Secret Key",
        # 'sk_live_' followed by 24 to 34 characters
        regex=re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Stripe production secret key granting full programmatic access to charge cards and refund customers.",
        remediation="Roll key immediately at dashboard.stripe.com/apikeys."
    ),
    SecretPattern(
        id="stripe_restricted_key",
        name="Stripe Live Restricted Key",
        # 'rk_live_' followed by 24 to 34 characters
        regex=re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,34})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Stripe restricted access key with scoped permissions.",
        remediation="Revoke restricted key at dashboard.stripe.com/apikeys."
    ),

    # -------------------------------------------------------------------------
    # 6. Asymmetric Cryptographic Private Keys (PEM / OpenSSH / PGP)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="rsa_private_key",
        name="RSA Private Key Header",
        regex=re.compile(r"(-----BEGIN RSA PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Unencrypted RSA Private Key block in PKCS#1 PEM format.",
        remediation="Generate new RSA key pair. Remove compromised private key from host and authorized_keys."
    ),
    SecretPattern(
        id="openssh_private_key",
        name="OpenSSH Private Key Header",
        regex=re.compile(r"(-----BEGIN OPENSSH PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="OpenSSH format private key file.",
        remediation="Generate new SSH key pair (`ssh-keygen -t ed25519`). Remove public key from ~/.ssh/authorized_keys."
    ),
    SecretPattern(
        id="ec_dsa_private_key",
        name="EC or DSA Private Key Header",
        regex=re.compile(r"(-----BEGIN (?:EC|DSA) PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Elliptic Curve or DSA format private key header.",
        remediation="Revoke certificate and regenerate key pair."
    ),
    SecretPattern(
        id="pgp_private_key",
        name="PGP Private Key Block",
        regex=re.compile(r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="OpenPGP ASCII Armored private key block.",
        remediation="Issue PGP revocation certificate and publish to keyservers."
    ),
    SecretPattern(
        id="pkcs8_private_key",
        name="Generic PKCS#8 Private Key Header",
        regex=re.compile(r"(-----BEGIN PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Standard PKCS#8 unencrypted private key header.",
        remediation="Revoke dependent certificates and rotate private key."
    ),

    # -------------------------------------------------------------------------
    # 7. Authentication Tokens & Signatures (JWT)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="jwt_token",
        name="JSON Web Token (JWT)",
        # 'eyJ' header, 'eyJ' payload, and base64 signature
        regex=re.compile(
            r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
        ),
        severity="HIGH",
        confidence="HIGH",
        description="Standard JSON Web Token (RFC 7519) carrying authentication claims and signatures.",
        remediation="Invalidate token session in authentication server and verify signing secret integrity."
    ),

    # -------------------------------------------------------------------------
    # 8. Chat & Social Platforms (Discord, Telegram)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="discord_bot_token",
        name="Discord Bot Token",
        # Discord bot token: UserID (Base64) + timestamp + HMAC signature
        regex=re.compile(r"\b([MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Discord bot authorization token.",
        remediation="Reset token at discord.com/developers/applications."
    ),
    SecretPattern(
        id="discord_webhook_url",
        name="Discord Webhook URL",
        regex=re.compile(
            r"(https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68})"
        ),
        severity="HIGH",
        confidence="HIGH",
        description="Discord channel webhook integration URL.",
        remediation="Delete webhook in Discord Channel Settings -> Integrations."
    ),
    SecretPattern(
        id="telegram_bot_token",
        name="Telegram Bot Token",
        # Bot user ID followed by 35-character secret string
        regex=re.compile(r"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Telegram Bot API authentication token.",
        remediation="Revoke token via BotFather with `/revoke` command."
    ),

    # -------------------------------------------------------------------------
    # 9. Telecommunications & Communications (Twilio, SendGrid, Mailgun)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="twilio_account_sid",
        name="Twilio Account SID",
        regex=re.compile(r"\b(AC[a-f0-9]{32})\b"),
        severity="MEDIUM",
        confidence="HIGH",
        description="Twilio account identifier prefix.",
        remediation="Ensure accompanying Twilio Auth Token is also kept confidential."
    ),
    SecretPattern(
        id="twilio_auth_token",
        name="Twilio Auth Token Assignment",
        regex=re.compile(
            r"(?i)\b(?:twilio_auth_token|twilio_token|auth_token)\s*[:=]\s*['\"]([a-f0-9]{32})['\"]"
        ),
        severity="CRITICAL",
        confidence="HIGH",
        description="Twilio 32-character hexadecimal authorization token.",
        remediation="Rotate Auth Token in Twilio Console."
    ),
    SecretPattern(
        id="sendgrid_api_key",
        name="SendGrid API Key",
        regex=re.compile(r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Twilio SendGrid email dispatch API key.",
        remediation="Delete and regenerate key in SendGrid Settings -> API Keys."
    ),
    SecretPattern(
        id="mailgun_api_key",
        name="Mailgun API Key",
        regex=re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Mailgun transaction email API key.",
        remediation="Rotate primary API key in Mailgun Dashboard -> API Security."
    ),

    # -------------------------------------------------------------------------
    # 10. Developer Ecosystem & Package Registries (HuggingFace, NPM, PyPI)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="huggingface_token",
        name="Hugging Face Access Token",
        regex=re.compile(r"\b(hf_[a-zA-Z0-9]{34})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="Hugging Face model hub user access token.",
        remediation="Revoke token at huggingface.co/settings/tokens."
    ),
    SecretPattern(
        id="npm_access_token",
        name="NPM Access Token",
        regex=re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="NPM package publication token.",
        remediation="Revoke token via `npm token revoke` or at npmjs.com/settings/tokens."
    ),
    SecretPattern(
        id="pypi_api_token",
        name="PyPI Upload API Token",
        regex=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Python Package Index (PyPI) package publishing token.",
        remediation="Revoke token immediately in PyPI Account Settings."
    ),

    # -------------------------------------------------------------------------
    # 11. Monitoring & Infrastructure (Datadog, Vault, GCP Service Account)
    # -------------------------------------------------------------------------
    SecretPattern(
        id="datadog_api_key",
        name="Datadog API Key",
        regex=re.compile(r"\b(?:datadog|dd)_[a-f0-9]{32}\b"),
        severity="HIGH",
        confidence="MEDIUM",
        description="Datadog monitoring and metric ingestion API key.",
        remediation="Revoke key in Datadog Organization Settings -> API Keys."
    ),
    SecretPattern(
        id="hashicorp_vault_token",
        name="HashiCorp Vault Token",
        regex=re.compile(r"\b(s\.[a-zA-Z0-9]{24})\b"),
        severity="CRITICAL",
        confidence="MEDIUM",
        description="HashiCorp Vault access client token.",
        remediation="Revoke token using `vault token revoke`."
    ),
    SecretPattern(
        id="gcp_service_account_private_key_id",
        name="GCP Service Account Key ID",
        regex=re.compile(r'"private_key_id":\s*"([0-9a-f]{40})"'),
        severity="HIGH",
        confidence="HIGH",
        description="Google Cloud Platform Service Account JSON key ID descriptor.",
        remediation="Delete service account key in GCP IAM & Admin -> Service Accounts."
    ),

    # -------------------------------------------------------------------------
    # 12. Database Connection Strings & Generic Secret Assignments
    # -------------------------------------------------------------------------
    SecretPattern(
        id="database_connection_uri",
        name="Database Connection URI with Credentials",
        regex=re.compile(
            r"((?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_\-\.]+:[^@\s/:]+@[a-zA-Z0-9\.\-]+(?::\d+)?/[a-zA-Z0-9_\-\.]*)"
        ),
        severity="CRITICAL",
        confidence="HIGH",
        description="Database connection URI containing embedded plaintext password.",
        remediation="Change database user password and inject credentials via environment variables."
    ),
    SecretPattern(
        id="generic_secret_assignment",
        name="Generic Secret Assignment",
        regex=re.compile(
            r"(?i)\b(?:api_key|apikey|secret_key|client_secret|auth_token|access_token|private_key|app_secret|db_password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{16,80})['\"]"
        ),
        severity="HIGH",
        confidence="MEDIUM",
        description="Generic programming variable assignment holding a potential plaintext secret.",
        remediation="Move secret value to an external secret store or environment variable."
    ),
]


def find_pattern_by_id(pattern_id: str) -> Optional[SecretPattern]:
    """
    Look up a registered SecretPattern by its unique string identifier.

    Args:
        pattern_id: The ID string (e.g. 'aws_access_key_id').

    Returns:
        The matching SecretPattern or None if not found.
    """
    for pattern in SCANNER_PATTERNS:
        if pattern.id == pattern_id:
            return pattern
    return None
