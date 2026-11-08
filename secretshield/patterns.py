"""
Program: Git Secret Shield - Curated Secret Signature Patterns
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Define deterministic, non-backtracking regular expression signature definitions for over 35 cloud vendors, OAuth providers, AI API keys, payment gateways, and private keys with zero external dependencies.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## re: Regular expression compilation and matching engine
import re
## dataclasses: Structured immutable data container for signature definitions
from dataclasses import dataclass
## typing: Static type definitions for pattern lists and optional lookups
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


## =============================================================================
## CURATED DETECTION PATTERNS (35+ SPECIFIC VENDOR & CREDENTIAL PATTERNS)
## =============================================================================
## Designed strictly with non-backtracking regular expressions to avoid ReDoS O(2^N)
## and linear time O(N) evaluation across text lines.

SCANNER_PATTERNS: List[SecretPattern] = [
    ## -------------------------------------------------------------------------
    ## 1. Amazon Web Services (AWS) Credentials
    ## -------------------------------------------------------------------------
    ## AWS Access Key ID: Standard IAM user credential starting with AKIA
    SecretPattern(
        id="aws_access_key_id",
        name="AWS Access Key ID",
        regex=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Identifies Amazon Web Services 20-character Access Key IDs starting with 'AKIA'.",
        remediation="Revoke key in AWS IAM Console immediately. Check AWS CloudTrail for unauthorized API calls."
    ),
    ## AWS Secret Access Key: Paired 40-character secret token assigned to environment variable
    SecretPattern(
        id="aws_secret_access_key",
        name="AWS Secret Access Key Assignment",
        regex=re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key|aws_key)\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        severity="CRITICAL",
        confidence="HIGH",
        description="Identifies AWS Secret Access Key string assignments (40 characters).",
        remediation="Revoke corresponding AWS IAM access key pair immediately and rotate."
    ),

    ## -------------------------------------------------------------------------
    ## 2. GitHub Access Tokens (All Flavors)
    ## -------------------------------------------------------------------------
    ## Classic Personal Access Token (PAT) with 'ghp_' prefix
    SecretPattern(
        id="github_pat_classic",
        name="GitHub Personal Access Token (Classic)",
        regex=re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="GitHub classic personal access token with standard 'ghp_' prefix.",
        remediation="Revoke in GitHub Settings -> Developer settings -> Personal access tokens."
    ),
    ## Fine-Grained Personal Access Token with 'github_pat_' prefix
    SecretPattern(
        id="github_pat_fine_grained",
        name="GitHub Fine-Grained Personal Access Token",
        regex=re.compile(r"\b(github_pat_[0-9a-zA-Z_]{82})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="GitHub fine-grained repository access token.",
        remediation="Revoke in GitHub Settings -> Developer settings -> Personal access tokens (fine-grained)."
    ),
    ## OAuth Access Token with 'gho_' prefix
    SecretPattern(
        id="github_oauth_access_token",
        name="GitHub OAuth Access Token",
        regex=re.compile(r"\b(gho_[0-9a-zA-Z]{36})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="GitHub OAuth application client access token.",
        remediation="Revoke token via GitHub OAuth application authorizations."
    ),
    ## GitHub App User-to-Server Token with 'ghu_' prefix
    SecretPattern(
        id="github_user_to_server_token",
        name="GitHub User-to-Server Token",
        regex=re.compile(r"\b(ghu_[0-9a-zA-Z]{36})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="GitHub App user-to-server token.",
        remediation="Revoke in GitHub App installations."
    ),
    ## GitHub App Server-to-Server Token with 'ghs_' prefix
    SecretPattern(
        id="github_server_to_server_token",
        name="GitHub Server-to-Server Token",
        regex=re.compile(r"\b(ghs_[0-9a-zA-Z]{36})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="GitHub App server-to-server installation token.",
        remediation="Revoke through GitHub App API."
    ),
    ## GitHub App Refresh Token with 'ghr_' prefix
    SecretPattern(
        id="github_refresh_token",
        name="GitHub Refresh Token",
        regex=re.compile(r"\b(ghr_[0-9a-zA-Z]{36})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="GitHub App long-lived refresh token.",
        remediation="Revoke via OAuth token refresh endpoint."
    ),

    ## -------------------------------------------------------------------------
    ## 3. Slack Integration Tokens & Webhooks
    ## -------------------------------------------------------------------------
    ## Slack Bot Token starting with 'xoxb-'
    SecretPattern(
        id="slack_bot_token",
        name="Slack Bot Token",
        regex=re.compile(r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Slack bot integration token with workspace messaging privileges.",
        remediation="Revoke token at api.slack.com/apps and reinstall bot."
    ),
    ## Slack User Impersonation Token starting with 'xoxp-'
    SecretPattern(
        id="slack_user_token",
        name="Slack User Token",
        regex=re.compile(r"\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Slack user API token with full impersonation privileges.",
        remediation="Revoke token immediately at api.slack.com/apps."
    ),
    ## Slack App Token starting with 'xapp-'
    SecretPattern(
        id="slack_app_token",
        name="Slack App Token",
        regex=re.compile(r"\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+)\b"),
        severity="HIGH",
        confidence="HIGH",
        description="Slack App-level token for socket mode and organizational operations.",
        remediation="Regenerate token in Slack App Settings -> Basic Information."
    ),
    ## Slack Incoming Webhook URL
    SecretPattern(
        id="slack_webhook_url",
        name="Slack Incoming Webhook URL",
        regex=re.compile(
            r"(https://hooks\.slack\.com/services/T[0-9A-Z]{8,12}/B[0-9A-Z]{8,12}/[0-9A-Za-z]{24})"
        ),
        severity="HIGH",
        confidence="HIGH",
        description="Slack incoming webhook URL permitting unauthenticated channel messaging.",
        remediation="Delete webhook URL from Slack App incoming webhooks configuration."
    ),

    ## -------------------------------------------------------------------------
    ## 4. Large Language Model & AI API Keys (OpenAI, Anthropic, Google Gemini)
    ## -------------------------------------------------------------------------
    ## Standard OpenAI API Key starting with 'sk-'
    SecretPattern(
        id="openai_api_key",
        name="OpenAI API Key (Standard)",
        regex=re.compile(r"\b(sk-[a-zA-Z0-9]{48})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Standard legacy OpenAI API authentication secret key.",
        remediation="Revoke immediately at platform.openai.com/api-keys."
    ),
    ## Modern Project-Scoped OpenAI API Key starting with 'sk-proj-'
    SecretPattern(
        id="openai_project_api_key",
        name="OpenAI Project-Scoped API Key",
        regex=re.compile(r"\b(sk-proj-[a-zA-Z0-9_-]{48,128})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Modern OpenAI project-scoped API authorization key.",
        remediation="Revoke in OpenAI Dashboard -> Project Settings -> API Keys."
    ),
    ## Anthropic Claude API Key starting with 'sk-ant-api'
    SecretPattern(
        id="anthropic_api_key",
        name="Anthropic Claude API Key",
        regex=re.compile(r"\b(sk-ant-api[0-9]{2}-[a-zA-Z0-9_-]{80,120})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Anthropic Claude API client authentication key.",
        remediation="Revoke immediately in Anthropic Console (console.anthropic.com)."
    ),
    ## Google Cloud & Gemini API Key starting with 'AIza'
    SecretPattern(
        id="google_gemini_api_key",
        name="Google AI / Gemini API Key",
        regex=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Google Cloud API key (Gemini, Maps, Firebase, etc.).",
        remediation="Delete or restrict key in Google Cloud Console -> APIs & Services -> Credentials."
    ),

    ## -------------------------------------------------------------------------
    ## 5. Stripe Payment Processing Keys
    ## -------------------------------------------------------------------------
    ## Stripe Live Secret Key starting with 'sk_live_'
    SecretPattern(
        id="stripe_secret_key",
        name="Stripe Live Secret Key",
        regex=re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,34})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Stripe production secret key granting full programmatic access to charge cards and refund customers.",
        remediation="Roll key immediately at dashboard.stripe.com/apikeys."
    ),
    ## Stripe Live Restricted Key starting with 'rk_live_'
    SecretPattern(
        id="stripe_restricted_key",
        name="Stripe Live Restricted Key",
        regex=re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,34})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Stripe restricted access key with scoped permissions.",
        remediation="Revoke restricted key at dashboard.stripe.com/apikeys."
    ),

    ## -------------------------------------------------------------------------
    ## 6. Asymmetric Cryptographic Private Keys (PEM / OpenSSH / PGP)
    ## -------------------------------------------------------------------------
    ## RSA Private Key PEM header
    SecretPattern(
        id="rsa_private_key",
        name="RSA Private Key Header",
        regex=re.compile(r"(-----BEGIN RSA PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Unencrypted RSA Private Key block in PKCS#1 PEM format.",
        remediation="Generate new RSA key pair. Remove compromised private key from host and authorized_keys."
    ),
    ## OpenSSH Private Key header
    SecretPattern(
        id="openssh_private_key",
        name="OpenSSH Private Key Header",
        regex=re.compile(r"(-----BEGIN OPENSSH PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="OpenSSH format private key file.",
        remediation="Generate new SSH key pair (`ssh-keygen -t ed25519`). Remove public key from ~/.ssh/authorized_keys."
    ),
    ## Elliptic Curve or DSA Private Key header
    SecretPattern(
        id="ec_dsa_private_key",
        name="EC or DSA Private Key Header",
        regex=re.compile(r"(-----BEGIN (?:EC|DSA) PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Elliptic Curve or DSA format private key header.",
        remediation="Revoke certificate and regenerate key pair."
    ),
    ## OpenPGP ASCII Armored Private Key block
    SecretPattern(
        id="pgp_private_key",
        name="PGP Private Key Block",
        regex=re.compile(r"(-----BEGIN PGP PRIVATE KEY BLOCK-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="OpenPGP ASCII Armored private key block.",
        remediation="Issue PGP revocation certificate and publish to keyservers."
    ),
    ## Generic PKCS#8 Unencrypted Private Key header
    SecretPattern(
        id="pkcs8_private_key",
        name="Generic PKCS#8 Private Key Header",
        regex=re.compile(r"(-----BEGIN PRIVATE KEY-----)"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Standard PKCS#8 unencrypted private key header.",
        remediation="Revoke dependent certificates and rotate private key."
    ),

    ## -------------------------------------------------------------------------
    ## 7. Authentication Tokens & Signatures (JWT)
    ## -------------------------------------------------------------------------
    ## Standard JSON Web Token (RFC 7519) format
    SecretPattern(
        id="jwt_token",
        name="JSON Web Token (JWT)",
        regex=re.compile(
            r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
        ),
        severity="HIGH",
        confidence="HIGH",
        description="Standard JSON Web Token (RFC 7519) carrying authentication claims and signatures.",
        remediation="Invalidate token session in authentication server and verify signing secret integrity."
    ),

    ## -------------------------------------------------------------------------
    ## 8. Chat & Social Platforms (Discord, Telegram)
    ## -------------------------------------------------------------------------
    ## Discord Bot Authentication Token
    SecretPattern(
        id="discord_bot_token",
        name="Discord Bot Token",
        regex=re.compile(r"\b([MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Discord bot authorization token.",
        remediation="Reset token at discord.com/developers/applications."
    ),
    ## Discord Webhook Integration URL
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
    ## Telegram Bot API Authentication Token
    SecretPattern(
        id="telegram_bot_token",
        name="Telegram Bot Token",
        regex=re.compile(r"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Telegram Bot API authentication token.",
        remediation="Revoke token via BotFather with `/revoke` command."
    ),

    ## -------------------------------------------------------------------------
    ## 9. Telecommunications & Communications (Twilio, SendGrid, Mailgun)
    ## -------------------------------------------------------------------------
    ## Twilio Account SID identifier
    SecretPattern(
        id="twilio_account_sid",
        name="Twilio Account SID",
        regex=re.compile(r"\b(AC[a-f0-9]{32})\b"),
        severity="MEDIUM",
        confidence="HIGH",
        description="Twilio account identifier prefix.",
        remediation="Ensure accompanying Twilio Auth Token is also kept confidential."
    ),
    ## Twilio 32-character Auth Token assignment
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
    ## SendGrid Email API Key starting with 'SG.'
    SecretPattern(
        id="sendgrid_api_key",
        name="SendGrid API Key",
        regex=re.compile(r"\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Twilio SendGrid email dispatch API key.",
        remediation="Delete and regenerate key in SendGrid Settings -> API Keys."
    ),
    ## Mailgun Transaction Email API Key
    SecretPattern(
        id="mailgun_api_key",
        name="Mailgun API Key",
        regex=re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Mailgun transaction email API key.",
        remediation="Rotate primary API key in Mailgun Dashboard -> API Security."
    ),

    ## -------------------------------------------------------------------------
    ## 10. Developer Ecosystem & Package Registries (HuggingFace, NPM, PyPI)
    ## -------------------------------------------------------------------------
    ## Hugging Face User Access Token starting with 'hf_'
    SecretPattern(
        id="huggingface_token",
        name="Hugging Face Access Token",
        regex=re.compile(r"\b(hf_[a-zA-Z0-9]{34})\b"),
        severity="HIGH",
        confidence="HIGH",
        description="Hugging Face model hub user access token.",
        remediation="Revoke token at huggingface.co/settings/tokens."
    ),
    ## NPM Package Publication Access Token starting with 'npm_'
    SecretPattern(
        id="npm_access_token",
        name="NPM Access Token",
        regex=re.compile(r"\b(npm_[a-zA-Z0-9]{36})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="NPM package publication token.",
        remediation="Revoke token via `npm token revoke` or at npmjs.com/settings/tokens."
    ),
    ## PyPI Upload API Token starting with 'pypi-AgEIcHlwaS5vcmc'
    SecretPattern(
        id="pypi_api_token",
        name="PyPI Upload API Token",
        regex=re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,})\b"),
        severity="CRITICAL",
        confidence="HIGH",
        description="Python Package Index (PyPI) package publishing token.",
        remediation="Revoke token immediately in PyPI Account Settings."
    ),

    ## -------------------------------------------------------------------------
    ## 11. Monitoring & Infrastructure (Datadog, Vault, GCP Service Account)
    ## -------------------------------------------------------------------------
    ## Datadog Monitoring Ingestion API Key
    SecretPattern(
        id="datadog_api_key",
        name="Datadog API Key",
        regex=re.compile(r"\b(?:datadog|dd)_[a-f0-9]{32}\b"),
        severity="HIGH",
        confidence="MEDIUM",
        description="Datadog monitoring and metric ingestion API key.",
        remediation="Revoke key in Datadog Organization Settings -> API Keys."
    ),
    ## HashiCorp Vault Client Token starting with 's.'
    SecretPattern(
        id="hashicorp_vault_token",
        name="HashiCorp Vault Token",
        regex=re.compile(r"\b(s\.[a-zA-Z0-9]{24})\b"),
        severity="CRITICAL",
        confidence="MEDIUM",
        description="HashiCorp Vault access client token.",
        remediation="Revoke token using `vault token revoke`."
    ),
    ## GCP Service Account Private Key ID JSON field descriptor
    SecretPattern(
        id="gcp_service_account_private_key_id",
        name="GCP Service Account Key ID",
        regex=re.compile(r'"private_key_id":\s*"([0-9a-f]{40})"'),
        severity="HIGH",
        confidence="HIGH",
        description="Google Cloud Platform Service Account JSON key ID descriptor.",
        remediation="Delete service account key in GCP IAM & Admin -> Service Accounts."
    ),

    ## -------------------------------------------------------------------------
    ## 12. Database Connection Strings & Generic Secret Assignments
    ## -------------------------------------------------------------------------
    ## Database URI containing plaintext credentials (postgres, mysql, mongodb, redis)
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
    ## Generic variable assignment holding credential values in code
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
    ## Iterate through registered scanner patterns
    for pattern in SCANNER_PATTERNS:
        ## If pattern identifier matches requested ID, return it immediately
        if pattern.id == pattern_id:
            return pattern

    ## Return None if no pattern matched the requested identifier
    return None
