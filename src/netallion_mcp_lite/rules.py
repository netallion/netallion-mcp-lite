"""Commodity detection rules for Netallion MCP Lite.

INTENTIONALLY PUBLIC. Every rule here matches a credential/secret format that
is already widely documented in open tools and vendor docs (AWS, GitHub, Stripe,
etc.). None of this logic is derived from, copied from, or dependent on
Netallion's proprietary detection engine. The differentiated technology —
the full pattern corpus, BPE detection, live verifiers, FP classification, and
runtime AI-threat rules — lives exclusively in Netallion AI Assurance and is
NOT present in this package.

Design test applied to every rule: "Would we be comfortable publishing this
exact detection logic permanently on GitHub for competitors to copy?" Only
rules that pass are included. High-entropy/BPE-style generic detection is
deliberately excluded — it cannot be done well without proprietary technique.

Patterns are written to be simple and linear-time (no nested/ambiguous
quantifiers) to avoid catastrophic backtracking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

Severity = str  # "critical" | "high" | "medium" | "low"


@dataclass(frozen=True)
class Rule:
    """A single commodity detection rule."""

    id: str
    name: str
    severity: Severity
    description: str
    pattern: re.Pattern[str]
    remediation: str
    # 1-based index of the capture group holding the secret to redact; 0 = whole match.
    secret_group: int = 0
    tags: tuple[str, ...] = field(default_factory=tuple)


_ROTATE = (
    "Revoke/rotate this credential at the provider, remove it from the code or "
    "config, and load it from a secret manager or environment variable instead."
)

# ---------------------------------------------------------------------------
# Rules — commodity, high-confidence formats only.
# ---------------------------------------------------------------------------
RULES: tuple[Rule, ...] = (
    Rule(
        id="aws-access-key-id",
        name="AWS Access Key ID",
        severity="high",
        description="Amazon Web Services access key identifier (AKIA/ASIA prefix).",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        remediation="Deactivate the key in AWS IAM and issue a replacement. " + _ROTATE,
        tags=("cloud", "aws"),
    ),
    Rule(
        id="aws-secret-access-key",
        name="AWS Secret Access Key (assignment)",
        severity="high",
        description="A 40-char AWS secret access key assigned to an aws_secret_access_key field.",
        pattern=re.compile(
            r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+]{40})[\"']?"
        ),
        remediation="Rotate the AWS secret access key immediately in IAM. " + _ROTATE,
        secret_group=1,
        tags=("cloud", "aws"),
    ),
    Rule(
        id="github-pat-classic",
        name="GitHub Personal Access Token (classic)",
        severity="high",
        description="GitHub classic personal access token (ghp_ prefix).",
        pattern=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        remediation="Revoke the token in GitHub Developer settings. " + _ROTATE,
        tags=("vcs", "github"),
    ),
    Rule(
        id="github-oauth-token",
        name="GitHub OAuth Access Token",
        severity="high",
        description="GitHub OAuth access token (gho_ prefix).",
        pattern=re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        remediation=_ROTATE,
        tags=("vcs", "github"),
    ),
    Rule(
        id="github-app-token",
        name="GitHub App Token",
        severity="high",
        description="GitHub app user-to-server / server-to-server token (ghu_/ghs_ prefix).",
        pattern=re.compile(r"\b(?:ghu|ghs)_[A-Za-z0-9]{36}\b"),
        remediation=_ROTATE,
        tags=("vcs", "github"),
    ),
    Rule(
        id="github-refresh-token",
        name="GitHub Refresh Token",
        severity="medium",
        description="GitHub refresh token (ghr_ prefix).",
        pattern=re.compile(r"\bghr_[A-Za-z0-9]{36}\b"),
        remediation=_ROTATE,
        tags=("vcs", "github"),
    ),
    Rule(
        id="github-fine-grained-pat",
        name="GitHub Fine-Grained PAT",
        severity="high",
        description="GitHub fine-grained personal access token (github_pat_ prefix).",
        pattern=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        remediation="Revoke the fine-grained token in GitHub Developer settings. " + _ROTATE,
        tags=("vcs", "github"),
    ),
    Rule(
        id="gitlab-pat",
        name="GitLab Personal Access Token",
        severity="high",
        description="GitLab personal access token (glpat- prefix).",
        pattern=re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
        remediation="Revoke the token in GitLab access-token settings. " + _ROTATE,
        tags=("vcs", "gitlab"),
    ),
    Rule(
        id="openai-api-key",
        name="OpenAI API Key",
        severity="high",
        description="OpenAI API key (sk- prefix, incl. sk-proj-/sk-svcacct- with _/- in the body).",
        # Two precise forms: a known modern prefix (proj-/svcacct-/admin-) with a
        # long body, OR the classic long all-alphanumeric key. Matches real keys
        # without flagging ordinary sk-<kebab-case> identifiers.
        pattern=re.compile(
            r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b"
            r"|\bsk-[A-Za-z0-9]{32,}\b"
        ),
        remediation="Revoke the key in the OpenAI dashboard. " + _ROTATE,
        tags=("ai", "openai"),
    ),
    Rule(
        id="anthropic-api-key",
        name="Anthropic API Key",
        severity="high",
        description="Anthropic API key (sk-ant- prefix).",
        pattern=re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{80,}\b"),
        remediation="Revoke the key in the Anthropic console. " + _ROTATE,
        tags=("ai", "anthropic"),
    ),
    Rule(
        id="google-api-key",
        name="Google API Key",
        severity="high",
        description="Google API key (AIza prefix).",
        pattern=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        remediation="Regenerate the key in the Google Cloud console. " + _ROTATE,
        tags=("cloud", "google"),
    ),
    Rule(
        id="slack-token",
        name="Slack Token",
        severity="high",
        description="Slack API token (xoxb/xoxa/xoxp/xoxr/xoxs prefix).",
        pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
        remediation="Revoke the token in Slack app settings. " + _ROTATE,
        tags=("saas", "slack"),
    ),
    Rule(
        id="slack-webhook-url",
        name="Slack Incoming Webhook URL",
        severity="medium",
        description="Slack incoming webhook URL (hooks.slack.com/services/...).",
        pattern=re.compile(
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]{20,}"
        ),
        remediation="Delete and recreate the webhook in Slack. " + _ROTATE,
        tags=("saas", "slack"),
    ),
    Rule(
        id="stripe-live-secret-key",
        name="Stripe Live Secret Key",
        severity="critical",
        description="Stripe live-mode secret/restricted key (sk_live_/rk_live_).",
        pattern=re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
        remediation="Roll the key in the Stripe dashboard immediately. " + _ROTATE,
        tags=("payments", "stripe"),
    ),
    Rule(
        id="stripe-test-secret-key",
        name="Stripe Test Secret Key",
        severity="low",
        description="Stripe test-mode secret/restricted key (sk_test_/rk_test_).",
        pattern=re.compile(r"\b(?:sk|rk)_test_[0-9a-zA-Z]{24,}\b"),
        remediation="Test-mode key — still remove from source and roll if unsure. " + _ROTATE,
        tags=("payments", "stripe"),
    ),
    Rule(
        id="twilio-api-key",
        name="Twilio API Key SID",
        severity="high",
        description="Twilio API key SID (SK + 32 hex).",
        pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        remediation="Delete the API key in the Twilio console. " + _ROTATE,
        tags=("saas", "twilio"),
    ),
    Rule(
        id="twilio-account-sid",
        name="Twilio Account SID",
        severity="medium",
        description="Twilio account SID (AC + 32 hex).",
        pattern=re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
        remediation="Account SID is an identifier; ensure the paired auth token is not exposed.",
        tags=("saas", "twilio"),
    ),
    Rule(
        id="sendgrid-api-key",
        name="SendGrid API Key",
        severity="high",
        description="SendGrid API key (SG. prefix).",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
        remediation="Delete the key in SendGrid settings. " + _ROTATE,
        tags=("saas", "sendgrid"),
    ),
    Rule(
        id="npm-access-token",
        name="npm Access Token",
        severity="high",
        description="npm access token (npm_ prefix).",
        pattern=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        remediation="Revoke the token in your npm account settings. " + _ROTATE,
        tags=("package", "npm"),
    ),
    Rule(
        id="pem-private-key",
        name="Private Key (PEM header)",
        severity="critical",
        description="A PEM-encoded private key block header.",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        remediation="Treat the key as compromised: rotate the key pair and revoke any certs. " + _ROTATE,
        tags=("crypto", "private-key"),
    ),
    Rule(
        id="jwt",
        name="JSON Web Token",
        # Low severity: JWTs are structural (not inherently secret), so this is a
        # low-confidence signal. Severity communicates that confidence for now.
        severity="low",
        description="A JWT (three base64url segments, header starts with eyJ).",
        pattern=re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        remediation="If this token grants access, invalidate the session/signing key. " + _ROTATE,
        tags=("token", "jwt"),
    ),
    Rule(
        id="db-connection-uri",
        name="Database Connection URI with Credentials",
        severity="high",
        description="A database URI with an embedded username:password (postgres/mysql/mongodb/redis/amqp).",
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@[^\s/]+"
        ),
        remediation="Rotate the database password and move the URI to a secret manager. " + _ROTATE,
        tags=("database",),
    ),
    Rule(
        id="authorization-bearer",
        name="Authorization Bearer Token",
        severity="medium",
        description="An Authorization header assigning a Bearer token.",
        pattern=re.compile(
            r"(?i)authorization\s*[:=]\s*[\"']?bearer\s+([A-Za-z0-9\-._~+/]{20,}={0,2})"
        ),
        remediation="Rotate the bearer token/credential it represents. " + _ROTATE,
        secret_group=1,
        tags=("token",),
    ),
    Rule(
        id="generic-api-key-assignment",
        name="Generic API Key / Token Assignment",
        # Low severity/confidence: also matches placeholders/examples.
        severity="low",
        description="A quoted value assigned to an api_key / secret_key / access_token style field.",
        pattern=re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*[\"']([A-Za-z0-9\-_]{16,})[\"']"
        ),
        remediation="Confirm whether this is a live secret; if so, rotate it. " + _ROTATE,
        secret_group=1,
        tags=("generic",),
    ),
    Rule(
        id="generic-password-assignment",
        name="Hardcoded Password Assignment",
        severity="low",
        description="A quoted value assigned to a password / passwd / pwd field.",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']([^\"']{6,})[\"']"
        ),
        remediation="Do not hardcode passwords; load from a secret manager and rotate if real.",
        secret_group=1,
        tags=("generic",),
    ),
    Rule(
        id="azure-storage-account-key",
        name="Azure Storage Account Key",
        severity="high",
        description="An Azure Storage AccountKey= value (88-char base64).",
        pattern=re.compile(r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{86,}==)"),
        remediation="Regenerate the storage account key in the Azure portal. " + _ROTATE,
        secret_group=1,
        tags=("cloud", "azure"),
    ),
    Rule(
        id="telegram-bot-token",
        name="Telegram Bot Token",
        severity="medium",
        description="A Telegram bot token (numeric id : 35-char secret).",
        pattern=re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
        remediation="Revoke the bot token via BotFather (/revoke). " + _ROTATE,
        tags=("saas", "telegram"),
    ),
)


def rule_by_id(rule_id: str) -> Rule | None:
    for rule in RULES:
        if rule.id == rule_id:
            return rule
    return None
