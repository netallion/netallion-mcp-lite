"""Rules: count, uniqueness, and a format-valid positive sample per rule."""

from __future__ import annotations

import re

import pytest

from netallion_mcp_lite.rules import RULES
from netallion_mcp_lite.scanner import scan_text

VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# One format-valid (fake, non-live) sample line per rule id.
SAMPLES: dict[str, str] = {
    "aws-access-key-id": "key = AKIAIOSFODNN7EXAMPLE",
    "aws-secret-access-key": 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    "github-pat-classic": "token=ghp_" + "a" * 36,
    "github-oauth-token": "gho_" + "b" * 36,
    "github-app-token": "ghu_" + "c" * 36,
    "github-refresh-token": "ghr_" + "d" * 36,
    "github-fine-grained-pat": "github_pat_" + "a" * 82,
    "gitlab-pat": "glpat-" + "a" * 20,
    "openai-api-key": "OPENAI_KEY=sk-proj-" + "a" * 12 + "_" + "b" * 12 + "-" + "c" * 12,
    "anthropic-api-key": "sk-ant-api03-" + "a" * 80,
    "google-api-key": "AIza" + "a" * 35,
    "slack-token": "xoxb-1234567890-abcdefghijABC",
    "slack-webhook-url": "https://hooks.slack.com/services/T00000000/B00000000/" + "a" * 24,
    "stripe-live-secret-key": "sk_live_" + "a" * 24,
    "stripe-test-secret-key": "sk_test_" + "a" * 24,
    "twilio-api-key": "SK" + "0" * 32,
    "twilio-account-sid": "AC" + "0" * 32,
    "sendgrid-api-key": "SG." + "a" * 22 + "." + "b" * 43,
    "npm-access-token": "npm_" + "a" * 36,
    "pem-private-key": "-----BEGIN RSA PRIVATE KEY-----",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I",
    "db-connection-uri": "postgres://user:s3cr3tpass@db.internal:5432/app",
    "authorization-bearer": "Authorization: Bearer " + "a" * 30,
    "generic-api-key-assignment": 'api_key = "' + "a" * 20 + '"',
    "generic-password-assignment": 'password = "hunter2!!"',
    "azure-storage-account-key": "AccountKey=" + "a" * 86 + "==",
    "telegram-bot-token": "123456789:" + "A" * 35,
}


def test_rule_count_is_commodity_sized():
    assert 20 <= len(RULES) <= 30


def test_rule_ids_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_all_rules_have_valid_shape():
    for r in RULES:
        assert r.id and r.name and r.description and r.remediation
        assert r.severity in VALID_SEVERITIES
        assert isinstance(r.pattern, re.Pattern)


def test_every_rule_has_a_sample():
    assert set(SAMPLES) == {r.id for r in RULES}, "add/remove a SAMPLES entry to match RULES"


@pytest.mark.parametrize("rule_id,sample", list(SAMPLES.items()))
def test_sample_triggers_its_rule(rule_id: str, sample: str):
    found = {f.rule_id for f in scan_text(sample)}
    assert rule_id in found, f"{rule_id} did not match its own sample"


def test_clean_text_has_no_findings():
    clean = "def add(a, b):\n    return a + b  # just some ordinary code\n"
    assert scan_text(clean) == []


def test_openai_does_not_flag_kebab_identifiers():
    text = 'className = "sk-button-primary-large-outlined-variant"'
    assert "openai-api-key" not in {f.rule_id for f in scan_text(text)}


def test_openai_classic_key_matches():
    found = {f.rule_id for f in scan_text("key=sk-" + "A1b2C3d4" * 6)}  # 48 alnum
    assert "openai-api-key" in found
