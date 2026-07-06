"""Deterministic regex detectors for structured PII and secrets.

Fully offline. Each rule maps a pattern to a (category, type) and an optional
validator that rejects false positives (e.g. Luhn for credit cards).
"""

from __future__ import annotations

import re
from typing import Callable, List, Optional, Tuple

from ..config import Finding

# category constants (kept in sync with config.categories)
CLASSIC_PII = "classic_pii"
FINANCIAL_SECRETS = "financial_secrets"


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum — validates most real credit-card numbers."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13 or len(nums) > 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _iban_ok(candidate: str) -> bool:
    """ISO 7064 mod-97 check for IBANs."""
    s = candidate.replace(" ", "").upper()
    if len(s) < 15 or len(s) > 34:
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    try:
        return int(digits) % 97 == 1
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Rule table: (name, category, type, compiled regex, optional validator)
# Validator receives the matched string and returns True to keep the finding.
# --------------------------------------------------------------------------- #
Rule = Tuple[str, str, str, "re.Pattern[str]", Optional[Callable[[str], bool]]]

_RULES: List[Rule] = [
    (
        "email", CLASSIC_PII, "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        None,
    ),
    (
        # E.164-ish / common international & US formats. Deliberately conservative.
        "phone", CLASSIC_PII, "PHONE",
        re.compile(
            r"(?<!\w)(?:\+?\d{1,3}[\s.\-]?)?(?:\(\d{2,4}\)[\s.\-]?)?"
            r"\d{2,4}[\s.\-]\d{3,4}[\s.\-]?\d{3,4}(?!\w)"
        ),
        lambda m: sum(c.isdigit() for c in m) >= 9,
    ),
    (
        "credit_card", FINANCIAL_SECRETS, "CREDIT_CARD",
        re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)"),
        _luhn_ok,
    ),
    (
        "iban", FINANCIAL_SECRETS, "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b"),
        _iban_ok,
    ),
    (
        "us_ssn", CLASSIC_PII, "US_SSN",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        None,
    ),
    (
        "aws_access_key", FINANCIAL_SECRETS, "AWS_ACCESS_KEY",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        None,
    ),
    (
        "aws_secret_key", FINANCIAL_SECRETS, "AWS_SECRET_KEY",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})['\"]?"),
        None,
    ),
    (
        "google_api_key", FINANCIAL_SECRETS, "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        None,
    ),
    (
        "slack_token", FINANCIAL_SECRETS, "SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,72}\b"),
        None,
    ),
    (
        "github_token", FINANCIAL_SECRETS, "GITHUB_TOKEN",
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
        None,
    ),
    (
        "private_key", FINANCIAL_SECRETS, "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r"[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        None,
    ),
    (
        "jwt", FINANCIAL_SECRETS, "JWT",
        re.compile(r"\bey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        None,
    ),
    (
        "conn_string", FINANCIAL_SECRETS, "CONNECTION_STRING",
        re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
            r"[^\s:@/]+:[^\s:@/]+@[^\s/]+",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "generic_secret_assign", FINANCIAL_SECRETS, "SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|token|access[_\-]?key)\b"
            r"\s*[=:]\s*['\"]([^'\"\s]{6,})['\"]"
        ),
        None,
    ),
    (
        "ipv4", CLASSIC_PII, "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        None,
    ),
]


def detect(doc: str, enabled_categories: dict) -> List[Finding]:
    """Run every enabled regex rule over ``doc`` and return findings."""
    findings: List[Finding] = []
    for _name, category, ftype, pattern, validator in _RULES:
        if not enabled_categories.get(category, True):
            continue
        for m in pattern.finditer(doc):
            matched = m.group(0)
            if validator and not validator(matched):
                continue
            findings.append(
                Finding(
                    category=category,
                    type=ftype,
                    start=m.start(),
                    end=m.end(),
                    text=matched,
                    confidence=1.0,
                    source="regex",
                )
            )
    return findings
