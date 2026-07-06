"""Microsoft Information Protection (MIP) *textual* marking detector.

Genuine MIP sensitivity labels live in Office/OLE file metadata, which plain
Markdown does not carry. This detector finds the visible classification markings
and banners that people paste into document bodies, e.g.:

    Sensitivity: Highly Confidential
    Trend Micro - Confidential
    CLASSIFICATION: RESTRICTED
    [Internal Use Only]

Category: mip_labels
"""

from __future__ import annotations

import re
from typing import List

from ..config import Finding

MIP_LABELS = "mip_labels"

# Common sensitivity terms seen in MIP / corporate classification schemes.
_LABEL_TERMS = (
    r"Highly\s+Confidential",
    r"Confidential",
    r"Restricted",
    r"Internal\s+Use\s+Only",
    r"Internal\s+Only",
    r"Internal",
    r"Public",
    r"General",
    r"Secret",
    r"Top\s+Secret",
    r"Proprietary",
    r"Private",
    r"Do\s+Not\s+Distribute",
    r"Non[\s\-]?Business",
)
_TERMS_RE = "|".join(_LABEL_TERMS)
# Uppercase variants for the case-SENSITIVE all-caps standalone pattern, so that
# lowercase prose words ("public", "internal", "secret") are NOT matched, but a
# deliberate "CONFIDENTIAL" / "RESTRICTED" banner is. \s+ becomes \s+ (still fine).
_TERMS_UPPER = "|".join(t.upper() for t in _LABEL_TERMS)

_PATTERNS = [
    # "Sensitivity: Confidential" / "Classification - Restricted" / "Label: Internal"
    re.compile(
        rf"(?i)\b(?:sensitivity|classification|label|clearance)\b\s*[:\-]\s*"
        rf"(?:{_TERMS_RE})\b(?:\s*\\\s*[\w \-]+)?"
    ),
    # Company-prefixed banner: "Trend Micro - Confidential", "ACME | Highly Confidential"
    re.compile(rf"(?i)\b[\w][\w &.\-]{{1,40}}\s*[\-|]\s*(?:{_TERMS_RE})\b"),
    # Standalone markings only — must look like a real marking, NOT a bare word
    # occurring mid-prose. We accept three anchored forms:
    #   1) bracketed:            [Internal Use Only]  ( [ ... ] )
    #   2) ALL-CAPS token:       CONFIDENTIAL  (case-sensitive, so "public" prose is ignored)
    #   3) the sole content of a line (optionally bracketed), e.g. a banner line
    re.compile(rf"(?i)\[\s*(?:{_TERMS_RE})\s*\]"),
    re.compile(rf"\b(?:{_TERMS_UPPER})\b"),
    re.compile(rf"(?im)^\s*(?:\[\s*)?(?:{_TERMS_RE})(?:\s*\])?\s*$"),
]


def detect(doc: str, enabled_categories: dict) -> List[Finding]:
    if not enabled_categories.get(MIP_LABELS, True):
        return []

    findings: List[Finding] = []
    seen_spans = set()
    for idx, pattern in enumerate(_PATTERNS):
        for m in pattern.finditer(doc):
            span = (m.start(), m.end())
            # Skip if fully contained in an already-found (earlier, richer) span.
            if any(s <= span[0] and span[1] <= e for s, e in seen_spans):
                continue
            matched = m.group(0).strip()
            # Patterns 0-1 are richly-labeled ("Sensitivity: ...", company banner)
            # and most reliable; patterns 2-4 are anchored standalone markings
            # (bracketed, ALL-CAPS, or a whole-line banner) — still reliable, since
            # they no longer fire on bare lowercase words in prose.
            conf = 0.95 if idx < 2 else 0.85
            findings.append(
                Finding(
                    category=MIP_LABELS,
                    type="MIP_MARKING",
                    start=m.start(),
                    end=m.start() + len(m.group(0)),
                    text=matched,
                    confidence=conf,
                    source="mip",
                )
            )
            seen_spans.add(span)
    return findings
