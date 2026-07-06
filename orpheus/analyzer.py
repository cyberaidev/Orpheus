"""Orchestrates the hybrid detection pipeline.

regex + MIP passes run first (cheap, precise). If enabled, a local-LLM pass adds
contextual/corporate-sensitive spans and any PII the regexes missed. All findings
are merged and de-duplicated into a single ordered list.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from .config import Finding
from .detectors import mip, regex_rules
from .llm import LLMBackend, LLMError

# Chunk size for the LLM pass (characters). Keeps prompts within a small model's
# comfortable context while overlapping a little to avoid splitting entities.
_CHUNK = 3500
_OVERLAP = 200

_LLM_SYSTEM = """You are a data-loss-prevention scanner. Find spans of SENSITIVE \
information in the text below. Focus on things regular expressions miss:
- personal names, physical/postal addresses, dates of birth
- internal project codenames, unreleased product or financial figures
- customer/partner company names in a confidential context
- anything a corporation would consider Confidential or Internal-only

Do NOT report generic words, public info, or common terms.

Return ONLY a JSON array. Each element:
{"text": "<exact substring copied verbatim from the input>", "type": "<SHORT_UPPER_LABEL>", "category": "<classic_pii|corporate_sensitive>", "reason": "<short why>"}
If nothing sensitive is found, return [].
The "text" MUST be copied exactly so it can be located. No commentary outside the JSON."""


def _extract_json_array(raw: str) -> List[dict]:
    """Best-effort: pull the first JSON array out of a chatty model reply."""
    if not raw:
        return []
    # Fast path.
    try:
        val = json.loads(raw)
        if isinstance(val, list):
            return val
    except json.JSONDecodeError:
        pass
    # Find the first balanced [ ... ] block.
    start = raw.find("[")
    if start == -1:
        return []
    depth = 0
    for i in range(start, len(raw)):
        if raw[i] == "[":
            depth += 1
        elif raw[i] == "]":
            depth -= 1
            if depth == 0:
                candidate = raw[start : i + 1]
                try:
                    val = json.loads(candidate)
                    return val if isinstance(val, list) else []
                except json.JSONDecodeError:
                    return []
    return []


def _llm_findings(
    doc: str, backend: LLMBackend, enabled_categories: Dict[str, bool]
) -> List[Finding]:
    """Run the LLM over the document in chunks and map hits back to offsets."""
    findings: List[Finding] = []
    pos = 0
    while pos < len(doc):
        chunk = doc[pos : pos + _CHUNK]
        prompt = f"{_LLM_SYSTEM}\n\n---TEXT START---\n{chunk}\n---TEXT END---"
        try:
            raw = backend.complete(prompt)
        except LLMError:
            # A failed chunk shouldn't kill the whole scan; regex findings stand.
            pos += _CHUNK - _OVERLAP
            continue

        for item in _extract_json_array(raw):
            if not isinstance(item, dict):
                continue
            text = (item.get("text") or "").strip()
            if not text or len(text) < 2:
                continue
            category = item.get("category", "corporate_sensitive")
            if category not in ("classic_pii", "corporate_sensitive"):
                category = "corporate_sensitive"
            if not enabled_categories.get(category, True):
                continue
            # Locate the verbatim text within the chunk, map to absolute offset.
            local = chunk.find(text)
            if local == -1:
                # Model paraphrased; try a loose whitespace-insensitive search.
                loose = re.escape(text).replace(r"\ ", r"\s+")
                m = re.search(loose, chunk)
                if not m:
                    continue
                local, end_local = m.start(), m.end()
            else:
                end_local = local + len(text)
            findings.append(
                Finding(
                    category=category,
                    type=(item.get("type") or "SENSITIVE").upper()[:40],
                    start=pos + local,
                    end=pos + end_local,
                    text=doc[pos + local : pos + end_local],
                    confidence=0.7,
                    source="llm",
                    note=(item.get("reason") or "")[:200],
                )
            )
        pos += _CHUNK - _OVERLAP
    return findings


def _dedupe(findings: List[Finding]) -> List[Finding]:
    """Sort by position; drop findings fully covered by another.

    On overlap, prefer the higher-precedence source (regex > mip > llm) and the
    longer span.
    """
    priority = {"regex": 3, "mip": 2, "llm": 1}
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: List[Finding] = []
    for f in ordered:
        covered = False
        for k in kept:
            # overlap?
            if f.start < k.end and k.start < f.end:
                # If existing span fully contains this one and is >= priority, skip.
                if k.start <= f.start and f.end <= k.end and \
                        priority[k.source] >= priority[f.source]:
                    covered = True
                    break
        if not covered:
            kept.append(f)
    kept.sort(key=lambda f: f.start)
    return kept


def analyze(
    doc: str,
    cfg: Dict[str, Any],
    backend: Optional[LLMBackend] = None,
    use_llm: bool = True,
) -> List[Finding]:
    """Return the merged, de-duplicated list of findings for ``doc``."""
    cats = cfg.get("categories", {})
    findings: List[Finding] = []
    findings += regex_rules.detect(doc, cats)
    findings += mip.detect(doc, cats)

    if use_llm and cfg.get("llm_scan", True) and backend is not None:
        # Only worth calling the model if a category it serves is on.
        if cats.get("corporate_sensitive", True) or cats.get("classic_pii", True):
            findings += _llm_findings(doc, backend, cats)

    return _dedupe(findings)
