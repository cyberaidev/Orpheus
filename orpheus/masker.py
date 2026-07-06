"""Findings reporting and document masking.

Given a document string and its findings, this module produces two artefacts
alongside the source file (or into ``cfg["output_dir"]`` when set):

    <base>.orpheus-report.md   a Markdown findings report (always written)
    <base>.masked.md           a redacted copy (only when there are findings and
                               masking.mode == "copy")

The original file is never touched — the caller reads it and hands us the text.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .config import Finding

# Canonical category display order used in the report summary.
_CATEGORY_ORDER = (
    "classic_pii",
    "financial_secrets",
    "mip_labels",
    "corporate_sensitive",
)

# Orpheus output-file suffixes. Single-sourced here and imported by the watcher
# and CLI so the "ignore our own outputs" list can never drift out of sync.
_OUTPUT_SUFFIXES = (".masked.md", ".orpheus-report.md")


def is_orpheus_output(name: str) -> bool:
    """True if ``name`` (a filename or path) is one of Orpheus's own outputs."""
    base = Path(name).name
    return base.endswith(_OUTPUT_SUFFIXES)


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #
def _snippet(text: str, limit: int = 60) -> str:
    """Collapse whitespace, escape table pipes, and truncate for a table cell."""
    # Newlines/tabs -> space, then collapse any run of whitespace to one space.
    collapsed = re.sub(r"\s+", " ", text.replace("\n", " ").replace("\t", " ")).strip()
    # Escape pipes so a snippet can't break the Markdown table layout.
    collapsed = collapsed.replace("|", r"\|")
    if len(collapsed) > limit:
        # ASCII "..." (not U+2026) so report text stays ASCII-safe for any
        # downstream consumer that assumes plain ASCII.
        return collapsed[:limit] + "..."
    return collapsed


def _output_paths(source_path: str, cfg: Dict[str, Any]) -> Tuple[Path, Path]:
    """Return (report_path, masked_path) for ``source_path`` honouring output_dir.

    NOTE: if output_dir is set and two sources in different dirs share a name,
    their outputs collide. That's out of scope for this local tool.
    """
    src = Path(source_path)
    name = src.name
    # Strip a trailing ".md" to build the base; otherwise keep the full name.
    base = name[:-3] if name.endswith(".md") else name
    out_dir = Path(cfg["output_dir"]) if cfg.get("output_dir") else src.parent
    report_path = out_dir / f"{base}.orpheus-report.md"
    masked_path = out_dir / f"{base}.masked.md"
    return report_path, masked_path


def _build_report(source_path: str, doc: str, findings: List[Finding]) -> str:
    """Render the Markdown findings report."""
    lines: List[str] = ["# Orpheus scan report", ""]
    lines.append(f"**Source:** `{source_path}`")
    lines.append(f"**Findings:** {len(findings)}")
    lines.append("")

    # No-findings short-circuit: header + explicit note, nothing else.
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    # Sort defensively even though analyze() already sorts by start.
    ordered = sorted(findings, key=lambda f: f.start)

    # --- Summary count by category -------------------------------------- #
    counts: Dict[str, int] = {}
    for f in ordered:
        counts[f.category] = counts.get(f.category, 0) + 1
    lines.append("## Summary")
    lines.append("")
    # Canonical categories first, then any unexpected ones for completeness.
    seen = set()
    for cat in _CATEGORY_ORDER:
        if counts.get(cat, 0) > 0:
            lines.append(f"- {cat}: {counts[cat]}")
            seen.add(cat)
    for cat in sorted(counts):
        if cat not in seen:
            lines.append(f"- {cat}: {counts[cat]}")
    lines.append(f"- **Total:** {len(ordered)}")
    lines.append("")

    # --- Findings table ------------------------------------------------- #
    lines.append("## Findings")
    lines.append("")
    lines.append("| Line | Category | Type | Snippet | Confidence | Source |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for f in ordered:
        lines.append(
            f"| {f.line_number(doc)} | {f.category} | {f.type} | "
            f"{_snippet(f.text)} | {f.confidence:.2f} | {f.source} |"
        )
    lines.append("")

    # --- Notes (only if any finding carries one) ------------------------ #
    noted = [f for f in ordered if f.note]
    if noted:
        lines.append("## Notes")
        lines.append("")
        for f in noted:
            # Reuse snippet's whitespace/pipe cleanup but allow the full note
            # (LLM notes are already capped at 200 chars upstream).
            note_text = _snippet(f.note, limit=200)
            lines.append(f"- L{f.line_number(doc)} {f.type}: {note_text}")
        lines.append("")

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def mask_document(doc: str, findings: List[Finding], cfg: Dict[str, Any]) -> str:
    """Return ``doc`` with every finding's span replaced per the masking style."""
    if not findings:
        return doc

    style = (cfg.get("masking") or {}).get("style", "label")

    # Apply right-to-left so earlier (lower) offsets stay valid as we splice.
    # Sort a *copy* — never mutate the caller's list.
    ordered = sorted(findings, key=lambda f: f.start, reverse=True)

    out = doc
    # Overlap protection: track the lowest start already masked. analyze()
    # dedupes, but if two spans still overlap, skipping the later (leftward)
    # one avoids splicing into text we've already rewritten.
    prev_start = len(doc)
    for f in ordered:
        if f.end > prev_start:  # overlaps something already masked -> skip
            continue
        if style == "block":
            replacement = "█" * (f.end - f.start)  # U+2588, offset-authoritative
        else:  # "label" and any unknown style fall back to a label
            replacement = f"[REDACTED:{f.type}]"
        out = out[: f.start] + replacement + out[f.end :]
        prev_start = f.start
    return out


def write_outputs(
    source_path: str, doc: str, findings: List[Finding], cfg: Dict[str, Any]
) -> Dict[str, str]:
    """Write the report (always) and the masked copy (conditionally).

    Returns a dict of the paths actually written: always ``{"report": ...}``,
    plus ``"masked"`` only when a masked copy was produced.
    """
    report_path, masked_path = _output_paths(source_path, cfg)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report_path.write_text(_build_report(source_path, doc, findings), encoding="utf-8")
    written: Dict[str, str] = {"report": str(report_path)}

    mode = (cfg.get("masking") or {}).get("mode", "copy")
    # Only write a masked copy when there's something to redact and we're in
    # "copy" mode (not "report_only").
    if findings and mode != "report_only":
        masked_path.write_text(mask_document(doc, findings, cfg), encoding="utf-8")
        written["masked"] = str(masked_path)

    return written
