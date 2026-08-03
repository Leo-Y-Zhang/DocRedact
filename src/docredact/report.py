"""Markdown findings report: a shareable summary of one extraction.

Renders the already-built document dict, so it is exactly as safe as that document:
in mask mode values are null and the report shows them masked. Deterministic -- no
timestamps beyond the document's own ``generated_at``, stable ordering throughout.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .metadata import SEVERITY_ORDER, metadata_for

_CONFIDENCE_ORDER = ("high", "medium", "low")


def _severity_counts(entities: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev.value: 0 for sev in SEVERITY_ORDER}
    for entity in entities:
        counts[entity["severity"]] += 1
    return counts


def _md_escape(cell: str) -> str:
    return cell.replace("|", "\\|").replace("`", "'")


def render_markdown(document: dict[str, Any]) -> str:
    """Render one extracted document as a Markdown findings report."""
    entities = document["entities"]
    assert isinstance(entities, list)
    counts = _severity_counts(entities)
    lines = [
        f"# DocRedact report: {document['source']}",
        "",
        "Local-first extraction and detection. Fully offline; no network calls.",
        "",
        f"- Format: `{document['format']}`",
        f"- SHA-256: `{document['sha256']}`",
        f"- Size: {document['size_bytes']} bytes, {len(document['blocks'])} blocks",
        f"- Findings: {len(entities)} ("
        + ", ".join(f"{name} {count}" for name, count in counts.items())
        + ")",
        f"- Redaction mode: `{document['redaction']['mode']}`",
        "",
        "## Findings",
        "",
    ]
    if not entities:
        lines.append("No findings.")
    else:
        lines.extend(
            [
                "| Severity | Confidence | Type | Block | Value | Reference |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for entity in entities:
            value = "*masked*" if entity["value"] is None else f"`{_md_escape(entity['value'])}`"
            reference = metadata_for(entity["type"])[1]
            lines.append(
                f"| {entity['severity']} | {entity['confidence']} | {entity['type']} "
                f"| {entity['block']} | {value} | {reference} |"
            )

    sanitized = document.get("sanitized")
    if isinstance(sanitized, dict):
        lines.extend(["", "## Sanitized artifact", "", f"Written to `{sanitized['path']}`.", ""])
        manifest = sanitized["manifest"]
        if manifest:
            lines.extend(["| Token | Type | Occurrences |", "| --- | --- | --- |"])
            lines.extend(
                f"| `{m['token']}` | {m['type']} | {m['occurrences']} |" for m in manifest
            )

    warnings = document["warnings"]
    assert isinstance(warnings, list)
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {w}" for w in warnings)

    return "\n".join(lines).rstrip() + "\n"


def render_stats(document: dict[str, Any]) -> str:
    """A compact, deterministically-ordered summary of one extraction (for --stats)."""
    entities = document["entities"]
    assert isinstance(entities, list)
    severity = _severity_counts(entities)
    confidence = Counter(e["confidence"] for e in entities)
    by_type = Counter(e["type"] for e in entities)
    blocks = document["blocks"]
    assert isinstance(blocks, list)
    kinds = Counter(b["kind"] for b in blocks)
    lines = [
        "STATS",
        f"  format: {document['format']}",
        f"  blocks: {len(blocks)} ("
        + ", ".join(f"{kind} {kinds[kind]}" for kind in sorted(kinds)) + ")",
        f"  findings: {len(entities)} ("
        + ", ".join(f"{name} {count}" for name, count in severity.items()) + ")",
        "  confidence: "
        + ", ".join(f"{c} {confidence.get(c, 0)}" for c in _CONFIDENCE_ORDER),
        "  by type:",
    ]
    lines.extend(f"    {type_}  {by_type[type_]}" for type_ in sorted(by_type))
    return "\n".join(lines) + "\n"
