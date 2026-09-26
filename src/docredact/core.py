"""Document pipeline: file bytes -> blocks -> entities -> JSON-ready dict."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .baseline import fingerprint
from .detectors import Confidence, Entity, scan_text
from .extractors import Block, detect_format, extract_blocks
from .metadata import metadata_for
from .policy import Policy
from .redact import mask_text
from .sanitize import render_artifact, rendered_blocks, sanitize_blocks

REDACT_MODES = ("report", "mask", "strict")


def build_sanitized(
    path: Path,
    min_confidence: Confidence = Confidence.LOW,
    policy: Policy | None = None,
) -> tuple[str, list[dict[str, object]]]:
    """Build the sanitized plain-text artifact for ``path`` plus its manifest.

    Every finding at/above ``min_confidence`` is replaced by a consistent
    ``[TYPE_N]`` token (same value -> same token document-wide); the manifest
    lists tokens with types and occurrence counts and never a raw value. Hidden
    kinds (tracked deletions, comments, annotations) are left out of both: they
    are scanned and reported by ``build_document``, never rendered.
    """
    fmt = detect_format(path)
    blocks, _ = extract_blocks(path.read_bytes(), fmt)
    blocks = rendered_blocks(blocks)
    min_rank = min_confidence.rank
    per_block = {
        b.index: [e for e in scan_text(b.text, policy) if e.confidence.rank >= min_rank]
        for b in blocks
    }
    texts, manifest = sanitize_blocks(blocks, per_block)
    return render_artifact(fmt, texts), manifest


def build_document(
    path: Path,
    redact: str = "report",
    timestamp: bool = False,
    min_confidence: Confidence = Confidence.LOW,
    policy: Policy | None = None,
) -> dict[str, object]:
    """Extract ``path`` into the documented JSON schema (as a plain dict).

    ``redact``: "report" and "strict" keep text and entity values intact;
    "mask" rewrites block text with [REDACTED:<type>] tokens and nulls out
    entity values/offsets so nothing sensitive remains in the output.
    ``timestamp``: when False (default) ``generated_at`` is null, keeping
    the output byte-for-byte deterministic.
    ``min_confidence``: findings below this confidence are dropped BEFORE
    redaction, so in mask mode only the kept findings are masked -- raising
    the bar deliberately leaves lower-confidence values in the text.
    ``policy``: optional custom detectors / allowlist / built-in disables.
    """
    if redact not in REDACT_MODES:
        raise ValueError(f"unknown redact mode: {redact!r}")
    fmt = detect_format(path)
    data = path.read_bytes()
    blocks, warnings = extract_blocks(data, fmt)

    min_rank = min_confidence.rank
    per_block: dict[int, list[Entity]] = {
        b.index: [e for e in scan_text(b.text, policy) if e.confidence.rank >= min_rank]
        for b in blocks
    }
    found: list[tuple[int, Entity]] = [
        (b.index, e) for b in blocks for e in per_block[b.index]
    ]
    masked = redact == "mask"
    if masked:
        blocks = [
            Block(b.index, b.kind, mask_text(b.text, per_block[b.index]))
            for b in blocks
        ]
    by_type: dict[str, int] = {}
    for _, entity in found:
        by_type[entity.type] = by_type.get(entity.type, 0) + 1

    return {
        "extractor_version": __version__,
        "generated_at": (
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if timestamp
            else None
        ),
        "source": path.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "format": fmt,
        "blocks": [{"index": b.index, "kind": b.kind, "text": b.text} for b in blocks],
        "entities": [
            {
                "type": e.type,
                "value": None if masked else e.value,
                "block": block_index,
                "start": None if masked else e.start,
                "end": None if masked else e.end,
                "confidence": e.confidence.value,
                "severity": metadata_for(e.type)[0].value,
                # Value-free hash for the baseline workflow; computed from the raw
                # value even in mask mode (the hash itself reveals nothing directly).
                "fingerprint": fingerprint(e.type, path.name, e.value),
            }
            for block_index, e in found
        ],
        "redaction": {
            "mode": redact,
            "total": len(found),
            "by_type": dict(sorted(by_type.items())),
            "masked": masked,
        },
        "warnings": warnings,
    }
