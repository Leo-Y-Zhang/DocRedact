"""Minimal SARIF 2.1.0 emitter for tree scans (``scan --format sarif``).

Emits one run with a rules catalogue built from the curated detector metadata table and
one result per finding. Deliberately value-free: messages name the detector type,
severity, and confidence but never the detected value, and the only fingerprint is the
same value-free hash the baseline workflow uses (under ``partialFingerprints``), so the
SARIF file is safe to upload to a CI annotation service even when the scan ran in
report mode. Block index and in-block character offsets ride along under result
``properties`` (DocRedact has no line numbers, so no fabricated ``region`` is emitted).

Deterministic by construction: rules are sorted by id, results keep the scan's stable
file-then-offset ordering, and nothing reads the clock.
"""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .metadata import Severity, metadata_for

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF has four levels (none/note/warning/error); map the curated severities down.
_LEVELS = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def render_sarif(findings: list[dict[str, Any]]) -> str:
    """Render scan findings (entity dicts with a tree-relative ``path``) as SARIF 2.1.0."""
    rule_ids = sorted({str(f["type"]) for f in findings})
    rule_index = {rule_id: i for i, rule_id in enumerate(rule_ids)}
    rules: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        severity, reference = metadata_for(rule_id)
        rules.append(
            {
                "id": rule_id,
                "shortDescription": {"text": f"{rule_id} finding"},
                "defaultConfiguration": {"level": _LEVELS[severity]},
                "properties": {"severity": severity.value, "reference": reference},
            }
        )
    results: list[dict[str, Any]] = []
    for finding in findings:
        results.append(
            {
                "ruleId": finding["type"],
                "ruleIndex": rule_index[str(finding["type"])],
                "level": _LEVELS[Severity(finding["severity"])],
                "message": {
                    "text": f"{finding['type']} finding "
                    f"(severity {finding['severity']}, confidence {finding['confidence']})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["path"]},
                        }
                    }
                ],
                "partialFingerprints": {"docredactFingerprint/v1": finding["fingerprint"]},
                "properties": {
                    "block": finding["block"],
                    "start": finding["start"],
                    "end": finding["end"],
                },
            }
        )
    document = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "docredact", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
