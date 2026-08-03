"""Masking and redaction-mode tests."""

from __future__ import annotations

from pathlib import Path

from docredact.core import build_document
from docredact.detectors import scan_text
from docredact.redact import mask_text

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_mask_replaces_span_and_keeps_context() -> None:
    text = "email jane.doe@example.com here"
    assert mask_text(text, scan_text(text)) == "email [REDACTED:email] here"


def test_mask_handles_multiple_entities() -> None:
    text = "jane.doe@example.com card 4111111111111111"
    assert mask_text(text, scan_text(text)) == "[REDACTED:email] card [REDACTED:credit_card]"


def test_mask_idempotent_on_all_fixtures() -> None:
    fixtures = sorted(FIXTURES.glob("sample.*"))
    assert len(fixtures) == 8
    for path in fixtures:
        doc = build_document(path)
        for block in doc["blocks"]:
            once = mask_text(block["text"], scan_text(block["text"]))
            twice = mask_text(once, scan_text(once))
            assert twice == once, path.name


def test_mask_mode_document_hides_values() -> None:
    doc = build_document(FIXTURES / "sample.txt", redact="mask")
    assert doc["redaction"]["masked"] is True
    assert doc["redaction"]["total"] > 0
    assert all(
        e["value"] is None and e["start"] is None and e["end"] is None
        for e in doc["entities"]
    )
    joined = " ".join(b["text"] for b in doc["blocks"])
    assert "jane.doe@example.com" not in joined
    assert "[REDACTED:email]" in joined


def test_report_mode_keeps_text_and_values() -> None:
    doc = build_document(FIXTURES / "sample.txt", redact="report")
    assert doc["redaction"]["masked"] is False
    assert "jane.doe@example.com" in " ".join(b["text"] for b in doc["blocks"])
    assert any(
        e["type"] == "email" and e["value"] == "jane.doe@example.com"
        for e in doc["entities"]
    )


def test_by_type_counts_match_entity_list() -> None:
    doc = build_document(FIXTURES / "sample.md")
    by_type = doc["redaction"]["by_type"]
    assert sum(by_type.values()) == doc["redaction"]["total"] == len(doc["entities"])
    assert by_type["email"] == 1
    assert list(by_type) == sorted(by_type)  # deterministic ordering
