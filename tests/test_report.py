"""Severity metadata + the Markdown findings report."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from conftest import FIXTURES
from docredact.core import build_document
from docredact.detectors import DETECTORS_BY_NAME
from docredact.metadata import DETECTOR_METADATA, Severity, metadata_for
from docredact.report import render_markdown


class TestMetadataTable:
    def test_every_builtin_detector_has_metadata(self) -> None:
        assert set(DETECTOR_METADATA) == set(DETECTORS_BY_NAME)

    def test_every_entry_has_severity_and_reference(self) -> None:
        for type_, (severity, reference) in DETECTOR_METADATA.items():
            assert isinstance(severity, Severity), type_
            assert reference and isinstance(reference, str), type_

    def test_custom_types_get_the_default(self) -> None:
        severity, reference = metadata_for("my_custom_rule")
        assert severity is Severity.MEDIUM and reference == "custom rule"

    def test_key_material_outranks_pii(self) -> None:
        assert metadata_for("pem_key")[0].rank > metadata_for("email")[0].rank
        assert metadata_for("api_key")[0].rank > metadata_for("ipv4")[0].rank


class TestSeverityInDocument:
    def test_entities_carry_severity(self) -> None:
        doc = build_document(FIXTURES / "sample.txt")
        entities = doc["entities"]
        assert isinstance(entities, list) and entities
        assert all(e["severity"] in {"low", "medium", "high", "critical"} for e in entities)

    def test_api_key_is_critical(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("key AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        (entity,) = build_document(f)["entities"]
        assert entity["severity"] == "critical"


class TestMarkdownReport:
    def test_renders_summary_and_findings_table(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com key AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        text = render_markdown(build_document(f))
        assert text.startswith("# DocRedact report: doc.txt")
        assert "critical 1" in text and "low 1" in text
        assert "| critical | high | api_key |" in text
        assert "CWE-798" in text

    def test_masked_document_shows_no_values(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        text = render_markdown(build_document(f, redact="mask"))
        assert "a@example.com" not in text
        assert "*masked*" in text

    def test_deterministic(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com and 192.0.2.7\n", encoding="utf-8")
        assert render_markdown(build_document(f)) == render_markdown(build_document(f))

    def test_no_findings_renders_cleanly(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("nothing here\n", encoding="utf-8")
        assert "No findings." in render_markdown(build_document(f))

    def test_pipe_in_value_is_escaped(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        doc = build_document(f)
        doc["entities"][0]["value"] = "a|b@example.com"
        assert "a\\|b@example.com" in render_markdown(doc)


class TestCliFormat:
    def test_markdown_format_end_to_end(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f), "--format", "markdown"],
            capture_output=True, text=True, check=True,
        )
        assert proc.stdout.startswith("# DocRedact report: doc.txt")

    def test_markdown_includes_sanitized_manifest(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        out = tmp_path / "safe.txt"
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f),
             "--format", "markdown", "--write-redacted", str(out)],
            capture_output=True, text=True, check=True,
        )
        assert "## Sanitized artifact" in proc.stdout
        assert "[EMAIL_1]" in proc.stdout

    def test_scan_prints_severity_rollup(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "scan", str(FIXTURES)],
            capture_output=True, text=True, check=True,
        )
        assert "severity: critical=" in proc.stdout
