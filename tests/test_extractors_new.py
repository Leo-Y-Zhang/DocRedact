"""The Step 5 format extractors: .eml, .json, .yaml/.yml, .log, .ini.

Each new format gets benign coverage AND a hostile-input guard, mirroring the discipline of
the original six extractors.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import FIXTURES
from docredact.core import build_document
from docredact.extractors import ExtractionError, detect_format, extract_blocks


def _extract(name: str, content: str, tmp_path: Path) -> dict[str, object]:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return build_document(path)


class TestEml:
    def test_fixture_headers_become_blocks_and_addresses_are_found(self) -> None:
        doc = build_document(FIXTURES / "sample.eml")
        blocks = doc["blocks"]
        assert isinstance(blocks, list)
        kinds = [b["kind"] for b in blocks]
        assert kinds.count("header") == 4  # From, To, Cc, Subject
        entities = doc["entities"]
        assert isinstance(entities, list)
        values = {e["value"] for e in entities if e["type"] == "email"}
        assert {"jane.doe@example.com", "john.roe@example.com", "support@example.com"} <= values

    def test_multipart_html_part_is_extracted(self, tmp_path: Path) -> None:
        eml = (
            "From: a@example.com\n"
            "To: b@example.com\n"
            "Subject: multi\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/alternative; boundary="B"\n'
            "\n--B\n"
            'Content-Type: text/plain; charset="utf-8"\n'
            "\nplain part mail c@example.com\n"
            "\n--B\n"
            'Content-Type: text/html; charset="utf-8"\n'
            "\n<p>html part mail d@example.com</p>\n"
            "\n--B--\n"
        )
        doc = _extract("m.eml", eml, tmp_path)
        entities = doc["entities"]
        assert isinstance(entities, list)
        values = {e["value"] for e in entities if e["type"] == "email"}
        assert {"c@example.com", "d@example.com"} <= values

    def test_attachment_is_skipped_with_visible_warning(self, tmp_path: Path) -> None:
        eml = (
            "From: a@example.com\nSubject: att\nMIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="B"\n'
            "\n--B\n"
            'Content-Type: text/plain\n'
            "\nbody text\n"
            "\n--B\n"
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n"
            "\nZmFrZQ==\n"
            "\n--B--\n"
        )
        doc = _extract("a.eml", eml, tmp_path)
        warnings = doc["warnings"]
        assert isinstance(warnings, list)
        assert "not scanned: attachment (application/octet-stream)" in warnings

    def test_headers_only_email_still_scans(self, tmp_path: Path) -> None:
        doc = _extract("h.eml", "From: x@example.com\nSubject: no body\n\n", tmp_path)
        entities = doc["entities"]
        assert isinstance(entities, list)
        assert any(e["value"] == "x@example.com" for e in entities)

    def test_html_part_mailto_href_is_scanned(self, tmp_path: Path) -> None:
        # The mailto fix flows into EML automatically because text/html parts
        # ride through the same HTML extractor.
        eml = (
            "From: a@example.com\nSubject: link\nMIME-Version: 1.0\n"
            'Content-Type: text/html; charset="utf-8"\n'
            '\n<p><a href="mailto:hidden.reply@example.com">reply here</a></p>\n'
        )
        doc = _extract("l.eml", eml, tmp_path)
        entities = doc["entities"]
        assert isinstance(entities, list)
        assert any(e["value"] == "hidden.reply@example.com" for e in entities)


class TestJson:
    def test_key_paths_ride_along_with_values(self, tmp_path: Path) -> None:
        doc = _extract("c.json", '{"aws": {"key": "AKIAIOSFODNN7EXAMPLE"}}', tmp_path)
        blocks = doc["blocks"]
        assert isinstance(blocks, list)
        assert blocks[0]["text"] == "aws.key: AKIAIOSFODNN7EXAMPLE"
        assert blocks[0]["kind"] == "field"

    def test_arrays_are_indexed(self, tmp_path: Path) -> None:
        doc = _extract("a.json", '{"hosts": ["192.0.2.1", "192.0.2.2"]}', tmp_path)
        blocks = doc["blocks"]
        assert isinstance(blocks, list)
        assert [b["text"] for b in blocks] == [
            "hosts[0]: 192.0.2.1",
            "hosts[1]: 192.0.2.2",
        ]

    def test_non_string_leaves_are_rendered(self, tmp_path: Path) -> None:
        doc = _extract("n.json", '{"port": 443, "on": true, "note": null}', tmp_path)
        blocks = doc["blocks"]
        assert isinstance(blocks, list)
        assert [b["text"] for b in blocks] == ["port: 443", "on: true", "note: null"]

    def test_malformed_json_is_a_clean_error(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ExtractionError):
            build_document(path)

    def test_deeply_nested_json_is_rejected_not_a_crash(self) -> None:
        hostile = "[" * 5000 + "]" * 5000
        with pytest.raises(ExtractionError):
            extract_blocks(hostile.encode(), "json")

    def test_depth_cap_has_a_clean_message(self) -> None:
        # Deep but under the C parser's own recursion limit: trips OUR cap.
        hostile = json.dumps(_nest(300))
        with pytest.raises(ExtractionError, match="nesting"):
            extract_blocks(hostile.encode(), "json")

    def test_wide_long_key_amplification_is_capped(self) -> None:
        # Each leaf re-embeds the long key path -> quadratic output. A small file
        # must hit the aggregate char cap with a clean error, not OOM/hang.
        hostile = json.dumps({"k" * 20000: [0] * 5000})
        with pytest.raises(ExtractionError, match="aggregate cap"):
            extract_blocks(hostile.encode(), "json")


def _nest(depth: int) -> object:
    value: object = "leaf"
    for _ in range(depth):
        value = {"k": value}
    return value


class TestPlainTextFormats:
    def test_yaml_lines_are_scanned_without_yaml_parsing(self, tmp_path: Path) -> None:
        doc = _extract("c.yaml", "aws_key: AKIAIOSFODNN7EXAMPLE\nhost: 192.0.2.9\n", tmp_path)
        entities = doc["entities"]
        assert isinstance(entities, list)
        assert {e["type"] for e in entities} == {"api_key", "ipv4"}

    def test_yml_extension_maps_to_yaml(self, tmp_path: Path) -> None:
        assert detect_format(tmp_path / "x.yml") == "yaml"

    def test_log_and_ini_are_scanned(self, tmp_path: Path) -> None:
        log = _extract("app.log", "2026-01-01 login from 192.0.2.4 user a@example.com\n", tmp_path)
        ini = _extract("app.ini", "[db]\npassword = hunter2-fixture-value\n", tmp_path)
        log_entities = log["entities"]
        ini_entities = ini["entities"]
        assert isinstance(log_entities, list) and isinstance(ini_entities, list)
        assert {e["type"] for e in log_entities} == {"ipv4", "email"}
        assert log["format"] == "log" and ini["format"] == "ini"


class TestScanExcludesPolicyFile:
    def test_docredact_yaml_is_not_scanned(self, tmp_path: Path) -> None:
        (tmp_path / ".docredact.yaml").write_text(
            'detectors:\n  - name: emp\n    regex: "EMP-\\d{6}"\n', encoding="utf-8"
        )
        (tmp_path / "doc.yaml").write_text("host: 192.0.2.9\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "scan", str(tmp_path)],
            capture_output=True, text=True, check=True,
        )
        assert ".docredact.yaml" not in proc.stdout  # config, not a document
        assert "doc.yaml" in proc.stdout
        assert "policy: applying" in proc.stderr  # still applied as policy
