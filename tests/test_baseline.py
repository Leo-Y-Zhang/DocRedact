"""The baseline workflow: value-free fingerprints, write/load, fail-only-on-new.

Contract under test: the raw value never appears in a baseline file or fingerprint; the
same value in the same file is one accepted finding regardless of position; the same value
in a DIFFERENT file is a new finding; strict mode gates only on new findings.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from docredact.baseline import BaselineError, fingerprint, load_baseline, write_baseline
from docredact.core import build_document


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "docredact", *argv], capture_output=True, text=True
    )


class TestFingerprint:
    def test_stable_and_value_free(self) -> None:
        fp = fingerprint("email", "doc.txt", "a@example.com")
        assert fp == fingerprint("email", "doc.txt", "a@example.com")
        assert len(fp) == 16 and "a@example.com" not in fp

    def test_source_is_part_of_the_fingerprint(self) -> None:
        assert fingerprint("email", "a.txt", "x@example.com") != fingerprint(
            "email", "b.txt", "x@example.com"
        )

    def test_type_is_part_of_the_fingerprint(self) -> None:
        assert fingerprint("email", "a.txt", "v") != fingerprint("iban", "a.txt", "v")

    def test_entities_carry_fingerprints_even_when_masked(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        report = build_document(f)
        masked = build_document(f, redact="mask")
        (r_entity,) = report["entities"]
        (m_entity,) = masked["entities"]
        assert r_entity["fingerprint"] == m_entity["fingerprint"]
        assert m_entity["value"] is None  # masked stays value-free

    def test_same_value_moving_in_file_keeps_fingerprint(self, tmp_path: Path) -> None:
        a = tmp_path / "doc.txt"
        a.write_text("mail a@example.com\n", encoding="utf-8")
        first = build_document(a)["entities"][0]["fingerprint"]
        a.write_text("intro paragraph\n\nnow mail a@example.com\n", encoding="utf-8")
        second = build_document(a)["entities"][0]["fingerprint"]
        assert first == second


class TestWriteLoad:
    def test_round_trip_sorted_deduplicated(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        write_baseline(path, ["bb", "aa", "bb"])
        assert load_baseline(path) == frozenset({"aa", "bb"})
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw == {"version": 1, "fingerprints": ["aa", "bb"]}
        assert path.read_text(encoding="utf-8").endswith("\n")

    def test_write_is_deterministic(self, tmp_path: Path) -> None:
        a, b = tmp_path / "a.json", tmp_path / "b.json"
        write_baseline(a, ["x", "y"])
        write_baseline(b, ["y", "x"])
        assert a.read_bytes() == b.read_bytes()

    def test_malformed_fails_closed(self, tmp_path: Path) -> None:
        for content in ("not json", "[]", '{"version": 99}', '{"version": 1, "fingerprints": "x"}'):
            path = tmp_path / "bad.json"
            path.write_text(content, encoding="utf-8")
            with pytest.raises(BaselineError):
                load_baseline(path)

    def test_missing_file_fails_closed(self, tmp_path: Path) -> None:
        with pytest.raises(BaselineError):
            load_baseline(tmp_path / "absent.json")


class TestCliWorkflow:
    def test_accept_then_pass_then_fail_on_new(self, tmp_path: Path) -> None:
        doc = tmp_path / "doc.txt"
        doc.write_text("mail a@example.com\n", encoding="utf-8")
        baseline = tmp_path / "baseline.json"

        # 1) accept the current state (exit 0 even in strict mode)
        proc = _run("extract", str(doc), "--redact", "strict", "--write-baseline", str(baseline))
        assert proc.returncode == 0

        # 2) unchanged tree passes strict
        proc = _run("extract", str(doc), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 0
        assert "1 finding(s) suppressed, 0 new" in proc.stderr
        assert json.loads(proc.stdout)["entities"] == []

        # 3) a NEW leak appears -> strict fails, report shows only the new one
        doc.write_text("mail a@example.com and b@example.com\n", encoding="utf-8")
        proc = _run("extract", str(doc), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 3
        entities = json.loads(proc.stdout)["entities"]
        assert [e["value"] for e in entities] == ["b@example.com"]

    def test_baseline_totals_reflect_new_only(self, tmp_path: Path) -> None:
        doc = tmp_path / "doc.txt"
        doc.write_text("mail a@example.com\n", encoding="utf-8")
        baseline = tmp_path / "baseline.json"
        _run("extract", str(doc), "--write-baseline", str(baseline))
        doc.write_text("mail a@example.com and 192.0.2.7\n", encoding="utf-8")
        proc = _run("extract", str(doc), "--baseline", str(baseline))
        redaction = json.loads(proc.stdout)["redaction"]
        assert redaction["total"] == 1 and redaction["by_type"] == {"ipv4": 1}

    def test_refresh_flow_drops_fixed_findings(self, tmp_path: Path) -> None:
        doc = tmp_path / "doc.txt"
        doc.write_text("mail a@example.com and 192.0.2.7\n", encoding="utf-8")
        baseline = tmp_path / "baseline.json"
        _run("extract", str(doc), "--write-baseline", str(baseline))
        before = load_baseline(baseline)
        # the email gets fixed; refresh with both flags in one run
        doc.write_text("host 192.0.2.7\n", encoding="utf-8")
        proc = _run("extract", str(doc), "--baseline", str(baseline), "--write-baseline", str(baseline))
        assert proc.returncode == 0
        after = load_baseline(baseline)
        assert len(after) == 1 and after < before  # email fingerprint dropped

    def test_same_value_in_a_new_file_is_a_new_finding(self, tmp_path: Path) -> None:
        a = tmp_path / "a.txt"
        a.write_text("mail a@example.com\n", encoding="utf-8")
        baseline = tmp_path / "baseline.json"
        _run("extract", str(a), "--write-baseline", str(baseline))
        b = tmp_path / "b.txt"
        b.write_text("mail a@example.com\n", encoding="utf-8")
        proc = _run("extract", str(b), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 3  # leaked into a second file -> new

    def test_malformed_baseline_is_clean_exit_1(self, tmp_path: Path) -> None:
        doc = tmp_path / "doc.txt"
        doc.write_text("hello\n", encoding="utf-8")
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        proc = _run("extract", str(doc), "--baseline", str(bad))
        assert proc.returncode == 1
        assert "docredact: error:" in proc.stderr and "Traceback" not in proc.stderr

    def test_baseline_file_never_contains_values(self, tmp_path: Path) -> None:
        doc = tmp_path / "doc.txt"
        doc.write_text("mail a@example.com key AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        baseline = tmp_path / "baseline.json"
        _run("extract", str(doc), "--write-baseline", str(baseline))
        blob = baseline.read_text(encoding="utf-8")
        assert "a@example.com" not in blob and "AKIA" not in blob
