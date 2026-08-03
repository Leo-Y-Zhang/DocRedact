"""Committed example artifacts must equal a fresh render (drift guard).

`examples/sample-report.md`, `examples/sample-safe.txt`, `examples/fixtures-scan.jsonl`,
and `examples/fixtures-scan.sarif` are checked in as showcase output. Because every
renderer is deterministic, regenerating them must reproduce them byte-for-byte. If a
detector, renderer, or extractor changes without refreshing the samples, these tests
name the commands to run:

    docredact extract fixtures/sample.txt --format markdown \
        --out examples/sample-report.md --write-redacted examples/sample-safe.txt
    docredact scan fixtures --format jsonl --out examples/fixtures-scan.jsonl
    docredact scan fixtures --format sarif --out examples/fixtures-scan.sarif
"""
from __future__ import annotations

import subprocess
import sys

from conftest import FIXTURES, PROJECT_ROOT
from docredact.core import build_document, build_sanitized
from docredact.report import render_markdown

_EXAMPLES = PROJECT_ROOT / "examples"


def _scan_fixtures(fmt: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "docredact", "scan", str(FIXTURES), "--format", fmt],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _fresh_report() -> str:
    document = build_document(FIXTURES / "sample.txt")
    artifact, manifest = build_sanitized(FIXTURES / "sample.txt")
    document["sanitized"] = {"path": "sample-safe.txt", "manifest": manifest}
    return render_markdown(document)


def test_sample_report_is_current() -> None:
    committed = (_EXAMPLES / "sample-report.md").read_text(encoding="utf-8")
    assert _fresh_report() == committed, (
        "examples/sample-report.md is stale; regenerate it (see this file's docstring)"
    )


def test_sample_safe_artifact_is_current() -> None:
    committed = (_EXAMPLES / "sample-safe.txt").read_text(encoding="utf-8")
    artifact, _ = build_sanitized(FIXTURES / "sample.txt")
    assert artifact == committed, (
        "examples/sample-safe.txt is stale; regenerate it (see this file's docstring)"
    )


def test_committed_artifact_contains_no_fixture_secrets() -> None:
    blob = (_EXAMPLES / "sample-safe.txt").read_text(encoding="utf-8")
    for secret in ("jane.doe@example.com", "4111111111111111", "AKIAIOSFODNN7EXAMPLE"):
        assert secret not in blob, secret


def test_fixtures_scan_jsonl_is_current() -> None:
    committed = (_EXAMPLES / "fixtures-scan.jsonl").read_text(encoding="utf-8")
    assert _scan_fixtures("jsonl") == committed, (
        "examples/fixtures-scan.jsonl is stale; regenerate it (see this file's docstring)"
    )


def test_fixtures_scan_sarif_is_current() -> None:
    committed = (_EXAMPLES / "fixtures-scan.sarif").read_text(encoding="utf-8")
    assert _scan_fixtures("sarif") == committed, (
        "examples/fixtures-scan.sarif is stale; regenerate it (see this file's docstring)"
    )


def test_committed_sarif_contains_no_fixture_secrets() -> None:
    # The SARIF emitter is value-free by design; the committed artifact must stay so.
    blob = (_EXAMPLES / "fixtures-scan.sarif").read_text(encoding="utf-8")
    for secret in (
        "jane.doe@example.com",
        "4111111111111111",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOiJub25lIn0",
        "GB82WEST12345698765432",
    ):
        assert secret not in blob, secret
