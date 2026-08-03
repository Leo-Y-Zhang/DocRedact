"""End-to-end CLI tests, run via subprocess with the active (venv) python."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EXPECTED_KEYS = [
    "extractor_version",
    "generated_at",
    "source",
    "sha256",
    "size_bytes",
    "format",
    "blocks",
    "entities",
    "redaction",
    "warnings",
]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "docredact", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def test_extract_outputs_valid_json_with_schema_keys() -> None:
    proc = run_cli("extract", str(FIXTURES / "sample.txt"))
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert list(doc) == EXPECTED_KEYS
    assert doc["source"] == "sample.txt"  # basename only, never a path
    assert "/" not in doc["source"] and "\\" not in doc["source"]
    assert len(doc["sha256"]) == 64


@pytest.mark.parametrize(
    ("name", "fmt"),
    [
        ("sample.pdf", "pdf"),
        ("sample.txt", "txt"),
        ("sample.md", "md"),
        ("sample.html", "html"),
        ("sample.csv", "csv"),
        ("sample.docx", "docx"),
    ],
)
def test_extract_every_format_end_to_end(name: str, fmt: str) -> None:
    proc = run_cli("extract", str(FIXTURES / name))
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["format"] == fmt
    assert doc["blocks"]
    assert doc["entities"]


def test_extract_output_is_deterministic() -> None:
    first = run_cli("extract", str(FIXTURES / "sample.pdf"))
    second = run_cli("extract", str(FIXTURES / "sample.pdf"))
    assert first.stdout == second.stdout != ""


def test_extract_timestamp_flag_sets_generated_at() -> None:
    proc = run_cli("extract", str(FIXTURES / "sample.txt"), "--timestamp")
    doc = json.loads(proc.stdout)
    assert isinstance(doc["generated_at"], str)
    assert doc["generated_at"].endswith("Z")


def test_extract_pretty_prints_indented_json() -> None:
    proc = run_cli("extract", str(FIXTURES / "sample.txt"), "--pretty")
    assert proc.stdout.startswith('{\n  "')
    json.loads(proc.stdout)


def test_extract_mask_hides_values_everywhere() -> None:
    proc = run_cli("extract", str(FIXTURES / "sample.txt"), "--redact", "mask")
    assert proc.returncode == 0
    assert "jane.doe@example.com" not in proc.stdout
    assert "[REDACTED:email]" in proc.stdout


def test_extract_strict_exits_3_on_findings() -> None:
    proc = run_cli("extract", str(FIXTURES / "sample.txt"), "--redact", "strict")
    assert proc.returncode == 3
    json.loads(proc.stdout)  # JSON is still emitted


def test_extract_strict_exits_0_on_clean_file(tmp_path: Path) -> None:
    path = tmp_path / "clean.txt"
    path.write_text("nothing sensitive here\n", encoding="utf-8")
    proc = run_cli("extract", str(path), "--redact", "strict")
    assert proc.returncode == 0, proc.stderr


def test_extract_out_writes_json_file(tmp_path: Path) -> None:
    out = tmp_path / "doc.json"
    proc = run_cli("extract", str(FIXTURES / "sample.csv"), "--out", str(out))
    assert proc.returncode == 0
    assert proc.stdout == ""
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["format"] == "csv"


def test_extract_missing_file_exits_1(tmp_path: Path) -> None:
    proc = run_cli("extract", str(tmp_path / "missing.txt"))
    assert proc.returncode == 1
    assert "error" in proc.stderr.lower()


def test_extract_unsupported_extension_exits_1(tmp_path: Path) -> None:
    path = tmp_path / "image.png"
    path.write_bytes(b"\x89PNG")
    proc = run_cli("extract", str(path))
    assert proc.returncode == 1


def test_extract_corrupt_pdf_gives_clean_error_with_no_leak(tmp_path: Path) -> None:
    # Regression: pypdf reports non-fatal parser conditions ("invalid pdf
    # header: b'...'", "EOF marker not found") through the stdlib `logging`
    # module. DocRedact never configured logging, so with no handler anywhere in
    # that chain, Python's logging "handler of last resort" printed those
    # records straight to the real process stderr -- bypassing docredact's own
    # clean error message and, worse, echoing raw bytes read from the
    # untrusted PDF back onto stderr. A never-leak tool must not leak the
    # document it was asked to scan (or its own parser internals) that way:
    # stderr must contain only the one generic docredact error line.
    path = tmp_path / "corrupt.pdf"
    path.write_bytes(b"%PDF-1.4\nthis is not a valid pdf body \xf8{I\xd8= garbage")
    proc = run_cli("extract", str(path))
    assert proc.returncode == 1
    assert proc.stdout == ""
    stderr_lines = [line for line in proc.stderr.splitlines() if line]
    assert len(stderr_lines) == 1, proc.stderr
    assert stderr_lines[0].startswith("docredact: error: failed to parse PDF:")
    lowered = proc.stderr.lower()
    for leaked in ("invalid pdf header", "eof marker", str(path), "traceback"):
        assert leaked not in lowered, proc.stderr


def test_scan_directory_prints_summary_table() -> None:
    proc = run_cli("scan", str(FIXTURES))
    assert proc.returncode == 0, proc.stderr
    for expected in (
        "FILE",
        "FORMAT",
        "sample.csv",
        "sample.docx",
        "sample.eml",
        "sample.html",
        "sample.json",
        "sample.md",
        "sample.pdf",
        "sample.txt",
    ):
        assert expected in proc.stdout
    assert "total: 8 files" in proc.stdout


def test_scan_glob_filters_files() -> None:
    proc = run_cli("scan", str(FIXTURES), "--glob", "*.txt")
    assert proc.returncode == 0
    assert "sample.txt" in proc.stdout
    assert "sample.pdf" not in proc.stdout
    assert "total: 1 files" in proc.stdout


def test_scan_missing_directory_exits_1(tmp_path: Path) -> None:
    proc = run_cli("scan", str(tmp_path / "nope"))
    assert proc.returncode == 1


def test_console_script_help() -> None:
    exe = Path(sys.executable).with_name("docredact.exe")
    if not exe.exists():
        exe = Path(sys.executable).with_name("docredact")
    if not exe.exists():
        pytest.skip("console script not installed")
    proc = subprocess.run(
        [str(exe), "--help"], capture_output=True, text=True, encoding="utf-8"
    )
    assert proc.returncode == 0
    assert "extract" in proc.stdout and "scan" in proc.stdout
