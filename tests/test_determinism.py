"""Reproducibility harness: extraction output must be byte-identical run to run, and must
never leak the local filesystem (absolute paths, usernames) into a report.

This is the determinism floor the whole "to the max" build stands on; every later feature
(policy, tokenized redaction, baseline) must keep it green.
"""
from __future__ import annotations

import getpass
import json
import subprocess
import sys
from pathlib import Path

from conftest import FIXTURES, PROJECT_ROOT
from docredact.core import build_document

_SUPPORTED = {".csv", ".docx", ".eml", ".htm", ".html", ".json", ".md", ".pdf", ".txt"}
_FIXTURE_FILES = sorted(p for p in FIXTURES.iterdir() if p.suffix.lower() in _SUPPORTED)


def _render(path: Path, redact: str = "report") -> str:
    return json.dumps(build_document(path, redact=redact), indent=2)


class TestByteIdentical:
    def test_every_fixture_extracts_identically_three_times(self) -> None:
        assert _FIXTURE_FILES, "no fixtures found"
        for path in _FIXTURE_FILES:
            renders = {_render(path) for _ in range(3)}
            assert len(renders) == 1, f"{path.name} was not byte-identical across runs"

    def test_mask_mode_is_also_deterministic(self) -> None:
        for path in _FIXTURE_FILES:
            assert _render(path, "mask") == _render(path, "mask"), path.name

    def test_generated_at_is_null_by_default(self) -> None:
        doc = build_document(_FIXTURE_FILES[0])
        assert doc["generated_at"] is None


class TestNoFilesystemLeak:
    def test_source_is_basename_only(self) -> None:
        for path in _FIXTURE_FILES:
            doc = build_document(path)
            source = doc["source"]
            assert isinstance(source, str)
            assert "/" not in source and "\\" not in source, source

    def test_no_absolute_path_or_username_in_output(self) -> None:
        root = str(PROJECT_ROOT).replace("\\", "/")
        user = getpass.getuser()
        for path in _FIXTURE_FILES:
            blob = _render(path).replace("\\\\", "/").replace("\\", "/")
            assert root not in blob, f"{path.name} leaks the project root"
            # The fixture *content* is synthetic and never contains the local username.
            assert user not in blob, f"{path.name} leaks the local username"


class TestScanMachineOutputs:
    """The jsonl and sarif tree outputs sit under the same determinism floor."""

    def _scan(self, fmt: str) -> str:
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "scan", str(FIXTURES), "--format", fmt],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    def test_jsonl_and_sarif_are_byte_identical_across_runs(self) -> None:
        for fmt in ("jsonl", "sarif"):
            first = self._scan(fmt)
            assert first != ""
            assert first == self._scan(fmt), f"scan --format {fmt} was not deterministic"

    def test_no_absolute_path_or_username_in_machine_output(self) -> None:
        root = str(PROJECT_ROOT).replace("\\", "/")
        user = getpass.getuser()
        for fmt in ("jsonl", "sarif"):
            blob = self._scan(fmt).replace("\\\\", "/").replace("\\", "/")
            assert root not in blob, f"{fmt} leaks the project root"
            assert user not in blob, f"{fmt} leaks the local username"
