"""Determinism-under-load + performance guard, and the --stats summary.

Proves the enlarged pipeline (10 formats, policy, tokenization, baseline fingerprints)
stays byte-identical and fast on a large corpus, so scale never silently reorders output.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

from docredact.core import build_document, build_sanitized
from docredact.report import render_stats

_DOC = (
    "Report {i}: contact user{i}@example.com or +1-555-01{i:02d}.\n\n"
    "Server 192.0.2.{i} card 4111 1111 1111 1111 iban GB82WEST12345698765432\n"
)


def _corpus(root: Path, n: int = 120) -> list[Path]:
    paths = []
    for i in range(n):
        if i % 3 == 0:
            path = root / f"f{i}.txt"
            path.write_text(_DOC.format(i=i % 100), encoding="utf-8")
        elif i % 3 == 1:
            path = root / f"f{i}.json"
            path.write_text(
                json.dumps({"owner": f"user{i}@example.com", "host": f"192.0.2.{i % 250}"}),
                encoding="utf-8",
            )
        else:
            path = root / f"f{i}.log"
            path.write_text(f"login user{i}@example.com from 192.0.2.{i % 250}\n", encoding="utf-8")
        paths.append(path)
    return paths


def test_large_corpus_extracts_reproducibly(tmp_path: Path) -> None:
    paths = _corpus(tmp_path)
    digests = set()
    for _ in range(3):
        hasher = hashlib.sha256()
        for path in paths:
            hasher.update(json.dumps(build_document(path)).encode())
            artifact, manifest = build_sanitized(path)
            hasher.update(artifact.encode())
            hasher.update(json.dumps(manifest).encode())
        digests.add(hasher.hexdigest())
    assert len(digests) == 1, "output was not byte-identical across 3 corpus passes"


def test_large_corpus_scans_quickly(tmp_path: Path) -> None:
    paths = _corpus(tmp_path, n=200)
    start = time.perf_counter()
    total = sum(len(build_document(p)["entities"]) for p in paths)
    elapsed = time.perf_counter() - start
    assert total > 200, "expected plenty of findings"
    assert elapsed < 10.0, f"200-file corpus took {elapsed:.2f}s"


class TestStats:
    def test_render_is_deterministic_and_sorted(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com key AKIAIOSFODNN7EXAMPLE 192.0.2.7\n", encoding="utf-8")
        doc = build_document(f)
        text = render_stats(doc)
        assert text == render_stats(build_document(f))
        assert "STATS" in text and "findings: 3" in text
        type_lines = [ln.split()[0] for ln in text.splitlines() if ln.startswith("    ")]
        assert type_lines == sorted(type_lines)

    def test_cli_stats_goes_to_stderr_not_stdout(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f), "--stats"],
            capture_output=True, text=True, check=True,
        )
        assert "STATS" in proc.stderr
        assert json.loads(proc.stdout)  # report on stdout stays pure JSON
