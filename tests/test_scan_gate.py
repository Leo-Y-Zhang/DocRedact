"""Tree-level CI gate: ``scan --redact strict``, a directory-wide baseline, jsonl/sarif.

Contract under test: the human table stays the default output and its exit codes are
unchanged for existing invocations; a baseline written from one scan suppresses exactly
those findings on the next; a NEW secret anywhere in the tree fails strict mode reporting
only the new finding; parse errors keep exit code 1 and outrank every other code (an
unparsed file means the gate did not actually see the whole tree); jsonl and sarif output
is deterministic, and sarif never contains a detected value.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from conftest import FIXTURES
from docredact import __version__
from docredact.baseline import load_baseline

# The DOCX fixture builder lives next to the fixtures; import it for crafted docs.
sys.path.insert(0, str(FIXTURES))
from make_fixtures import build_docx  # noqa: E402


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "docredact", *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _tree(tmp_path: Path) -> Path:
    """A small mixed-format tree (md/csv/json, one subdirectory) with 3 findings."""
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "readme.md").write_text("Contact a@example.com for access.\n", encoding="utf-8")
    (root / "hosts.csv").write_text("name,addr\ngateway,192.0.2.7\n", encoding="utf-8")
    (root / "sub" / "config.json").write_text('{"owner": "b@example.com"}\n', encoding="utf-8")
    return root


class TestStrictGate:
    def test_strict_exits_3_on_findings_and_still_prints_the_table(self, tmp_path: Path) -> None:
        proc = _run("scan", str(_tree(tmp_path)), "--redact", "strict")
        assert proc.returncode == 3
        assert "total: 3 files, 3 entities" in proc.stdout
        assert "severity: low=3" in proc.stdout

    def test_strict_exits_0_on_clean_tree(self, tmp_path: Path) -> None:
        root = tmp_path / "clean"
        root.mkdir()
        (root / "notes.txt").write_text("nothing sensitive here\n", encoding="utf-8")
        proc = _run("scan", str(root), "--redact", "strict")
        assert proc.returncode == 0, proc.stderr

    def test_report_mode_still_exits_0_on_findings(self, tmp_path: Path) -> None:
        proc = _run("scan", str(_tree(tmp_path)))
        assert proc.returncode == 0, proc.stderr

    def test_parse_error_exits_1_even_with_write_baseline(self, tmp_path: Path) -> None:
        # An unparseable file means the recorded baseline is incomplete: the error
        # exit must win so CI never silently accepts a tree it could not read.
        root = _tree(tmp_path)
        (root / "broken.pdf").write_bytes(b"%PDF-1.4 not a real pdf body")
        baseline = tmp_path / "baseline.json"
        proc = _run("scan", str(root), "--redact", "strict", "--write-baseline", str(baseline))
        assert proc.returncode == 1
        assert "docredact: error: broken.pdf" in proc.stderr


class TestTreeBaseline:
    def test_accept_then_pass_then_fail_on_new(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"

        # 1) accept the current tree (exit 0 even in strict mode)
        proc = _run("scan", str(root), "--redact", "strict", "--write-baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        assert len(load_baseline(baseline)) == 3

        # 2) unchanged tree passes strict
        proc = _run("scan", str(root), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        assert "baseline: 3 finding(s) suppressed, 0 new" in proc.stderr

        # 3) a NEW leak anywhere in the tree -> strict fails, only the new one reported
        (root / "sub" / "notes.txt").write_text("key AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        proc = _run("scan", str(root), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 3
        assert "baseline: 3 finding(s) suppressed, 1 new" in proc.stderr
        assert "total: 4 files, 1 entities (api_key=1)" in proc.stdout

    def test_table_counts_reflect_new_only(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        _run("scan", str(root), "--write-baseline", str(baseline))
        (root / "readme.md").write_text(
            "Contact a@example.com for access. Backup: c@example.com\n", encoding="utf-8"
        )
        proc = _run("scan", str(root), "--baseline", str(baseline))
        assert proc.returncode == 0
        assert "total: 3 files, 1 entities (email=1)" in proc.stdout
        assert "severity: low=1" in proc.stdout

    def test_refresh_flow_drops_fixed_findings(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        _run("scan", str(root), "--write-baseline", str(baseline))
        before = load_baseline(baseline)
        (root / "hosts.csv").write_text("name,addr\ngateway,offline\n", encoding="utf-8")
        proc = _run("scan", str(root), "--baseline", str(baseline), "--write-baseline", str(baseline))
        assert proc.returncode == 0
        after = load_baseline(baseline)
        assert len(after) == 2 and after < before  # the ipv4 fingerprint dropped out

    def test_extract_baseline_composes_with_scan(self, tmp_path: Path) -> None:
        # Fingerprints are source-scoped the same way in both commands, so a
        # baseline written per-file by extract suppresses that file's findings
        # in a whole-tree scan.
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        proc = _run("extract", str(root / "readme.md"), "--write-baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        proc = _run("scan", str(root), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 3
        assert "baseline: 1 finding(s) suppressed, 2 new" in proc.stderr

    def test_malformed_baseline_is_clean_exit_1(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        proc = _run("scan", str(_tree(tmp_path)), "--baseline", str(bad))
        assert proc.returncode == 1
        assert "docredact: error:" in proc.stderr and "Traceback" not in proc.stderr

    def test_baseline_file_never_contains_values_or_paths(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        _run("scan", str(root), "--write-baseline", str(baseline))
        blob = baseline.read_text(encoding="utf-8")
        for leaked in ("a@example.com", "b@example.com", "192.0.2.7", "config.json", "sub/"):
            assert leaked not in blob, leaked

    def test_baseline_kept_inside_the_tree_is_not_scanned(self, tmp_path: Path) -> None:
        # Like .docredact.yaml, the gate's own state file is configuration, not a
        # document: a baseline stored in the tree must not be scanned (or flag
        # its own fingerprints) on the next run.
        root = _tree(tmp_path)
        baseline = root / "baseline.json"
        proc = _run("scan", str(root), "--redact", "strict", "--write-baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        assert "total: 3 files" in proc.stdout  # the fresh baseline.json is excluded
        proc = _run("scan", str(root), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        assert "total: 3 files" in proc.stdout
        assert "baseline: 3 finding(s) suppressed, 0 new" in proc.stderr

    def test_empty_tree_writes_empty_baseline(self, tmp_path: Path) -> None:
        root = tmp_path / "empty"
        root.mkdir()
        baseline = tmp_path / "baseline.json"
        proc = _run("scan", str(root), "--redact", "strict", "--write-baseline", str(baseline))
        assert proc.returncode == 0
        assert load_baseline(baseline) == frozenset()
        assert "no matching files" in proc.stdout


class TestBackCompat:
    def test_default_invocation_output_shape_is_unchanged(self, tmp_path: Path) -> None:
        proc = _run("scan", str(_tree(tmp_path)))
        assert proc.returncode == 0
        lines = proc.stdout.splitlines()
        assert lines[0].startswith("FILE")
        assert lines[-2].startswith("total: 3 files, 3 entities")
        assert lines[-1].startswith("severity:")
        # Subdirectory paths stay tree-relative posix, exactly as before.
        assert any(line.startswith("sub/config.json") for line in lines)


class TestJsonl:
    def test_one_finding_per_line_with_stable_keys_and_ordering(self, tmp_path: Path) -> None:
        proc = _run("scan", str(_tree(tmp_path)), "--format", "jsonl")
        assert proc.returncode == 0, proc.stderr
        findings = [json.loads(line) for line in proc.stdout.splitlines()]
        assert len(findings) == 3
        assert list(findings[0]) == [
            "path", "type", "value", "block", "start", "end",
            "confidence", "severity", "fingerprint",
        ]
        # Files in sorted tree order, entities in document order within each file.
        assert [f["path"] for f in findings] == ["hosts.csv", "readme.md", "sub/config.json"]
        assert findings[2] == {
            "path": "sub/config.json",
            "type": "email",
            "value": "b@example.com",
            "block": findings[2]["block"],
            "start": findings[2]["start"],
            "end": findings[2]["end"],
            "confidence": "high",
            "severity": "low",
            "fingerprint": findings[2]["fingerprint"],
        }

    def test_mask_mode_nulls_values_and_offsets(self, tmp_path: Path) -> None:
        proc = _run("scan", str(_tree(tmp_path)), "--format", "jsonl", "--redact", "mask")
        assert proc.returncode == 0
        for line in proc.stdout.splitlines():
            finding = json.loads(line)
            assert finding["value"] is None
            assert finding["start"] is None and finding["end"] is None
        assert "a@example.com" not in proc.stdout

    def test_deterministic_across_runs(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        first = _run("scan", str(root), "--format", "jsonl")
        second = _run("scan", str(root), "--format", "jsonl")
        assert first.stdout == second.stdout != ""

    def test_baseline_lists_only_the_new_finding(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        _run("scan", str(root), "--write-baseline", str(baseline))
        (root / "sub" / "notes.txt").write_text("key AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        proc = _run(
            "scan", str(root), "--redact", "strict",
            "--baseline", str(baseline), "--format", "jsonl",
        )
        assert proc.returncode == 3
        findings = [json.loads(line) for line in proc.stdout.splitlines()]
        assert [(f["path"], f["type"]) for f in findings] == [("sub/notes.txt", "api_key")]

    def test_out_writes_lf_only_file_and_keeps_stdout_empty(self, tmp_path: Path) -> None:
        out = tmp_path / "findings.jsonl"
        proc = _run("scan", str(_tree(tmp_path)), "--format", "jsonl", "--out", str(out))
        assert proc.returncode == 0
        assert proc.stdout == ""
        raw = out.read_bytes()
        assert raw.count(b"\n") == 3 and b"\r" not in raw

    def test_empty_tree_emits_no_lines(self, tmp_path: Path) -> None:
        root = tmp_path / "empty"
        root.mkdir()
        proc = _run("scan", str(root), "--format", "jsonl")
        assert proc.returncode == 0
        assert proc.stdout == ""
        assert "no matching files" in proc.stderr


class TestSarif:
    def _scan_sarif(self, root: Path, *extra: str) -> tuple[dict[str, Any], str]:
        proc = _run("scan", str(root), "--format", "sarif", *extra)
        return json.loads(proc.stdout), proc.stdout

    def test_envelope_is_minimal_valid_sarif(self, tmp_path: Path) -> None:
        doc, _ = self._scan_sarif(_tree(tmp_path))
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-2.1.0.json")
        (run,) = doc["runs"]
        driver = run["tool"]["driver"]
        assert driver["name"] == "docredact" and driver["version"] == __version__
        rules = driver["rules"]
        assert [r["id"] for r in rules] == sorted(r["id"] for r in rules)
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
            assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    def test_severity_to_level_mapping(self, tmp_path: Path) -> None:
        root = tmp_path / "levels"
        root.mkdir()
        (root / "a.txt").write_text("key AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
        (root / "b.txt").write_text("iban GB82WEST12345698765432\n", encoding="utf-8")
        (root / "c.txt").write_text("mail a@example.com\n", encoding="utf-8")
        doc, _ = self._scan_sarif(root)
        levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
        assert levels == {"api_key": "error", "iban": "warning", "email": "note"}
        defaults = {
            r["id"]: r["defaultConfiguration"]["level"]
            for r in doc["runs"][0]["tool"]["driver"]["rules"]
        }
        assert defaults == {"api_key": "error", "iban": "warning", "email": "note"}

    def test_locations_use_tree_relative_posix_uris(self, tmp_path: Path) -> None:
        doc, _ = self._scan_sarif(_tree(tmp_path))
        uris = [
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in doc["runs"][0]["results"]
        ]
        assert uris == ["hosts.csv", "readme.md", "sub/config.json"]

    def test_output_is_value_free(self, tmp_path: Path) -> None:
        _, blob = self._scan_sarif(_tree(tmp_path))
        for value in ("a@example.com", "b@example.com", "192.0.2.7"):
            assert value not in blob, value

    def test_fingerprints_match_the_jsonl_output(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        doc, _ = self._scan_sarif(root)
        jsonl = _run("scan", str(root), "--format", "jsonl")
        expected = [json.loads(line)["fingerprint"] for line in jsonl.stdout.splitlines()]
        actual = [
            r["partialFingerprints"]["docredactFingerprint/v1"]
            for r in doc["runs"][0]["results"]
        ]
        assert actual == expected

    def test_baseline_filters_results(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        baseline = tmp_path / "baseline.json"
        _run("scan", str(root), "--write-baseline", str(baseline))
        (root / "extra.txt").write_text("mail d@example.com\n", encoding="utf-8")
        doc, _ = self._scan_sarif(root, "--baseline", str(baseline))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "extra.txt"

    def test_deterministic_across_runs(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        first = _run("scan", str(root), "--format", "sarif")
        second = _run("scan", str(root), "--format", "sarif")
        assert first.stdout == second.stdout != ""

    def test_empty_tree_emits_a_valid_empty_run(self, tmp_path: Path) -> None:
        root = tmp_path / "empty"
        root.mkdir()
        proc = _run("scan", str(root), "--format", "sarif")
        assert proc.returncode == 0
        doc = json.loads(proc.stdout)
        (run,) = doc["runs"]
        assert run["results"] == [] and run["tool"]["driver"]["rules"] == []
        assert "no matching files" in proc.stderr


class TestDocxPartCoverageFlowsThroughTheGate:
    """A secret living ONLY in a DOCX footer must ride the whole 1.1 pipeline:
    strict gate failure, jsonl/sarif emission, and baseline suppression."""

    def _docx_tree(self, tmp_path: Path) -> Path:
        root = tmp_path / "tree"
        root.mkdir()
        data = build_docx(
            (("nothing sensitive in the body",),),
            (),
            footers=("footer leak: footer.leak@example.com",),
        )
        (root / "doc.docx").write_bytes(data)
        return root

    def test_footer_only_secret_fails_strict_and_baselines_away(self, tmp_path: Path) -> None:
        root = self._docx_tree(tmp_path)
        proc = _run("scan", str(root), "--redact", "strict")
        assert proc.returncode == 3  # the gate now SEES the footer

        baseline = tmp_path / "baseline.json"
        proc = _run("scan", str(root), "--redact", "strict", "--write-baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        assert len(load_baseline(baseline)) == 1

        proc = _run("scan", str(root), "--redact", "strict", "--baseline", str(baseline))
        assert proc.returncode == 0, proc.stderr
        assert "baseline: 1 finding(s) suppressed, 0 new" in proc.stderr

    def test_footer_finding_reaches_jsonl_and_sarif(self, tmp_path: Path) -> None:
        root = self._docx_tree(tmp_path)
        proc = _run("scan", str(root), "--format", "jsonl")
        (finding,) = [json.loads(line) for line in proc.stdout.splitlines()]
        assert finding["path"] == "doc.docx"
        assert finding["type"] == "email"
        assert finding["value"] == "footer.leak@example.com"

        proc = _run("scan", str(root), "--format", "sarif")
        doc = json.loads(proc.stdout)
        (result,) = doc["runs"][0]["results"]
        assert result["ruleId"] == "email"
        assert result["partialFingerprints"]["docredactFingerprint/v1"] == finding["fingerprint"]
        assert "footer.leak@example.com" not in proc.stdout  # sarif stays value-free
