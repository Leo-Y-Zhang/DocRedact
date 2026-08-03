"""The declarative policy engine: custom detectors, allowlist, disables + the YAML subset.

Discipline under test: user detectors only ADD findings, the allowlist only REMOVES them,
validators only set confidence, and anything malformed produces a VISIBLE warning while the
rest of the policy still applies.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from docredact.core import build_document
from docredact.detectors import Confidence, scan_text
from docredact.policy import (
    EMPTY,
    Policy,
    UserDetector,
    discover_policy,
    load_policy,
    parse_yaml_subset,
)

_FULL_POLICY = """\
# example policy
detectors:
  - name: employee_id
    regex: "EMP-\\d{6}"
    confidence: high
  - name: ticket
    regex: "TICKET-\\d+"
allowlist:
  values:
    - "jane.doe@example.com"
  patterns:
    - "192\\.0\\.2\\.\\d+"
disable:
  - person_name
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


class TestYamlSubset:
    def test_full_document_parses(self) -> None:
        doc = parse_yaml_subset(_FULL_POLICY)
        assert doc["disable"] == ["person_name"]
        assert doc["allowlist"]["values"] == ["jane.doe@example.com"]
        assert doc["detectors"][0] == {
            "name": "employee_id", "regex": "EMP-\\d{6}", "confidence": "high",
        }
        assert doc["detectors"][1] == {"name": "ticket", "regex": "TICKET-\\d+"}

    def test_quoted_strings_are_literal_no_escapes(self) -> None:
        doc = parse_yaml_subset('key: "a\\d{2}b"')
        assert doc["key"] == "a\\d{2}b"  # backslash survives untouched

    def test_comments_and_blanks_are_skipped(self) -> None:
        assert parse_yaml_subset("# only a comment\n\n") == {}

    def test_inline_comment_stripped_from_unquoted_scalar(self) -> None:
        assert parse_yaml_subset("key: value # trailing")["key"] == "value"

    def test_trailing_comment_after_quoted_value_is_dropped(self) -> None:
        # Regression: the comment must not merge into the quoted value.
        assert parse_yaml_subset('key: "value"   # comment')["key"] == "value"

    def test_quoted_value_containing_hash_survives_in_map(self) -> None:
        assert parse_yaml_subset('key: "a #b"')["key"] == "a #b"

    def test_quoted_value_containing_hash_survives_in_list_of_maps(self) -> None:
        doc = parse_yaml_subset('detectors:\n  - name: x_id\n    regex: "a #b"')
        assert doc["detectors"][0]["regex"] == "a #b"

    def test_quoted_list_scalar_with_trailing_comment(self) -> None:
        doc = parse_yaml_subset('allowlist:\n  values:\n    - "v@example.com"  # ok')
        assert doc["allowlist"]["values"] == ["v@example.com"]

    def test_junk_after_quoted_value_is_a_visible_error(self) -> None:
        try:
            parse_yaml_subset('key: "value" garbage')
        except ValueError as exc:
            assert "after quoted value" in str(exc)
        else:
            raise AssertionError("junk after a quoted value should be rejected")

    def test_docstring_example_round_trips_without_warnings(self, tmp_path: Path) -> None:
        # The exact allowlist form shown in the module docstring must work.
        text = (
            'allowlist:\n'
            '  values:\n'
            '    - "jane.doe@example.com"    # exact match, never flagged\n'
            '  patterns:\n'
            '    - "AKIA0+EXAMPLE"           # full-value regex, never flagged\n'
        )
        policy, warnings = load_policy(_write(tmp_path / ".docredact.yaml", text))
        assert warnings == []
        assert policy.allow_values == frozenset({"jane.doe@example.com"})
        assert policy.allow_patterns[0].pattern == "AKIA0+EXAMPLE"

    def test_tabs_are_rejected_with_line_number(self) -> None:
        try:
            parse_yaml_subset("key:\n\t- x")
        except ValueError as exc:
            assert "line 2" in str(exc) and "tab" in str(exc).lower()
        else:
            raise AssertionError("tabs should be rejected")

    def test_duplicate_keys_are_rejected(self) -> None:
        try:
            parse_yaml_subset("a: 1\na: 2")
        except ValueError as exc:
            assert "duplicate" in str(exc)
        else:
            raise AssertionError("duplicate keys should be rejected")


class TestLoadPolicy:
    def test_full_policy_loads_without_warnings(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(_write(tmp_path / ".docredact.yaml", _FULL_POLICY))
        assert warnings == []
        assert [d.name for d in policy.detectors] == ["employee_id", "ticket"]
        assert policy.detectors[0].confidence is Confidence.HIGH
        assert policy.detectors[1].confidence is Confidence.MEDIUM  # default
        assert policy.allow_values == frozenset({"jane.doe@example.com"})
        assert policy.disabled == frozenset({"person_name"})

    def test_unknown_key_warns_rest_applies(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(
            _write(tmp_path / "p.yaml", "banana: yes\ndisable:\n  - person_name\n")
        )
        assert any("banana" in w for w in warnings)
        assert policy.disabled == frozenset({"person_name"})  # still applied

    def test_bad_regex_warns_and_skips_only_that_detector(self, tmp_path: Path) -> None:
        text = (
            "detectors:\n"
            '  - name: broken\n    regex: "(unclosed"\n'
            '  - name: fine\n    regex: "OK-\\d+"\n'
        )
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", text))
        assert any("broken" in w and "invalid regex" in w for w in warnings)
        assert [d.name for d in policy.detectors] == ["fine"]

    def test_builtin_name_collision_is_refused(self, tmp_path: Path) -> None:
        text = 'detectors:\n  - name: email\n    regex: "x"\n'
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", text))
        assert policy.detectors == ()
        assert any("collides" in w for w in warnings)

    def test_unknown_disable_warns(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", "disable:\n  - nope\n"))
        assert policy.disabled == frozenset()
        assert any("nope" in w for w in warnings)

    def test_unknown_validator_warns_detector_kept(self, tmp_path: Path) -> None:
        text = 'detectors:\n  - name: x_id\n    regex: "\\d+"\n    validator: sha512\n'
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", text))
        assert [d.name for d in policy.detectors] == ["x_id"]
        assert policy.detectors[0].validator is None
        assert any("sha512" in w for w in warnings)

    def test_malformed_file_is_empty_policy_plus_warning(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", "key:\n\t- tabbed\n"))
        assert policy == EMPTY
        assert warnings and "could not be read" in warnings[0]

    def test_missing_file_warns_not_crashes(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(tmp_path / "absent.yaml")
        assert policy == EMPTY and warnings


class TestScanWithPolicy:
    def test_user_detector_adds_findings_under_its_name(self) -> None:
        policy, _ = _load_inline('detectors:\n  - name: emp\n    regex: "EMP-\\d{6}"\n')
        found = scan_text("id EMP-123456 ok", policy)
        assert [(e.type, e.value) for e in found] == [("emp", "EMP-123456")]
        assert found[0].confidence is Confidence.MEDIUM

    def test_luhn_validator_drives_confidence(self) -> None:
        policy, _ = _load_inline(
            'detectors:\n  - name: acct\n    regex: "ACCT \\d{4} \\d{4} \\d{4} \\d{4}"\n    validator: luhn\n'
        )
        good = scan_text("ACCT 4111 1111 1111 1111", policy)
        bad = scan_text("ACCT 4111 1111 1111 1112", policy)
        (good_acct,) = [e for e in good if e.type == "acct"]
        (bad_acct,) = [e for e in bad if e.type == "acct"]
        assert good_acct.confidence is Confidence.HIGH
        assert bad_acct.confidence is Confidence.LOW  # reported, not hidden

    def test_allowlist_value_removes_exact_match_only(self) -> None:
        policy, _ = _load_inline('allowlist:\n  values:\n    - "a@example.com"\n')
        found = scan_text("mail a@example.com and b@example.com", policy)
        assert [e.value for e in found] == ["b@example.com"]

    def test_allowlist_pattern_is_full_value_match(self) -> None:
        policy, _ = _load_inline('allowlist:\n  patterns:\n    - "192\\.0\\.2\\.\\d+"\n')
        found = scan_text("hosts 192.0.2.7 and 198.51.100.9", policy)
        assert [e.value for e in found] == ["198.51.100.9"]

    def test_disable_kills_builtin(self) -> None:
        policy, _ = _load_inline("disable:\n  - person_name\n")
        assert scan_text("see Mr. John Smith", policy) == []

    def test_no_policy_is_unchanged_behavior(self) -> None:
        assert scan_text("mail a@example.com") == scan_text("mail a@example.com", None)


def _load_inline(text: str) -> tuple[Policy, list[str]]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        return load_policy(_write(Path(tmp) / "p.yaml", text))


class TestDiscovery:
    def test_explicit_wins(self, tmp_path: Path) -> None:
        explicit = _write(tmp_path / "custom.yaml", "")
        assert discover_policy(tmp_path, explicit) == explicit

    def test_finds_docredact_yaml_beside_target_file(self, tmp_path: Path) -> None:
        cfg = _write(tmp_path / ".docredact.yaml", "disable:\n  - person_name\n")
        target = _write(tmp_path / "doc.txt", "hello")
        assert discover_policy(target, None) == cfg

    def test_no_cwd_fallback(self, tmp_path: Path, monkeypatch) -> None:
        cwd = tmp_path / "cwd"
        target = tmp_path / "target"
        cwd.mkdir()
        target.mkdir()
        _write(cwd / ".docredact.yaml", "disable:\n  - person_name\n")
        monkeypatch.chdir(cwd)
        assert discover_policy(target, None) is None


class TestCliIntegration:
    def test_rules_flag_end_to_end(self, tmp_path: Path) -> None:
        rules = _write(tmp_path / "rules.yaml", 'detectors:\n  - name: emp\n    regex: "EMP-\\d{6}"\n')
        doc_file = _write(tmp_path / "sub" / "doc.txt", "id EMP-654321")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(doc_file), "--rules", str(rules)],
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(proc.stdout)
        assert {e["type"] for e in doc["entities"]} == {"emp"}
        assert "policy: applying" in proc.stderr

    def test_auto_discovery_beside_input(self, tmp_path: Path) -> None:
        _write(tmp_path / ".docredact.yaml", "disable:\n  - email\n")
        doc_file = _write(tmp_path / "doc.txt", "mail a@example.com")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(doc_file)],
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(proc.stdout)
        assert doc["entities"] == []
        assert "policy: applying" in proc.stderr

    def test_policy_warning_reaches_stderr(self, tmp_path: Path) -> None:
        rules = _write(tmp_path / "rules.yaml", "banana: 1\n")
        doc_file = _write(tmp_path / "doc.txt", "hello")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(doc_file), "--rules", str(rules)],
            capture_output=True, text=True, check=True,
        )
        assert "warning:" in proc.stderr and "banana" in proc.stderr

    def test_mask_masks_custom_detector_hits(self, tmp_path: Path) -> None:
        rules = _write(tmp_path / "rules.yaml", 'detectors:\n  - name: emp\n    regex: "EMP-\\d{6}"\n')
        doc_file = _write(tmp_path / "sub2" / "doc.txt", "id EMP-777777 ok")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(doc_file),
             "--rules", str(rules), "--redact", "mask"],
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(proc.stdout)
        assert "[REDACTED:emp]" in doc["blocks"][0]["text"]

    def test_iban_validator_over_long_match_survives_scan_batch(self, tmp_path: Path) -> None:
        # A crafted document + a permissive iban_mod97 rule must not abort the batch
        # with a raw traceback (the old int() checksum crashed past 4300 digits).
        rules = _write(
            tmp_path / "rules.yaml",
            'detectors:\n  - name: acct\n    regex: "[A-Z]{2}[0-9A-Z]{10,}"\n    validator: iban_mod97\n',
        )
        _write(tmp_path / "docs" / "hostile.txt", "GB" + "A" * 5000 + "\n")
        _write(tmp_path / "docs" / "good.txt", "mail a@example.com\n")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "scan", str(tmp_path / "docs"), "--rules", str(rules)],
            capture_output=True, text=True,
        )
        assert "Traceback" not in proc.stderr
        assert "good.txt" in proc.stdout  # the batch still completed
        assert "total: 2 files" in proc.stdout

    def test_determinism_with_policy(self, tmp_path: Path) -> None:
        _write(tmp_path / ".docredact.yaml", _FULL_POLICY)
        doc_file = _write(tmp_path / "doc.txt", "EMP-123456 mail jane.doe@example.com Mr. John Smith")
        policy, _ = load_policy(tmp_path / ".docredact.yaml")
        first = json.dumps(build_document(doc_file, policy=policy))
        second = json.dumps(build_document(doc_file, policy=policy))
        assert first == second


def test_userdetector_is_frozen() -> None:
    import re as _re

    detector = UserDetector("x_id", _re.compile("x"))
    try:
        detector.name = "other"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("UserDetector should be frozen")
