"""Sanitized-artifact output: consistent tokenization + value-free manifest.

The contract: same value -> same token document-wide; distinct values -> _1/_2 per type in
first-appearance order; the manifest never carries a raw value; artifacts are deterministic
plain-text renderings.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from docredact.core import build_sanitized
from docredact.detectors import Confidence, scan_text
from docredact.extractors import Block
from docredact.policy import load_policy
from docredact.sanitize import assign_tokens, render_artifact, sanitize_blocks


def _blocks(*texts: str) -> list[Block]:
    return [Block(i, "paragraph", t) for i, t in enumerate(texts)]


def _scan_all(blocks: list[Block]) -> dict[int, list]:
    return {b.index: scan_text(b.text) for b in blocks}


class TestTokenAssignment:
    def test_same_value_same_token_across_blocks(self) -> None:
        blocks = _blocks("mail a@example.com now", "again a@example.com later")
        texts, manifest = sanitize_blocks(blocks, _scan_all(blocks))
        assert texts == ["mail [EMAIL_1] now", "again [EMAIL_1] later"]
        assert manifest == [{"token": "[EMAIL_1]", "type": "email", "occurrences": 2}]

    def test_distinct_values_count_up(self) -> None:
        blocks = _blocks("a@example.com then b@example.com then a@example.com")
        texts, manifest = sanitize_blocks(blocks, _scan_all(blocks))
        assert texts == ["[EMAIL_1] then [EMAIL_2] then [EMAIL_1]"]
        assert [m["token"] for m in manifest] == ["[EMAIL_1]", "[EMAIL_2]"]
        assert [m["occurrences"] for m in manifest] == [2, 1]

    def test_counters_are_per_type(self) -> None:
        blocks = _blocks("a@example.com and 192.0.2.7")
        texts, _ = sanitize_blocks(blocks, _scan_all(blocks))
        assert texts == ["[EMAIL_1] and [IPV4_1]"]

    def test_manifest_never_contains_raw_values(self) -> None:
        blocks = _blocks("card 4111 1111 1111 1111 mail a@example.com")
        _, manifest = sanitize_blocks(blocks, _scan_all(blocks))
        blob = json.dumps(manifest)
        assert "4111" not in blob and "a@example.com" not in blob
        assert set(manifest[0]) == {"token", "type", "occurrences"}

    def test_assignment_order_is_first_appearance(self) -> None:
        blocks = _blocks("first 192.0.2.7", "then a@example.com")
        _, manifest = assign_tokens(blocks, _scan_all(blocks))
        assert [m["type"] for m in manifest] == ["ipv4", "email"]


class TestOverlapUnionReplacement:
    """A dropped overlapping entity must not leave ANY of its bytes in the output."""

    def test_partial_overlap_tail_is_consumed(self) -> None:
        from docredact.detectors import Confidence, Entity

        blocks = [Block(0, "paragraph", "AAAAABBBBBCCCCC rest")]
        a = Entity("email", "AAAAABBBBB", 0, 10, Confidence.HIGH)
        b = Entity("iban", "BBBBBCCCCC", 5, 15, Confidence.HIGH)
        texts, manifest = sanitize_blocks(blocks, {0: [a, b]})
        assert texts == ["[EMAIL_1] rest"]  # union consumed, no CCCCC tail
        assert "CCCCC" not in texts[0]
        assert manifest == [{"token": "[EMAIL_1]", "type": "email", "occurrences": 1}]

    def test_chained_overlaps_collapse_into_one_cluster(self) -> None:
        from docredact.detectors import Confidence, Entity

        blocks = [Block(0, "paragraph", "0123456789abcdef end")]
        ents = [
            Entity("email", "01234", 0, 5, Confidence.HIGH),
            Entity("iban", "34567", 3, 8, Confidence.HIGH),
            Entity("ipv4", "789abcdef", 7, 16, Confidence.HIGH),
        ]
        texts, _ = sanitize_blocks(blocks, {0: ents})
        assert texts == ["[EMAIL_1] end"]

    def test_mask_also_consumes_the_union(self) -> None:
        from docredact.detectors import Confidence, Entity
        from docredact.redact import mask_text

        text = "AAAAABBBBBCCCCC rest"
        a = Entity("email", "AAAAABBBBB", 0, 10, Confidence.HIGH)
        b = Entity("iban", "BBBBBCCCCC", 5, 15, Confidence.HIGH)
        assert mask_text(text, [a, b]) == "[REDACTED:email] rest"

    def test_high_entropy_extending_past_a_specific_hit_stays_reported(self) -> None:
        from docredact.detectors import scan_text

        # An email brushed by a longer high-entropy token: dropping the token
        # entirely would silently un-report the suspected secret's tail.
        token = "aB3xK9mQ2wE7rT5yU1iO4pZ8mN6v"
        text = f"x@example.com{token}"
        types = {e.type for e in scan_text(text)}
        assert "high_entropy" in types


class TestRenderArtifact:
    def test_paragraph_formats_join_with_blank_line(self) -> None:
        assert render_artifact("txt", ["one", "two"]) == "one\n\ntwo\n"
        assert render_artifact("md", ["# a", "body"]) == "# a\n\nbody\n"

    def test_csv_rows_stay_one_per_line(self) -> None:
        assert render_artifact("csv", ["a, b", "c, d"]) == "a, b\nc, d\n"

    def test_empty_blocks_dropped(self) -> None:
        assert render_artifact("pdf", ["page one", "", "page three"]) == "page one\n\npage three\n"

    def test_empty_document_is_empty(self) -> None:
        assert render_artifact("txt", []) == ""


class TestBuildSanitized:
    def test_txt_end_to_end(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("Contact a@example.com or call 555-0142 now.\n\nAgain: a@example.com.\n", encoding="utf-8")
        artifact, manifest = build_sanitized(f)
        assert artifact == "Contact [EMAIL_1] or call [PHONE_1] now.\n\nAgain: [EMAIL_1].\n"
        assert {m["token"]: m["occurrences"] for m in manifest} == {"[EMAIL_1]": 2, "[PHONE_1]": 1}

    def test_deterministic_bytes(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("a@example.com and 192.0.2.7 and Mr. John Smith\n", encoding="utf-8")
        assert build_sanitized(f) == build_sanitized(f)

    def test_min_confidence_leaves_low_findings_in_place(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com see Mr. John Smith\n", encoding="utf-8")
        artifact, _ = build_sanitized(f, min_confidence=Confidence.HIGH)
        assert "[EMAIL_1]" in artifact and "Mr. John Smith" in artifact

    def test_custom_detector_tokens_use_rule_name(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.yaml"
        rules.write_text('detectors:\n  - name: emp\n    regex: "EMP-\\d{6}"\n', encoding="utf-8")
        policy, _ = load_policy(rules)
        f = tmp_path / "doc.txt"
        f.write_text("badge EMP-123456 ok\n", encoding="utf-8")
        artifact, manifest = build_sanitized(f, policy=policy)
        assert artifact == "badge [EMP_1] ok\n"
        assert manifest[0]["type"] == "emp"

    def test_no_findings_artifact_is_clean_text(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("nothing sensitive here\n", encoding="utf-8")
        artifact, manifest = build_sanitized(f)
        assert artifact == "nothing sensitive here\n" and manifest == []


class TestCliWriteRedacted:
    def test_end_to_end_artifact_and_manifest(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("Contact a@example.com twice: a@example.com\n", encoding="utf-8")
        out = tmp_path / "safe.txt"
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f), "--write-redacted", str(out)],
            capture_output=True, text=True, check=True,
        )
        assert out.read_text(encoding="utf-8") == "Contact [EMAIL_1] twice: [EMAIL_1]\n"
        doc = json.loads(proc.stdout)
        assert doc["sanitized"]["path"] == "safe.txt"  # basename only
        assert doc["sanitized"]["manifest"] == [
            {"token": "[EMAIL_1]", "type": "email", "occurrences": 2}
        ]

    def test_artifact_contains_no_detected_values(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text(
            "mail a@example.com key AKIAIOSFODNN7EXAMPLE card 4111 1111 1111 1111 "
            "iban GB82WEST12345698765432 host 192.0.2.7\n",
            encoding="utf-8",
        )
        out = tmp_path / "safe.txt"
        subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f), "--write-redacted", str(out)],
            capture_output=True, text=True, check=True,
        )
        artifact = out.read_text(encoding="utf-8")
        for secret in ("a@example.com", "AKIA", "4111", "GB82", "192.0.2.7"):
            assert secret not in artifact, secret

    def test_composes_with_mask_mode(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.txt"
        f.write_text("mail a@example.com\n", encoding="utf-8")
        out = tmp_path / "safe.txt"
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f),
             "--redact", "mask", "--write-redacted", str(out)],
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(proc.stdout)
        assert "[REDACTED:email]" in doc["blocks"][0]["text"]  # JSON masked
        assert "[EMAIL_1]" in out.read_text(encoding="utf-8")  # artifact tokenized

    def test_csv_artifact_keeps_rows(self, tmp_path: Path) -> None:
        f = tmp_path / "doc.csv"
        f.write_text("name,email\njane,a@example.com\njohn,b@example.com\n", encoding="utf-8")
        out = tmp_path / "safe.txt"
        subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f), "--write-redacted", str(out)],
            capture_output=True, text=True, check=True,
        )
        assert out.read_text(encoding="utf-8") == (
            "name, email\njane, [EMAIL_1]\njohn, [EMAIL_2]\n"
        )
