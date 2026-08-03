"""The confidence model: validator-driven per-finding confidence + --min-confidence.

Discipline: a validator can only RAISE confidence or confirm a hit -- it never hides a
finding. Every shape hit is still reported; the checksum outcome just tells you how much to
trust it.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from conftest import FIXTURES
from docredact.core import build_document
from docredact.detectors import (
    Confidence,
    detect_credit_cards,
    detect_emails,
    detect_high_entropy,
    detect_ibans,
    detect_ipv4,
    detect_person_names,
    iban_mod97_valid,
    scan_text,
)

# The documented example IBAN (checksum-valid) and a single-digit mutation of it.
_VALID_IBAN = "GB82WEST12345698765432"
_INVALID_IBAN = "GB82WEST12345698765433"


class TestIbanMod97:
    def test_documented_example_is_valid(self) -> None:
        assert iban_mod97_valid(_VALID_IBAN)

    def test_single_digit_mutation_fails(self) -> None:
        assert not iban_mod97_valid(_INVALID_IBAN)

    def test_more_known_valid_ibans(self) -> None:
        for iban in ("DE89370400440532013000", "FR1420041010050500013M02606"):
            assert iban_mod97_valid(iban), iban

    def test_garbage_is_invalid_not_a_crash(self) -> None:
        for bad in ("", "GB", "GB82", "GB82 WEST", "!!!!!!", "GB82WEST1234569876543!"):
            assert not iban_mod97_valid(bad), bad

    def test_overlong_input_does_not_crash_on_int_limit(self) -> None:
        # A user detector with the iban_mod97 validator can feed an arbitrarily
        # long match; the old int() form raised past 4300 digits. Must fail fast.
        assert not iban_mod97_valid("GB" + "A" * 5000)


class TestValidatorDrivenConfidence:
    def test_valid_iban_is_high(self) -> None:
        (entity,) = detect_ibans(f"pay to {_VALID_IBAN} today")
        assert entity.confidence is Confidence.HIGH

    def test_checksum_failing_iban_is_still_reported_but_low(self) -> None:
        (entity,) = detect_ibans(f"pay to {_INVALID_IBAN} today")
        assert entity.type == "iban"  # never hidden -- honest heuristic
        assert entity.confidence is Confidence.LOW

    def test_luhn_valid_card_is_high(self) -> None:
        (entity,) = detect_credit_cards("card 4111 1111 1111 1111 ok")
        assert entity.confidence is Confidence.HIGH

    def test_email_is_high(self) -> None:
        (entity,) = detect_emails("mail jane.doe@example.com now")
        assert entity.confidence is Confidence.HIGH

    def test_ipv4_is_medium(self) -> None:
        (entity,) = detect_ipv4("host 192.0.2.10 up")
        assert entity.confidence is Confidence.MEDIUM

    def test_person_name_is_low(self) -> None:
        (entity,) = detect_person_names("Contact Mr. John Smith about this")
        assert entity.confidence is Confidence.LOW

    def test_high_entropy_scales_with_entropy(self) -> None:
        # 24 distinct chars = ~4.58 bits/char -> medium; 18 distinct over 24 chars
        # = ~4.08 bits/char (the 4.0-4.5 band) -> low.
        strong = "aB3xK9mQ2wE7rT5yU1iO4pZ8"
        weak = "abcdefghijklmnopqrabcdef"
        (strong_hit,) = detect_high_entropy(strong)
        assert strong_hit.confidence is Confidence.MEDIUM
        (weak_hit,) = detect_high_entropy(weak)
        assert weak_hit.confidence is Confidence.LOW


class TestConfidenceRanks:
    def test_rank_ordering(self) -> None:
        assert Confidence.LOW.rank < Confidence.MEDIUM.rank < Confidence.HIGH.rank

    def test_scan_text_preserves_confidence(self) -> None:
        found = scan_text(f"mail a@example.com, name Mr. John Smith, iban {_VALID_IBAN}")
        by_type = {e.type: e.confidence for e in found}
        assert by_type["email"] is Confidence.HIGH
        assert by_type["person_name"] is Confidence.LOW
        assert by_type["iban"] is Confidence.HIGH


class TestDocumentSurface:
    def test_entities_carry_confidence_in_json(self) -> None:
        doc = build_document(FIXTURES / "sample.txt")
        entities = doc["entities"]
        assert isinstance(entities, list) and entities
        assert all(e["confidence"] in {"low", "medium", "high"} for e in entities)

    def test_min_confidence_filters_and_shrinks_totals(self, tmp_path: Path) -> None:
        f = tmp_path / "mixed.txt"
        f.write_text("mail a@example.com and see Mr. John Smith\n", encoding="utf-8")
        all_doc = build_document(f)
        high_doc = build_document(f, min_confidence=Confidence.HIGH)
        assert {e["type"] for e in all_doc["entities"]} == {"email", "person_name"}
        assert {e["type"] for e in high_doc["entities"]} == {"email"}
        redaction = high_doc["redaction"]
        assert isinstance(redaction, dict) and redaction["total"] == 1

    def test_mask_with_min_confidence_masks_only_kept(self, tmp_path: Path) -> None:
        f = tmp_path / "mixed.txt"
        f.write_text("mail a@example.com and see Mr. John Smith\n", encoding="utf-8")
        doc = build_document(f, redact="mask", min_confidence=Confidence.HIGH)
        blocks = doc["blocks"]
        assert isinstance(blocks, list)
        text = blocks[0]["text"]
        assert "[REDACTED:email]" in text
        assert "Mr. John Smith" in text  # below the bar -> deliberately left in place

    def test_schema_is_additive(self) -> None:
        doc = build_document(FIXTURES / "sample.txt")
        assert set(doc) == {
            "extractor_version", "generated_at", "source", "sha256", "size_bytes",
            "format", "blocks", "entities", "redaction", "warnings",
        }


class TestCliFlag:
    def test_min_confidence_flag_end_to_end(self, tmp_path: Path) -> None:
        f = tmp_path / "mixed.txt"
        f.write_text("mail a@example.com and see Mr. John Smith\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f), "--min-confidence", "high"],
            capture_output=True, text=True, check=True,
        )
        doc = json.loads(proc.stdout)
        assert {e["type"] for e in doc["entities"]} == {"email"}

    def test_strict_respects_min_confidence(self, tmp_path: Path) -> None:
        f = tmp_path / "lowonly.txt"
        f.write_text("see Mr. John Smith\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "docredact", "extract", str(f),
             "--redact", "strict", "--min-confidence", "high"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0  # nothing at/above high -> pipeline passes
