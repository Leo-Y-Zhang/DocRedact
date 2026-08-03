"""Property-based layer (Hypothesis) for the sanitize / redact / policy paths.

Backs two standing claims with generated evidence instead of hand-picked cases:

- never-crashes: scan_text, mask_text, sanitize_blocks, render_artifact and the
  policy loader accept arbitrary text without raising anything beyond their
  documented error types;
- redaction-completeness: every planted secret is detected, and no byte of any
  detected value survives masking or tokenization (the union-coverage contract
  of select_replacements, exercised on arbitrary overlapping spans).

Determinism note: the suite's guarantee is "green is green", so the Hypothesis
profile is derandomized (fixed example generation, no example database written
next to the repo). deadline=None because wall-clock deadlines flake on loaded
Windows CI runners; these are pure functions, so runtime is bounded by
max_examples, not by a per-example stopwatch.
"""
from __future__ import annotations

import contextlib
import json
import re
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from docredact.detectors import Confidence, Entity, scan_text
from docredact.extractors import Block
from docredact.policy import BUILTIN_DETECTOR_NAMES, EMPTY, Policy, load_policy, parse_yaml_subset
from docredact.redact import mask_text, select_replacements
from docredact.sanitize import render_artifact, sanitize_blocks

settings.register_profile("docredact", derandomize=True, database=None, deadline=None, max_examples=100)
settings.load_profile("docredact")

_TOKEN_SHAPE = re.compile(r"^\[[A-Z0-9_]+_[1-9]\d*\]$")

# Every value is fake by construction (example.com, the reserved 555-01xx
# range, documented AWS/IBAN examples, well-known Luhn test numbers) and none
# is a substring of another, so "not in masked output" checks stay exact.
_PLANTED_SECRETS = (
    "jane.doe@example.com",
    "+1-555-0142",
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_0123456789abcdefghijklmnopqrstuvwxyz",
    "4111111111111111",
    "GB82WEST12345698765432",
    "eyJhbGciOiJub25lIn0.eyJkZW1vIjoidHJ1ZSJ9.c2lnbmF0dXJl",
    "192.0.2.55",
)

# Filler that cannot extend or fabricate a finding: short lowercase words (too
# short for the high-entropy detector) and separators that keep every planted
# value on its own word boundary.
_FILLER_WORDS = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", max_size=8)
_SEPARATORS = st.sampled_from((" ", "\n", "  ", "\n\n", " . ", ", "))


@st.composite
def _text_with_secrets(draw: st.DrawFn) -> tuple[str, list[str]]:
    """Random filler text with 1-4 known secrets planted on clean boundaries."""
    secrets = draw(st.lists(st.sampled_from(_PLANTED_SECRETS), min_size=1, max_size=4))
    pieces: list[str] = []
    for secret in secrets:
        pieces.append(draw(_FILLER_WORDS))
        pieces.append(draw(_SEPARATORS))
        pieces.append(secret)
        pieces.append(draw(_SEPARATORS))
    pieces.append(draw(_FILLER_WORDS))
    return "".join(pieces), secrets


@st.composite
def _synthetic_entities(draw: st.DrawFn) -> tuple[int, list[Entity]]:
    """Arbitrary (possibly overlapping, duplicated, nested) spans over a text."""
    length = draw(st.integers(min_value=1, max_value=120))
    entities: list[Entity] = []
    for _ in range(draw(st.integers(min_value=0, max_value=10))):
        start = draw(st.integers(min_value=0, max_value=length - 1))
        end = draw(st.integers(min_value=start + 1, max_value=length))
        type_ = draw(st.sampled_from(("email", "iban", "high_entropy", "custom_rule")))
        entities.append(Entity(type_, "x" * (end - start), start, end, Confidence.HIGH))
    return length, entities


def _keys(entities: list[Entity]) -> set[tuple[int, int, str, str]]:
    return {(e.start, e.end, e.type, e.value) for e in entities}


class TestNeverCrashes:
    @given(st.text(max_size=300))
    def test_scan_mask_sanitize_render_accept_arbitrary_text(self, text: str) -> None:
        entities = scan_text(text)
        for entity in entities:
            assert 0 <= entity.start < entity.end <= len(text)
            assert text[entity.start : entity.end] == entity.value
        ordered = [(e.start, e.end, e.type) for e in entities]
        assert ordered == sorted(ordered)  # documented deterministic ordering

        masked = mask_text(text, entities)
        assert ("[REDACTED:" in masked) == bool(entities)

        texts, manifest = sanitize_blocks([Block(0, "paragraph", text)], {0: entities})
        assert len(texts) == 1
        for entry in manifest:
            assert set(entry) == {"token", "type", "occurrences"}
            assert _TOKEN_SHAPE.match(str(entry["token"]))

        artifact = render_artifact("txt", texts)
        assert artifact == "" or artifact.endswith("\n")
        assert artifact == render_artifact("txt", texts)  # deterministic

    @given(st.text(max_size=300))
    def test_yaml_subset_parser_raises_nothing_beyond_valueerror(self, text: str) -> None:
        # ValueError (with a line number) is the documented failure mode;
        # anything else escaping here fails the test.
        with contextlib.suppress(ValueError):
            parse_yaml_subset(text)

    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(st.text(max_size=300))
    def test_load_policy_never_raises_on_arbitrary_file_content(
        self, tmp_path: Path, text: str
    ) -> None:
        # The same scratch file is overwritten per example: load_policy must
        # return (policy, warnings) for ANY content, never an exception.
        path = tmp_path / "rules.yaml"
        path.write_text(text, encoding="utf-8")
        policy, warnings = load_policy(path)
        assert isinstance(policy, Policy)
        assert all(isinstance(w, str) for w in warnings)


class TestRedactionCompleteness:
    @given(_text_with_secrets())
    def test_every_planted_secret_is_detected(self, payload: tuple[str, list[str]]) -> None:
        text, secrets = payload
        values = {e.value for e in scan_text(text)}
        for secret in secrets:
            assert secret in values, secret

    @given(_text_with_secrets())
    def test_no_planted_secret_survives_masking(self, payload: tuple[str, list[str]]) -> None:
        text, secrets = payload
        masked = mask_text(text, scan_text(text))
        for secret in secrets:
            assert secret not in masked, secret

    @given(_text_with_secrets())
    def test_no_planted_secret_survives_tokenization(
        self, payload: tuple[str, list[str]]
    ) -> None:
        # Two identical blocks double as the cross-block consistency check:
        # same value -> same token, so both sanitized texts must be equal.
        text, secrets = payload
        blocks = [Block(0, "paragraph", text), Block(1, "paragraph", text)]
        per_block = {b.index: scan_text(b.text) for b in blocks}
        texts, manifest = sanitize_blocks(blocks, per_block)
        assert texts[0] == texts[1]
        blob = json.dumps(manifest)
        for secret in secrets:
            assert secret not in texts[0], secret
            assert secret not in blob, secret
        occurrences = [entry["occurrences"] for entry in manifest]
        clusters = sum(len(select_replacements(per_block[b.index])) for b in blocks)
        assert sum(occurrences) == clusters  # type: ignore[arg-type]
        tokens = [entry["token"] for entry in manifest]
        assert len(tokens) == len(set(tokens))


class TestUnionCoverage:
    """select_replacements' contract on arbitrary overlapping spans: disjoint,
    ordered clusters that cover the FULL union, so no byte of any detected
    value can survive replacement."""

    @given(_synthetic_entities())
    def test_clusters_are_disjoint_ordered_and_cover_every_span(
        self, payload: tuple[int, list[Entity]]
    ) -> None:
        length, entities = payload
        clusters = select_replacements(entities)
        for (_, _, prev_end), (_, next_start, _) in zip(clusters, clusters[1:], strict=False):
            assert prev_end <= next_start
        for winner, start, end in clusters:
            assert 0 <= start < end <= length
            assert winner in entities
        for entity in entities:
            assert any(
                start <= entity.start and entity.end <= end for _, start, end in clusters
            ), entity

    @given(_synthetic_entities())
    def test_masking_removes_exactly_the_covered_characters(
        self, payload: tuple[int, list[Entity]]
    ) -> None:
        # Independent coverage oracle: a boolean array, not the cluster list.
        # Mask tokens contain no "0", so counting "0"s in the output measures
        # precisely which original characters survived.
        length, entities = payload
        text = "0" * length
        covered = [False] * length
        for entity in entities:
            for i in range(entity.start, entity.end):
                covered[i] = True
        masked = mask_text(text, entities)
        assert masked.count("0") == length - sum(covered)
        assert masked.count("[REDACTED:") == len(select_replacements(entities))


class TestPolicyProperties:
    @given(st.text(max_size=300))
    def test_empty_policy_is_a_no_op(self, text: str) -> None:
        assert scan_text(text, EMPTY) == scan_text(text)

    @given(_text_with_secrets(), st.data())
    def test_allowlist_only_ever_removes_findings(
        self, payload: tuple[str, list[str]], data: st.DataObject
    ) -> None:
        text, _ = payload
        baseline = scan_text(text)
        values = sorted({e.value for e in baseline})
        chosen = data.draw(st.lists(st.sampled_from(values), unique=True)) if values else []
        policy = Policy(allow_values=frozenset(chosen))
        filtered = scan_text(text, policy)
        assert _keys(filtered) <= _keys(baseline)  # never adds, never rewrites
        assert all(e.value not in policy.allow_values for e in filtered)

    @given(_text_with_secrets(), st.sets(st.sampled_from(sorted(BUILTIN_DETECTOR_NAMES)), max_size=4))
    def test_disabled_detectors_never_report(
        self, payload: tuple[str, list[str]], disabled: set[str]
    ) -> None:
        text, _ = payload
        policy = Policy(disabled=frozenset(disabled))
        assert all(e.type not in disabled for e in scan_text(text, policy))
