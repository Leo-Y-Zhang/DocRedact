"""Declarative detection policy: custom detectors, allowlist, and built-in disables.

A small ``.docredact.yaml`` beside the scanned file (or ``--rules FILE``) tunes detection
without forking DocRedact:

    detectors:
      - name: employee_id
        regex: "EMP-\\d{6}"
        confidence: medium          # optional; default medium
      - name: card_dump
        regex: "\\d{13,19}"
        validator: luhn             # optional: luhn | iban_mod97 -> pass=high, fail=low
    allowlist:
      values:
        - "jane.doe@example.com"    # exact match, never flagged
      patterns:
        - "AKIA0+EXAMPLE"           # full-value regex match, never flagged
    disable:
      - person_name                 # built-in detector names

Nothing is ever hidden silently: a malformed file, unknown key, bad regex, invalid name, or
unknown validator produces a visible WARNING (surfaced on stderr by the CLI) and the rest of
the policy still applies. An allowlist can only REMOVE findings; a validator only sets
confidence; user detectors only ADD findings under their own type name.

The file is parsed by a deliberately minimal YAML-subset parser (below) instead of a YAML
library: no new dependency, and none of YAML's parsing attack surface (anchors, aliases,
tags, multi-documents are simply not part of the language). The subset: maps, lists of
scalars, lists of flat maps, ``#`` comments, and quoted strings taken LITERALLY (no escape
processing -- so regexes like ``"EMP-\\d{6}"`` mean exactly what they show).

Threat model note: the policy file is trusted local configuration, exactly like CLI
arguments. User-supplied regexes run against every extracted block; patterns are
length-capped, but a pathological pattern can still be slow -- write rules you trust.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detectors import Confidence

MAX_PATTERN_LENGTH = 500
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")

BUILTIN_DETECTOR_NAMES = frozenset(
    {
        "email", "phone", "api_key", "jwt", "pem_key",
        "high_entropy", "credit_card", "ipv4", "iban", "person_name",
    }
)

_VALIDATORS = ("luhn", "iban_mod97")
_KNOWN_KEYS = frozenset({"detectors", "allowlist", "disable"})
_DETECTOR_KEYS = frozenset({"name", "regex", "confidence", "validator"})
_ALLOWLIST_KEYS = frozenset({"values", "patterns"})


@dataclass(frozen=True)
class UserDetector:
    """One user-defined detector: a named regex with an optional checksum validator."""

    name: str
    pattern: re.Pattern[str]
    confidence: Confidence = Confidence.MEDIUM
    validator: str | None = None  # "luhn" | "iban_mod97" -> pass=high, fail=low


@dataclass(frozen=True)
class Policy:
    """A validated, immutable detection policy."""

    detectors: tuple[UserDetector, ...] = ()
    allow_values: frozenset[str] = frozenset()
    allow_patterns: tuple[re.Pattern[str], ...] = ()
    disabled: frozenset[str] = frozenset()


EMPTY = Policy()


# -- minimal YAML-subset parser ------------------------------------------------


class _SubsetError(ValueError):
    """Raised with a line number when input falls outside the documented subset."""


def _tokenize(text: str) -> list[tuple[int, int, str]]:
    """Yield (line_number, indent, content) for meaningful lines; reject tabs."""
    out: list[tuple[int, int, str]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw:
            raise _SubsetError(f"line {number}: tabs are not allowed (use spaces)")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        out.append((number, indent, stripped))
    return out


def _scalar(raw: str, number: int) -> str:
    """Resolve one scalar to its final value: quote-aware and comment-aware.

    A quoted scalar is taken LITERALLY (no escape processing) between its quotes,
    and only whitespace or a ``# comment`` may follow the closing quote (anything
    else is a visible error, so a comment can never silently merge into a value).
    An unquoted scalar drops a trailing `` # comment``.
    """
    if raw[:1] in ("'", '"'):
        quote = raw[0]
        close = raw.find(quote, 1)
        if close == -1:
            raise _SubsetError(f"line {number}: unterminated quoted string")
        tail = raw[close + 1 :].strip()
        if tail and not tail.startswith("#"):
            raise _SubsetError(f"line {number}: unexpected text after quoted value: {tail!r}")
        return raw[1:close]
    return raw.split(" #", 1)[0].rstrip()


def _parse_block(
    lines: list[tuple[int, int, str]], pos: int, indent: int
) -> tuple[Any, int]:
    """Parse the block starting at ``pos`` whose lines share ``indent``."""
    number, _, content = lines[pos]
    if content.startswith("- "):
        return _parse_list(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_map(
    lines: list[tuple[int, int, str]], pos: int, indent: int
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while pos < len(lines) and lines[pos][1] == indent:
        number, _, content = lines[pos]
        if content.startswith("- "):
            raise _SubsetError(f"line {number}: unexpected list item in a mapping")
        if ":" not in content:
            raise _SubsetError(f"line {number}: expected 'key: value' or 'key:'")
        key, _, rest = content.partition(":")
        key = key.strip()
        rest = rest.strip()
        if key in result:
            raise _SubsetError(f"line {number}: duplicate key {key!r}")
        if rest:
            result[key] = _scalar(rest, number)
            pos += 1
        else:
            pos += 1
            if pos < len(lines) and lines[pos][1] > indent:
                value, pos = _parse_block(lines, pos, lines[pos][1])
                result[key] = value
            else:
                result[key] = None
    if pos < len(lines) and lines[pos][1] > indent:
        raise _SubsetError(f"line {lines[pos][0]}: unexpected indentation")
    return result, pos


def _parse_list(
    lines: list[tuple[int, int, str]], pos: int, indent: int
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while pos < len(lines) and lines[pos][1] == indent and lines[pos][2].startswith("- "):
        number, _, content = lines[pos]
        raw = content[2:].strip()
        if ":" in raw and not raw.startswith(("'", '"')):
            # `- key: value` starts a flat map item; its remaining entries sit two
            # columns deeper (aligned under the key). Re-inject the first entry
            # UNSTRIPPED so _parse_map does the key/value split and _scalar sees
            # the value's own quoting (stripping the comment here would mangle a
            # quoted value that contains ' #').
            item_indent = indent + 2
            virtual = [(number, item_indent, raw)]
            follow = pos + 1
            while follow < len(lines) and lines[follow][1] == item_indent and not lines[follow][2].startswith("- "):
                virtual.append(lines[follow])
                follow += 1
            value, _ = _parse_map(virtual, 0, item_indent)
            result.append(value)
            pos = follow
        else:
            result.append(_scalar(raw, number))
            pos += 1
    return result, pos


def parse_yaml_subset(text: str) -> Any:
    """Parse the documented policy subset into dicts/lists/strings.

    Raises ``ValueError`` (with a line number) on anything outside the subset.
    """
    lines = _tokenize(text)
    if not lines:
        return {}
    value, pos = _parse_block(lines, 0, lines[0][1])
    if pos != len(lines):
        raise _SubsetError(f"line {lines[pos][0]}: unexpected content after the document")
    return value


# -- schema validation ----------------------------------------------------------


def _compile(pattern: str, where: str, warnings: list[str]) -> re.Pattern[str] | None:
    if len(pattern) > MAX_PATTERN_LENGTH:
        warnings.append(f"{where}: pattern longer than {MAX_PATTERN_LENGTH} chars; ignored")
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        warnings.append(f"{where}: invalid regex ({exc}); ignored")
        return None


def _load_detector(raw: Any, index: int, warnings: list[str]) -> UserDetector | None:
    where = f"detectors[{index}]"
    if not isinstance(raw, dict):
        warnings.append(f"{where}: expected a mapping with name/regex; ignored")
        return None
    for key in raw:
        if key not in _DETECTOR_KEYS:
            warnings.append(f"{where}: unknown key {key!r}")
    name = raw.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        warnings.append(f"{where}: name must match [a-z][a-z0-9_]{{0,31}}; ignored")
        return None
    if name in BUILTIN_DETECTOR_NAMES:
        warnings.append(f"{where}: name {name!r} collides with a built-in detector; ignored")
        return None
    regex = raw.get("regex")
    if not isinstance(regex, str) or not regex:
        warnings.append(f"{where} ({name}): missing regex; ignored")
        return None
    pattern = _compile(regex, f"{where} ({name})", warnings)
    if pattern is None:
        return None
    confidence = Confidence.MEDIUM
    if "confidence" in raw:
        try:
            confidence = Confidence(str(raw["confidence"]))
        except ValueError:
            warnings.append(
                f"{where} ({name}): invalid confidence {raw['confidence']!r}; using medium"
            )
    validator = raw.get("validator")
    if validator is not None and validator not in _VALIDATORS:
        warnings.append(
            f"{where} ({name}): unknown validator {validator!r} "
            f"(expected one of: {', '.join(_VALIDATORS)}); ignored"
        )
        validator = None
    return UserDetector(name, pattern, confidence, validator)


def load_policy(path: Path) -> tuple[Policy, list[str]]:
    """Load and validate a policy file. Returns (policy, warnings).

    Malformed input yields an empty (or partial) policy plus warnings -- never an
    exception, and never a silent miss.
    """
    warnings: list[str] = []
    try:
        raw = parse_yaml_subset(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return EMPTY, [f"policy file {path.name} could not be read: {exc}"]
    if raw is None or raw == {}:
        return EMPTY, warnings
    if not isinstance(raw, dict):
        return EMPTY, [f"policy file {path.name} is not a mapping; ignoring it"]

    for key in raw:
        if key not in _KNOWN_KEYS:
            warnings.append(f"policy has unknown key {key!r}")

    detectors: list[UserDetector] = []
    raw_detectors = raw.get("detectors")
    if raw_detectors is not None:
        if isinstance(raw_detectors, list):
            for index, item in enumerate(raw_detectors):
                detector = _load_detector(item, index, warnings)
                if detector is not None:
                    detectors.append(detector)
        else:
            warnings.append("policy 'detectors' must be a list; ignored")

    allow_values: set[str] = set()
    allow_patterns: list[re.Pattern[str]] = []
    raw_allow = raw.get("allowlist")
    if raw_allow is not None:
        if isinstance(raw_allow, dict):
            for key in raw_allow:
                if key not in _ALLOWLIST_KEYS:
                    warnings.append(f"allowlist has unknown key {key!r}")
            values = raw_allow.get("values")
            if values is not None:
                if isinstance(values, list) and all(isinstance(v, str) for v in values):
                    allow_values.update(values)
                else:
                    warnings.append("allowlist 'values' must be a list of strings; ignored")
            patterns = raw_allow.get("patterns")
            if patterns is not None:
                if isinstance(patterns, list) and all(isinstance(p, str) for p in patterns):
                    for index, text in enumerate(patterns):
                        pattern = _compile(text, f"allowlist.patterns[{index}]", warnings)
                        if pattern is not None:
                            allow_patterns.append(pattern)
                else:
                    warnings.append("allowlist 'patterns' must be a list of strings; ignored")
        else:
            warnings.append("policy 'allowlist' must be a mapping; ignored")

    disabled: set[str] = set()
    raw_disable = raw.get("disable")
    if raw_disable is not None:
        if isinstance(raw_disable, list):
            for name in raw_disable:
                if name in BUILTIN_DETECTOR_NAMES:
                    disabled.add(name)
                else:
                    warnings.append(f"policy disables unknown detector {name!r}")
        else:
            warnings.append("policy 'disable' must be a list; ignored")

    return (
        Policy(tuple(detectors), frozenset(allow_values), tuple(allow_patterns), frozenset(disabled)),
        warnings,
    )


def discover_policy(target: Path, explicit: Path | None) -> Path | None:
    """Resolve which policy file applies: ``--rules`` wins, else a ``.docredact.yaml``
    beside the target file (or inside the target directory). Discovery is confined
    to the target's location -- there is deliberately no current-working-directory
    fallback, so a stray policy elsewhere can never silently change results."""
    if explicit is not None:
        return explicit
    root = target if target.is_dir() else target.parent
    candidate = root / ".docredact.yaml"
    return candidate if candidate.is_file() else None
