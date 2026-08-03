"""Baseline workflow: adopt DocRedact on an existing tree and fail only on NEW findings.

``--write-baseline FILE`` records a fingerprint for every currently reported finding;
``--baseline FILE`` suppresses exactly those findings from the report (and from strict
gating) so CI alerts only on regressions. Combining both flags refreshes the baseline.

The fingerprint is ``sha256("<type>|<source>|<value>")`` truncated to 16 hex chars:

- The raw value never appears in a baseline file or report -- only its hash.
- ``source`` (the basename) is included, so accepting a secret in one file does NOT
  accept the same secret leaking into another file (that is a new finding).
- Block indexes and offsets are deliberately excluded: the same value moving around
  inside the same file is still the same accepted finding, so ordinary edits do not
  invalidate a baseline.

Honesty note: fingerprints are unsalted (they must be reproducible across machines), so a
*guessable* value's presence could be confirmed by brute force against its hash. Treat
baseline files with the same care as the scanned documents. This is the standard
tradeoff of secret-baseline tools.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .extractors import DocRedactError

BASELINE_VERSION = 1


class BaselineError(DocRedactError):
    """A baseline file is missing, malformed, or unwritable (fails closed, exit 1)."""


def fingerprint(type_: str, source: str, value: str) -> str:
    """Stable, value-free fingerprint of one finding."""
    digest = hashlib.sha256(f"{type_}|{source}|{value}".encode()).hexdigest()
    return digest[:16]


def write_baseline(path: Path, fingerprints: list[str]) -> None:
    """Write a deterministic (sorted, de-duplicated) baseline file."""
    payload = {"version": BASELINE_VERSION, "fingerprints": sorted(set(fingerprints))}
    try:
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot write baseline file: {exc}") from exc


def load_baseline(path: Path) -> frozenset[str]:
    """Load a baseline file, failing closed on anything malformed."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"cannot read baseline file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineError(f"malformed baseline file {path.name}: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("version") != BASELINE_VERSION:
        raise BaselineError(
            f"malformed baseline file {path.name}: expected version {BASELINE_VERSION}"
        )
    fingerprints = raw.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(
        isinstance(f, str) for f in fingerprints
    ):
        raise BaselineError(
            f"malformed baseline file {path.name}: 'fingerprints' must be a list of strings"
        )
    return frozenset(fingerprints)
