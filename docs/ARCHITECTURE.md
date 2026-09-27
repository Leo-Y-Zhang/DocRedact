# DocRedact architecture

DocRedact is a local-first, read-only document extraction and redaction engine.
This document describes how one invocation flows through the code and the
invariants that keep its output safe and byte-for-byte reproducible. For the
user-facing feature list see the [README](../README.md); for upgrading from
0.x see [MIGRATION.md](MIGRATION.md).

## The pipeline

```
input path
    |
    v
extractors.detect_format ----> one of 11 formats by extension
extractors.extract_blocks ---> list[Block{index, kind, text}] + warnings
    |     pdf: pypdf w/ aggregate text + page caps      docx: capped zip + XXE-refusing XML
    |     eml: stdlib email (headers/parts)             json: leaf flattening w/ depth cap
    |     txt/md/html/csv/yaml/log/ini: stdlib text extractors
    v
detectors.scan_text(text, policy)   per block
    |     10 built-ins (skipping policy-disabled) + policy custom detectors
    |     validators drive Confidence (luhn, iban mod-97, entropy scaling)
    |     high-entropy hits overlapping a specific hit are dropped (merged-interval search)
    |     allowlist filters LAST (can only remove)
    v
core.build_document
    |     min_confidence filter (BEFORE masking)
    |     confidence/severity/fingerprint stamped per entity
    |     mask mode: blocks rewritten, values/offsets nulled
    v
document dict (the documented JSON schema)
    |
    +--> cli: --write-redacted -> core.build_sanitized -> sanitize.py tokens + manifest
    +--> cli: --write-baseline / --baseline (fingerprint record / suppress-known;
    |         extract per file, scan across the whole tree)
    +--> report.render_markdown / render_stats     or json.dumps
    +--> cli scan: summary table, jsonl (one finding per line), or
                   sarif.render_sarif (value-free SARIF 2.1.0)
```

`core.build_document` is a pure function of the file bytes plus its
arguments. Everything after it (baseline suppression, rendering, artifact
writing) is orchestrated by `cli.py`, so the library core stays free of
process concerns.

## The three load-bearing designs

### Consistent tokenization (`sanitize.py`)

`--write-redacted` does not just delete findings - it assigns each unique
`(type, value)` pair a stable token in first-appearance order (`[EMAIL_1]`,
`[EMAIL_2]`, ...) and replaces every occurrence document-wide. Cross-references
survive sanitization: a reader can tell two paragraphs mention the same
account without learning what it is. The manifest records token/type/count
only - never a value. Masking (`redact.mask_text`) and tokenization share one
`select_nonoverlapping` span resolver, so both replace exactly the same spans.

### The policy engine (`policy.py`)

A `.docredact.yaml` is parsed by a deliberately minimal YAML-subset parser
(~90 lines: maps, lists of scalars, lists of flat maps, comments; quoted
strings literal; tabs and duplicate keys rejected with line numbers). The
subset choice is a security decision: no YAML library dependency and none of
YAML's anchor/alias/tag attack surface. Validation is warning-driven - a bad
regex, unknown key, colliding name, or unknown validator warns visibly and the
rest of the policy applies. The discipline mirrors the detectors: user rules
only ADD findings, allowlists only REMOVE them, validators only set
confidence. Discovery is confined to the target's directory (no cwd
fallback), and the CLI always prints the applied policy path.

### Value-free baselines (`baseline.py`)

A finding's fingerprint is `sha256("type|source|value")[:16]`. Values here
are the secrets themselves, so - unlike a location-based scanner baseline -
the raw value never enters the baseline file, and position is excluded so
edits do not invalidate acceptance. Source *is* included: the same secret
appearing in a second file is a new leak. Baselines fail closed (malformed ->
exit 1) and are sorted/deduplicated for clean diffs. Because the source is
the basename in both commands, one baseline serves `extract` (per file) and
`scan` (whole tree) interchangeably; `scan` excludes the baseline file itself
from scanning when it sits inside the tree, and its parse errors keep exit 1
precedence over both a strict pass and a fresh `--write-baseline`.

## Determinism invariants

Reproducible output is what makes the drift-tested examples and the baseline
workflow possible:

- No wall clock: `generated_at` is null unless `--timestamp` is passed;
  nothing else reads time or randomness.
- Stable ordering everywhere: blocks by extraction order, entities sorted by
  `(start, end, type)`, manifest by first appearance, baselines sorted,
  stats sections sorted.
- Basename-only sources: no absolute path or username can enter a report.
- Enforced by `tests/test_determinism.py` (every fixture byte-identical
  across runs, leak checks), `tests/test_stress.py` (a 120-file corpus hashes
  identically across passes), and `tests/test_examples.py` (committed
  showcase artifacts must equal a fresh render).

## Untrusted-input posture

Every extractor treats its input as attacker-controlled:

- PDF: pypdf's per-stream decompression cap is complemented by an
  **aggregate** extracted-text cap (~25 M chars) and a page-count ceiling,
  because a small PDF can share one stream across many pages.
- DOCX: `word/document.xml` is rejected if its advertised size exceeds
  ~100 MB, then read with a bounded `cap + 1` read so a lying header cannot
  bypass the guard; XML containing `<!DOCTYPE`/`<!ENTITY` is refused (XXE).
- JSON: own 200-level nesting cap plus a RecursionError backstop.
- EML: stdlib parsing, expansion proportional to input; attachments are
  skipped with a visible `not scanned:` warning, never silently.
- Content that is present but not read (attachments, embedded files and
  objects, image-only pages, undecodable text) is always a `not scanned:`
  warning, and `--redact strict` fails closed on it (exit 1).
- Detector regexes are linear-time (RFC-bounded email segments); the
  high-entropy overlap filter is a merged-interval binary search, not a
  nested scan.
- A parse failure anywhere becomes a clean `ExtractionError` (exit 1) and
  never aborts a `scan` batch.

See the README's threat-model section for the full statement, including what
is out of scope.
