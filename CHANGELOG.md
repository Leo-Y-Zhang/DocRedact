# Changelog

All notable changes to this project are documented here.
Format loosely follows Keep a Changelog; versions follow SemVer.

## [Unreleased]

### Changed - BREAKING: the project was renamed Argus -> DocRedact

The old name said nothing about what the tool does and collided with several
unrelated products. Nothing about the pipeline, detectors, exit codes, or the
JSON schema changed; the identifiers that carried the old name did:

| Was | Is now |
| --- | --- |
| `argus` console script, `python -m argus` | `docredact`, `python -m docredact` |
| `import argus`, `src/argus/` | `import docredact`, `src/docredact/` |
| distribution name `argus` | `docredact` |
| `.argus.yaml` policy file | `.docredact.yaml` |
| `argus: error: ...` on stderr | `docredact: error: ...` |
| SARIF driver name `argus`, `partialFingerprints` key `argusFingerprint/v1` | `docredact`, `docredactFingerprint/v1` |
| Markdown report heading `# Argus report:` | `# DocRedact report:` |
| `ArgusError` exception base class | `DocRedactError` |

To upgrade: reinstall (`pip install -e ".[dev]"`), rename any `.argus.yaml`
to `.docredact.yaml`, and update the command name in scripts and CI steps.
Baseline files are unaffected - fingerprints are `sha256(type|source|value)`
and never contained the tool name, so an existing baseline keeps suppressing
exactly the findings it recorded. A CI job that keys off the old SARIF
`partialFingerprints` name will see every result as new once.

### Fixed - UTF-16 documents scanned as zero findings

Text formats decoded their bytes as UTF-8 unconditionally, with
`errors="replace"`. That never fails loudly: UTF-16, which Windows tooling
(Notepad, PowerShell redirection, Excel's "Unicode Text" export) writes with a
BOM as a matter of course, comes back with every ASCII character interleaved
with U+0000, so no detector can match it. A `.txt` holding
`AKIAIOSFODNN7EXAMPLE` in UTF-16 reported zero findings, zero warnings, and
exit 0 under `--redact strict` - the identical UTF-8 file exits 3.

A byte-order mark now selects the encoding (UTF-8/16/32), and a strict decode
is attempted before the lossy one so that undecodable bytes produce a visible
`input is not valid utf-8` warning instead of nothing. PDF, DOCX, and EML are
unaffected: they never went through this path.

### Fixed - DOCX text inside content controls, comments and tracked deletions was never scanned

Three kinds of DOCX text reached no detector and produced no warning, so
`--redact strict` exited 0 on a document that plainly carried the value:

- **Content controls.** Only direct `w:p`/`w:tbl` children of the body (and of
  each header, footer and note) were read, so any paragraph, table row or
  table cell wrapped in a content control (`w:sdt`) or custom-XML markup was
  dropped - which covers Word's cover pages, tables of contents, the
  page-number footer gallery and most form templates. That text is now read
  in place. Body block indexes after such a control move, because the
  skipped text now takes its place in the order; baselines are unaffected,
  since fingerprints never contained a block index.
- **Tracked deletions.** Deleted text is kept in the file as `w:delText` and
  shown to anyone who turns on All Markup, but the extractor only read `w:t`.
  It is now scanned as new `deletion` blocks, one per contiguous deletion,
  appended after everything else.
- **Comments.** `word/comments.xml` is now scanned as `comment` blocks after
  the endnotes, under the same aggregate size budget and DTD refusal as every
  other part.

Embedded objects (`word/embeddings/`) are still not opened, but each one now
produces an `embedded object skipped (not scanned)` warning instead of
nothing.

### Fixed - PDF annotations and filled-in form fields were never scanned

Only the page content stream went through a detector. A filled-in form shows
its values through widget appearance streams, and a FreeText box or sticky
note keeps its text in the annotation, so a typed-in email or a key pasted
into a comment scanned as zero findings. Annotation text (and a Link's
`mailto:` target, percent-decoded as for HTML) now becomes `annotation`
blocks, and every filled-in form field a `name: value` `field` block, both
appended after the last page so page block indexes still equal page numbers.
Both count against the existing aggregate text cap. Embedded files are not
opened; each produces an `embedded file skipped (not scanned)` warning.

### Fixed - `scan` dropped every extraction warning

`extract` records extraction warnings in its JSON, but `scan` threw them away:
none of the table, JSONL or SARIF outputs carried them and nothing reached
stderr. A tree holding a legacy-encoded text file or an email with an
attachment therefore passed `scan --redact strict` in complete silence, even
though part of it was never read - exactly what the decoding fix above
promised could not happen. Each warning now goes to stderr as
`warning: <path>: <message>`; stdout and exit codes are unchanged.

Entries below this line describe releases made under the old name and are
left as they were written.

## [1.2.0] - 2026-07-31

Closes the two blind spots the 1.1 Limitations section documented: content
outside the DOCX body, and addresses hiding inside HTML `mailto:` links.
Everything is additive - commands, flags, exit codes, JSON keys, and body
block indexes are unchanged, and because fingerprints never contained a
block index, pre-1.2 baseline files keep suppressing exactly the findings
they recorded.

### Added

- **DOCX header/footer/footnote/endnote scanning**: `word/headerN.xml`,
  `word/footerN.xml`, `word/footnotes.xml`, and `word/endnotes.xml` are
  extracted as new `header`/`footer`/`footnote`/`endnote` block kinds,
  appended after the body blocks in a deterministic order (headers in
  numeric order, then footers, then notes - independent of the zip's member
  listing). A secret living only in a footer now flows through the table,
  JSONL, SARIF, and the strict gate (exit 3) and is suppressed by baselines
  like any other finding.
- **HTML `mailto:` target scanning**: anchor hrefs are percent-decoded and
  injected space-padded into the enclosing block as scannable text,
  including RFC 6068 `?to=`/`?cc=`/`?bcc=` query addresses, so a mailbox
  hidden behind "Contact support" anchor text is detected. Also applies to
  `text/html` EML parts. Extracted text can therefore contain link targets
  that were not visible on the rendered page - that is the point.
- **Hypothesis property layer** (`tests/test_properties.py`; dev-only
  `hypothesis>=6.100` dependency): 11 properties on a derandomized profile
  (deterministic run to run, no example database) backing never-crashes
  (scan/mask/sanitize/render/policy loader on arbitrary text) and redaction
  completeness (planted secrets always detected, never surviving masking or
  tokenization; replacement-span union coverage checked against an
  independent boolean-array oracle). 287 -> 318 tests.

### Security

- The DOCX decompression-bomb cap is now one **aggregate byte budget**
  (~100 MB) across every scanned XML part - previously it applied to
  `word/document.xml` only - so a hostile archive cannot multiply the
  ceiling by stuffing in extra header/footer parts. The DTD/entity (XXE)
  rejection likewise applies to each scanned part. Honest edge: a document
  whose combined scanned parts exceed the budget is now rejected where 1.1
  would have read only its body - by design, since the extra parts are
  exactly where the blind spot was.

## [1.1.0] - 2026-07-30

The CI-adoption story now works at tree scale: `scan` gained the same
fail-only-on-new gate `extract` had, plus machine-readable output. Everything
is additive - the human table stays the default, and existing commands,
flags, exit codes, and JSON keys are unchanged.

### Added

- **Tree-level strict gate** (`scan --redact strict`): exit 3 when the tree
  has any (new, if baselined) finding; `report` stays the default and `mask`
  nulls values/offsets in the machine output. Parse errors keep exit 1 and
  outrank both a strict pass and a fresh baseline - an unparsed file means
  the gate did not actually see the whole tree.
- **Directory-wide baseline** (`scan --baseline` / `--write-baseline`):
  fingerprints are the same value-free, source-scoped hashes `extract` uses,
  so per-file extract baselines and one tree-wide scan baseline compose and
  interchange. All outputs report only NEW findings when a baseline is
  supplied; both flags together refresh the file. A baseline kept inside the
  scanned tree is excluded from scanning (gate state, not a document), like
  `.argus.yaml`. Documented caveat: fingerprints are basename-scoped, so two
  same-named files in different subdirectories share fingerprints for
  identical values.
- **`scan --format jsonl`** (the roadmap item): one finding per line - a
  tree-relative posix `path` plus the documented entity fields - in stable
  file-then-offset order, byte-identical across runs.
- **`scan --format sarif`**: a minimal, valid SARIF 2.1.0 run - rules
  catalogue built from the curated severity/CWE table, severity-to-level
  mapping (critical/high -> error, medium -> warning, low -> note),
  tree-relative `physicalLocation` URIs, block/offset under result
  `properties`, and the baseline fingerprint under `partialFingerprints`.
  Value-free by design: messages and fingerprints never contain a detected
  value, so the file is safe to hand to a CI annotation service even when
  the scan ran in report mode. An empty tree still emits a valid empty run.
- **`scan --out FILE`**: write the rendered output (any format) to a file
  with LF endings instead of stdout.
- Committed showcase artifacts `examples/fixtures-scan.jsonl` and
  `examples/fixtures-scan.sarif` with byte-for-byte drift guards and a
  no-secrets-in-sarif test; the determinism harness now covers both machine
  formats (byte-identical across runs, no path/username leak). 255 -> 287
  tests.

## [1.0.0] - 2026-07-10

The 1.0 release turns Argus from an offline extractor-with-detectors into a
local-first, policy-driven redaction engine that emits safe, shareable
artifacts. Everything below is additive: existing commands, exit codes, and
JSON keys keep working, and output stays byte-for-byte deterministic. See
`docs/MIGRATION.md` for the 0.x upgrade notes.

### Added

- **Sanitized artifacts** (`extract --write-redacted PATH`). Writes a safe
  plain-text copy of the document with every finding replaced by a
  *consistent token*: the same value is the same token document-wide
  (`[EMAIL_1]` everywhere it occurs; a second distinct email is `[EMAIL_2]`),
  so cross-references survive sanitization without leaking the value. A
  value-free redaction manifest (token, type, occurrences) rides along in the
  JSON under an additive `sanitized` key with a basename-only path.
- **Declarative policy** (`.argus.yaml` beside the input, or `--rules FILE`):
  named custom detectors (regex + optional `luhn`/`iban_mod97` validator
  driving confidence), an allowlist (exact values and full-match patterns
  that only ever REMOVE findings), and `disable:` for built-in detectors.
  Parsed by a deliberately minimal YAML-subset parser: no new dependency,
  none of YAML's attack surface (no anchors/aliases/tags), quoted strings
  taken literally so regexes read as written. Malformed anything produces a
  visible stderr warning while the rest of the policy applies; the applied
  policy path is always printed; discovery has no cwd fallback.
- **Confidence model.** Every finding carries `confidence` (low/medium/high)
  driven by real validators: a new ISO 7064 mod-97 IBAN check (pass = high,
  fail = low, still always reported), Luhn-gated cards high, precise shapes
  (email/api_key/jwt/pem/phone) high, ipv4 medium, person-name low,
  high-entropy scaled by measured entropy. New `--min-confidence` filter
  (applied before masking; documented semantics).
- **Baseline workflow.** Every entity carries a value-free `fingerprint`
  (sha256 of type|source|value, truncated to 16 hex chars); `--write-baseline`
  records the current findings and exits 0, `--baseline` suppresses exactly
  those and strict mode exits 3 only on NEW findings; both flags together
  refresh. The same secret leaking into a second file is a new finding.
  Malformed baselines fail closed with a clean exit-1 error.
- **Severity metadata.** A curated per-detector table (severity + closest
  CWE reference): private keys and cloud keys critical, JWTs and card data
  high, suspected secrets medium, contact PII and IPs low. Surfaced in every
  entity, in the new report, and in a `scan` severity rollup line.
- **Markdown findings report** (`--format markdown`): summary counts,
  findings table (masked values stay masked), CWE references, sanitized
  manifest, and warnings - deterministic and shareable.
- **Five new formats.** `.eml` (From/To/Cc/Bcc/Reply-To/Subject headers become
  precise blocks; text/plain and text/html parts extracted; attachments
  skipped with a visible warning), `.json` (one field block per leaf with its
  full key path, e.g. `aws.access_key_id: AKIA...`, arrays indexed, own
  200-level nesting cap with hostile-input tests), and
  `.yaml`/`.yml`/`.log`/`.ini` scanned as plain text lines (deliberately no
  YAML parser). `scan` excludes `.argus.yaml` itself from discovery.
- `--stats`: a deterministic per-document summary (blocks by kind, findings
  by severity/confidence/type) printed to stderr.
- Committed showcase artifacts `examples/sample-report.md` +
  `examples/sample-safe.txt` with a byte-for-byte drift guard and a
  no-secrets-in-artifact test.
- Tooling: ruff and mypy `--strict` clean and enforced in CI; a determinism
  harness (every fixture byte-identical across runs, basename-only sources,
  no filesystem/username leak); a stress guard (a 120-file corpus hashes
  identically across passes; a 200-file corpus stays fast).
- New deterministic fixtures `sample.eml` and `sample.json`; 118 -> 239
  tests.

### Security
- Fixed a ReDoS in the email detector: the domain pattern backtracked
  quadratically on adversarial input (a long run of `a.` labels with no
  valid TLD), so a ~200 KB block of document text could burn tens of
  seconds of CPU on any untrusted file. Segment lengths are now bounded
  (RFC 5321), making matching linear; real-email detection is unchanged.
- CSV extraction now wraps `csv.Error` (raised, for example, when a field
  exceeds the stdlib size limit) as an `ExtractionError`. Previously it
  escaped unwrapped, crashing `extract` with a path-leaking traceback and
  aborting an entire `scan` batch on a single malicious file.
- Fixed a PDF output-amplification DoS: pypdf caps decompression **per
  stream only**, so a ~12 KB / 50-page PDF sharing one stream could expand
  to ~100 M characters and burn minutes of CPU. `_extract_pdf` now bounds
  the aggregate extracted text (~25 M chars) and page count across pages,
  raising `ExtractionError` past the cap. Normal documents are unaffected.
- Fixed a DOCX decompression-bomb DoS: `word/document.xml` was read
  uncapped, so a ~1 MB DOCX decompressing to ~1 GB forced multi-GB heap.
  The extractor now rejects an over-cap advertised uncompressed size
  (~100 MB) and uses a bounded `cap + 1` read so a lying zip header cannot
  bypass the guard.
- Fixed a quadratic (`O(H*S)`) high-entropy overlap filter in `scan_text`:
  a ~0.5 MB high-entropy-heavy block took ~5 s. The filter now uses a
  sorted, merged-interval binary search (near-linear), with byte-identical
  output to the previous nested scan.
- README threat-model section rewritten to accurately describe the now-
  bounded PDF/DOCX amplification vectors and near-linear detectors, and to
  state honestly what remains out of scope (input-proportional RAM, other
  archive members, fixed non-configurable caps).
- 8 new regression tests (118 total).

## [0.2.0] - 2026-07-07

### Added
- DOCX extraction (`.docx`) via stdlib `zipfile` + `xml.etree`, no new
  runtime dependency: `word/document.xml` body paragraphs become
  `paragraph` blocks (runs are joined with no separator, so entities that
  Word splits across runs are still detected; tabs and breaks become
  whitespace) and table rows become `row` blocks (cells joined with
  `", "`, mirroring the csv extractor).
- Hardening: DOCX inputs whose XML contains DTD or entity declarations
  are refused with an extraction error (XXE / entity-expansion guard);
  missing archives, missing `word/document.xml`, and malformed XML all
  fail cleanly with exit code 1.
- Deterministic synthetic `fixtures/sample.docx` plus generator support
  in `fixtures/make_fixtures.py` (hand-written OOXML parts, fixed zip
  timestamps and permissions, stored entries; same fake PII set,
  including an email deliberately split across two runs).
- 7 new tests (108 total): paragraph/table extraction, run joining,
  corrupt-zip and missing-part errors, DTD rejection, detector
  integration on the DOCX fixture, and CLI end-to-end coverage
  including the scan table.
- gitleaks secret-scanning job in CI (gitleaks/gitleaks-action@v2).
- `.gitleaks.toml` allowlist covering only the documented synthetic
  fixture secrets (scoped to `fixtures/`, `tests/`, and the specific
  fake values); no detection rule is disabled.

## [0.1.0] - 2026-07-06

### Added
- Extraction of PDF (pypdf), txt, md, html (stdlib parser), and csv (stdlib)
  into a documented, deterministic JSON schema with per-block indices.
- Ten sensitive-data detectors: email, phone, API-key-shaped strings
  (AWS AKIA / GitHub ghp_ gho_ / generic sk-), JWT shape, PEM private-key
  headers, high-entropy tokens, Luhn-validated card numbers, IPv4,
  IBAN-shaped strings, and a weak honorific-based person-name heuristic.
- Redaction modes: report, mask (idempotent [REDACTED:type] tokens),
  and strict (exit code 3 on any finding).
- CLI: `argus extract` and `argus scan` (batch summary table),
  also runnable as `python -m argus`.
- Deterministic synthetic fixtures plus their generator
  (`fixtures/make_fixtures.py`), including a hand-written minimal PDF.
- 101 pytest tests covering every extractor, every detector (positive and
  negative), masking idempotence, strict-mode exit code, and CLI end-to-end.
