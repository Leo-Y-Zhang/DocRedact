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

### Changed - strict mode fails closed on content that was not scanned

`--redact strict` already exited 1 on a file that failed to parse, because a
gate that did not read a file did not check it. Content skipped inside a file
that *did* parse only produced a warning, so strict exited 0 on a PDF carrying
an attached file with a key in it, a DOCX with an embedded workbook, a scanned
(image-only) PDF page, a page pypdf could not parse, and an e-mail whose
attachment held the secret. Two cases were silent: text in a subset font with
no ToUnicode map (pypdf emits the glyph ids as garbage), and UTF-16 written
without a byte-order mark (valid UTF-8 to the decoder, zero findings).

Every warning that means "present but not read" now starts with
`not scanned: `, and strict mode treats any of them like a parse error: exit
1, outranking a finding (3) and a fresh `--write-baseline` (0). `extract`
prints each gap as a `docredact: error:` line; `scan` names each partially
read file. Report and mask modes still write their output, warnings included,
and exit as before. New gaps: DOCX embedded objects, macros and other binary
parts (images and printer settings excepted) and altChunk-imported content;
PDF embedded files (by name), fonts without a Unicode mapping, U+FFFD in
extracted text, and an earlier revision that cannot be opened. The existing
warnings were reworded to the prefix (`attachment skipped (not scanned): X`
is now `not scanned: attachment (X)`). A blank PDF page no longer warns.

### Fixed - an output could overwrite the input it was reading

`--write-redacted` or `--out` pointed at the input replaced the original
document (with its sanitized rendering or the JSON report), exit 0.
`--write-redacted X --out X` wrote the artifact and then replaced it with the
report - raw values included - in the file the user was about to share as the
safe copy. And a `scan --write-baseline` path inside the tree is excluded from
scanning as the gate's own state, so naming a real document there both hid its
findings and replaced it with an empty baseline. Before anything is written,
an output that is the input document (any document in the tree, for `scan`),
the policy file or the baseline being read is now refused with exit 1, as are
two outputs on one path; `--write-baseline` may replace an existing file only
if it is a baseline, so the in-place refresh still works.

### Fixed - hidden DOCX and PDF content was never scanned

Text a document carries outside its visible body reached no detector, so
`--redact strict` exited 0 on a file that plainly held the value. All of it is
now scanned and reported, as new block kinds appended after the existing ones
(page and note indexes do not move):

- **DOCX content controls** (`w:sdt`, `w:customXml`) - cover pages, tables of
  contents, the page-number footer gallery, form templates - are read in
  place. This is visible text, so it is rendered too; body block indexes after
  such a control move (baselines are unaffected: fingerprints never held one).
- **DOCX text boxes** no longer fuse with their host paragraph:
  `KeyAKIAIOSFODNN7EXAMPLEjane.doe@example.com` hid the key inside one "email".
- **`deletion`** - DOCX tracked deletions (`w:delText`).
- **`comment`** - `word/comments.xml`.
- **`annotation`** and form **`field`** - PDF sticky notes, FreeText boxes and
  filled-in AcroForm values.
- **`metadata`** - PDF Info and XMP; DOCX core, extended and custom
  properties (author, last editor, company, keywords, anything custom).
- **`link`** - DOCX external relationship targets and `HYPERLINK` field codes;
  PDF link URIs. Percent-decoded, and every URL, not only `mailto:`.
- **`alt_text`** - DOCX image and shape descriptions.
- **`revision`** - text that only an earlier revision of an incrementally
  updated PDF still holds: "redacting" a page by saving over it leaves the
  original page in the file.

Everything except content controls, text boxes and form fields is scanned but
**not rendered into the sanitized artifact**, which is the document as its
reader sees it: resurrecting what the author deleted, or what they never saw,
into the copy that gets shared would hand the recipient exactly what the
detectors cannot recognise (a bare name, a salary). New DOCX parts share the
aggregate size budget and DTD refusal; the XMP packet is refused if it carries
a DTD; PDF annotation, metadata and revision text share the aggregate text cap,
and revisions are capped at 100.

A test now also pins down that text a PDF viewer hides - under a black box,
invisible, white, clipped, off the page, in a hidden layer - is still scanned.

### Fixed - `scan` dropped every extraction warning

`extract` records extraction warnings in its JSON, but `scan` threw them away:
none of the table, JSONL or SARIF outputs carried them and nothing reached
stderr. Each warning now goes to stderr as `warning: <path>: <message>`;
stdout stays pure output.

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
