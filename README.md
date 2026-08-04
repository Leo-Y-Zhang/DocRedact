# DocRedact - local-first document extraction and redaction CLI

[![CI](https://github.com/Leo-Y-Zhang/DocRedact/actions/workflows/ci.yml/badge.svg)](https://github.com/Leo-Y-Zhang/DocRedact/actions/workflows/ci.yml)

DocRedact pulls text and structure out of local documents into clean JSON,
detects sensitive-looking data with validator-driven confidence, and produces
**safe, shareable artifacts** - a sanitized copy of the document where every
finding is replaced by a consistent token. It runs fully offline: no network
calls, no external APIs, one small runtime dependency (pypdf).

This is an educational / portfolio tool. The detectors are honest,
well-tested heuristics - useful as a pre-flight check before sharing extracted
text, not a substitute for a professional DLP product.

## What 1.0 does

- **Extracts eleven formats** into indexed text blocks: PDF (pypdf), `.docx`
  (stdlib zip + XML), `.eml` (headers become precise blocks; text parts and
  HTML parts extracted; attachments skipped with a visible warning), `.json`
  (one block per leaf with its full key path - a finding names the config key
  it sits under, e.g. `aws.access_key_id: AKIA...`), plus `.txt`, `.md`,
  `.html`/`.htm`, `.csv`, and `.yaml`/`.yml`/`.log`/`.ini` as scanned text.
- **Detects** with ten built-in detectors (emails, phones, API-key shapes,
  JWTs, PEM keys, high-entropy tokens, Luhn-valid cards, IPv4, IBAN,
  person-name heuristic), each with:
  - a **confidence** (low/medium/high) driven by real validators - Luhn for
    cards, ISO 7064 mod-97 for IBANs (a checksum-failing IBAN is still
    reported, just at low confidence; validators never hide a finding);
  - a **severity** and CWE reference from a curated table (private keys and
    cloud keys are critical; JWTs and card data high; contact PII low).
- **Redacts three ways**:
  - `--redact mask` - rewrite the JSON report with `[REDACTED:type]` tokens;
  - `--write-redacted PATH` - write a **sanitized copy of the document**
    where the same value is always the same token (`[EMAIL_1]` everywhere it
    occurs), so cross-references survive without leaking the value, plus a
    value-free manifest;
  - `--redact strict` - fail a pipeline (exit 3) when anything is found.
- **Tunes with a declarative policy** (`.docredact.yaml` beside the input or
  `--rules FILE`): named custom detectors (regex + optional
  `luhn`/`iban_mod97` validator), an allowlist that only ever *removes*
  findings, and `disable:` for built-ins. Anything malformed warns visibly;
  the applied policy path is always printed.
- **Adopts on legacy trees with a baseline**: `--write-baseline` records
  value-free fingerprints, `--baseline` reports (and strict-gates) only NEW
  findings.
- **Stays deterministic**: `generated_at` is null unless you pass
  `--timestamp`, ordering is stable, sources are basename-only, and the JSON,
  Markdown report, sanitized artifact, and baseline files are byte-identical
  between runs - proven by a determinism harness and a 120-file stress guard.

## What 1.1 adds

The per-file CI gate now works at tree scale. `docredact scan` gained the same
gate `extract` had - `--redact strict` plus `--baseline`/`--write-baseline`,
failing only on NEW findings - and two machine formats:

- `--format jsonl`: one finding per line (a tree-relative posix path plus the
  documented entity fields), stable ordering, pipes straight into `jq`.
- `--format sarif`: a minimal, valid SARIF 2.1.0 run - rules catalogue from
  the curated severity/CWE table, severity-to-level mapping, tree-relative
  `physicalLocation` URIs - that is **value-free by design**: messages and
  fingerprints never contain a detected value, so the file is safe to hand
  to a CI annotation service even when the scan ran in report mode.
- `--out FILE`: write the rendered output (any format) with LF endings.

The human table stays the default output, and existing commands, flags, and
exit codes are unchanged. See "Tree-level CI gate" below for the recipe.

## What 1.2 adds

Two blind spots that the 1.1 Limitations section documented are now closed -
the parts of a document people forget they cannot see:

- **DOCX headers, footers, footnotes, and endnotes are scanned.**
  `word/headerN.xml`, `word/footerN.xml`, `word/footnotes.xml`, and
  `word/endnotes.xml` become new `header`/`footer`/`footnote`/`endnote`
  block kinds, appended after the body blocks in a fixed order (headers in
  numeric order, then footers, then notes) - so body block indexes match
  1.1 output exactly, and a secret living only in a footer now fails the
  strict gate like any other finding.
- **HTML `mailto:` targets are scanned.** Anchor hrefs are percent-decoded
  and injected into the enclosing block as scannable text - including
  RFC 6068 `?to=`/`?cc=`/`?bcc=` query addresses - so a personal mailbox
  hiding behind "Contact support" anchor text is detected. This applies to
  `text/html` EML parts too, and it means extracted text can now contain
  link targets that were not visible on the rendered page (that is the
  point).
- **A Hypothesis property layer** (dev-only dependency) backs the
  never-crash and redaction-completeness guarantees: 11 properties on a
  derandomized profile assert that scan/mask/sanitize/render/policy-load
  never crash on arbitrary text, that planted secrets are always detected
  and never survive masking or tokenization, and that replacement-span
  union coverage matches an independent oracle.

Baselines stay compatible: fingerprints never included a block index, so a
pre-1.2 baseline file keeps suppressing exactly the findings it recorded.

## Install

Requires Python 3.10+ (developed on 3.13). From the project root:

```
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"     # Windows
# .venv/bin/python -m pip install -e ".[dev]"           # POSIX
```

Run the tests: `.venv/Scripts/pytest -q` (334 tests).

## Quickstart

Extract one document (fixtures ship with the repo and contain only fake data):

```
docredact extract fixtures/sample.txt --pretty
```

Each entity now carries `confidence`, `severity`, and a value-free
`fingerprint` alongside the value and offsets:

```json
{
  "type": "email",
  "value": "jane.doe@example.com",
  "block": 1, "start": 8, "end": 28,
  "confidence": "high",
  "severity": "low",
  "fingerprint": "7e8de132638f4796"
}
```

Write a **sanitized copy** you can actually share:

```
docredact extract fixtures/sample.txt --write-redacted safe.txt
```

`safe.txt` (excerpt; compare `examples/sample-safe.txt`, the committed artifact):

```
...
Contact [EMAIL_1] or call [PHONE_1] for support.

Payment card on file: [CREDIT_CARD_1] (Visa test number).
AWS key sample: [API_KEY_1]
...
```

The JSON gains a `sanitized` manifest - tokens, types, and counts, never a
raw value. A human-readable report instead of JSON:

```
docredact extract fixtures/sample.txt --format markdown
```

(see `examples/sample-report.md` for the committed output.)

Scan a directory:

```
docredact scan fixtures
```

```
FILE         FORMAT  BLOCKS  ENTITIES
sample.csv   csv     3       6
sample.docx  docx    10      11
sample.eml   eml     8       6
...
total: 8 files, 54 entities (api_key=8, credit_card=8, email=16, ...)
severity: critical=9, high=9, medium=2, low=34
```

### Policy: custom detectors, allowlist, disables

Drop a `.docredact.yaml` beside the input (or pass `--rules FILE`):

```yaml
detectors:
  - name: employee_id
    regex: "EMP-\d{6}"
    confidence: high
  - name: account_number
    regex: "ACCT \d{4} \d{4} \d{4} \d{4}"
    validator: luhn          # pass = high confidence, fail = low (never hidden)
allowlist:
  values:
    - "jane.doe@example.com" # exact value, never flagged
  patterns:
    - "192\.0\.2\.\d+"       # full-value regex, never flagged (TEST-NET)
disable:
  - person_name              # built-in detector names
```

The file is parsed by a deliberately minimal YAML-subset parser (maps, lists,
flat map lists, comments): no YAML library, none of YAML's parsing attack
surface, and **quoted strings are literal** - no escape processing - so the
regexes above mean exactly what they show. Unknown keys, bad regexes, invalid
names, and unknown validators each produce a visible `warning:` on stderr
while the rest of the policy still applies; the CLI always prints
`policy: applying <path>` so a policy can never quietly change results.
Custom detector hits are masked and tokenized like built-ins (`[EMPLOYEE_ID_1]`).

The policy file is trusted local configuration, like CLI arguments:
user-supplied regexes run against every extracted block, so write rules you
trust (patterns are length-capped but not sandboxed).

### Baseline workflow (CI)

Adopting a scanner on an existing tree usually drowns you in historical
findings. The baseline lets CI fail only on **regressions**:

```
# one-time: accept the current state (exits 0, even in strict mode)
docredact extract report.txt --redact strict --write-baseline baseline.json

# on every run: fail only on NEW findings
docredact extract report.txt --redact strict --baseline baseline.json
# exit 0 -> nothing new; stderr says "baseline: N finding(s) suppressed, 0 new"
# exit 3 -> a NEW finding appeared; the report shows only the new ones

# refresh after fixing findings (fixed ones drop out):
docredact extract report.txt --baseline baseline.json --write-baseline baseline.json
```

The fingerprint is `sha256("<type>|<source>|<value>")` truncated to 16 hex
chars - the raw value never enters a baseline file. The source basename is
part of the hash, so an accepted secret leaking into a *second* file is a new
finding; positions are excluded, so the same value moving inside its file
survives ordinary edits. Fingerprints are unsalted (they must reproduce
across machines), so a *guessable* value could be confirmed by brute force
against its hash - treat baseline files with the same care as the documents.

### Tree-level CI gate

The same workflow scales from one file to a whole directory, and because
`scan` uses the same source-scoped fingerprints, per-file `extract` baselines
and one directory-wide `scan` baseline are interchangeable:

```
# one-time: accept everything currently in the tree (exits 0, even in strict mode)
docredact scan docs/ --redact strict --write-baseline baseline.json

# on every run: fail only when something NEW appears anywhere in the tree
docredact scan docs/ --redact strict --baseline baseline.json
# exit 0 -> nothing new; stderr says "baseline: N finding(s) suppressed, 0 new"
# exit 3 -> a NEW finding appeared; the output shows only the new ones
# exit 1 -> a file failed to parse - this outranks 0 AND 3, because an
#           unparsed file means the gate did not actually see the whole tree

# machine-readable variants for CI plumbing
docredact scan docs/ --baseline baseline.json --format jsonl   # one finding per line
docredact scan docs/ --format sarif --out docredact.sarif          # value-free SARIF 2.1.0
```

A pre-commit hook or CI step is that one strict command pointed at your tree:

```sh
#!/bin/sh
# .git/hooks/pre-commit (or a CI step; nonzero exit blocks the commit/build)
docredact scan . --redact strict --baseline .docredact-baseline.json
```

The baseline file may live inside the scanned tree: like `.docredact.yaml`, it is
treated as the gate's own state, not a document, and is excluded from
scanning. Each JSONL line carries `path` (tree-relative posix, never an
absolute path) followed by the documented entity fields; `--redact mask`
nulls `value`/`start`/`end` there too.

Two honest caveats. First, the gate only vouches for files it parsed - a
broken file exits 1 instead of passing silently; fix it or exclude it with
`--glob` before relying on the gate. Second, fingerprints use the basename
(that is what makes extract and scan baselines compose), so two same-named
files in *different subdirectories* holding the same value share a
fingerprint: accepting `a/config.json`'s finding also accepts the identical
value in `b/config.json`.

### CLI reference

```
docredact extract FILE [--out FILE] [--format json|markdown] [--redact report|mask|strict]
                   [--min-confidence low|medium|high] [--rules FILE]
                   [--write-redacted PATH] [--baseline FILE] [--write-baseline FILE]
                   [--pretty] [--stats] [--timestamp]
docredact scan DIR [--glob PATTERN] [--rules FILE] [--redact report|mask|strict]
               [--baseline FILE] [--write-baseline FILE]
               [--format table|jsonl|sarif] [--out FILE]
```

Exit codes:

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| 0    | success (scan: even when entities were found, unless `--redact strict`; any error-free --write-baseline run) |
| 1    | runtime error (missing file, unsupported/corrupt format, malformed baseline, IO failure) |
| 2    | usage error (argparse default for bad arguments)                     |
| 3    | `--redact strict` found at least one (new, if baselined) finding (extract and scan) |

`--min-confidence` drops findings below the bar *before* masking - raising it
deliberately leaves lower-confidence values in the text. `scan` exits 1 if
the directory is missing or any file failed to parse - that outranks both a
strict pass and `--write-baseline`'s exit 0 - and skips `.docredact.yaml` (it is
configuration, not a document - it still applies as policy) plus the gate's
own `--baseline`/`--write-baseline` files when they sit inside the tree.

### JSON output schema

Top-level keys, in order:

| Key                 | Meaning                                                                 |
|---------------------|-------------------------------------------------------------------------|
| `extractor_version` | docredact version that produced the document                                |
| `generated_at`      | `null` by default (deterministic); UTC ISO-8601 with `--timestamp`      |
| `source`            | basename of the input file only - never a full path                     |
| `sha256`            | SHA-256 of the raw input bytes                                          |
| `size_bytes`        | input size in bytes                                                     |
| `format`            | one of `pdf`, `docx`, `eml`, `json`, `txt`, `md`, `html`, `csv`, `yaml`, `log`, `ini` |
| `blocks`            | ordered `{index, kind, text}`; kinds: `page`, `section`, `paragraph`, `element`, `row`, `header` (eml + docx), `footer`, `footnote`, `endnote` (docx), `field` (json) |
| `entities`          | ordered `{type, value, block, start, end, confidence, severity, fingerprint}`; in `mask` mode `value`/`start`/`end` are null |
| `redaction`         | `{mode, total, by_type, masked}` summary                                |
| `sanitized`         | only with `--write-redacted`: `{path (basename), manifest}`             |
| `warnings`          | extraction warnings (image-only PDF pages, skipped attachments, ...)    |

## Architecture

```
src/docredact/
  __init__.py     version
  __main__.py     python -m docredact
  cli.py          argparse CLI, exit codes, policy/baseline wiring, scan table/jsonl
  core.py         pipeline: bytes -> blocks -> entities -> JSON dict; build_sanitized
  extractors.py   format detection + 10 per-format block extractors (all capped)
  detectors.py    Entity, Confidence, validators (luhn, iban mod-97), 10 detect_*, scan_text
  policy.py       .docredact.yaml: YAML-subset parser, custom detectors, allowlist, disables
  sanitize.py     consistent [TYPE_N] tokenization + value-free manifest
  baseline.py     value-free fingerprints + baseline write/load
  metadata.py     curated per-type severity + CWE reference table
  redact.py       mask_text + shared span-overlap resolution
  report.py       Markdown findings report + --stats renderer
  sarif.py        value-free SARIF 2.1.0 emitter for scan --format sarif
fixtures/         8 synthetic sample documents + their deterministic generator
examples/         committed showcase report, sanitized artifact + tree-scan jsonl/sarif (drift-tested)
tests/            334 pytest tests (unit + subprocess end-to-end + property-based + stress)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the pipeline and the
determinism invariants, and [`docs/MIGRATION.md`](docs/MIGRATION.md) for
upgrading from 0.x and for the Argus -> DocRedact rename.

### Design documents

Written retrospectively against v1.2.0, from the code rather than from this
README:

- [`docs/PRD.md`](docs/PRD.md) - the problem, who it is for, what is
  deliberately out of scope, and the alternatives that were rejected.
- [`docs/TDD.md`](docs/TDD.md) - the schemas, the interface contracts, the
  trust boundaries, the failure modes and the rollback.
- [`docs/APP_FLOW.md`](docs/APP_FLOW.md) - every output state and exit code,
  with real output.
- [`docs/DESIGN_BRIEF.md`](docs/DESIGN_BRIEF.md) - the terminal-output rules,
  and what the tool refuses to do.

## Safety and privacy notes

- Fully offline. DocRedact never opens a socket; everything happens on your
  machine.
- JSON output records the input filename as a basename only, never a full
  path, so directory structures and usernames do not leak into reports.
- All committed fixtures are synthetic: `example.com` addresses, 555-01xx
  reserved phone numbers, the documented AWS example key
  `AKIAIOSFODNN7EXAMPLE`, well-known Luhn test card numbers, TEST-NET IPs,
  and the documented example IBAN.
- `report` and `strict` modes intentionally include detected values in the
  JSON (that is the report). Use `mask` mode - or share the sanitized
  artifact instead - when the output itself must be safe.

### Threat model

DocRedact parses **untrusted documents** (PDF, DOCX, EML, JSON, HTML, CSV,
Markdown, plain text). Its input surfaces and posture:

- **No network, no credentials.** No module under `src/docredact/` imports
  `socket`, `ssl`, `http`, `urllib.request` or `subprocess`, and none reads an
  environment secret. The single import from the URL namespace is
  `urllib.parse.unquote`, used to percent-decode a `mailto:` href out of
  scanned HTML - string manipulation with no transport behind it.
  `tests/test_no_network.py` walks the AST of every source module and fails CI
  if that ever stops being true. (pypdf itself does import `subprocess`, and
  may invoke an external image decoder for JBIG2 images if you have one
  installed - a dependency behaviour, not something DocRedact initiates.)
- **XML external entities (XXE) / entity expansion.** Every scanned DOCX XML
  part (body, headers, footers, footnotes, endnotes) is checked for
  `<!DOCTYPE`/`<!ENTITY` and refused before parsing; the stdlib `xml.etree`
  parser does not resolve external entities. HTML uses `html.parser` (no
  DTD/entity-fetch surface). The policy file uses a YAML-*subset* parser with
  no anchors, aliases, or tags at all.
- **Algorithmic denial of service.** Detector regexes match in linear time
  (the email detector's segment lengths are RFC-bounded); the high-entropy
  overlap filter is near-linear; JSON nesting is depth-capped (200) with a
  RecursionError backstop; deeply nested or huge inputs fail with a clean
  error, never a hang.
- **Decompression / output-amplification bombs.** pypdf's per-stream cap is
  complemented by an aggregate extracted-text cap (~25 M chars) and a page
  ceiling for PDFs; DOCX enforces one aggregate byte budget (~100 MB) across
  *every* scanned XML part - body, headers, footers, footnotes, endnotes -
  so extra parts cannot multiply the ceiling, rejecting first on the
  advertised uncompressed size and then via a bounded read so a lying zip
  header cannot bypass the guard. EML and JSON expansion is proportional to
  input size.
- **Malformed / hostile files** (bad PDFs, non-zip DOCX, oversized CSV
  fields, broken JSON/EML) surface as a clean error (exit 1); in `scan` mode
  one bad file does not abort the batch.

What DocRedact does **not** defend against: peak memory proportional to the input
plus the fixed extraction caps (no streaming mode); DOCX archive members
other than the scanned XML parts (body, headers, footers, foot/endnotes) are
not inspected; the `--out`/`--write-redacted`/baseline paths and
the policy file are trusted CLI-level configuration; detection is heuristic,
not a guarantee (see Limitations).

## Limitations

- Detectors are heuristics. Expect false negatives (unformatted phone
  numbers, hex-only secrets under the entropy threshold) and false positives
  (the high-entropy detector on long identifiers; version-like dotted quads -
  which is why ipv4 findings are medium confidence).
- The person-name heuristic only matches Honorific + two capitalized words
  and misses bare names entirely: low confidence by design. Do not rely on it
  for real PII removal.
- The sanitized artifact is a deterministic plain-text *rendering* built from
  extracted blocks, not a binary round-trip: extraction normalizes
  whitespace, CSV quoting, and HTML markup, and PDF/DOCX cannot be rebuilt
  from text.
- The pem_key detector matches the `-----BEGIN ...-----` header (the key body
  is typically caught separately by the high-entropy detector), so a
  sanitized artifact can retain the bare `-----END ...-----` marker line -
  visible in `examples/sample-safe.txt`. The marker itself carries no key
  material.
- IBAN validation is checksum-only (no per-country length table). YAML files
  are scanned as plain text, not parsed. Among HTML attribute values only
  `mailto:` hrefs are scanned (since 1.2); other attributes (`title`,
  `data-*`, non-mailto URLs) are not. EML attachments are not scanned
  (skipping them warns visibly).
- OCR is out of scope: image-only PDF pages produce an explicit warning.
- Encrypted or malformed PDFs fail with exit code 1 rather than partial
  extraction.

## Roadmap

Shipped in 1.0: sanitized artifacts with consistent tokenization, the
`.docredact.yaml` policy engine, validator-driven confidence, severity + CWE
metadata, the baseline workflow, five new formats, and the Markdown report.
Shipped in 1.1: the tree-level CI gate (scan strict mode + directory-wide
baseline) and the JSONL + SARIF scan output. Shipped in 1.2: DOCX
header/footer/footnote/endnote scanning, HTML `mailto:` targets, and the
Hypothesis property layer. Still on the list:

- OCR for scanned PDFs via an optional local tesseract backend.
- A per-country IBAN length table on top of the mod-97 check.
- ODT extraction; scanning EML attachments (today they warn visibly).

## License

Proprietary - All Rights Reserved - portfolio viewing only. Read it, run it,
check it; no reuse rights are granted. [`LICENSE`](LICENSE) carries the
copyright notice and the complete terms, and by its section 10.4 it supersedes
any other statement of terms - including this summary.
