# DocRedact: technical design

Against v1.2.0, read out of the code. Requirements side: [PRD.md](PRD.md).

## Shape of the thing

One pure function does the work; one thin CLI does everything that touches the
process.

`core.build_document(path, redact, timestamp, min_confidence, policy)` maps
file bytes plus its arguments to the documented JSON dict: detect format,
extract ordered blocks, run every detector over each block's text, filter by
confidence, optionally mask, stamp severity and fingerprint. Nothing in it
reads the clock, the environment, the network or the working directory.

Everything that does - argument parsing, policy discovery, baseline
suppression, file writing, exit codes - lives in `cli.py`. That split is why
the determinism tests are cheap to write and why the library is testable
without subprocesses.

About 2,400 lines across 13 modules. One runtime dependency (pypdf).
Python 3.10+.

```
extractors.detect_format / extract_blocks   ->  list[Block{index, kind, text}] + warnings
detectors.scan_text(text, policy)           ->  list[Entity{type, value, start, end, confidence}]
core.build_document                         ->  document dict (the JSON schema)
   cli --write-redacted -> core.build_sanitized -> sanitize.py  (artifact + manifest)
   cli --baseline       -> baseline.py                           (suppress known)
   report.py / sarif.py / cli._render_scan_table                 (rendering)
```

## Hostile input

There is no authentication, no authorisation, no RLS and no `anon` role - one
local process, run by someone who already has read access to the files. What
does exist is a hard split between untrusted and trusted input, and it is
worth writing down because the two are only one argument apart on the same
command line.

**Untrusted: the document bytes.** Every extractor treats them as
attacker-controlled.

| Surface | Control |
| --- | --- |
| PDF | Aggregate extracted-text cap (~25M chars) and a 50,000-page ceiling on top of pypdf's per-stream cap, because one shared stream can be re-emitted across many pages. |
| DOCX | One aggregate ~100MB budget across *every* scanned XML part, so extra header parts cannot multiply the ceiling; rejected first on the advertised size, then on a bounded `budget + 1` read so a lying zip header cannot bypass it; `<!DOCTYPE`/`<!ENTITY` refused per part (XXE). |
| JSON | 200-level depth cap plus a `RecursionError` backstop, plus a 25M-char cap on flattened output (each leaf re-embeds its key path, so width amplifies quadratically). |
| HTML / policy file | `html.parser` and a YAML subset - neither has a DTD or entity-fetch surface. |
| Detector regexes | Bounded segments, RFC-derived (the unbounded email pattern backtracked quadratically on `x@a.a.a...`); the high-entropy overlap filter is a merged-interval binary search rather than a nested scan. |
| pypdf's own logging | Muzzled with a `NullHandler` and `propagate = False`. Without it, Python's handler of last resort printed pypdf's recovery messages - sometimes quoting raw bytes from the input file - straight to stderr, past the tool's own generic error line. A tool whose premise is "never leak" must not echo the document it was asked to scan. |

**Trusted: the CLI arguments and the policy file.** `--out`,
`--write-redacted` and the baseline paths are written without confirmation and
will overwrite - except that an output which is an input (the document, any
document in a scanned tree, the policy file, the baseline being read) or
another output is refused with exit 1 before anything is written, and
`--write-baseline` only replaces a file that already is a baseline. Policy regexes run against every block; they are length-capped
at 500 characters but not sandboxed. This is documented in `policy.py` and in
the README's threat model, and it is the boundary a future change is most
likely to blur - by fetching a policy from a URL, say.

## The three files that are a contract

There is no database. The persisted schemas are three files, and all three are
part of the compatibility promise.

### The extraction document (stdout, or `extract --out`)

| Key | Type | Notes |
| --- | --- | --- |
| `extractor_version` | str | `docredact.__version__`. Embedded in SARIF too, so SARIF changes on every version bump. |
| `generated_at` | str \| **null** | **Null by default.** Only set with `--timestamp`. Nulling the clock is what makes byte-identical output possible. |
| `source` | str | Basename only, never a path - no directory layout or username can leak into a report. |
| `sha256`, `size_bytes` | str, int | Of the raw input bytes. |
| `format` | str | One of 11 names from `extractors.FORMATS`. |
| `blocks` | list | `{index, kind, text}`. Kinds: `page`, `section`, `paragraph`, `element`, `row`, `field`, `header`, `footer`, `footnote`, `endnote`, and the hidden kinds `annotation`, `revision`, `comment`, `deletion`, `alt_text`, `metadata`, `link` - scanned and reported, never rendered into the sanitized artifact (`sanitize.HIDDEN_KINDS`). |
| `entities` | list | `{type, value, block, start, end, confidence, severity, fingerprint}`. **In `mask` mode `value`, `start` and `end` are null** - the one place a consumer must handle nulls. |
| `redaction` | dict | `{mode, total, by_type, masked}`. |
| `sanitized` | dict, **optional** | Present only with `--write-redacted`. A consumer must treat it as absent by default. |
| `warnings` | list[str] | Empty extractions, and content present but not read - each of those starts `not scanned: ` (image-only pages, embedded files, attachments, undecodable text) and fails `--redact strict` with exit 1. |

The case that actually reaches a consumer is a field that is absent or null on
output predating a change:

- `confidence`, `severity`, `fingerprint` and `sanitized` did not exist before
  1.0. Anything parsing older output must tolerate their absence.
- `generated_at` is null on nearly every run by design, not by accident.
- Block kinds `header`/`footer`/`footnote`/`endnote` did not exist before 1.2.
  They are appended *after* the body blocks precisely so that existing body
  block indexes did not shift.
- The hidden kinds and PDF form-field `field` blocks are newer still, and
  follow the same rule: DOCX comments come after the endnotes, then tracked
  deletions, metadata, links and alt text; PDF annotations and links, form
  fields, metadata and earlier-revision text come after the last page, so a
  page block's index is still its page number. DOCX content controls are the
  exception: they are visible body text, read in place, so body indexes after
  one move (fingerprints never held a block index).

### The baseline file (`--write-baseline`)

`{"version": 1, "fingerprints": [...]}`, sorted and de-duplicated for clean
diffs. A fingerprint is `sha256("<type>|<source>|<value>")[:16]`. Position is
deliberately excluded, so edits do not invalidate acceptance; `source` is
deliberately included, because the same secret in a second file is a new leak
rather than an accepted one. Loading fails **closed**: a missing, unreadable,
wrong-version or structurally invalid file raises `BaselineError` and exits 1
rather than silently suppressing nothing.

### The policy file (`.docredact.yaml` or `--rules FILE`)

`detectors:` (name, regex, optional confidence, optional `luhn`/`iban_mod97`
validator), `allowlist:` (`values`, `patterns`), `disable:` (built-in names).
Parsed by a YAML-*subset* parser in `policy.py`, not a YAML library. Every
malformed element degrades to a `warning:` on stderr while the rest of the
policy still applies - the file can never fail in the direction of hiding a
finding.

## API surface

```python
# core.py
build_document(path: Path, redact: str = "report", timestamp: bool = False,
               min_confidence: Confidence = Confidence.LOW,
               policy: Policy | None = None) -> dict[str, object]
build_sanitized(path: Path, min_confidence=Confidence.LOW,
                policy: Policy | None = None) -> tuple[str, list[dict[str, object]]]

# extractors.py
detect_format(path: Path) -> str                     # raises UnsupportedFormatError
extract_blocks(data: bytes, fmt: str) -> tuple[list[Block], list[str]]

# detectors.py
scan_text(text: str, policy: Policy | None = None) -> list[Entity]
luhn_valid(number: str) -> bool ; iban_mod97_valid(iban: str) -> bool

# policy.py
discover_policy(target: Path, explicit: Path | None) -> Path | None
load_policy(path: Path) -> tuple[Policy, list[str]]  # never raises; warnings out

# baseline.py
fingerprint(type_: str, source: str, value: str) -> str
write_baseline(path: Path, fingerprints: list[str]) -> None
load_baseline(path: Path) -> frozenset[str]          # raises BaselineError

# redact.py / sanitize.py - one shared span resolver, so masking and
# tokenization replace exactly the same ranges
select_replacements(entities) -> list[tuple[Entity, int, int]]
mask_text(text, entities) -> str
sanitize_blocks(blocks, entities_by_block) -> tuple[list[str], list[dict]]

# cli.py
main(argv: list[str] | None = None) -> int           # the process exit code
```

Five contracts the tests hold to, each of which a change could quietly break:

- `build_document` is a pure function of the file bytes and its arguments.
- A validator may only **raise or lower confidence**, never remove a finding.
  A checksum-failing IBAN is still reported, at low confidence.
- An allowlist may only **remove**. A user detector may only **add**, under its
  own type name; built-in names are refused with a warning.
- `select_replacements` covers the **union** of an overlapping cluster, not
  just the winning span, so no byte of any detected value survives.
- `--min-confidence` filters **before** masking, so raising the bar in mask
  mode deliberately leaves lower-confidence values in the text.

## Version compatibility (the migration analogue)

| # | Change | Reversible? | Rollback |
| --- | --- | --- | --- |
| 1.0 | Added `confidence`, `severity`, `fingerprint`, optional `sanitized` | Yes, additive | Ignore the new keys |
| 1.1 | Added `scan` strict gate, tree baseline, JSONL + SARIF | Yes, additive | Keep using the table |
| 1.2 | Appended `header`/`footer`/`footnote`/`endnote` blocks **after** body blocks | Yes - body indexes unchanged, fingerprints never held a block index | Pre-1.2 baselines keep working untouched |
| rename | `.argus.yaml` -> `.docredact.yaml`; SARIF `argusFingerprint/v1` -> `docredactFingerprint/v1`; console script and package | Yes | `git revert`, reinstall, rename the policy file back |

One asymmetry: the rename is the first change that is **not** additive. An
un-renamed `.argus.yaml` is not discovered, and the only signal is the
*absence* of the `policy: applying <path>` line on stderr. That is a
fail-quiet path in a tool that otherwise fails loud, which is why the CHANGELOG
entry and the MIGRATION note both call it out.

## What breaks, and who finds out

| What breaks | Who notices | How we detect it | How we undo it |
| --- | --- | --- | --- |
| **A detector misses a value (false negative)** | Nobody - until the shared artifact leaks | Only the fixture plants and the Hypothesis properties, at build time. **There is no runtime detection, by nature.** | Nothing. The artifact is already sent. This single failure mode is why the README refuses the word "DLP". |
| A file in the tree fails to parse | CI, immediately | `scan` exits 1, which outranks both a strict pass and a fresh `--write-baseline` | Fix the file or exclude it with `--glob`; never suppress it |
| Baseline file malformed or unreadable | CI, immediately | `BaselineError`, exit 1 - fails closed rather than suppressing nothing | Restore the file from version control |
| An un-renamed `.argus.yaml` after the rename | The user, only if they read stderr | Absence of `policy: applying <path>` | Rename the file to `.docredact.yaml` |
| Hostile document (bomb, XXE, ReDoS) | The user | Clean `ExtractionError`, exit 1, never a hang or a traceback | N/A - nothing was written |
| A guessable value brute-forced out of a shared baseline file | Nobody | **No detection exists.** Unsalted hashes are the price of cross-machine reproducibility | Rotate the value; treat baselines as sensitive |
| `extract --out` writes CRLF on Windows while `scan --out` and `--write-redacted` force LF | Anyone diffing output across platforms | git's `eol=lf` normalisation warning on commit | Open defect, not yet fixed; see the PRD's loose ends |

## Undoing it

Nothing to roll back in the usual sense. The tool holds no state of its own,
opens no connections, and touches nothing outside the paths named on the
command line. Reverting is `git revert` plus `pip install -e ".[dev]"` to
regenerate the console script - under a minute.

The two irreversible acts it can perform are the user's to control. It
overwrites output paths without asking: `--out`, `--write-redacted` and
`--write-baseline` all clobber, so point them at fresh paths. The one thing
it refuses to clobber is an input, or one output with another. And a written
artifact cannot be recalled - as the PRD puts it, the output *is* the access
control.

For the rename specifically: revert the commit, reinstall, and rename
`.docredact.yaml` back to `.argus.yaml`. Baseline files need no action either
way, because the fingerprint never contained the tool name.

## The tests that would fail

422 of them. Grouped by what they would catch:

- **Positive** - `test_detectors.py` asserts every detector's true positives;
  `test_extractors.py` asserts each of the 11 formats produces the expected
  block kinds; `test_examples.py` asserts the committed showcase artifacts
  equal a fresh render byte-for-byte, which is the drift guard.
- **Negative** - the same detector file asserts non-matches, including the
  fixture `task-abcdefghijklmnopqrstuvwx`, which exists specifically to catch
  a loosening of the `sk-` API-key pattern. `test_examples.py` asserts the
  committed artifact and SARIF contain **none** of the six fixture secrets.
- **Boundary** - `test_extractors_new.py` covers decompression caps, DTD
  refusal, oversized CSV fields and JSON depth. `test_scan_gate.py` covers the
  exit-code precedence (parse error beats strict pass beats fresh baseline)
  and the state-file exclusion. `test_properties.py` runs 11 Hypothesis
  properties on a derandomized profile: scan / mask / sanitize / render /
  policy-load never crash on arbitrary text, planted secrets are always found
  and never survive replacement, and span-union coverage matches an
  independent oracle.
- **Determinism** - `test_determinism.py` (every fixture byte-identical across
  runs) and `test_stress.py` (a 120-file corpus hashing identically across
  passes).

CI runs a bare `pytest -q` with the working directory *not* on `sys.path`, so
tests import helpers as `from conftest import ...`. Verify locally with
`.venv/Scripts/python.exe -m pytest` before claiming green.

## How it actually got built

0.x was extractors for PDF/DOCX/txt/md/html/csv, regex detectors and the JSON
schema - enough to see whether the idea held up.

1.0 was the three crown jewels: sanitized artifacts with consistent
tokenization, the policy engine, and validator-driven confidence plus the
baseline. Five more formats, severity/CWE metadata and the Markdown report
came with it.

1.1 took the same gate to tree scale - `scan --redact strict`, a tree-wide
baseline, JSONL and SARIF.

1.2 closed the two documented blind spots (DOCX headers, footers and notes;
HTML `mailto:` targets) and added the Hypothesis property layer.

After 1.2, adversarial review turned up two detector corrections, both in the
false-negative direction: IBANs printed in groups of four, and cards printed
next to an expiry or reference number.
