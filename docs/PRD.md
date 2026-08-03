# DocRedact: product requirements

Written against v1.2.0, from the shipped code.
Companions: [TDD](TDD.md) · [App Flow](APP_FLOW.md) · [Design Brief](DESIGN_BRIEF.md)

## The document you stopped reading

The dangerous data in a document is the data you have stopped looking at. A
DOCX carries a name in a footer you never scroll to; an HTML page hides a
personal mailbox behind "Contact support" in a `mailto:` href; a config dump
buries an AWS key ten levels down a JSON tree. When you hand that document to
someone - an invoice to an accountant, a log bundle into a bug report, a
directory of notes into a repository - you are betting on having remembered
all of it.

The two existing answers both fail this case. Cloud DLP services want you to
upload the document you are specifically trying not to leak. Offline secret
scanners (gitleaks, trufflehog and friends) read source trees, not PDF, DOCX
or EML, and they *report* - they hand you a list, not a document you can
safely send.

## The asymmetry everything else follows from

There is one bad outcome here, and it is not the noisy one.

A false positive is a nuisance: an over-redacted reference number, a
`[TOKEN_3]` where a harmless string used to be. A false negative is the whole
failure. A user is told the artifact is clean, shares it, and a live card
number goes with it.

So every rule in the tool bends in one direction. Validators may only *raise*
confidence, never hide a finding - a checksum-failing IBAN is still reported,
just quietly. Allowlists have to be written out by hand. A card match covers
the union of every Luhn-valid window rather than picking the best one, because
over-redacting a neighbouring reference number is cosmetic and leaking one
digit of a PAN is not. A document that cannot be parsed exits 1 and outranks
every "pass" result, because a gate that did not read the file did not check
it.

Read the rest of this document as consequences of that paragraph.

## Requirements

**Must**

- Extract PDF, DOCX, EML, JSON and seven text formats into indexed blocks.
- Detect the secret and PII classes that actually appear in shared documents,
  each carrying a confidence and a severity.
- Emit a sanitized copy with consistent per-value tokens plus a value-free
  manifest.
- Be deterministic and fully offline.
- Fail closed on anything it could not read.

**Should**

- A declarative policy file for custom detectors, an allowlist and disables.
- Machine output for CI (JSONL, SARIF 2.1.0) that is safe to upload.
- A baseline, so adoption on a legacy tree is not a wall of findings.

Four capabilities are deliberately absent from this version. There is no OCR
for image-only PDF pages; they produce an explicit warning instead. The
redacted artifact is a text rendering, not a PDF that is still a PDF. No
detection is model-based, so no NER for names or entities. And nothing reaches
inside EML attachments, or inside HTML attributes other than `mailto:` hrefs.

## How you would know it works

Each of these is a claim with a test behind it, so the list can be falsified
by running something rather than by taking its word.

- [x] A document goes in and a text artifact comes out that contains none of
      the detected values but still reads as the same document - the same
      account appearing in two paragraphs is visibly the same account
      (`[IBAN_1]` both times). Enforced by `tests/test_sanitize.py` and
      `tests/test_examples.py::test_committed_artifact_contains_no_fixture_secrets`.
- [x] Same input plus same flags produces byte-identical output on every run.
      Enforced by `tests/test_determinism.py` and a 120-file corpus in
      `tests/test_stress.py`.
- [x] Zero network activity: nothing in `src/docredact/` imports `socket`,
      `ssl`, `http`, `urllib.request`, `subprocess`, or any HTTP client, so no
      code path can open a connection or start a process. The one import from
      the URL namespace is `urllib.parse.unquote` in `extractors.py`, used to
      percent-decode a `mailto:` href out of scanned HTML so an address cannot
      hide from the email detector as `jane%40example.com`; `urllib.parse` is
      pure string manipulation and pulls in no transport. The only runtime
      dependency is pypdf, which does import `subprocess` (`pypdf.filters`,
      for an optional external JBIG2 image decoder) - a dependency behaviour
      DocRedact never initiates, recorded here rather than papered over.
      Enforced by `tests/test_no_network.py`, which walks the AST of every
      module under `src/docredact/` on every CI run.
- [x] A team can point it at an existing messy tree and have CI fail only on
      *new* findings from day one (`--write-baseline` once, `--baseline`
      thereafter).
- [x] Nothing is ever suppressed silently. Every allowlist hit, disabled
      detector, malformed policy line, and baseline suppression is announced
      on stderr or as a `warning:` line.

## Who it is for, and where the line is

The author, before sharing anything extracted out of their own projects, and
anyone with the same three constraints: the file must not leave the machine,
the formats are office documents rather than source code, and what is wanted
back is a **shareable artifact** rather than a findings list.

It is explicitly not for a compliance function. The detectors are heuristics.
The README says so, and that honesty is a requirement of the project rather
than a disclaimer bolted onto it. In the same spirit, five things sit outside
the boundary permanently:

- **Being a DLP control.** No coverage guarantee is offered or implied. A
  clean run means "no detector matched", not "this document is safe".
- **Binary round-trip redaction.** Removing text from a PDF content stream
  without leaving it recoverable is a different and much harder project. A
  plain-text rendering is at least honest about what it is.
- **Network anything** - no upload, no update check, no telemetry, no optional
  cloud detector. This is the property that makes the tool usable at all for
  its purpose, so it is a constraint rather than a preference.
- **A server, accounts, or multi-user anything.** One process, run by the
  person who already has the file open.
- **Sandboxing the policy file.** Policy regexes are trusted local
  configuration, exactly like CLI arguments. They are length-capped at 500
  characters, but they do run against every block.

## Privacy, and the thing that cannot be revoked

*What personal data does this touch?* Whatever the user points it at -
potentially the most sensitive documents they own. It reads them, never moves
them, and writes only to paths the user names.

*Who can see it?* Only whoever can read the output. Two of the three outputs
are deliberately unsafe by default: `--redact report` and `--redact strict`
put detected values into the JSON, because that JSON *is* the report. The safe
surfaces are `--redact mask`, the `--write-redacted` artifact, and SARIF -
value-free by construction, so it can be uploaded to a CI annotation service
even when the scan itself ran in report mode.

*What happens when someone's access is revoked?* Nothing, and that is the
honest answer. There is no identity, no session and no server, so there is
nothing to revoke. The consequence is that **the output is the access
control**: once an artifact is written it is outside the tool's reach forever.
The design response is that the default artifact is the safe one, and the
unsafe modes have to be asked for by name.

One caveat deserves its own paragraph. Baseline fingerprints are
`sha256("type|source|value")[:16]` and unsalted, because they have to
reproduce across machines. A *guessable* value's presence can therefore be
confirmed by brute force against a baseline file. Baseline files deserve the
same care as the documents they came from.

## Roads not taken

| Considered | Why it was dropped |
| --- | --- |
| A YAML library for the policy file | A dependency plus YAML's anchor/alias/tag/multi-document parsing surface, on a file whose whole job is to be trusted config. Replaced by a ~90-line documented YAML *subset* parser: maps, lists, comments, literal quoted strings, line-numbered errors. |
| Location-based baselines (file + line, as most scanners do) | Positions churn on every edit, so the baseline invalidates itself. Value-hash fingerprints survive ordinary edits; the price is the unsalted-hash caveat above, which is documented rather than hidden. |
| Deleting findings from the artifact instead of tokenizing | Deletion destroys cross-references - a reader cannot tell that two paragraphs name the same account. Consistent `[TYPE_N]` tokens keep the structure and leak nothing. |
| Requiring the whole regex match to pass Luhn | Measured to return **zero** findings for the commonest real layout, `4111 1111 1111 1111 05/28`, sending a full PAN into the "safe" artifact with `--redact strict` exiting 0. Replaced by group-boundary candidate windows. |
| ML/NER for person names | A model dependency, non-deterministic output, and offline weights measured in hundreds of MB - all three break a stated constraint. Kept a deliberately weak honorific heuristic at low confidence, documented as unreliable. |
| Colour and progress output in the terminal | Breaks CI logs and pipes, and a spinner is a clock. See the [Design Brief](DESIGN_BRIEF.md). |

## Loose ends

None of these block anything that shipped. They are the honest edges.

`--min-confidence` exists on `extract` but not on `scan`, so a tree scan
cannot raise the bar the way a single extraction can. Deliberate omission or
oversight? It reads like an oversight.

`extract --out` writes platform-native line endings while `scan --out` and
`--write-redacted` force LF. Determinism holds per platform but not across
them; see the failure-mode table in the TDD.

The high-entropy detector cannot see hex-only secrets - four bits per
character at most, under the 4.0 threshold. Lowering the threshold trades that
for a flood of false positives on ordinary identifiers. Unresolved, and
recorded in the README's Limitations.
