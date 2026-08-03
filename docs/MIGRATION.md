# DocRedact migration notes

## Argus -> DocRedact (the rename)

The project was called **Argus** through 1.2.0. Nothing about the pipeline,
the detectors, the exit codes, or the JSON schema changed with the rename, but
every identifier carrying the old name did. Three things to change on upgrade:

1. Reinstall so the console script is regenerated: `pip install -e ".[dev]"`.
   The command is now `docredact` (or `python -m docredact`); `argus` is gone.
2. Rename any policy file: `.argus.yaml` -> `.docredact.yaml`. Discovery looks
   for the new name only, so an un-renamed file is silently *not* applied -
   check for the `policy: applying <path>` line on stderr after upgrading.
3. Update the command name in scripts, pre-commit hooks and CI steps, and the
   mypy path if you vendored it (`src/argus` -> `src/docredact`).

Two things you do **not** need to change. Baseline files still work untouched:
a fingerprint is `sha256("<type>|<source>|<value>")[:16]` and never contained
the tool name. Existing JSON consumers still work: no key changed. The one
consumer that will notice is a CI service keyed on the SARIF
`partialFingerprints` name, which went from `argusFingerprint/v1` to
`docredactFingerprint/v1` - it will treat every result as new once.

The rest of this document covers version upgrades. Those sections were written
under the old name and have been updated to the new one, so the commands in
them are the ones to run today.

## 1.0 -> 1.1

Nothing to do. 1.1 only adds to `scan` (the strict gate, the tree-wide
baseline, `--format jsonl|sarif`, `--out`); the table stays the default
output and every existing command, flag, exit code, and JSON key is
unchanged. The rest of this document covers the 0.x -> 1.0 upgrade.

## 0.x -> 1.0

DocRedact 1.0 is a large capability release designed to drop in over a 0.x setup
with no changes to your commands.

## TL;DR

- **CLI is backward compatible.** Every 0.x flag, subcommand, and exit code
  behaves the same. All new flags are additive.
- **JSON is additive.** Entities gained `confidence`, `severity`, and
  `fingerprint`; the document can gain a `sanitized` key (only with
  `--write-redacted`). No existing key changed meaning; consumers that read
  by key keep working.
- **Determinism is unchanged**: same input, same command, same bytes.

## New capabilities (opt-in)

| Capability | How to use |
| --- | --- |
| Sanitized shareable copy | `extract FILE --write-redacted safe.txt` |
| Custom rules / allowlist / disables | `.docredact.yaml` beside the input, or `--rules FILE` |
| Confidence filtering | `--min-confidence {low,medium,high}` |
| Fail only on new findings | `--write-baseline` once, then `--baseline` in CI |
| Markdown findings report | `--format markdown` |
| Per-document summary on stderr | `--stats` |

## New formats

`.eml`, `.json`, `.yaml`/`.yml`, `.log`, and `.ini` are now supported. Two
behaviour notes if you run `scan` over directories that contain such files:

- Files with these extensions that were previously **skipped** are now
  extracted and scanned, so `scan` totals can grow after upgrading.
- `.docredact.yaml` itself is excluded from scan discovery (it is configuration);
  it is instead auto-applied as the policy, announced on stderr.

## Semantics worth knowing

- `--min-confidence` filters findings **before** masking: raising the bar in
  mask mode deliberately leaves lower-confidence values in the text.
- A checksum-failing IBAN is still reported (at low confidence). Validators
  and allowlists never hide findings silently; only an explicit allowlist
  entry or baseline suppresses, and both are visible (warnings/stderr count).
- Baseline fingerprints include the source basename: renaming a file makes
  its accepted findings "new" once. Refresh with
  `--baseline FILE --write-baseline FILE` after renames.
- The sanitized artifact is a plain-text rendering built from extracted
  blocks, not a binary round-trip (PDF/DOCX cannot be rebuilt from text).

## Upgrade checklist

1. Reinstall: `pip install -e ".[dev]"` (runtime dependency is still just
   pypdf).
2. Run your existing command unchanged; confirm the exit code is what you
   expect.
3. If `scan` now reports more files/entities, that is the new formats -
   review, then adopt a baseline or a policy allowlist as appropriate.
4. Optionally adopt the new capabilities from the table above.
