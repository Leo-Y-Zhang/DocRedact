# Design Brief - DocRedact's terminal output

Companion to [PRD.md](PRD.md) and [APP_FLOW.md](APP_FLOW.md).

The only surface this project has is text in a terminal and text in a file.
That is still a designed surface - it has a layout, a hierarchy, a channel
model and a set of things it refuses to do. The refusals come first here,
because they are the part a well-meaning future change would break first.

## What it refuses to do

Written to be specific enough to enforce in review.

- **No ANSI escapes, ever** - not even "only when `isatty()`". A conditional
  TTY branch means the output is no longer one artifact, and the determinism
  tests only ever see the non-TTY branch.
- **No progress indication.** It reads the clock, and it writes to the same
  stream as the results.
- **No colour-coded severity.** `critical` is a word. It survives a pipe, a
  screen reader, and a monochrome log viewer.
- **Nothing on stdout that is not the result.** Notices, warnings and errors go
  to stderr without exception, so `--format jsonl | jq` never breaks.
- **No truncation with an ellipsis.** Column widths are computed from the
  content. A truncated fingerprint or filename is a wrong answer, not a tidy
  one.
- **No detected value in any surface that is safe by default.** SARIF, the
  sanitized manifest and baseline files carry types, counts and hashes only.
  Adding a value to any of them for "better context" is a defect, not a
  feature.

## What it should feel like

Boring, aligned, and byte-stable. A run should look identical whether it is
read by a person, a pipe, or a CI log viewer six months later.

What it must never feel like is a dashboard. No colour, no boxes, no spinner,
no emoji, no "scanning 4/8..." counter. Every one of those either reads the
clock, writes escape codes, or invites the reader to skim a severity by hue -
and this is a tool whose entire value is that its output can be trusted
literally.

## The reader who matters

Two readers, and the design serves the second one first.

1. A person about to send a document, running one command and reading a
   findings table once.
2. **A CI log, and the person reading that log after it failed.** They did not
   run the command, cannot re-run it interactively, and have only the captured
   bytes. Anything that renders differently outside a TTY has failed them.

## Borrowed from

`git status`, for carrying structure with alignment and grouping instead of
colour, and for producing the same output whether or not it is a TTY.

`gitleaks`, for treating the exit-code contract as the primary interface and
the human text as a secondary courtesy. DocRedact's four exit codes are the
load-bearing part of its UI.

SARIF as a format, for making severity an enumerated field rather than a
visual treatment. Copied directly: severity is a word in a column, never a
colour.

## The scan table

Built in `cli._render_scan_table`.

Four columns - `FILE`, `FORMAT`, `BLOCKS`, `ENTITIES` - each padded to the
widest cell **including the header**, joined by exactly two spaces, and
right-stripped so no line carries trailing whitespace into a diff. A file that
failed to parse keeps its row and shows `-  -  ERROR`; it is never dropped,
because a missing row would read as a clean file.

Two summary lines follow, in fixed order: a total with a per-type breakdown
sorted alphabetically, then a severity roll-up in fixed `critical, high,
medium, low` order - never in count order, which would make two runs look
different for the same data.

`--stats` (stderr) uses a two-space indent under a bare `STATS` heading, with
sections in fixed order and keys sorted within each section. The Markdown
report uses one `#` heading, a short metadata list, then one table per section;
a document with no findings gets the sentence `No findings.` rather than an
empty table.

## Hierarchy without escape codes

One monospace family - the reader's. Hierarchy comes from three things only:
column alignment, fixed section order, and a bare uppercase word as a heading
(`STATS`, `FILE`). No underlining, no bold, no box drawing; all three are
escape sequences or non-ASCII characters that a log viewer may mangle.

## File artifacts

| Artifact | Formatting | Why |
| --- | --- | --- |
| JSON (`extract`) | Compact by default, `--pretty` for `indent=2` | Compact is the pipeable default; pretty is opt-in |
| JSONL (`scan`) | One compact object per line | Line-oriented so `jq`, `grep` and `head` all work |
| SARIF | `indent=2`, trailing newline | Read by humans in diffs as often as by tools |
| Baseline | `indent=2`, sorted, de-duplicated | It lives in version control; the diff is the interface |
| Sanitized artifact | UTF-8, **LF**, trailing newline | Cross-platform stability |

**Known inconsistency:** `extract --out` writes platform-native line endings
while `scan --out` and `--write-redacted` force LF. On Windows that makes one
of the five artifacts CRLF. It is a defect, recorded in the TDD's failure-mode
table, not a design choice.

## Done means

- [ ] No ANSI escape byte is emitted on any path
- [ ] stdout carries only results; every notice, warning and error is on stderr
- [ ] Severity and confidence are readable as words with colour removed
- [ ] Two runs over the same input produce identical bytes
- [ ] Every file artifact ends with exactly one newline, and none carries
      trailing whitespace
- [ ] The empty case says something, and the error case names the file
