"""Command-line interface: ``docredact extract`` and ``docredact scan``.

Exit codes:
    0  success (scan: even when entities were found, unless --redact strict)
    1  runtime error (missing file, unsupported/corrupt format, IO failure)
    2  usage error (argparse default for bad arguments)
    3  --redact strict found at least one (new, if baselined) finding
       (extract and scan; scan parse errors outrank this and stay exit 1)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .baseline import load_baseline, write_baseline
from .core import REDACT_MODES, build_document, build_sanitized
from .detectors import Confidence
from .extractors import FORMATS, DocRedactError
from .metadata import SEVERITY_ORDER
from .policy import Policy, discover_policy, load_policy
from .report import render_markdown, render_stats
from .sarif import render_sarif

_CONFIDENCE_NAMES = [c.value for c in (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)]


def _resolve_policy(target: Path, rules: str | None) -> Policy | None:
    """Load the applicable policy (--rules or a .docredact.yaml beside the target).

    The applied path and every load warning are printed to stderr, so a policy
    can never quietly change what gets reported.
    """
    policy_path = discover_policy(target, Path(rules) if rules else None)
    if policy_path is None:
        return None
    print(f"policy: applying {policy_path.as_posix()}", file=sys.stderr)
    policy, warnings = load_policy(policy_path)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    return policy

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_STRICT = 3


def main(argv: list[str] | None = None) -> int:
    """Console entry point; returns the process exit code."""
    args = _build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (DocRedactError, OSError) as exc:
        print(f"docredact: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docredact",
        description="Local-first document extraction and redaction (fully offline).",
    )
    parser.add_argument(
        "--version", action="version", version=f"docredact {__version__}"
    )
    sub = parser.add_subparsers(required=True, metavar="COMMAND")

    extract = sub.add_parser(
        "extract", help="extract one document to JSON with entity detection"
    )
    extract.add_argument("file", help="input document (pdf/docx/txt/md/html/csv)")
    extract.add_argument("--out", metavar="FILE", help="write JSON here instead of stdout")
    extract.add_argument(
        "--redact",
        choices=REDACT_MODES,
        default="report",
        help="report: list findings; mask: replace them in text; "
        "strict: exit 3 if any finding (default: report)",
    )
    extract.add_argument(
        "--min-confidence",
        choices=_CONFIDENCE_NAMES,
        default="low",
        help="drop findings below this confidence before reporting/masking "
        "(mask mode then leaves lower-confidence values in the text; default: low)",
    )
    extract.add_argument(
        "--rules",
        metavar="FILE",
        help="policy file with custom detectors/allowlist/disables "
        "(default: a .docredact.yaml beside the input, if present)",
    )
    extract.add_argument(
        "--write-redacted",
        metavar="PATH",
        help="also write a sanitized plain-text copy of the document, with every "
        "finding replaced by a consistent [TYPE_N] token (same value -> same token); "
        "the JSON gains a value-free 'sanitized' manifest",
    )
    extract.add_argument(
        "--baseline",
        metavar="FILE",
        help="suppress findings recorded in baseline FILE and report only new ones; "
        "strict mode then exits 3 only on NEW findings",
    )
    extract.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="record the current findings' value-free fingerprints to FILE for later "
        "--baseline runs and exit 0 (also in strict mode)",
    )
    extract.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="output format (markdown renders a shareable findings report; default: json)",
    )
    extract.add_argument("--pretty", action="store_true", help="indent the JSON output")
    extract.add_argument(
        "--stats",
        action="store_true",
        help="print a deterministic summary (by type/severity/confidence) to stderr",
    )
    extract.add_argument(
        "--timestamp",
        action="store_true",
        help="set generated_at to the current UTC time (default: null, deterministic)",
    )
    extract.set_defaults(func=_cmd_extract)

    scan = sub.add_parser(
        "scan", help="scan a directory of documents and print a summary table"
    )
    scan.add_argument("dir", help="directory to scan")
    scan.add_argument(
        "--glob",
        default="**/*",
        metavar="PATTERN",
        help="glob under DIR; unsupported extensions are skipped (default: **/*)",
    )
    scan.add_argument(
        "--rules",
        metavar="FILE",
        help="policy file with custom detectors/allowlist/disables "
        "(default: a .docredact.yaml inside DIR, if present)",
    )
    scan.add_argument(
        "--redact",
        choices=REDACT_MODES,
        default="report",
        help="report: include finding values in machine output; mask: null them; "
        "strict: exit 3 if any (new, if baselined) finding (default: report)",
    )
    scan.add_argument(
        "--baseline",
        metavar="FILE",
        help="suppress findings recorded in baseline FILE across the whole tree and "
        "report only new ones; strict mode then exits 3 only on NEW findings",
    )
    scan.add_argument(
        "--write-baseline",
        metavar="FILE",
        help="record every current finding's value-free fingerprint to FILE for later "
        "--baseline runs and exit 0, also in strict mode (parse errors still exit 1)",
    )
    scan.add_argument(
        "--format",
        choices=("table", "jsonl", "sarif"),
        default="table",
        help="output format: table (human summary), jsonl (one finding per line), "
        "sarif (value-free SARIF 2.1.0 for CI annotation) (default: table)",
    )
    scan.add_argument(
        "--out",
        metavar="FILE",
        help="write the rendered output here instead of stdout (LF line endings)",
    )
    scan.set_defaults(func=_cmd_scan)
    return parser


def _cmd_extract(args: argparse.Namespace) -> int:
    target = Path(args.file)
    policy = _resolve_policy(target, args.rules)
    min_confidence = Confidence(args.min_confidence)
    document = build_document(target, args.redact, args.timestamp, min_confidence, policy)
    if args.write_redacted:
        artifact, manifest = build_sanitized(target, min_confidence, policy)
        out_path = Path(args.write_redacted)
        out_path.write_text(artifact, encoding="utf-8", newline="\n")
        # Basename only, mirroring "source" -- the JSON never embeds local paths.
        document["sanitized"] = {"path": out_path.name, "manifest": manifest}

    entities = document["entities"]
    assert isinstance(entities, list)
    if args.write_baseline:
        # Recorded before suppression, so --baseline + --write-baseline refreshes the
        # file with every currently reported finding (fixed ones drop out).
        write_baseline(Path(args.write_baseline), [e["fingerprint"] for e in entities])
    if args.baseline:
        known = load_baseline(Path(args.baseline))
        new = [e for e in entities if e["fingerprint"] not in known]
        suppressed = len(entities) - len(new)
        print(f"baseline: {suppressed} finding(s) suppressed, {len(new)} new", file=sys.stderr)
        document["entities"] = new
        redaction = document["redaction"]
        assert isinstance(redaction, dict)
        redaction["total"] = len(new)
        by_type: dict[str, int] = {}
        for e in new:
            by_type[e["type"]] = by_type.get(e["type"], 0) + 1
        redaction["by_type"] = dict(sorted(by_type.items()))

    if args.format == "markdown":
        payload = render_markdown(document).rstrip("\n")
    else:
        payload = json.dumps(document, indent=2 if args.pretty else None)
    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    if args.stats:
        print(render_stats(document), end="", file=sys.stderr)
    if args.write_baseline:
        return EXIT_OK  # everything just recorded is accepted by definition
    redaction = document["redaction"]
    assert isinstance(redaction, dict)
    if args.redact == "strict" and redaction["total"]:
        return EXIT_STRICT
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.dir)
    if not root.is_dir():
        print(f"docredact: error: not a directory: {args.dir}", file=sys.stderr)
        return EXIT_ERROR
    # The gate's own state files are configuration, not documents: a baseline
    # kept inside the tree must not be scanned (it would flag its own
    # fingerprints as high-entropy-looking JSON fields on the next run).
    state_files = {Path(f).resolve() for f in (args.baseline, args.write_baseline) if f}
    paths = sorted(
        (
            p
            for p in root.glob(args.glob)
            if p.is_file()
            and p.suffix.lower() in FORMATS
            # The policy file is configuration, not a document to scan (it would
            # otherwise match the .yaml extractor and flag its own rule regexes).
            and p.name != ".docredact.yaml"
            and (not state_files or p.resolve() not in state_files)
        ),
        key=lambda p: p.relative_to(root).as_posix(),
    )
    if not paths:
        # An empty tree has no findings; recording that is still meaningful.
        if args.write_baseline:
            write_baseline(Path(args.write_baseline), [])
        if args.format == "table":
            print("no matching files")
        else:
            # Machine output stays parseable: the notice moves to stderr and the
            # SARIF form is still a valid (empty) run a CI upload step can consume.
            print("no matching files", file=sys.stderr)
            if args.format == "sarif":
                _write_output(args.out, render_sarif([]))
        return EXIT_OK

    policy = _resolve_policy(root, args.rules)
    # (tree-relative posix path, document or None when the file failed to parse)
    entries: list[tuple[str, dict[str, Any] | None]] = []
    errors = 0
    for path in paths:
        name = path.relative_to(root).as_posix()
        try:
            document = build_document(path, redact=args.redact, policy=policy)
        except (DocRedactError, OSError) as exc:
            print(f"docredact: error: {name}: {exc}", file=sys.stderr)
            entries.append((name, None))
            errors += 1
            continue
        entries.append((name, document))

    # One flat findings list for the whole tree: each finding is the entity dict
    # with its tree-relative path prepended (never an absolute path).
    findings: list[dict[str, Any]] = []
    for name, doc in entries:
        if doc is None:
            continue
        entities = doc["entities"]
        assert isinstance(entities, list)
        findings.extend({"path": name, **entity} for entity in entities)

    if args.write_baseline:
        # Recorded before suppression, so --baseline + --write-baseline refreshes the
        # file with every currently reported finding (fixed ones drop out).
        write_baseline(Path(args.write_baseline), [f["fingerprint"] for f in findings])
    if args.baseline:
        known = load_baseline(Path(args.baseline))
        new = [f for f in findings if f["fingerprint"] not in known]
        print(
            f"baseline: {len(findings) - len(new)} finding(s) suppressed, {len(new)} new",
            file=sys.stderr,
        )
        findings = new

    if args.format == "jsonl":
        payload = "".join(json.dumps(f) + "\n" for f in findings)
    elif args.format == "sarif":
        payload = render_sarif(findings)
    else:
        payload = _render_scan_table(entries, findings)
    _write_output(args.out, payload)

    if errors:
        # A file the gate could not read outranks everything else: neither a freshly
        # recorded baseline nor a quiet strict pass covers the whole tree then.
        return EXIT_ERROR
    if args.write_baseline:
        return EXIT_OK  # everything just recorded is accepted by definition
    if args.redact == "strict" and findings:
        return EXIT_STRICT
    return EXIT_OK


def _write_output(out: str | None, payload: str) -> None:
    """Print ``payload`` (or write it to ``out`` with LF endings, byte-deterministic)."""
    if out:
        Path(out).write_text(payload, encoding="utf-8", newline="\n")
    else:
        print(payload, end="")


def _render_scan_table(
    entries: list[tuple[str, dict[str, Any] | None]], findings: list[dict[str, Any]]
) -> str:
    """Render the human summary table (identical to 1.0 when no baseline filters)."""
    per_path: dict[str, int] = {}
    totals: dict[str, int] = {}
    severity_totals: dict[str, int] = {}
    for finding in findings:
        per_path[finding["path"]] = per_path.get(finding["path"], 0) + 1
        totals[finding["type"]] = totals.get(finding["type"], 0) + 1
        severity_totals[finding["severity"]] = severity_totals.get(finding["severity"], 0) + 1
    rows: list[tuple[str, str, str, str]] = []
    for name, document in entries:
        if document is None:
            rows.append((name, "-", "-", "ERROR"))
            continue
        blocks = document["blocks"]
        assert isinstance(blocks, list)
        fmt = str(document["format"])
        rows.append((name, fmt, str(len(blocks)), str(per_path.get(name, 0))))

    header = ("FILE", "FORMAT", "BLOCKS", "ENTITIES")
    widths = [max(len(row[i]) for row in (header, *rows)) for i in range(4)]
    lines = [
        "  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True)).rstrip()
        for row in (header, *rows)
    ]
    detail = ", ".join(f"{t}={n}" for t, n in sorted(totals.items()))
    suffix = f" ({detail})" if detail else ""
    lines.append(f"total: {len(entries)} files, {len(findings)} entities{suffix}")
    if severity_totals:
        rollup = ", ".join(
            f"{sev.value}={severity_totals[sev.value]}"
            for sev in SEVERITY_ORDER
            if sev.value in severity_totals
        )
        lines.append(f"severity: {rollup}")
    return "\n".join(lines) + "\n"
