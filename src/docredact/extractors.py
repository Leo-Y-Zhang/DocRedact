"""Format detection and text-block extraction for PDF, DOCX, txt, md, html, and csv."""

from __future__ import annotations

import csv
import email
import email.policy
import io
import json
import logging
import re
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree

from pypdf import PdfReader

# pypdf reports non-fatal parser conditions (bad header, missing EOF marker,
# non-compliant structure it is recovering from, ...) through the stdlib
# `logging` module, using logger names rooted at "pypdf" (see
# https://pypdf.readthedocs.io/en/latest/user/suppress-warnings.html). DocRedact
# never configures logging, so with no handler anywhere in that chain,
# Python's logging "handler of last resort" prints every one of those
# records straight to the real process stderr -- bypassing the clean
# `docredact: error: ...` message this module builds and, worse, sometimes
# echoing raw bytes read from the untrusted input file (e.g. an "invalid pdf
# header: b'...'" message quoting the file's own first bytes). A tool whose
# entire premise is "never leak" must not leak the document it was asked to
# scan, or its own internal parsing state, onto stderr that way. Attaching a
# NullHandler and disabling propagation on the "pypdf" logger silences every
# pypdf.* logger (they are children of it in the logging hierarchy), leaving
# DocRedactError's own deliberately generic messages as the only thing on stderr.
logging.getLogger("pypdf").addHandler(logging.NullHandler())
logging.getLogger("pypdf").propagate = False


class DocRedactError(Exception):
    """Base class for docredact errors surfaced as exit code 1."""


class UnsupportedFormatError(DocRedactError):
    """The file extension does not map to a supported format."""


class ExtractionError(DocRedactError):
    """The file bytes could not be parsed as the detected format."""


FORMATS = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".txt": "txt",
    ".md": "md",
    ".html": "html",
    ".htm": "html",
    ".csv": "csv",
    ".eml": "eml",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".log": "log",
    ".ini": "ini",
}

# Aggregate output caps that bound extraction cost on hostile inputs. pypdf's
# 75 MB decompression cap is PER-STREAM only, and zip headers can lie about a
# member's size, so both extractors need their own aggregate ceiling. The caps
# are far above any real document (a 25 MB text page or a 100 MB DOCX body is
# already absurd) so normal files never trip them.
_PDF_MAX_TEXT_CHARS = 25_000_000  # ~25 MB of extracted UTF-8 text across pages
_PDF_MAX_PAGES = 50_000  # sanity ceiling on page count
_DOCX_MAX_XML_BYTES = 100_000_000  # ~100 MB uncompressed word/document.xml


@dataclass(frozen=True)
class Block:
    """One extracted text unit: a page, section, paragraph, element, or row."""

    index: int
    kind: str
    text: str


def detect_format(path: Path) -> str:
    """Map a file extension to a format name, or raise UnsupportedFormatError."""
    fmt = FORMATS.get(path.suffix.lower())
    if fmt is None:
        supported = ", ".join(sorted(FORMATS))
        raise UnsupportedFormatError(
            f"unsupported file type {path.suffix or path.name!r} (supported: {supported})"
        )
    return fmt


def extract_blocks(data: bytes, fmt: str) -> tuple[list[Block], list[str]]:
    """Extract ordered text blocks plus warnings from raw file bytes."""
    if fmt == "pdf":
        return _extract_pdf(data)
    if fmt == "docx":
        return _extract_docx(data)
    if fmt == "eml":
        return _extract_eml(data)
    text = data.decode("utf-8", errors="replace")
    blocks = _TEXT_EXTRACTORS[fmt](text)
    warnings = [] if blocks else ["no text blocks extracted"]
    return blocks, warnings


def _blocks(kind: str, texts: Iterable[str]) -> list[Block]:
    return [Block(i, kind, t) for i, t in enumerate(texts)]


def _extract_txt(text: str) -> list[Block]:
    paragraphs = (p.strip() for p in re.split(r"\n\s*\n", text))
    return _blocks("paragraph", (p for p in paragraphs if p))


def _extract_md(text: str) -> list[Block]:
    sections: list[list[str]] = [[]]
    for line in text.splitlines():
        if re.match(r"#{1,6}\s", line):
            sections.append([line])
        else:
            sections[-1].append(line)
    joined = ("\n".join(lines).strip() for lines in sections)
    return _blocks("section", (s for s in joined if s))


class _HTMLTextParser(HTMLParser):
    """Collect visible text, flushing a block at block-level tag boundaries."""

    _BLOCK_TAGS = frozenset(
        {"p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "title", "tr", "div", "br"}
    )
    _SKIP_TAGS = frozenset({"script", "style"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.texts: list[str] = []
        self._buffer: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif tag in self._BLOCK_TAGS:
            self._flush()
        elif tag == "a" and not self._skip_depth:
            # mailto: hrefs carry real addresses that anchor text often hides
            # ("Contact support" linking to a personal mailbox), so the target
            # is injected into the surrounding block as scannable text. The
            # WHOLE tail after the scheme is kept -- RFC 6068 puts further
            # addresses in ?to=/?cc=/?bcc= and free text in ?subject=/?body=,
            # all of which can leak -- and percent-decoding happens first so
            # jane%40example.com cannot hide from the email detector. The
            # surrounding spaces keep the address from fusing with adjacent
            # anchor text into one undetectable blob (_flush collapses runs of
            # whitespace, so spacing in the final block text stays normal).
            href = next((value for name, value in attrs if name == "href" and value), None)
            if href is not None and href.strip()[:7].lower() == "mailto:":
                self._buffer.append(f" {unquote(href.strip()[7:])} ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag in self._BLOCK_TAGS:
            self._flush()

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self._buffer.append(data)

    def _flush(self) -> None:
        text = " ".join("".join(self._buffer).split())
        self._buffer.clear()
        if text:
            self.texts.append(text)


def _extract_html(text: str) -> list[Block]:
    parser = _HTMLTextParser()
    parser.feed(text)
    parser.close()
    parser._flush()
    return _blocks("element", parser.texts)


def _extract_csv(text: str) -> list[Block]:
    # csv raises lazily during iteration (e.g. a field over its size limit),
    # so materialize inside the guard and surface it as an ExtractionError -
    # otherwise the raw csv.Error escapes unwrapped, crashing `extract` with a
    # traceback and aborting a whole `scan` batch on one malicious file.
    try:
        rows = list(csv.reader(io.StringIO(text)))
    except csv.Error as exc:
        raise ExtractionError(f"failed to parse CSV: {exc}") from exc
    joined = (", ".join(cell.strip() for cell in row) for row in rows)
    return _blocks("row", (r for r in joined if r))


def _extract_pdf(data: bytes) -> tuple[list[Block], list[str]]:
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = list(reader.pages)
    except Exception as exc:
        raise ExtractionError(f"failed to parse PDF: {exc}") from exc
    # pypdf caps decompression PER STREAM (75 MB), but a page can share one
    # small stream and re-emit it, so a 12 KB / 50-page PDF can expand to
    # 100 M chars and burn minutes of CPU. Bound the AGGREGATE extracted text
    # (and page count) so total work stays proportional to a sane document.
    if len(pages) > _PDF_MAX_PAGES:
        raise ExtractionError(
            f"failed to parse PDF: too many pages ({len(pages)} > {_PDF_MAX_PAGES})"
        )
    blocks: list[Block] = []
    warnings: list[str] = []
    total_chars = 0
    for i, page in enumerate(pages):
        try:
            text = (page.extract_text() or "").strip()
        except Exception as exc:
            text = ""
            warnings.append(f"page {i}: text extraction failed ({exc})")
        total_chars += len(text)
        if total_chars > _PDF_MAX_TEXT_CHARS:
            raise ExtractionError(
                "failed to parse PDF: extracted text exceeds the "
                f"{_PDF_MAX_TEXT_CHARS}-character aggregate cap "
                "(possible decompression / output-amplification bomb)"
            )
        if not text:
            warnings.append(
                f"page {i}: no extractable text (image-only pages need OCR, "
                "which is out of scope)"
            )
        blocks.append(Block(i, "page", text))
    return blocks, warnings


_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_paragraph_text(paragraph: ElementTree.Element) -> str:
    """Join a w:p element's runs into one string.

    Runs are joined with no separator (Word fragments sentences into many
    runs, sometimes mid-token); w:tab and w:br become whitespace so adjacent
    tokens do not fuse.
    """
    parts: list[str] = []
    for node in paragraph.iter():
        if node.tag == f"{_W}t":
            parts.append(node.text or "")
        elif node.tag == f"{_W}tab":
            parts.append("\t")
        elif node.tag in (f"{_W}br", f"{_W}cr"):
            parts.append("\n")
    return "".join(parts).strip()


def _docx_row_text(row: ElementTree.Element) -> str:
    """Join a w:tr element's cells with ", " (mirrors the csv extractor)."""
    cells = []
    for cell in row.findall(f"{_W}tc"):
        texts = (_docx_paragraph_text(p) for p in cell.iter(f"{_W}p"))
        cells.append(" ".join(t for t in texts if t))
    return ", ".join(cells).strip()


# Header and footer parts are numbered by Word (word/header1.xml, ...); the
# numeric capture keeps their scan order numeric (header2 before header10),
# never the zip's listing order.
_DOCX_PART_RE = re.compile(r"^word/(header|footer)([1-9]\d*)\.xml$")

# Note-container parts: (part name, element localname, block kind).
_DOCX_NOTE_PARTS = (
    ("word/footnotes.xml", "footnote"),
    ("word/endnotes.xml", "endnote"),
)


def _read_docx_xml(
    archive: zipfile.ZipFile, name: str, budget: int
) -> tuple[ElementTree.Element, int]:
    """Read + parse one XML part under the REMAINING aggregate byte budget.

    Returns (root element, budget left for later parts). The size guard is
    aggregate across every scanned part, or a hostile archive could multiply
    the per-part ceiling by stuffing in extra header/footer parts. Reject via
    the header size first (cheap), then read only up to budget+1 and reject if
    the stream is actually larger, so a header that LIES about being small
    cannot bypass the guard.
    """
    info = archive.getinfo(name)
    if info.file_size > budget:
        raise ExtractionError(
            f"failed to parse DOCX: {name} uncompressed size "
            f"{info.file_size} exceeds the {budget}-byte cap "
            "(possible decompression bomb)"
        )
    with archive.open(name) as stream:
        payload = stream.read(budget + 1)
    if len(payload) > budget:
        raise ExtractionError(
            f"failed to parse DOCX: {name} exceeds the "
            f"{budget}-byte cap (possible decompression bomb)"
        )
    # Valid OOXML never carries a DTD. Rejecting DOCTYPE/ENTITY outright
    # closes the stdlib XML parser's XXE / entity-expansion attack surface
    # without adding a runtime dependency (the keywords are case-sensitive
    # in XML, so these two exact byte strings are sufficient). The check
    # applies to EVERY scanned part: a DTD in a header is as hostile as one
    # in the body.
    if b"<!DOCTYPE" in payload or b"<!ENTITY" in payload:
        raise ExtractionError(
            f"failed to parse DOCX: DTD or entity declarations are not allowed (in {name})"
        )
    try:
        return ElementTree.fromstring(payload), budget - len(payload)
    except ElementTree.ParseError as exc:
        raise ExtractionError(f"failed to parse DOCX: {name}: bad XML: {exc}") from exc


def _docx_container_blocks(
    container: Iterable[ElementTree.Element], paragraph_kind: str, blocks: list[Block]
) -> None:
    """Append paragraph and table-row blocks from one w:p/w:tbl container.

    Paragraphs take ``paragraph_kind`` (paragraph/header/footer/footnote/
    endnote, so a finding names where in the document it lives); table rows are
    always ``row``, mirroring the csv extractor. Anything else (sectPr, ...) is
    structure, not text, and is skipped.
    """
    for element in container:
        if element.tag == f"{_W}p":
            text = _docx_paragraph_text(element)
            if text:
                blocks.append(Block(len(blocks), paragraph_kind, text))
        elif element.tag == f"{_W}tbl":
            for row in element.findall(f"{_W}tr"):
                text = _docx_row_text(row)
                if text:
                    blocks.append(Block(len(blocks), "row", text))


def _docx_extra_parts(names: list[str]) -> list[tuple[str, str]]:
    """Deterministic (kind, part name) scan order for non-body parts.

    Headers first (numeric order), then footers, then footnotes/endnotes --
    a fixed order independent of how the zip happens to list its members, so
    block indexes (and the sanitized artifact built from them) never depend
    on which tool produced the archive.
    """
    numbered: dict[str, list[tuple[int, str]]] = {"header": [], "footer": []}
    for name in names:
        match = _DOCX_PART_RE.match(name)
        if match:
            numbered[match.group(1)].append((int(match.group(2)), name))
    ordered = [
        (kind, name)
        for kind in ("header", "footer")
        for _, name in sorted(set(numbered[kind]))
    ]
    ordered.extend(
        (kind, part) for part, kind in _DOCX_NOTE_PARTS if part in set(names)
    )
    return ordered


def _extract_docx(data: bytes) -> tuple[list[Block], list[str]]:
    """Extract body paragraphs/table rows plus header, footer, and foot/endnote text.

    Body blocks come first (their indexes match pre-1.2 output exactly), then
    headers, footers, footnotes, and endnotes -- closing the documented blind
    spot where a secret in a header/footer/footnote was never scanned.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            budget = _DOCX_MAX_XML_BYTES
            root, budget = _read_docx_xml(archive, "word/document.xml", budget)
            extras: list[tuple[str, ElementTree.Element]] = []
            for kind, name in _docx_extra_parts(archive.namelist()):
                part_root, budget = _read_docx_xml(archive, name, budget)
                extras.append((kind, part_root))
    except zipfile.BadZipFile as exc:
        raise ExtractionError(f"failed to parse DOCX: {exc}") from exc
    except KeyError as exc:
        raise ExtractionError(
            "failed to parse DOCX: no word/document.xml in archive"
        ) from exc

    blocks: list[Block] = []
    body = root.find(f"{_W}body")
    _docx_container_blocks(body if body is not None else (), "paragraph", blocks)
    for kind, part_root in extras:
        if kind in ("footnote", "endnote"):
            # Each w:footnote/w:endnote wraps its own paragraphs; Word's
            # separator/continuationSeparator stub notes carry no text and
            # therefore produce no blocks.
            for note in part_root.findall(f"{_W}{kind}"):
                _docx_container_blocks(note, kind, blocks)
        else:
            _docx_container_blocks(part_root, kind, blocks)
    warnings = [] if blocks else ["no text blocks extracted"]
    return blocks, warnings


_EML_HEADERS = ("From", "To", "Cc", "Bcc", "Reply-To", "Subject")
_JSON_MAX_DEPTH = 200
# Each JSON leaf re-embeds its full dotted key path, so a wide object with long
# keys amplifies output quadratically in the input size. Cap the aggregate
# emitted text (matching the PDF ceiling) so a small crafted file cannot expand
# to gigabytes of block text and OOM / hang the process.
_JSON_MAX_TEXT_CHARS = 25_000_000


def _extract_eml(data: bytes) -> tuple[list[Block], list[str]]:
    """Extract an RFC 5322 email: address/subject headers plus text body parts.

    Header lines become ``header`` blocks (so a From/To address is a finding with a
    precise location); text/plain parts become paragraphs and text/html parts go
    through the HTML extractor. Attachments and other content types are skipped
    with a visible warning -- they are not decoded or scanned.
    """
    try:
        message = email.message_from_bytes(data, policy=email.policy.default)
    except Exception as exc:  # email package raises a variety of ValueErrors
        raise ExtractionError(f"failed to parse EML: {exc}") from exc

    blocks: list[Block] = []
    warnings: list[str] = []

    def _add(kind: str, text: str) -> None:
        if text:
            blocks.append(Block(len(blocks), kind, text))

    for header in _EML_HEADERS:
        for value in message.get_all(header, []):
            _add("header", f"{header}: {value}")

    for part in message.walk():
        content_type = part.get_content_type()
        if part.is_multipart():
            continue
        if content_type == "text/plain":
            try:
                body = part.get_content()
            except Exception as exc:
                warnings.append(f"text part could not be decoded ({exc})")
                continue
            for paragraph in _extract_txt(str(body)):
                _add("paragraph", paragraph.text)
        elif content_type == "text/html":
            try:
                body = part.get_content()
            except Exception as exc:
                warnings.append(f"html part could not be decoded ({exc})")
                continue
            for element in _extract_html(str(body)):
                _add("element", element.text)
        else:
            warnings.append(f"attachment skipped (not scanned): {content_type}")

    if not blocks:
        warnings.append("no text blocks extracted")
    return blocks, warnings


def _flatten_json(value: object, path: str, depth: int, out: list[str], total: list[int]) -> None:
    if depth > _JSON_MAX_DEPTH:
        raise ExtractionError(
            f"failed to parse JSON: nesting deeper than {_JSON_MAX_DEPTH} levels"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            _flatten_json(item, child, depth + 1, out, total)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _flatten_json(item, f"{path}[{i}]", depth + 1, out, total)
    else:
        rendered = json.dumps(value) if not isinstance(value, str) else value
        line = f"{path}: {rendered}" if path else rendered
        total[0] += len(line)
        if total[0] > _JSON_MAX_TEXT_CHARS:
            raise ExtractionError(
                "failed to parse JSON: flattened text exceeds the "
                f"{_JSON_MAX_TEXT_CHARS}-character aggregate cap "
                "(possible output-amplification bomb)"
            )
        out.append(line)


def _extract_json(text: str) -> list[Block]:
    """Flatten a JSON document into one ``field`` block per leaf: ``a.b[0]: value``.

    Key paths ride along with each value, so a finding names the config key it
    sits under. Nesting is depth-capped with a clean error (a recursion guard
    against adversarial deeply-nested input).
    """
    try:
        parsed = json.loads(text)
    except RecursionError as exc:  # the C parser guards its own stack
        raise ExtractionError("failed to parse JSON: nesting too deep") from exc
    except json.JSONDecodeError as exc:
        raise ExtractionError(f"failed to parse JSON: {exc}") from exc
    lines: list[str] = []
    _flatten_json(parsed, "", 0, lines, [0])
    return _blocks("field", lines)


_TEXT_EXTRACTORS: dict[str, Callable[[str], list[Block]]] = {
    "txt": _extract_txt,
    "md": _extract_md,
    "html": _extract_html,
    "csv": _extract_csv,
    "json": _extract_json,
    # yaml/log/ini are scanned as plain text lines grouped into paragraphs: no
    # YAML parser (no dependency, none of YAML's attack surface) -- secrets in
    # values are still caught by the line scan, which is the honest tradeoff.
    "yaml": _extract_txt,
    "log": _extract_txt,
    "ini": _extract_txt,
}
