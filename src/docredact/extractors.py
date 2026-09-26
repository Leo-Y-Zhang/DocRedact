"""Format detection and text-block extraction for PDF, DOCX, txt, md, html, and csv."""

from __future__ import annotations

import codecs
import csv
import email
import email.policy
import io
import json
import logging
import re
import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote
from xml.etree import ElementTree

from pypdf import PageObject, PdfReader
from pypdf.generic import DictionaryObject, NameObject, PdfObject

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


# Every warning that means "part of this input was NOT read" starts with this
# prefix: an embedded file, an image-only page, a page pypdf could not parse, text
# in a font with no Unicode mapping, bytes that are not valid text, an e-mail
# attachment. A gate that did not read part of a file did not check it, so
# ``--redact strict`` treats any such warning like a parse error (exit 1). JSON
# consumers can test for the same prefix.
NOT_SCANNED = "not scanned: "


def is_gap(warning: str) -> bool:
    """True if ``warning`` reports content that was present but not scanned."""
    return warning.startswith(NOT_SCANNED)


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


# A byte-order mark states the encoding unambiguously, and Windows tooling
# (Notepad, PowerShell redirection, Excel's "Unicode Text" export) writes UTF-16
# with one routinely. Decoding those bytes as UTF-8 does not fail loudly: every
# ASCII character comes back interleaved with U+0000, so no detector can match
# and the document scans as zero findings with zero warnings -- a --redact strict
# gate exiting 0 on a file holding a plaintext AWS key. The UTF-32 marks must be
# tested before the UTF-16 ones: BOM_UTF32_LE starts with BOM_UTF16_LE.
_BOM_ENCODINGS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
    (codecs.BOM_UTF8, "utf-8-sig"),
)


def _decode_text(data: bytes) -> tuple[str, list[str]]:
    """Decode input bytes to text, honouring a BOM and warning on undecodable bytes.

    Falls back to UTF-8 when there is no BOM. A strict decode is attempted first
    so that lossy replacement is never silent: bytes this tool could not read are
    bytes it could not scan, and a report that omits that is a clean bill of
    health it did not earn.
    """
    encoding = next(
        (enc for bom, enc in _BOM_ENCODINGS if data.startswith(bom)), "utf-8"
    )
    try:
        text, warnings = data.decode(encoding), []
    except UnicodeDecodeError:
        text, warnings = data.decode(encoding, errors="replace"), [
            f"{NOT_SCANNED}input is not valid {encoding}: undecodable bytes were "
            "replaced, so some text may not have been scanned"
        ]
    # UTF-16 written WITHOUT a byte-order mark is valid UTF-8 as far as the
    # decoder is concerned: every ASCII character arrives with a U+0000 beside
    # it, nothing fails, and no detector can match. Text documents do not
    # contain NUL, so its presence means the bytes were not read as text.
    if "\x00" in text:
        warnings.append(
            f"{NOT_SCANNED}input contains NUL bytes (UTF-16 without a byte-order "
            "mark, or binary data), so its text was not read"
        )
    return text, warnings


def extract_blocks(data: bytes, fmt: str) -> tuple[list[Block], list[str]]:
    """Extract ordered text blocks plus warnings from raw file bytes."""
    if fmt == "pdf":
        return _extract_pdf(data)
    if fmt == "docx":
        return _extract_docx(data)
    if fmt == "eml":
        return _extract_eml(data)
    text, warnings = _decode_text(data)
    blocks = _TEXT_EXTRACTORS[fmt](text)
    if not blocks:
        warnings.append("no text blocks extracted")
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


def _pdf_text(value: object) -> str:
    """A PDF string value as stripped text; "" for names (checkbox states) and non-strings.

    pypdf hands back raw bytes for a string it could not decode as
    PDFDocEncoding or UTF-16; those are decoded here rather than dropped, so an
    oddly encoded comment is still scanned.
    """
    if isinstance(value, PdfObject):
        value = value.get_object()
    if isinstance(value, bytes):
        raw = value
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            value = raw.decode("latin-1")
    if isinstance(value, NameObject) or not isinstance(value, str):
        return ""
    return value.strip()


def _pdf_file_name(annotation: DictionaryObject) -> str:
    """The file name a FileAttachment annotation carries, or "(unnamed)"."""
    spec = annotation.get("/FS")
    spec = spec.get_object() if spec is not None else None
    if isinstance(spec, DictionaryObject):
        for key in ("/UF", "/F"):
            name = _pdf_text(spec.get(key))
            if name:
                return name
    return _pdf_text(spec) or "(unnamed)"


def _pdf_page_has_content(page: PageObject) -> bool:
    """True if the page draws anything at all (a blank page leaves nothing unread)."""
    contents = page.get_contents()
    return contents is not None and bool(contents.get_data().strip())


def _pdf_unmapped_fonts(page: PageObject) -> list[str]:
    """Names of the page's fonts whose text cannot be mapped to Unicode.

    A composite font with the Identity encoding stores glyph ids, not
    characters; without a /ToUnicode map nothing says which glyph is which
    letter, and pypdf silently emits the raw ids - garbage no detector can
    match. Subset fonts in PDFs produced by many tools look exactly like this.
    """
    resources = page.get("/Resources")
    resources = resources.get_object() if resources is not None else None
    fonts = resources.get("/Font") if isinstance(resources, DictionaryObject) else None
    fonts = fonts.get_object() if fonts is not None else None
    if not isinstance(fonts, DictionaryObject):
        return []
    unmapped = []
    for name, reference in fonts.items():
        font = reference.get_object() if isinstance(reference, PdfObject) else None
        if (
            isinstance(font, DictionaryObject)
            and font.get("/Subtype") == "/Type0"
            and font.get("/Encoding") in ("/Identity-H", "/Identity-V")
            and "/ToUnicode" not in font
        ):
            unmapped.append(str(name).lstrip("/"))
    return sorted(unmapped)


def _pdf_annotation_texts(
    page: PageObject, warnings: list[str]
) -> Iterator[tuple[str, str]]:
    """(kind, text) for the scannable text of one page's annotations.

    Sticky notes, FreeText boxes, commented highlights and the like keep their
    text in ``/Contents``, outside the page content stream that
    ``extract_text`` reads, so it was never scanned: those become
    ``annotation`` text. A Link's target URI - the address or the tokenised
    URL behind "click here" - is percent-decoded and becomes ``link`` text.
    Form widgets are skipped (their values come from the AcroForm walk), and so
    are Popups, which only display their parent's text. A file attached as an
    annotation is not opened; it is reported, as an EML attachment is.
    """
    annotations = page.get("/Annots")
    annotations = annotations.get_object() if annotations is not None else None
    if not isinstance(annotations, list):
        return
    for reference in annotations:
        annotation = reference.get_object() if isinstance(reference, PdfObject) else None
        if not isinstance(annotation, DictionaryObject):
            continue
        subtype = annotation.get("/Subtype")
        if subtype in ("/Widget", "/Popup"):
            continue
        if subtype == "/FileAttachment":
            warnings.append(f"{NOT_SCANNED}embedded file {_pdf_file_name(annotation)}")
        text = _pdf_text(annotation.get("/Contents"))
        if text:
            yield "annotation", text
        if subtype == "/Link":
            action = annotation.get("/A")
            action = action.get_object() if action is not None else None
            uri = _pdf_text(action.get("/URI")) if isinstance(action, DictionaryObject) else ""
            if uri:
                yield "link", unquote(uri)


def _pdf_field_texts(reader: PdfReader) -> Iterator[str]:
    """``name: value`` for every filled-in AcroForm field.

    A filled form shows its values through widget appearance streams, not the
    page content, so a typed-in email or phone number never reached a
    detector. Checkbox and radio states are names (``/Yes``), not text, and
    are skipped; a multi-select list's values are joined with ", ".
    """
    for name, field in (reader.get_fields() or {}).items():
        value = field.get("/V")
        value = value.get_object() if isinstance(value, PdfObject) else value
        values = value if isinstance(value, list) else [value]
        text = ", ".join(t for t in (_pdf_text(v) for v in values) if t)
        if text:
            yield f"{name}: {text}"


# An incremental update appends to the file and leaves everything before it in
# place, so each earlier revision is still a complete PDF: the bytes up to its
# own "startxref <offset> %%EOF". A linearized file's first-page section ends in
# "startxref 0 %%EOF", which is a stub rather than a revision.
_PDF_REVISION_END_RE = re.compile(rb"startxref\s+(\d+)\s*%%EOF")
_PDF_MAX_REVISIONS = 100


def _pdf_earlier_revision_ends(data: bytes) -> list[int]:
    """Byte offsets where each earlier (not the final) revision of ``data`` ends."""
    ends = [m.end() for m in _PDF_REVISION_END_RE.finditer(data) if int(m.group(1)) > 0]
    tail = len(data.rstrip())
    return [end for end in ends if end < tail]


def _extract_pdf(data: bytes) -> tuple[list[Block], list[str]]:
    """Extract the final revision, then any text only an earlier revision holds.

    Saving over a page ("redacting" it in an editor that saves incrementally)
    leaves the original page in the file. Each earlier revision is extracted
    in turn, and every block text it has that the final revision lacks becomes
    a ``revision`` block, appended last, so no existing block index moves. An
    earlier revision that cannot be opened is reported as not scanned.
    """
    used = [0]  # extracted characters across all revisions, for the aggregate cap
    blocks, warnings = _extract_pdf_revision(data, used)
    ends = _pdf_earlier_revision_ends(data)
    if len(ends) > _PDF_MAX_REVISIONS:
        raise ExtractionError(
            f"failed to parse PDF: too many revisions ({len(ends)} > {_PDF_MAX_REVISIONS})"
        )
    seen = {b.text for b in blocks}
    known = set(warnings)
    for number, end in enumerate(ends, start=1):
        try:
            old_blocks, old_warnings = _extract_pdf_revision(data[:end], used)
        except ExtractionError as exc:
            if "aggregate cap" in str(exc):
                raise
            warnings.append(f"{NOT_SCANNED}earlier revision {number} could not be read ({exc})")
            continue
        for block in old_blocks:
            if block.text and block.text not in seen:
                seen.add(block.text)
                blocks.append(Block(len(blocks), "revision", block.text))
        for warning in old_warnings:
            if is_gap(warning) and warning not in known:
                known.add(warning)
                rest = warning[len(NOT_SCANNED):]
                warnings.append(f"{NOT_SCANNED}earlier revision {number}: {rest}")
    return blocks, warnings


def _extract_pdf_revision(data: bytes, used: list[int]) -> tuple[list[Block], list[str]]:
    """Extract one block per page, then annotation, link, form-field and metadata text.

    Page blocks keep index == page number; ``annotation``/``link`` blocks (page
    order), ``field`` and ``metadata`` blocks follow, so no page block index
    moves. ``used`` carries the aggregate character count across revisions.
    """
    try:
        reader = PdfReader(io.BytesIO(data))
        pages = list(reader.pages)
    except Exception as exc:
        raise ExtractionError(f"failed to parse PDF: {exc}") from exc
    # pypdf caps decompression PER STREAM (75 MB), but a page can share one
    # small stream and re-emit it, so a 12 KB / 50-page PDF can expand to
    # 100 M chars and burn minutes of CPU. Bound the AGGREGATE extracted text
    # (and page count) so total work stays proportional to a sane document.
    # Annotation and field text counts too: many annotations can share one
    # string object in the same way.
    if len(pages) > _PDF_MAX_PAGES:
        raise ExtractionError(
            f"failed to parse PDF: too many pages ({len(pages)} > {_PDF_MAX_PAGES})"
        )
    blocks: list[Block] = []
    warnings: list[str] = []

    def charge(text: str) -> str:
        used[0] += len(text)
        if used[0] > _PDF_MAX_TEXT_CHARS:
            raise ExtractionError(
                "failed to parse PDF: extracted text exceeds the "
                f"{_PDF_MAX_TEXT_CHARS}-character aggregate cap "
                "(possible decompression / output-amplification bomb)"
            )
        return text

    extra: list[tuple[str, str]] = []  # (kind, text), appended after the pages
    for i, page in enumerate(pages):
        failed = False
        try:
            text = (page.extract_text() or "").strip()
        except Exception as exc:
            text, failed = "", True
            warnings.append(f"{NOT_SCANNED}page {i}: text extraction failed ({exc})")
        charge(text)
        try:
            unmapped = _pdf_unmapped_fonts(page)
        except Exception:
            unmapped = []
        if unmapped:
            warnings.append(
                f"{NOT_SCANNED}page {i}: text in font {', '.join(unmapped)} cannot be "
                "mapped to characters (no ToUnicode map)"
            )
        elif "\ufffd" in text:
            # pypdf emits U+FFFD for a glyph it cannot map to Unicode (a font
            # with a custom encoding and no ToUnicode map): that text was on
            # the page, but no detector can match what it became.
            warnings.append(
                f"{NOT_SCANNED}page {i}: some text could not be decoded (a font "
                "without a usable Unicode mapping)"
            )
        if not text and not failed:
            try:
                drawn = _pdf_page_has_content(page)
            except Exception:
                drawn = True  # unreadable content is not proof of a blank page
            if drawn:
                warnings.append(
                    f"{NOT_SCANNED}page {i} has no extractable text (image-only "
                    "pages need OCR, which is out of scope)"
                )
        blocks.append(Block(i, "page", text))
        try:
            for kind, note in _pdf_annotation_texts(page, warnings):
                extra.append((kind, charge(note)))
        except ExtractionError:
            raise
        except Exception as exc:
            warnings.append(f"{NOT_SCANNED}page {i}: annotations could not be read ({exc})")
    try:
        for field in _pdf_field_texts(reader):
            extra.append(("field", charge(field)))
    except ExtractionError:
        raise
    except Exception as exc:
        warnings.append(f"{NOT_SCANNED}form fields could not be read ({exc})")
    try:
        embedded = sorted(reader.attachments)
    except Exception as exc:
        embedded = []
        warnings.append(f"{NOT_SCANNED}embedded files could not be listed ({exc})")
    warnings.extend(f"{NOT_SCANNED}embedded file {name}" for name in embedded)
    try:
        for line in _pdf_metadata_texts(reader, warnings):
            extra.append(("metadata", charge(line)))
    except ExtractionError:
        raise
    except Exception as exc:
        warnings.append(f"{NOT_SCANNED}document metadata could not be read ({exc})")
    blocks.extend(Block(len(blocks) + n, kind, text) for n, (kind, text) in enumerate(extra))
    return blocks, warnings


_RDF_NS = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"


def _xml_texts(root: ElementTree.Element) -> Iterator[str]:
    """Every attribute value and text node under ``root``, in document order."""
    for element in root.iter():
        for key, value in element.attrib.items():
            if not key.startswith(_RDF_NS) and value.strip():
                yield value.strip()
        if element.text and element.text.strip():
            yield element.text.strip()


def _pdf_metadata_texts(reader: PdfReader, warnings: list[str]) -> list[str]:
    """``key: value`` per Info-dictionary entry, then one ``XMP: ...`` line.

    Author, title, subject, keywords and any custom Info key travel with the
    file and show in every viewer's Properties dialog; the XMP packet repeats
    them (plus creator tools, editing history and whatever else a producer
    writes) as XML. Neither is part of a page, so neither was ever scanned.
    """
    lines: list[str] = []
    info = reader.metadata
    if info is not None:
        for key in sorted(info):
            text = _pdf_text(info.get(key))
            if text:
                lines.append(f"{str(key).lstrip('/')}: {text}")
    root = reader.trailer.get("/Root")
    root = root.get_object() if root is not None else None
    stream = root.get("/Metadata") if isinstance(root, DictionaryObject) else None
    stream = stream.get_object() if stream is not None else None
    if stream is None or not hasattr(stream, "get_data"):
        return lines
    packet = stream.get_data()
    if b"<!DOCTYPE" in packet or b"<!ENTITY" in packet:
        warnings.append(f"{NOT_SCANNED}XMP metadata could not be read (DTD not allowed)")
        return lines
    try:
        xmp = ElementTree.fromstring(packet)
    except ElementTree.ParseError as exc:
        warnings.append(f"{NOT_SCANNED}XMP metadata could not be read (bad XML: {exc})")
        return lines
    text = " ".join(_xml_texts(xmp))
    if text:
        lines.append(f"XMP: {text}")
    return lines


_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _docx_paragraph_text(paragraph: ElementTree.Element) -> str:
    """Join a w:p element's runs into one string.

    Runs are joined with no separator (Word fragments sentences into many
    runs, sometimes mid-token); w:tab and w:br become whitespace so adjacent
    tokens do not fuse. A paragraph nested inside this one - a text box's
    content lives in a run of its host paragraph - is set off by line breaks
    on both sides, or its first and last words would fuse with the host's.
    The walk is iterative, so hostile nesting cannot exhaust the stack.
    """
    parts: list[str] = []
    stack: list[tuple[Iterator[ElementTree.Element], bool]] = [(iter(paragraph), False)]
    while stack:
        children, nested = stack[-1]
        node = next(children, None)
        if node is None:
            stack.pop()
            if nested and parts and parts[-1] != "\n":
                parts.append("\n")
            continue
        if node.tag == f"{_W}t":
            parts.append(node.text or "")
        elif node.tag == f"{_W}tab":
            parts.append("\t")
        elif node.tag in (f"{_W}br", f"{_W}cr"):
            parts.append("\n")
        is_paragraph = node.tag == f"{_W}p"
        if is_paragraph and parts and parts[-1] != "\n":
            parts.append("\n")
        stack.append((iter(node), is_paragraph))
    return "".join(parts).strip()


def _docx_children(element: Iterable[ElementTree.Element]) -> Iterator[ElementTree.Element]:
    """Yield ``element``'s children with block-level wrappers flattened away.

    Word wraps ordinary paragraphs, table rows and table cells in content
    controls (``w:sdt``, whose text lives in ``w:sdtContent``) and in custom-XML
    markup (``w:customXml``): cover pages, tables of contents, the page-number
    footer gallery and form templates are all built that way. Looking only at
    direct w:p/w:tbl/w:tr/w:tc children dropped that text without a warning.
    The walk is iterative, so hostile nesting cannot exhaust the stack.
    """
    stack = [iter(element)]
    while stack:
        for child in stack[-1]:
            if child.tag == f"{_W}sdt":
                content = child.find(f"{_W}sdtContent")
                if content is not None:
                    stack.append(iter(content))
                    break
            elif child.tag == f"{_W}customXml":
                stack.append(iter(child))
                break
            else:
                yield child
        else:
            stack.pop()


def _docx_row_text(row: ElementTree.Element) -> str:
    """Join a w:tr element's cells with ", " (mirrors the csv extractor)."""
    cells = []
    for cell in _docx_children(row):
        if cell.tag != f"{_W}tc":
            continue
        texts = (_docx_paragraph_text(p) for p in cell.iter(f"{_W}p"))
        cells.append(" ".join(t for t in texts if t))
    return ", ".join(cells).strip()


def _docx_deleted_texts(root: ElementTree.Element) -> list[str]:
    """Text of the tracked deletions in one part, one string per contiguous deletion.

    Deleted runs keep their text in ``w:delText`` (never ``w:t``), so the
    paragraph walk above never sees it -- yet it is still in the file, and
    Word shows it to anyone who turns on All Markup. Deleted runs that follow
    each other directly (Word splits a revision wherever formatting changes)
    are joined with no separator, like live runs; live text or a paragraph
    boundary ends a deletion.
    """
    segments: list[str] = []
    current: list[str] = []
    for node in root.iter():
        if node.tag == f"{_W}delText":
            current.append(node.text or "")
        elif node.tag in (f"{_W}t", f"{_W}p"):
            text = "".join(current).strip()
            if text:
                segments.append(text)
            current.clear()
        elif current and node.tag == f"{_W}tab":
            current.append("\t")
        elif current and node.tag in (f"{_W}br", f"{_W}cr"):
            current.append("\n")
    text = "".join(current).strip()
    if text:
        segments.append(text)
    return segments


# Header and footer parts are numbered by Word (word/header1.xml, ...); the
# numeric capture keeps their scan order numeric (header2 before header10),
# never the zip's listing order.
_DOCX_PART_RE = re.compile(r"^word/(header|footer)([1-9]\d*)\.xml$")

# Note-container parts: (part name, block kind). Each part holds one element
# per note, named after the kind (w:footnote, w:endnote, w:comment), and each
# of those wraps ordinary paragraphs and tables.
_DOCX_NOTE_PARTS = (
    ("word/footnotes.xml", "footnote"),
    ("word/endnotes.xml", "endnote"),
    ("word/comments.xml", "comment"),
)
_DOCX_NOTE_KINDS = frozenset(kind for _, kind in _DOCX_NOTE_PARTS)

# Embedded objects (an Excel sheet pasted into a report, an OLE object) are
# whole second documents in their own formats. They are not scanned, and each
# one is reported as not scanned, which fails the strict gate.
_DOCX_EMBEDDINGS_PREFIX = "word/embeddings/"
# Printer settings are a binary DEVMODE record, not document text.
_DOCX_PRINTER_PREFIX = "word/printerSettings/"
# An altChunk imports a whole other file (HTML, RTF, another DOCX) that Word
# merges into the body when it opens the document; its text is not in any XML
# part this extractor reads.
_ALTCHUNK_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk"
_RELS_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"


def _docx_unscanned_parts(
    names: list[str], rels: list[tuple[str, ElementTree.Element]]
) -> list[str]:
    """What the package carries that the extractor cannot read, one entry each.

    Embedded objects, imported altChunk content and other binary parts (macros,
    ActiveX controls) can all hold text; images are out of scope by design (no
    OCR) and printer settings hold none. Sorted, so output is deterministic.
    """
    found: list[str] = []
    for name in names:
        if name.endswith("/"):
            continue
        if name.startswith(_DOCX_EMBEDDINGS_PREFIX):
            found.append(f"embedded object {name}")
        elif name.lower().endswith(".bin") and not name.startswith(_DOCX_PRINTER_PREFIX):
            found.append(f"binary part {name}")
    for rels_name, root in rels:
        if not rels_name.startswith("word/_rels/"):
            continue
        for rel in root.iter(f"{_RELS_NS}Relationship"):
            if rel.get("Type") == _ALTCHUNK_TYPE:
                target = rel.get("Target", "")
                found.append(f"imported content word/{target.lstrip('/')}")
    return sorted(set(found))


# Document properties: author, last editor, company, manager, title, and any
# custom property a template or add-in stores. Word shows them under File >
# Info; none of them is part of the body.
_DOCX_PROPERTY_PARTS = ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml")


_HYPERLINK_FIELD_RE = re.compile(r'HYPERLINK\s+"([^"]+)"')


def _docx_link_targets(
    rels: list[tuple[str, ElementTree.Element]], parts: list[ElementTree.Element]
) -> list[str]:
    """Every external target the package points at, percent-decoded.

    A hyperlink's address is not in the text that shows ("our portal"): it is
    a TargetMode="External" relationship, and so is a template or image
    linked from a path on the author's machine. Word also writes hyperlinks
    as HYPERLINK field codes, whose target lives in w:instrText (or a
    w:fldSimple's w:instr) rather than any w:t.
    """
    targets = [
        unquote(rel.get("Target", ""))
        for _, root in rels
        for rel in root.iter(f"{_RELS_NS}Relationship")
        if rel.get("TargetMode") == "External" and rel.get("Target", "").strip()
    ]
    for root in parts:
        for paragraph in root.iter(f"{_W}p"):
            codes = [n.text or "" for n in paragraph.iter(f"{_W}instrText")]
            codes += [n.get(f"{_W}instr", "") for n in paragraph.iter(f"{_W}fldSimple")]
            targets.extend(unquote(t) for t in _HYPERLINK_FIELD_RE.findall("".join(codes)))
    return targets


_VML_NS = "{urn:schemas-microsoft-com:vml}"
_OFFICE_TITLE = "{urn:schemas-microsoft-com:office:office}title"


def _docx_alt_texts(parts: list[ElementTree.Element]) -> list[str]:
    """Distinct image and shape descriptions (alt text), in document order.

    Word stores them as attributes - ``descr``/``title`` on DrawingML
    ``docPr``/``cNvPr``, ``alt``/``o:title`` on legacy VML shapes - never as
    text runs, and fills them in itself ("A picture containing a person...")
    when the author does not. Duplicates (Word repeats a description on the
    picture's own ``cNvPr``) are reported once.
    """
    seen: dict[str, None] = {}
    for root in parts:
        for element in root.iter():
            name = _localname(element.tag)
            if name in ("docPr", "cNvPr"):
                values = (element.get("descr"), element.get("title"))
            elif element.tag.startswith(_VML_NS):
                values = (element.get("alt"), element.get(_OFFICE_TITLE))
            else:
                continue
            for value in values:
                if value and value.strip():
                    seen.setdefault(value.strip(), None)
    return list(seen)


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _docx_property_lines(name: str, root: ElementTree.Element) -> list[str]:
    """``property: value`` per non-empty document property in one docProps part."""
    lines: list[str] = []
    if name == "docProps/custom.xml":
        for prop in root:
            value = " ".join(t.strip() for t in prop.itertext() if t.strip())
            if value:
                lines.append(f"{prop.get('name', 'property')}: {value}")
        return lines
    for element in root.iter():
        if len(element) == 0 and element.text and element.text.strip():
            lines.append(f"{_localname(element.tag)}: {element.text.strip()}")
    return lines


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
    endnote/comment, so a finding names where in the document it lives); table
    rows are always ``row``, mirroring the csv extractor. Content controls and
    custom-XML wrappers are looked through; anything else (sectPr, ...) is
    structure, not text, and is skipped.
    """
    for element in _docx_children(container):
        if element.tag == f"{_W}p":
            text = _docx_paragraph_text(element)
            if text:
                blocks.append(Block(len(blocks), paragraph_kind, text))
        elif element.tag == f"{_W}tbl":
            for row in _docx_children(element):
                if row.tag != f"{_W}tr":
                    continue
                text = _docx_row_text(row)
                if text:
                    blocks.append(Block(len(blocks), "row", text))


def _docx_extra_parts(names: list[str]) -> list[tuple[str, str]]:
    """Deterministic (kind, part name) scan order for non-body parts.

    Headers first (numeric order), then footers, then footnotes, endnotes and
    comments -- a fixed order independent of how the zip happens to list its
    members, so block indexes (and the sanitized artifact built from them)
    never depend on which tool produced the archive.
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
    """Extract body paragraphs/table rows plus header, footer, note, comment and deleted text.

    Body blocks come first (their indexes match pre-1.2 output exactly), then
    headers, footers, footnotes, endnotes, comments, and finally the text of
    tracked deletions from all of those parts -- each new kind appended after
    the ones before it, so no existing block index moves.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            budget = _DOCX_MAX_XML_BYTES
            root, budget = _read_docx_xml(archive, "word/document.xml", budget)
            extras: list[tuple[str, ElementTree.Element]] = []
            names = archive.namelist()
            for kind, name in _docx_extra_parts(names):
                part_root, budget = _read_docx_xml(archive, name, budget)
                extras.append((kind, part_root))
            properties: list[tuple[str, ElementTree.Element]] = []
            for name in (n for n in _DOCX_PROPERTY_PARTS if n in names):
                part_root, budget = _read_docx_xml(archive, name, budget)
                properties.append((name, part_root))
            rels: list[tuple[str, ElementTree.Element]] = []
            for name in sorted(n for n in names if n.endswith(".rels")):
                part_root, budget = _read_docx_xml(archive, name, budget)
                rels.append((name, part_root))
            unscanned = _docx_unscanned_parts(names, rels)
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
        if kind in _DOCX_NOTE_KINDS:
            # Each w:footnote/w:endnote/w:comment wraps its own paragraphs;
            # Word's separator/continuationSeparator stub notes carry no text
            # and therefore produce no blocks.
            for note in part_root.findall(f"{_W}{kind}"):
                _docx_container_blocks(note, kind, blocks)
        else:
            _docx_container_blocks(part_root, kind, blocks)
    for part_root in (root, *(part for _, part in extras)):
        for text in _docx_deleted_texts(part_root):
            blocks.append(Block(len(blocks), "deletion", text))
    for name, part_root in properties:
        for line in _docx_property_lines(name, part_root):
            blocks.append(Block(len(blocks), "metadata", line))
    for target in _docx_link_targets(rels, [root, *(part for _, part in extras)]):
        blocks.append(Block(len(blocks), "link", target))
    for description in _docx_alt_texts([root, *(part for _, part in extras)]):
        blocks.append(Block(len(blocks), "alt_text", description))
    warnings = [] if blocks else ["no text blocks extracted"]
    warnings.extend(f"{NOT_SCANNED}{what}" for what in unscanned)
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
                warnings.append(f"{NOT_SCANNED}text part could not be decoded ({exc})")
                continue
            for paragraph in _extract_txt(str(body)):
                _add("paragraph", paragraph.text)
        elif content_type == "text/html":
            try:
                body = part.get_content()
            except Exception as exc:
                warnings.append(f"{NOT_SCANNED}html part could not be decoded ({exc})")
                continue
            for element in _extract_html(str(body)):
                _add("element", element.text)
        else:
            warnings.append(f"{NOT_SCANNED}attachment ({content_type})")

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
