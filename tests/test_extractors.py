"""Extraction tests for every supported input format, using committed fixtures."""

from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.annotations import FreeText, Link, Text
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

from docredact import extractors
from docredact.core import build_document
from docredact.extractors import (
    Block,
    ExtractionError,
    UnsupportedFormatError,
    detect_format,
    extract_blocks,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# The fixture builders live next to the fixtures; import them for crafted docs.
sys.path.insert(0, str(FIXTURES))
from make_fixtures import build_docx, build_pdf  # noqa: E402


def _blocks(name: str) -> tuple[list[Block], list[str]]:
    path = FIXTURES / name
    return extract_blocks(path.read_bytes(), detect_format(path))


def test_txt_paragraph_blocks() -> None:
    blocks, warnings = _blocks("sample.txt")
    assert warnings == []
    assert len(blocks) >= 3
    assert [b.index for b in blocks] == list(range(len(blocks)))
    assert all(b.kind == "paragraph" for b in blocks)
    assert "jane.doe@example.com" in "\n".join(b.text for b in blocks)


def test_md_section_blocks() -> None:
    blocks, _ = _blocks("sample.md")
    assert all(b.kind == "section" for b in blocks)
    assert blocks[0].text.startswith("# Synthetic")
    assert any("AKIAIOSFODNN7EXAMPLE" in b.text for b in blocks)


def test_html_blocks_strip_markup_scripts_styles() -> None:
    blocks, _ = _blocks("sample.html")
    joined = " ".join(b.text for b in blocks)
    assert "jane.doe@example.com" in joined
    assert "<" not in joined
    assert "apiHint" not in joined  # script content excluded
    assert "color:" not in joined  # style content excluded


def _html_text(html: str) -> str:
    blocks, _ = extract_blocks(html.encode(), "html")
    return " ".join(b.text for b in blocks)


def test_html_mailto_href_is_scanned() -> None:
    # The documented blind spot: an address living ONLY in the href, with
    # unrelated anchor text, used to vanish with the markup.
    joined = _html_text('<p>Reach <a href="mailto:hidden.contact@example.com">our team</a>.</p>')
    assert "hidden.contact@example.com" in joined


def test_html_fixture_mailto_target_is_extracted() -> None:
    blocks, _ = _blocks("sample.html")
    joined = " ".join(b.text for b in blocks)
    assert "hidden.support@example.com" in joined


def test_html_mailto_percent_encoding_and_query_addresses_are_decoded() -> None:
    # RFC 6068 allows percent-encoding and cc=/to= addresses in the query;
    # both must surface as scannable text, not stay hidden behind %40 or ?cc=.
    joined = _html_text(
        '<p><a href="MAILTO:jane%2Bops@example.com?cc=audit.trail@example.com'
        '&amp;subject=Account%20492">mail us</a></p>'
    )
    assert "jane+ops@example.com" in joined
    assert "audit.trail@example.com" in joined


def test_html_mailto_target_does_not_fuse_with_anchor_text() -> None:
    # The injected address must stay whitespace-separated: fused tokens would
    # mangle both addresses into one undetectable blob.
    joined = _html_text('<p><a href="mailto:a@example.com">b@example.com</a></p>')
    assert joined == "a@example.com b@example.com"


def test_html_non_mailto_hrefs_are_not_injected() -> None:
    assert _html_text('<p><a href="https://example.com/path">link</a></p>') == "link"


def test_html_anchor_without_href_is_harmless() -> None:
    assert _html_text('<p><a name="top">anchor</a> text</p>') == "anchor text"


def test_csv_row_blocks() -> None:
    blocks, _ = _blocks("sample.csv")
    assert all(b.kind == "row" for b in blocks)
    assert blocks[0].text == "name, email, phone, card, note"
    assert "4111111111111111" in blocks[1].text


def test_pdf_page_blocks() -> None:
    blocks, warnings = _blocks("sample.pdf")
    assert warnings == []
    assert [b.kind for b in blocks] == ["page", "page", "page"]
    assert "jane.doe@example.com" in blocks[0].text
    assert "AKIAIOSFODNN7EXAMPLE" in blocks[1].text
    assert "4111111111111111" in blocks[2].text


def test_docx_paragraph_and_row_blocks() -> None:
    blocks, warnings = _blocks("sample.docx")
    assert warnings == []
    assert [b.index for b in blocks] == list(range(len(blocks)))
    kinds = [b.kind for b in blocks]
    assert "paragraph" in kinds and "row" in kinds
    paragraphs = [b.text for b in blocks if b.kind == "paragraph"]
    assert any("AKIAIOSFODNN7EXAMPLE" in t for t in paragraphs)
    rows = [b.text for b in blocks if b.kind == "row"]
    assert rows[0] == "name, email, card"
    assert any("4111111111111111" in t for t in rows)


def test_docx_joins_runs_within_a_paragraph() -> None:
    # The fixture splits the email across two <w:r> runs; the extractor must
    # join runs with no separator or the entity is undetectable.
    blocks, _ = _blocks("sample.docx")
    assert any("jane.doe@example.com" in b.text for b in blocks if b.kind == "paragraph")


# -- DOCX headers / footers / footnotes / endnotes --------------------------------

_W_XMLNS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
_WP = "<w:p><w:r><w:t>%s</w:t></w:r></w:p>"


def _mini_docx(parts: dict[str, str]) -> bytes:
    """A crafted DOCX zip with exactly the given member parts."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in parts.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _mini_document(body: str = "") -> str:
    return f"<w:document {_W_XMLNS}><w:body>{body}</w:body></w:document>"


def test_docx_header_footer_footnote_blocks_are_extracted() -> None:
    blocks, warnings = _blocks("sample.docx")
    assert warnings == []
    by_kind: dict[str, str] = {}
    for block in blocks:
        by_kind[block.kind] = by_kind.get(block.kind, "") + " " + block.text
    assert "header.owner@example.com" in by_kind["header"]
    assert "+1-555-0177" in by_kind["footer"]
    assert "ghp_0123456789abcdefghijklmnopqrstuvwxyz" in by_kind["footnote"]


def test_docx_body_blocks_keep_their_indexes_and_come_first() -> None:
    # New coverage appends AFTER the body, so existing block indexes (and the
    # committed showcase artifacts built from them) stay stable.
    blocks, _ = _blocks("sample.docx")
    assert [b.index for b in blocks] == list(range(len(blocks)))
    ranks = {"paragraph": 0, "row": 0, "header": 1, "footer": 2, "footnote": 3}
    order = [ranks[b.kind] for b in blocks]
    assert order == sorted(order)


def test_docx_header_footer_footnote_findings_reach_the_report() -> None:
    doc = build_document(FIXTURES / "sample.docx")
    entities = doc["entities"]
    assert isinstance(entities, list)
    values = {e["value"] for e in entities}
    assert "header.owner@example.com" in values  # header-only email
    assert "+1-555-0177" in values  # footer-only phone
    assert "ghp_0123456789abcdefghijklmnopqrstuvwxyz" in values  # footnote-only token


def test_docx_endnotes_are_scanned_too() -> None:
    data = build_docx(
        (("body text",),), (), endnotes=("Endnote contact endnote.owner@example.com",)
    )
    blocks, _ = extract_blocks(data, "docx")
    endnotes = [b.text for b in blocks if b.kind == "endnote"]
    assert endnotes == ["Endnote contact endnote.owner@example.com"]


def test_docx_footnote_separator_stubs_yield_no_blocks() -> None:
    # Word always writes separator/continuationSeparator stub notes (ids -1, 0);
    # they carry no text and must not become empty blocks.
    data = build_docx((("body",),), (), footnotes=("only real note",))
    blocks, _ = extract_blocks(data, "docx")
    assert [b.text for b in blocks if b.kind == "footnote"] == ["only real note"]


def test_docx_multiple_header_parts_sort_numerically() -> None:
    # header10.xml must come after header2.xml: numeric part order, not the
    # lexicographic zip-listing order (which would also differ between tools).
    data = _mini_docx(
        {
            "word/document.xml": _mini_document(_WP % "body"),
            "word/header10.xml": f"<w:hdr {_W_XMLNS}>{_WP % 'tenth'}</w:hdr>",
            "word/header2.xml": f"<w:hdr {_W_XMLNS}>{_WP % 'second'}</w:hdr>",
        }
    )
    blocks, _ = extract_blocks(data, "docx")
    assert [b.text for b in blocks if b.kind == "header"] == ["second", "tenth"]


def test_docx_table_rows_inside_headers_are_scanned() -> None:
    header = (
        f"<w:hdr {_W_XMLNS}><w:tbl><w:tr>"
        f"<w:tc>{_WP % 'owner'}</w:tc><w:tc>{_WP % 'table.cell@example.com'}</w:tc>"
        f"</w:tr></w:tbl></w:hdr>"
    )
    data = _mini_docx(
        {"word/document.xml": _mini_document(_WP % "body"), "word/header1.xml": header}
    )
    blocks, _ = extract_blocks(data, "docx")
    rows = [b.text for b in blocks if b.kind == "row"]
    assert rows == ["owner, table.cell@example.com"]


def test_docx_dtd_in_header_part_is_rejected() -> None:
    # The XXE / entity-expansion guard covers EVERY scanned XML part, not just
    # the body: a DOCTYPE hidden in a header must be refused, not parsed.
    evil = (
        '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "y">]>'
        f"<w:hdr {_W_XMLNS}>{_WP % '&x;'}</w:hdr>"
    )
    data = _mini_docx(
        {"word/document.xml": _mini_document(_WP % "body"), "word/header1.xml": evil}
    )
    with pytest.raises(ExtractionError, match="header1.xml"):
        extract_blocks(data, "docx")


def test_docx_bad_xml_in_footer_part_is_a_clean_error() -> None:
    # A scanner that silently skipped an unparseable footer would hide exactly
    # the findings this feature exists to surface: fail closed instead.
    data = _mini_docx(
        {
            "word/document.xml": _mini_document(_WP % "body"),
            "word/footer1.xml": "<w:ftr this is not xml",
        }
    )
    with pytest.raises(ExtractionError, match="footer1.xml"):
        extract_blocks(data, "docx")


def test_docx_aggregate_cap_spans_supplementary_parts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The decompression-bomb budget is aggregate across ALL scanned XML parts:
    # a document.xml and a header each under the cap must still be rejected
    # when their sum is over it, or N parts would multiply the ceiling by N.
    monkeypatch.setattr(extractors, "_DOCX_MAX_XML_BYTES", 1_000)
    body = _mini_document(_WP % ("A" * 800))
    header = f"<w:hdr {_W_XMLNS}>{_WP % ('B' * 800)}</w:hdr>"
    assert len(body) <= 1_000 and len(header) <= 1_000  # each fits alone
    data = _mini_docx({"word/document.xml": body, "word/header1.xml": header})
    with pytest.raises(ExtractionError, match="decompression bomb"):
        extract_blocks(data, "docx")


def test_docx_bomb_in_footnotes_part_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # The header-size check + bounded read apply to supplementary parts too: a
    # tiny zip whose footnotes.xml decompresses huge is rejected, not slurped.
    monkeypatch.setattr(extractors, "_DOCX_MAX_XML_BYTES", 1_000_000)
    bomb = (
        f"<w:footnotes {_W_XMLNS}><!-- ".encode()
        + b"A" * 5_000_000
        + b" --></w:footnotes>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", _mini_document(_WP % "body"))
        archive.writestr("word/footnotes.xml", bomb)
    assert len(buffer.getvalue()) < 100_000
    with pytest.raises(ExtractionError, match="decompression bomb"):
        extract_blocks(buffer.getvalue(), "docx")


# -- DOCX content controls, tracked deletions, comments, embedded objects -------


def _sdt(inner: str) -> str:
    """Wrap ``inner`` in a content control, the way Word writes one."""
    return f"<w:sdt><w:sdtPr><w:alias w:val='c'/></w:sdtPr><w:sdtContent>{inner}</w:sdtContent></w:sdt>"


def test_docx_content_controls_are_scanned() -> None:
    # Cover pages, tables of contents and form templates wrap ordinary
    # paragraphs, rows and cells in content controls (w:sdt) or custom-XML
    # markup. That text is on the page, and it was dropped without a warning.
    cell = f"<w:tc>{_WP % 'cell'}</w:tc>"
    secret_cell = f"<w:tc>{_WP % 'AKIAIOSFODNN7EXAMPLE'}</w:tc>"
    body = (
        _WP % "first"
        + _sdt(_WP % "control jane.doe@example.com")
        + f"<w:customXml w:element='x'>{_WP % 'custom'}</w:customXml>"
        + "<w:tbl><w:tblPr/>"
        + _sdt(f"<w:tr>{cell}</w:tr>")
        + f"<w:tr>{cell}{_sdt(secret_cell)}</w:tr>"
        + "</w:tbl>"
        + _sdt(_sdt(_WP % "nested"))
        + _WP % "last"
    )
    data = _mini_docx({"word/document.xml": _mini_document(body)})
    blocks, warnings = extract_blocks(data, "docx")
    assert warnings == []
    assert [(b.kind, b.text) for b in blocks] == [
        ("paragraph", "first"),
        ("paragraph", "control jane.doe@example.com"),
        ("paragraph", "custom"),
        ("row", "cell"),
        ("row", "cell, AKIAIOSFODNN7EXAMPLE"),
        ("paragraph", "nested"),
        ("paragraph", "last"),
    ]


def test_docx_content_control_in_footer_is_scanned() -> None:
    # Word's page-number footer gallery puts the whole footer in a content control.
    footer = f"<w:ftr {_W_XMLNS}>{_sdt(_WP % 'Page 1 - footer.owner@example.com')}</w:ftr>"
    data = _mini_docx(
        {"word/document.xml": _mini_document(_WP % "body"), "word/footer1.xml": footer}
    )
    blocks, _ = extract_blocks(data, "docx")
    assert [b.text for b in blocks if b.kind == "footer"] == ["Page 1 - footer.owner@example.com"]


def test_docx_deeply_nested_content_controls_do_not_crash() -> None:
    # The unwrapping is iterative, so hostile nesting cannot hit the recursion limit.
    depth = 5_000
    body = "<w:sdt><w:sdtContent>" * depth + _WP % "deep" + "</w:sdtContent></w:sdt>" * depth
    blocks, _ = extract_blocks(_mini_docx({"word/document.xml": _mini_document(body)}), "docx")
    assert [b.text for b in blocks] == ["deep"]


def _deleted(text: str) -> str:
    return f"<w:del w:id='1' w:author='A'><w:r><w:delText>{text}</w:delText></w:r></w:del>"


def test_docx_tracked_deletions_are_scanned() -> None:
    # Deleted text stays in the file as w:delText and shows to anyone who turns
    # on All Markup, but it was never read: a card number deleted with Track
    # Changes on passed --redact strict.
    body = (
        "<w:p><w:r><w:t>Card: </w:t></w:r>"
        + _deleted("4111 1111 ")
        + _deleted("1111 1111")  # a second revision directly after the first
        + "<w:r><w:t>[removed]</w:t></w:r>"
        + _deleted("old.owner@example.com")  # separated by live text: its own block
        + "</w:p>"
        + _WP % "after"
    )
    data = _mini_docx({"word/document.xml": _mini_document(body)})
    blocks, warnings = extract_blocks(data, "docx")
    assert warnings == []
    # The live text is unchanged, and the deleted text comes after everything
    # else (so no existing block index moves), one block per contiguous deletion.
    assert [(b.kind, b.text) for b in blocks] == [
        ("paragraph", "Card: [removed]"),
        ("paragraph", "after"),
        ("deletion", "4111 1111 1111 1111"),
        ("deletion", "old.owner@example.com"),
    ]


def test_docx_tracked_deletion_findings_reach_the_report(tmp_path: Path) -> None:
    footer = f"<w:ftr {_W_XMLNS}><w:p>{_deleted('AKIAIOSFODNN7EXAMPLE')}</w:p></w:ftr>"
    body = _mini_document(f"<w:p>{_deleted('4111111111111111')}</w:p>")
    path = tmp_path / "revised.docx"
    path.write_bytes(_mini_docx({"word/document.xml": body, "word/footer1.xml": footer}))
    doc = build_document(path, redact="strict")
    found = {(e["type"], e["value"]) for e in doc["entities"]}  # type: ignore[union-attr]
    assert found == {("credit_card", "4111111111111111"), ("api_key", "AKIAIOSFODNN7EXAMPLE")}


def test_docx_comments_are_scanned() -> None:
    comments = (
        f"<w:comments {_W_XMLNS}><w:comment w:id='0' w:author='Reviewer'>"
        + _WP % "Ask reviewer.one@example.com before sending"
        + "</w:comment></w:comments>"
    )
    data = build_docx((("body",),), (), footnotes=("a note",))
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        parts = {name: source.read(name).decode() for name in source.namelist()}
    parts["word/comments.xml"] = comments
    blocks, _ = extract_blocks(_mini_docx(parts), "docx")
    # Comments come after the notes, so no earlier block index moves.
    assert [b.kind for b in blocks][-2:] == ["footnote", "comment"]
    assert blocks[-1].text == "Ask reviewer.one@example.com before sending"


def test_docx_embedded_objects_warn_that_they_were_not_scanned() -> None:
    # An embedded workbook is a second document that is not scanned, so
    # "0 findings" must not read as a clean bill of health for it.
    data = _mini_docx(
        {
            "word/document.xml": _mini_document(_WP % "body"),
            "word/embeddings/Microsoft_Excel_Worksheet.xlsx": "PK",
            "word/embeddings/oleObject1.bin": "ole",
            "word/media/image1.png": "png",
        }
    )
    _, warnings = extract_blocks(data, "docx")
    assert warnings == ["embedded object skipped (not scanned)"] * 2


def test_docx_not_a_zip_raises(tmp_path: Path) -> None:
    path = tmp_path / "broken.docx"
    path.write_bytes(b"this is not a zip archive")
    with pytest.raises(ExtractionError):
        extract_blocks(path.read_bytes(), detect_format(path))


def test_docx_zip_without_document_xml_raises() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("mimetype", "application/zip")
    with pytest.raises(ExtractionError):
        extract_blocks(buffer.getvalue(), "docx")


def test_docx_with_dtd_is_rejected() -> None:
    # XXE / entity-expansion guard: any DOCTYPE or ENTITY declaration in
    # word/document.xml must be refused, not parsed.
    evil = (
        '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "y">]>'
        '<w:document xmlns:w='
        '"http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", evil)
    with pytest.raises(ExtractionError):
        extract_blocks(buffer.getvalue(), "docx")


def test_docx_detector_integration() -> None:
    doc = build_document(FIXTURES / "sample.docx")
    assert doc["format"] == "docx"
    types = {e["type"] for e in doc["entities"]}  # type: ignore[index]
    assert {"email", "phone", "api_key", "credit_card", "person_name"} <= types
    emails = [
        e["value"]
        for e in doc["entities"]  # type: ignore[union-attr]
        if e["type"] == "email"
    ]
    assert "jane.doe@example.com" in emails


def test_csv_oversized_field_raises_extraction_error() -> None:
    # A single CSV field larger than the stdlib csv field-size limit (~128 KB)
    # raises csv.Error mid-iteration. That must surface as an ExtractionError
    # (clean exit 1), not an uncaught crash that aborts a whole `scan` batch
    # and prints a path-leaking traceback.
    data = b'"' + b"a" * 200_000 + b'"'
    with pytest.raises(ExtractionError):
        extract_blocks(data, "csv")


def test_unsupported_extension_raises(tmp_path: Path) -> None:
    path = tmp_path / "sample.xyz"
    path.write_text("hello", encoding="utf-8")
    with pytest.raises(UnsupportedFormatError):
        detect_format(path)


def test_build_document_schema_basics(tmp_path: Path) -> None:
    path = tmp_path / "tiny.txt"
    path.write_bytes(b"hello world\n")
    doc = build_document(path)
    assert doc["source"] == "tiny.txt"
    assert doc["format"] == "txt"
    assert doc["size_bytes"] == 12
    assert doc["sha256"] == hashlib.sha256(b"hello world\n").hexdigest()
    assert doc["generated_at"] is None
    assert doc["entities"] == []


def test_build_document_empty_file_warns(tmp_path: Path) -> None:
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    doc = build_document(path)
    assert doc["blocks"] == []
    assert "no text blocks extracted" in doc["warnings"]


def test_utf16_input_is_decoded_by_its_bom(tmp_path: Path) -> None:
    # Windows tooling (Notepad, PowerShell redirection, Excel's "Unicode Text"
    # export) writes UTF-16 with a BOM routinely. Decoding those bytes as UTF-8
    # does not fail loudly: every ASCII character comes back interleaved with
    # U+0000, so no detector can match and the document scans as ZERO findings
    # with ZERO warnings - a strict gate passes a file holding a plaintext AWS
    # key. A BOM states the encoding unambiguously, so honour it.
    path = tmp_path / "u16.txt"
    path.write_bytes(
        "contact jane.doe@example.com key AKIAIOSFODNN7EXAMPLE\n".encode("utf-16")
    )
    doc = build_document(path)
    blocks = doc["blocks"]
    assert isinstance(blocks, list)
    assert "\x00" not in blocks[0]["text"]
    entities = doc["entities"]
    assert isinstance(entities, list)
    assert {e["type"] for e in entities} >= {"email", "api_key"}


def test_undecodable_bytes_warn_instead_of_scanning_clean(tmp_path: Path) -> None:
    # Anything that is not valid UTF-8 and carries no BOM is still scanned on a
    # best-effort basis, but the report must SAY the input could not be decoded
    # cleanly. Without that, "0 findings" is indistinguishable from "0 findings
    # in the text I could actually read".
    data = b"mail jane\xff\xfe.doe@example.com\n"
    blocks, warnings = extract_blocks(data, "txt")
    assert blocks
    assert any("not valid" in w for w in warnings)


def test_pdf_aggregate_output_cap_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # DoS regression: pypdf caps decompression PER STREAM only, so a small
    # multi-page PDF that re-emits shared content can amplify to 100 M chars
    # and burn minutes of CPU. _extract_pdf now bounds the AGGREGATE extracted
    # text across pages. Lower the cap so a tiny, fast-to-build PDF trips the
    # same guard (no multi-minute repro baked into the suite).
    monkeypatch.setattr(extractors, "_PDF_MAX_TEXT_CHARS", 100)
    data = build_pdf(tuple(("X" * 60, "Y" * 60) for _ in range(10)))
    with pytest.raises(ExtractionError, match="aggregate cap"):
        extract_blocks(data, "pdf")


def test_pdf_page_count_cap_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # A page-count sanity ceiling bounds the per-page loop even before any text
    # is extracted. Lower it so a small multi-page PDF exercises the guard.
    monkeypatch.setattr(extractors, "_PDF_MAX_PAGES", 3)
    data = build_pdf(tuple(("page",) for _ in range(5)))
    with pytest.raises(ExtractionError, match="too many pages"):
        extract_blocks(data, "pdf")


# -- PDF annotations, form fields, embedded files ---------------------------------


def _pdf_with(
    annotations: tuple[tuple[int, Any], ...] = (),
    fields: tuple[tuple[str, Any], ...] = (),
    attachment: bytes | None = None,
) -> bytes:
    """The two-page fixture-style PDF plus annotations, filled form fields and a file.

    ``fields`` are (field name, /V value) pairs, each written as a text-field
    widget on page 0 and listed in the AcroForm, the way a filled form is saved.
    """
    base = build_pdf((("page one",), ("page two",)))
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(base)))
    for page_number, annotation in annotations:
        writer.add_annotation(page_number, annotation)
    widgets = ArrayObject()
    for name, value in fields:
        widget = DictionaryObject(
            {
                NameObject("/Type"): NameObject("/Annot"),
                NameObject("/Subtype"): NameObject("/Widget"),
                NameObject("/FT"): NameObject("/Tx"),
                NameObject("/T"): TextStringObject(name),
                NameObject("/V"): value,
                NameObject("/Rect"): ArrayObject([NumberObject(n) for n in (72, 600, 272, 620)]),
            }
        )
        widgets.append(writer._add_object(widget))
    if fields:
        writer.pages[0][NameObject("/Annots")] = widgets
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject(
            {NameObject("/Fields"): widgets}
        )
    if attachment is not None:
        writer.add_attachment("notes.txt", attachment)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def test_pdf_annotation_text_is_scanned(tmp_path: Path) -> None:
    # A FreeText box is drawn on the page and a sticky note opens with one
    # click, but neither is in the page content stream that extract_text reads.
    data = _pdf_with(
        (
            (1, FreeText(text="Key AKIAIOSFODNN7EXAMPLE", rect=(72, 500, 272, 540))),
            (0, Text(text="Reviewer: call +1-555-0142", rect=(72, 500, 92, 520))),
        )
    )
    blocks, warnings = extract_blocks(data, "pdf")
    assert warnings == []
    # Page blocks keep index == page number; annotations follow in page order.
    assert [(b.kind, b.text) for b in blocks] == [
        ("page", "page one"),
        ("page", "page two"),
        ("annotation", "Reviewer: call +1-555-0142"),
        ("annotation", "Key AKIAIOSFODNN7EXAMPLE"),
    ]
    path = tmp_path / "reviewed.pdf"
    path.write_bytes(data)
    found = {e["type"] for e in build_document(path)["entities"]}  # type: ignore[union-attr]
    assert found == {"phone", "api_key"}


def test_pdf_annotation_text_pypdf_cannot_decode_is_still_scanned() -> None:
    # UTF-8 written straight into a PDF string (common, and not PDFDocEncoding)
    # comes back from pypdf as raw bytes; it must be decoded, not dropped.
    note = Text(text="placeholder", rect=(72, 500, 92, 520))
    note[NameObject("/Contents")] = ByteStringObject(
        "café bytes.owner@example.com \x9f".encode()
    )
    blocks, _ = extract_blocks(_pdf_with(((0, note),)), "pdf")
    assert [b.text for b in blocks if b.kind == "annotation"] == [
        "café bytes.owner@example.com \x9f"
    ]


def test_pdf_link_mailto_target_is_scanned() -> None:
    # The PDF twin of the HTML mailto: rule: the address behind "Contact us"
    # is percent-decoded and scanned; other link targets are not injected.
    data = _pdf_with(
        (
            (0, Link(rect=(72, 500, 272, 520), url="mailto:hidden%40example.com?cc=cc@example.com")),
            (0, Link(rect=(72, 400, 272, 420), url="https://example.com/help")),
        )
    )
    blocks, _ = extract_blocks(data, "pdf")
    annotations = [b.text for b in blocks if b.kind == "annotation"]
    assert annotations == ["hidden@example.com?cc=cc@example.com"]


def test_pdf_filled_form_field_values_are_scanned(tmp_path: Path) -> None:
    # A filled form shows its values through widget appearance streams, not the
    # page content, so every typed-in email or phone number was invisible.
    data = _pdf_with(
        fields=(
            ("email", TextStringObject("jane.doe@example.com")),
            ("agree", NameObject("/Yes")),  # a checkbox state is not text
            ("cc", ArrayObject([TextStringObject("a@example.com"), TextStringObject("b@example.com")])),
            ("empty", TextStringObject("")),
        )
    )
    blocks, warnings = extract_blocks(data, "pdf")
    assert warnings == []
    assert [(b.kind, b.text) for b in blocks if b.kind != "page"] == [
        ("field", "email: jane.doe@example.com"),
        ("field", "cc: a@example.com, b@example.com"),
    ]
    path = tmp_path / "form.pdf"
    path.write_bytes(data)
    values = {e["value"] for e in build_document(path)["entities"]}  # type: ignore[union-attr]
    assert values == {"jane.doe@example.com", "a@example.com", "b@example.com"}


def test_pdf_embedded_file_warns_that_it_was_not_scanned() -> None:
    data = _pdf_with(attachment=b"AKIAIOSFODNN7EXAMPLE")
    blocks, warnings = extract_blocks(data, "pdf")
    assert warnings == ["embedded file skipped (not scanned)"]
    assert [b.kind for b in blocks] == ["page", "page"]


def test_pdf_annotation_text_counts_toward_the_aggregate_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Annotations can share one string object, so they are held to the same
    # aggregate ceiling as page text rather than getting a free pass.
    monkeypatch.setattr(extractors, "_PDF_MAX_TEXT_CHARS", 100)
    data = _pdf_with(((0, Text(text="Z" * 120, rect=(72, 500, 92, 520))),))
    with pytest.raises(ExtractionError, match="aggregate cap"):
        extract_blocks(data, "pdf")


def test_pdf_normal_document_is_unaffected() -> None:
    # The real caps must never trigger on an ordinary document.
    blocks, warnings = _blocks("sample.pdf")
    assert warnings == []
    assert len(blocks) == 3


def test_docx_decompression_bomb_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # DoS regression: a ~KB DOCX whose word/document.xml decompresses to ~1 GB
    # forced multi-GB heap. _extract_docx now rejects an over-cap uncompressed
    # size (from the zip header) before reading. Build a small, highly
    # compressible member and lower the cap so the guard fires fast.
    monkeypatch.setattr(extractors, "_DOCX_MAX_XML_BYTES", 1_000_000)
    bomb = (
        b'<?xml version="1.0"?><w:document xmlns:w='
        b'"http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b"<w:body><!-- " + b"A" * 5_000_000 + b" --></w:body></w:document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", bomb)
    # The ZIP itself is tiny; only the decompressed member is huge.
    assert len(buffer.getvalue()) < 100_000
    with pytest.raises(ExtractionError, match="decompression bomb"):
        extract_blocks(buffer.getvalue(), "docx")


def test_docx_bounded_read_defeats_lying_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A hostile ZIP can advertise a small uncompressed size in its header. The
    # bounded read (read cap+1, reject if larger) means a lying header cannot
    # bypass the guard: extraction still ends in a clean ExtractionError, never
    # an unbounded allocation.
    monkeypatch.setattr(extractors, "_DOCX_MAX_XML_BYTES", 500_000)
    body = b"<root>" + b"ABCD" * 500_000 + b"</root>"  # ~2 MB, over the cap
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("word/document.xml", body)

    real_zipfile = extractors.zipfile.ZipFile

    class _LyingZip(real_zipfile):  # type: ignore[valid-type,misc]
        def getinfo(self, name: str) -> zipfile.ZipInfo:
            info = super().getinfo(name)
            info.file_size = 5  # lie: claim tiny to skip the header check
            return info

    monkeypatch.setattr(extractors.zipfile, "ZipFile", _LyingZip)
    with pytest.raises(ExtractionError):
        extract_blocks(buffer.getvalue(), "docx")


def test_docx_normal_document_is_unaffected() -> None:
    # The real 100 MB cap must never trigger on an ordinary DOCX.
    blocks, warnings = _blocks("sample.docx")
    assert warnings == []
    assert len(blocks) > 0
