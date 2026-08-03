"""Extraction tests for every supported input format, using committed fixtures."""

from __future__ import annotations

import hashlib
import io
import sys
import zipfile
from pathlib import Path

import pytest

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
