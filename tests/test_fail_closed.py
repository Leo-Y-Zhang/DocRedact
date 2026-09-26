"""Fail closed on content that was not scanned.

A gate that did not read part of a file did not check it. Every piece of content the
extractors know they skipped - an embedded file, an image-only page, a page pypdf
could not parse, text in a font with no Unicode mapping, bytes that are not valid
text, an e-mail attachment - is reported as a warning starting with ``not scanned:``,
and ``--redact strict`` treats any such warning like a parse error: exit 1, outranking
both a finding (3) and a fresh ``--write-baseline`` (0). Report and mask modes still
produce their output, with the warning in it.

Every document here is synthetic: example.com addresses, the documented AWS example
key, and Luhn test card numbers.
"""
from __future__ import annotations

import io
import json
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

import pytest
from pypdf import PdfReader, PdfWriter

from conftest import FIXTURES
from docredact.extractors import NOT_SCANNED, extract_blocks

sys.path.insert(0, str(FIXTURES))
from make_fixtures import build_docx, build_pdf  # noqa: E402

_KEY = "AKIAIOSFODNN7EXAMPLE"


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "docredact", *argv],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def _raw_pdf(content: bytes, *, resources: bytes = b"", extra: tuple[bytes, ...] = (),
             stream_dict: bytes = b"", font: bytes = b"") -> bytes:
    """A one-page PDF with the given content stream (objects 1-5, then ``extra``)."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 5 0 R >> " + resources + b">> /Contents 4 0 R >>",
        b"<< /Length %d %s>>\nstream\n%s\nendstream" % (len(content), stream_dict, content),
        font or b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        *extra,
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, xref,
    )
    return bytes(out)


def _image_only_pdf() -> bytes:
    image = (
        b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray "
        b"/BitsPerComponent 8 /Length 1 >>\nstream\n\x80\nendstream"
    )
    return _raw_pdf(b"q 612 0 0 792 0 0 cm /Im1 Do Q",
                    resources=b"/XObject << /Im1 6 0 R >> ", extra=(image,))


def _broken_page_pdf() -> bytes:
    # A truncated Flate stream: pypdf raises while reading the page.
    packed = zlib.compress(f"BT /F1 12 Tf 72 700 Td ({_KEY}) Tj ET".encode())
    return _raw_pdf(packed[: len(packed) // 2], stream_dict=b"/Filter /FlateDecode ")


def _unmapped_font_pdf() -> bytes:
    # A subset CID font with the Identity encoding and no ToUnicode map: pypdf
    # "extracts" the glyph ids as if they were characters, so the page yields
    # garbage and no detector can match what was printed.
    descendant = (
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /ABCDEF+Custom "
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> >>"
    )
    font = (
        b"<< /Type /Font /Subtype /Type0 /BaseFont /ABCDEF+Custom "
        b"/Encoding /Identity-H /DescendantFonts [6 0 R] >>"
    )
    return _raw_pdf(b"BT /F1 12 Tf 72 700 Td <0024002600270028> Tj ET",
                    font=font, extra=(descendant,))


def _replacement_char_pdf() -> bytes:
    # A font whose encoding and ToUnicode map pypdf cannot load: the text comes
    # back as U+FFFD replacement characters.
    font = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Custom /FirstChar 32 "
        b"/Widths 99 0 R /Encoding /NoSuchEncoding /ToUnicode 98 0 R >>"
    )
    return _raw_pdf(f"BT /F1 12 Tf 72 700 Td ({_KEY}) Tj ET".encode(), font=font)


def _pdf_with_attachment() -> bytes:
    writer = PdfWriter(clone_from=PdfReader(io.BytesIO(build_pdf((("cover page",),)))))
    writer.add_attachment("keys.txt", _KEY.encode())
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _docx_with(extra: dict[str, bytes], rels: str = "") -> bytes:
    base = build_docx((("see the attached material",),), ())
    with zipfile.ZipFile(io.BytesIO(base)) as source:
        parts = {name: source.read(name) for name in source.namelist()}
    parts.update(extra)
    if rels:
        parts["word/_rels/document.xml.rels"] = (
            '<?xml version="1.0"?><Relationships xmlns='
            '"http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{rels}</Relationships>"
        ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in parts.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


_EML_ATTACHMENT = (
    "From: sender@example.com\nSubject: s\nMIME-Version: 1.0\n"
    'Content-Type: multipart/mixed; boundary="B"\n\n'
    "--B\nContent-Type: text/plain\n\nsee attached\n"
    "--B\nContent-Type: application/pdf\n"
    'Content-Disposition: attachment; filename="k.pdf"\n\nxyz\n--B--\n'
)

# name -> (file name, bytes, the gap warning that must be reported)
_GAPS: dict[str, tuple[str, bytes, str]] = {
    "pdf attachment": ("a.pdf", _pdf_with_attachment(), "embedded file keys.txt"),
    "image-only page": ("s.pdf", _image_only_pdf(), "page 0 has no extractable text"),
    "unreadable page": ("b.pdf", _broken_page_pdf(), "page 0: text extraction failed"),
    "unmapped font": ("f.pdf", _unmapped_font_pdf(), "page 0: text in font F1 cannot be mapped"),
    "replacement characters": (
        "r.pdf", _replacement_char_pdf(), "page 0: some text could not be decoded"
    ),
    "docx embedded workbook": (
        "e.docx",
        _docx_with({"word/embeddings/Microsoft_Excel_Worksheet.xlsx": b"PK"}),
        "embedded object word/embeddings/Microsoft_Excel_Worksheet.xlsx",
    ),
    "docx macros": (
        "m.docx", _docx_with({"word/vbaProject.bin": b"\xd0\xcf"}), "binary part word/vbaProject.bin"
    ),
    "docx imported chunk": (
        "c.docx",
        _docx_with(
            {"word/afchunk.htm": f"<p>{_KEY}</p>".encode()},
            '<Relationship Id="rIdChunk" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/aFChunk" Target="afchunk.htm"/>',
        ),
        "imported content word/afchunk.htm",
    ),
    "eml attachment": ("m.eml", _EML_ATTACHMENT.encode(), "attachment (application/pdf)"),
    "undecodable text": ("l.txt", "caf\xe9 menu".encode("cp1252"), "input is not valid utf-8"),
    "utf-16 without bom": (
        "u.txt", f"key {_KEY}\n".encode("utf-16-le"), "input contains NUL bytes"
    ),
}


@pytest.mark.parametrize("case", sorted(_GAPS))
def test_unscanned_content_is_reported(case: str) -> None:
    name, data, expected = _GAPS[case]
    _, warnings = extract_blocks(data, name.rsplit(".", 1)[1])
    gaps = [w for w in warnings if w.startswith(NOT_SCANNED)]
    assert any(expected in w for w in gaps), warnings


@pytest.mark.parametrize("case", sorted(_GAPS))
def test_strict_extract_fails_closed(tmp_path: Path, case: str) -> None:
    name, data, expected = _GAPS[case]
    path = tmp_path / name
    path.write_bytes(data)
    strict = _run("extract", str(path), "--redact", "strict")
    assert strict.returncode == 1, strict.stderr
    assert f"docredact: error: {NOT_SCANNED}" in strict.stderr
    assert expected in strict.stderr
    json.loads(strict.stdout)  # the report is still written
    # Report mode is a report, not a verdict: it still exits 0 and carries the gap.
    report = _run("extract", str(path))
    assert report.returncode == 0, report.stderr
    assert any(expected in w for w in json.loads(report.stdout)["warnings"])


def test_strict_gap_outranks_a_fresh_baseline(tmp_path: Path) -> None:
    path = tmp_path / "s.pdf"
    path.write_bytes(_image_only_pdf())
    proc = _run("extract", str(path), "--redact", "strict",
                "--write-baseline", str(tmp_path / "b.json"))
    assert proc.returncode == 1


def test_scan_strict_fails_closed_and_names_the_file(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "notes.txt").write_text("contact a@example.com\n", encoding="utf-8")
    (root / "scan.pdf").write_bytes(_image_only_pdf())
    strict = _run("scan", str(root), "--redact", "strict", "--format", "jsonl")
    assert strict.returncode == 1  # outranks the finding's 3
    assert [json.loads(line)["path"] for line in strict.stdout.splitlines()] == ["notes.txt"]
    assert "docredact: error: scan.pdf: not fully scanned" in strict.stderr
    baseline = _run("scan", str(root), "--redact", "strict",
                    "--write-baseline", str(tmp_path / "b.json"))
    assert baseline.returncode == 1  # a baseline cannot vouch for unread content
    report = _run("scan", str(root))
    assert report.returncode == 0
    assert "warning: scan.pdf: not scanned: page 0 has no extractable text" in report.stderr


def test_blank_page_is_not_a_gap(tmp_path: Path) -> None:
    # Nothing is drawn on a blank page, so there is nothing left unread.
    path = tmp_path / "blank.pdf"
    path.write_bytes(_raw_pdf(b""))
    proc = _run("extract", str(path), "--redact", "strict")
    assert proc.returncode == 0, proc.stderr
    assert not [w for w in json.loads(proc.stdout)["warnings"] if w.startswith(NOT_SCANNED)]


def test_docx_media_and_printer_settings_are_not_gaps() -> None:
    # Images are out of scope by design (no OCR) and printer settings hold no
    # document text; neither may turn every ordinary DOCX into a failure.
    data = _docx_with(
        {"word/media/image1.png": b"\x89PNG", "word/printerSettings/printerSettings1.bin": b"x"}
    )
    _, warnings = extract_blocks(data, "docx")
    assert warnings == []


def test_fixtures_have_no_gaps() -> None:
    proc = _run("scan", str(FIXTURES), "--redact", "strict")
    assert proc.returncode == 3  # findings, and nothing left unread
    assert "not scanned" not in proc.stderr
