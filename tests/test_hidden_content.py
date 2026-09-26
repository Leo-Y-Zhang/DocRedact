"""Text a DOCX or PDF carries outside its visible body: metadata, link targets,
image alt text and earlier revisions.

Each is scanned and reported - so the strict gate fails on a secret hiding there -
and none is rendered into the sanitized artifact, which is the document as its reader
sees it. All values are synthetic (example.com, the AWS example key, the reserved
555-01xx phone range, the sequential GitHub-token-shaped string).
"""
from __future__ import annotations

import io
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from conftest import FIXTURES
from docredact import extractors
from docredact.core import build_document, build_sanitized
from docredact.extractors import extract_blocks

sys.path.insert(0, str(FIXTURES))
from make_fixtures import build_docx, build_pdf  # noqa: E402

_KEY = "AKIAIOSFODNN7EXAMPLE"
_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"


def _pdf_objects(objects: list[bytes], trailer: bytes) -> bytes:
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer\n<< /Size %d %s >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1, trailer, xref,
    )
    return bytes(out)


def _stream(data: bytes, extra: bytes = b"") -> bytes:
    return b"<< /Length %d %s>>\nstream\n%s\nendstream" % (len(data), extra, data)


_XMP = (
    b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
    b'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
    b'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    b'<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="tool.owner@example.com">'
    b"<dc:creator><rdf:Seq><rdf:li>xmp.author@example.com</rdf:li></rdf:Seq></dc:creator>"
    b'</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>'
)


def _pdf_with_metadata(xmp: bytes = _XMP) -> bytes:
    return _pdf_objects(
        [
            b"<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            _stream(b"BT /F1 12 Tf 72 700 Td (Quarterly report) Tj ET"),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            _stream(xmp, b"/Type /Metadata /Subtype /XML "),
            b"<< /Author (info.author@example.com) /Title (Draft for +1-555-0142) "
            b"/Keywords (" + _KEY.encode() + b") >>",
        ],
        b"/Root 1 0 R /Info 7 0 R",
    )


def _docx(extra: dict[str, str], body: str = "", rels: str = "") -> bytes:
    base = build_docx((("Quarterly report",),), ())
    with zipfile.ZipFile(io.BytesIO(base)) as source:
        parts = {name: source.read(name).decode() for name in source.namelist()}
    if body:
        parts["word/document.xml"] = parts["word/document.xml"].replace(
            "<w:body>", "<w:body>" + body
        )
    if rels:
        parts["word/_rels/document.xml.rels"] = (
            '<?xml version="1.0"?><Relationships xmlns='
            f'"http://schemas.openxmlformats.org/package/2006/relationships">{rels}'
            "</Relationships>"
        )
    parts.update(extra)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, payload in parts.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


_CORE = (
    '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
    'package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
    "<dc:creator>core.author@example.com</dc:creator>"
    f"<cp:lastModifiedBy>{_KEY}</cp:lastModifiedBy></cp:coreProperties>"
)
_CUSTOM = (
    '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/'
    'officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/'
    'officeDocument/2006/docPropsVTypes"><property fmtid="{D5CDD505-2E9C-101B-9397-'
    '08002B2CF9AE}" pid="2" name="ReviewerPhone"><vt:lpwstr>+1-555-0177</vt:lpwstr>'
    "</property></Properties>"
)
_APP = (
    '<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/'
    'officeDocument/2006/extended-properties"><Company>company.contact@example.com</Company>'
    "</Properties>"
)


def _entities(data: bytes, name: str, tmp_path: Path) -> set[tuple[str, str]]:
    path = tmp_path / name
    path.write_bytes(data)
    doc = build_document(path)
    return {(e["type"], e["value"]) for e in doc["entities"]}  # type: ignore[union-attr]


def _artifact(data: bytes, name: str, tmp_path: Path) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return build_sanitized(path)[0]


class TestMetadata:
    def test_pdf_info_and_xmp_are_scanned(self, tmp_path: Path) -> None:
        blocks, warnings = extract_blocks(_pdf_with_metadata(), "pdf")
        assert warnings == []
        assert [(b.kind, b.text) for b in blocks] == [
            ("page", "Quarterly report"),
            ("metadata", "Author: info.author@example.com"),
            ("metadata", f"Keywords: {_KEY}"),
            ("metadata", "Title: Draft for +1-555-0142"),
            ("metadata", "XMP: tool.owner@example.com xmp.author@example.com"),
        ]
        assert _entities(_pdf_with_metadata(), "m.pdf", tmp_path) == {
            ("email", "info.author@example.com"),
            ("api_key", _KEY),
            ("phone", "+1-555-0142"),
            ("email", "tool.owner@example.com"),
            ("email", "xmp.author@example.com"),
        }

    def test_pdf_metadata_is_not_rendered(self, tmp_path: Path) -> None:
        assert _artifact(_pdf_with_metadata(), "m.pdf", tmp_path) == "Quarterly report\n"

    def test_xmp_with_a_dtd_is_not_parsed(self) -> None:
        evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'
        _, warnings = extract_blocks(_pdf_with_metadata(evil), "pdf")
        assert warnings == ["not scanned: XMP metadata could not be read (DTD not allowed)"]

    def test_docx_properties_are_scanned(self, tmp_path: Path) -> None:
        data = _docx(
            {"docProps/core.xml": _CORE, "docProps/app.xml": _APP, "docProps/custom.xml": _CUSTOM}
        )
        blocks, warnings = extract_blocks(data, "docx")
        assert warnings == []
        assert [(b.kind, b.text) for b in blocks if b.kind == "metadata"] == [
            ("metadata", "creator: core.author@example.com"),
            ("metadata", f"lastModifiedBy: {_KEY}"),
            ("metadata", "Company: company.contact@example.com"),
            ("metadata", "ReviewerPhone: +1-555-0177"),
        ]
        assert _entities(data, "p.docx", tmp_path) == {
            ("email", "core.author@example.com"),
            ("api_key", _KEY),
            ("email", "company.contact@example.com"),
            ("phone", "+1-555-0177"),
        }
        assert _artifact(data, "p.docx", tmp_path) == "Quarterly report\n"

    def test_docx_property_part_with_a_dtd_is_refused(self) -> None:
        evil = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "y">]><cp:coreProperties/>'
        try:
            extract_blocks(_docx({"docProps/core.xml": evil}), "docx")
        except Exception as exc:  # ExtractionError
            assert "docProps/core.xml" in str(exc)
        else:
            raise AssertionError("a DTD in docProps/core.xml must be refused")


_HYPERLINK = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"


class TestLinks:
    def test_docx_external_relationship_targets_are_scanned(self, tmp_path: Path) -> None:
        # The address behind "our portal" lives only in the relationship part;
        # so does a template or image linked from someone's home directory.
        body = (
            '<w:p><w:hyperlink r:id="rIdLink"><w:r><w:t>our portal</w:t></w:r>'
            "</w:hyperlink></w:p>"
        )
        rels = (
            f'<Relationship Id="rIdLink" Type="{_HYPERLINK}" '
            'Target="mailto:link.target%40example.com" TargetMode="External"/>'
            f'<Relationship Id="rIdApi" Type="{_HYPERLINK}" '
            f'Target="https://api.example.com/export?token={_TOKEN}" TargetMode="External"/>'
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        )
        data = _docx({}, body=body, rels=rels)
        blocks, warnings = extract_blocks(data, "docx")
        assert warnings == []
        assert [b.text for b in blocks if b.kind == "link"] == [
            "mailto:link.target@example.com",
            f"https://api.example.com/export?token={_TOKEN}",
        ]
        assert _entities(data, "l.docx", tmp_path) == {
            ("email", "link.target@example.com"),
            ("api_key", _TOKEN),
            ("high_entropy", f"token={_TOKEN}"),
        }
        assert "example.com" not in _artifact(data, "l.docx", tmp_path)

    def test_docx_hyperlink_field_code_is_scanned(self) -> None:
        body = (
            '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText '
            'xml:space="preserve"> HYPERLINK "mailto:field.code@example.com" \\o "tip" '
            '</w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r>'
            '<w:r><w:t>email us</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
        )
        blocks, _ = extract_blocks(_docx({}, body=body), "docx")
        assert [b.text for b in blocks if b.kind == "link"] == ["mailto:field.code@example.com"]
        assert "email us" in [b.text for b in blocks if b.kind == "paragraph"]

    def test_pdf_link_targets_are_scanned(self, tmp_path: Path) -> None:
        link = (
            b"<< /Type /Annot /Subtype /Link /Rect [72 690 300 710] /A << /S /URI "
            b"/URI (https://api.example.com/export?token=" + _TOKEN.encode() + b") >> >>"
        )
        mail = (
            b"<< /Type /Annot /Subtype /Link /Rect [72 650 300 670] /A << /S /URI "
            b"/URI (mailto:hidden%40example.com?cc=cc@example.com) >> >>"
        )
        data = _pdf_objects(
            [
                b"<< /Type /Catalog /Pages 2 0 R >>",
                b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources "
                b"<< /Font << /F1 5 0 R >> >> /Contents 4 0 R /Annots [6 0 R 7 0 R] >>",
                _stream(b"BT /F1 12 Tf 72 700 Td (Export here) Tj ET"),
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
                link,
                mail,
            ],
            b"/Root 1 0 R",
        )
        blocks, warnings = extract_blocks(data, "pdf")
        assert warnings == []
        assert [(b.kind, b.text) for b in blocks] == [
            ("page", "Export here"),
            ("link", f"https://api.example.com/export?token={_TOKEN}"),
            ("link", "mailto:hidden@example.com?cc=cc@example.com"),
        ]
        assert _entities(data, "l.pdf", tmp_path) == {
            ("api_key", _TOKEN),
            ("high_entropy", f"token={_TOKEN}"),
            ("email", "hidden@example.com"),
            ("email", "cc@example.com"),
        }
        assert _artifact(data, "l.pdf", tmp_path) == "Export here\n"


class TestAltText:
    def test_docx_alt_text_is_scanned_not_rendered(self, tmp_path: Path) -> None:
        wp = 'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"'
        pic = 'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"'
        vml = 'xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office"'
        body = (
            f"<w:p><w:r><w:drawing><wp:inline {wp}>"
            '<wp:docPr id="1" name="Picture 1" descr="Scan of badge for alt.text@example.com" '
            'title="Badge"/>'
            f'<pic:pic {pic}><pic:nvPicPr><pic:cNvPr id="0" name="badge.png" '
            'descr="Scan of badge for alt.text@example.com"/></pic:nvPicPr></pic:pic>'
            "</wp:inline></w:drawing></w:r></w:p>"
            f'<w:p><w:r><w:pict {vml}><v:shape alt="Legacy logo, call +1-555-0177">'
            '<v:imagedata o:title="logo"/></v:shape></w:pict></w:r></w:p>'
        )
        data = _docx({}, body=body)
        blocks, warnings = extract_blocks(data, "docx")
        assert warnings == []
        # One block per distinct description, in document order.
        assert [b.text for b in blocks if b.kind == "alt_text"] == [
            "Scan of badge for alt.text@example.com",
            "Badge",
            "Legacy logo, call +1-555-0177",
            "logo",
        ]
        assert _entities(data, "a.docx", tmp_path) == {
            ("email", "alt.text@example.com"),
            ("phone", "+1-555-0177"),
        }
        assert _artifact(data, "a.docx", tmp_path) == "Quarterly report\n"


def _incremental_update(base: bytes, number: int, body: bytes, size: int) -> bytes:
    """Append an incremental update replacing object ``number``, as an editor saves one."""
    prev = int(re.findall(rb"startxref\s+(\d+)", base)[-1])
    out = bytearray(base)
    offset = len(out)
    out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 1\n0000000000 65535 f \n%d 1\n%010d 00000 n \n" % (number, offset)
    out += b"trailer\n<< /Size %d /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (
        size, prev, xref,
    )
    return bytes(out)


def _redacted_by_update() -> bytes:
    # Page 1's content stream is object 4 in build_pdf's layout.
    base = build_pdf((("Account owner jane.doe@example.com key " + _KEY,), ("page two",)))
    return _incremental_update(
        base, 4, _stream(b"BT /F1 12 Tf 72 720 Td (Account owner [redacted]) Tj ET"), 8
    )


class TestEarlierRevisions:
    def test_text_removed_by_an_incremental_update_is_scanned(self, tmp_path: Path) -> None:
        # "Redacting" by saving over a page leaves the original page in the
        # file: any viewer that offers earlier versions, or a text editor,
        # shows it. It scanned as zero findings with exit 0.
        data = _redacted_by_update()
        assert _KEY.encode() in data
        blocks, warnings = extract_blocks(data, "pdf")
        assert warnings == []
        assert [(b.kind, b.text) for b in blocks] == [
            ("page", "Account owner [redacted]"),
            ("page", "page two"),
            ("revision", f"Account owner jane.doe@example.com key {_KEY}"),
        ]
        assert _entities(data, "r.pdf", tmp_path) == {
            ("email", "jane.doe@example.com"),
            ("api_key", _KEY),
        }
        assert _artifact(data, "r.pdf", tmp_path) == "Account owner [redacted]\n\npage two\n"

    def test_a_single_revision_pdf_has_no_revision_blocks(self) -> None:
        blocks, _ = extract_blocks((FIXTURES / "sample.pdf").read_bytes(), "pdf")
        assert {b.kind for b in blocks} == {"page"}

    def test_an_unreadable_earlier_revision_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # pypdf recovers from most damage, but when an earlier revision cannot
        # be opened at all the gate must not assume it held nothing.
        data = _redacted_by_update()
        real = extractors._extract_pdf_revision

        def fail_on_prefix(chunk: bytes, used: list[int]) -> Any:
            if len(chunk) < len(data):
                raise extractors.ExtractionError("failed to parse PDF: damaged")
            return real(chunk, used)

        monkeypatch.setattr(extractors, "_extract_pdf_revision", fail_on_prefix)
        blocks, warnings = extract_blocks(data, "pdf")
        assert [b.kind for b in blocks] == ["page", "page"]
        assert warnings == [
            "not scanned: earlier revision 1 could not be read (failed to parse PDF: damaged)"
        ]

    def test_revision_count_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(extractors, "_PDF_MAX_REVISIONS", 0)
        with pytest.raises(extractors.ExtractionError, match="too many revisions"):
            extract_blocks(_redacted_by_update(), "pdf")

    def test_linearization_stub_is_not_a_revision(self) -> None:
        # A linearized ("fast web view") file ends its first-page section with
        # "startxref 0 %%EOF"; that stub is not an earlier version.
        base = build_pdf((("single page",),))
        stub = b"%PDF-1.4\n% linearized stub\ntrailer\n<< /Size 1 >>\nstartxref\n0\n%%EOF\n"
        blocks, warnings = extract_blocks(stub + base[len(b"%PDF-1.4\n"):], "pdf")
        assert warnings == []
        assert [b.kind for b in blocks] == ["page"]


def _page_pdf(content: bytes, resources: bytes = b"", catalog: bytes = b"",
              extra: tuple[bytes, ...] = ()) -> bytes:
    return _pdf_objects(
        [
            b"<< /Type /Catalog /Pages 2 0 R " + catalog + b">>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> " + resources + b">> /Contents 4 0 R >>",
            _stream(content),
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            *extra,
        ],
        b"/Root 1 0 R",
    )


_SHOW = b"BT /F1 12 Tf 72 700 Td (hidden " + _KEY.encode() + b") Tj ET"
_FORM = _stream(_SHOW, b"/Type /XObject /Subtype /Form /BBox [0 0 612 792] "
                b"/Resources << /Font << /F1 5 0 R >> >> ")
_LAYERS = {
    # The classic failed redaction: a black box drawn over text that is still there.
    "under a black box": _page_pdf(_SHOW + b" 0 g 60 690 400 30 re f"),
    "invisible render mode": _page_pdf(_SHOW.replace(b"Tf ", b"Tf 3 Tr ")),
    "white on white": _page_pdf(b"1 1 1 rg " + _SHOW),
    "clipped away": _page_pdf(b"q 0 0 1 1 re W n " + _SHOW + b" Q"),
    "off the page": _page_pdf(_SHOW.replace(b"72 700 Td", b"-900 -900 Td")),
    "hidden layer": _page_pdf(
        b"/OC /oc1 BDC " + _SHOW + b" EMC",
        resources=b"/Properties << /oc1 6 0 R >> ",
        catalog=b"/OCProperties << /OCGs [6 0 R] /D << /OFF [6 0 R] >> >> ",
        extra=(b"<< /Type /OCG /Name (Hidden) >>",),
    ),
    "form xobject": _page_pdf(b"/Fm1 Do", resources=b"/XObject << /Fm1 6 0 R >> ",
                              extra=(_FORM,)),
}


@pytest.mark.parametrize("layer", sorted(_LAYERS))
def test_text_a_pdf_viewer_hides_is_still_scanned(layer: str) -> None:
    # Covering, hiding or clipping text does not remove it from the content
    # stream. These pass today because pypdf extracts regardless of
    # visibility; this pins that down, so a switch to a visibility-aware
    # extraction mode cannot quietly start trusting a black box.
    blocks, warnings = extract_blocks(_LAYERS[layer], "pdf")
    assert warnings == []
    assert [b.text for b in blocks] == [f"hidden {_KEY}"]
