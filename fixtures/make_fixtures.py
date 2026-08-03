"""Regenerate the synthetic fixture documents deterministically.

Usage:
    python fixtures/make_fixtures.py

Every value below is fake by construction: example.com addresses,
555-01xx reserved-range phone numbers, the documented AWS example key
AKIAIOSFODNN7EXAMPLE, well-known Luhn-valid card test numbers, TEST-NET
IP addresses, the documented example IBAN, and an obviously sequential
GitHub-token-shaped string. The PDF is hand-written minimal PDF 1.4
bytes and the DOCX is a stdlib zipfile of hand-written OOXML parts (no
third-party dependency), so output is byte-identical between runs.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Sequence
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent

TXT = """DocRedact synthetic text fixture. Everything here is fake test data.

Contact jane.doe@example.com or call +1-555-0142 for support.

Payment card on file: 4111111111111111 (Visa test number).
AWS key sample: AKIAIOSFODNN7EXAMPLE

-----BEGIN RSA PRIVATE KEY-----
bm90IGEgcmVhbCBrZXkgLSBmaXh0dXJlIG9ubHk=
-----END RSA PRIVATE KEY-----
"""

MD = """# Synthetic Project Notes

This file is a DocRedact test fixture. All data below is fake.

## Contacts

Reach Ms. Jane Doe at jane.doe@example.com or +1-555-0142.

## Credentials (fake)

AWS access key id: AKIAIOSFODNN7EXAMPLE
Bearer token: eyJhbGciOiJub25lIn0.eyJkZW1vIjoidHJ1ZSJ9.c2lnbmF0dXJl

## Banking (fake)

Card: 4111111111111111
IBAN: GB82WEST12345698765432
"""

HTML = """<!DOCTYPE html>
<html>
<head>
<title>Synthetic Account Page</title>
<style>body { color: black; }</style>
<script>var apiHint = "none";</script>
</head>
<body>
<h1>Account Overview</h1>
<p>Owner: Mr. John Smith (a fictional person for testing).</p>
<p>Email: <a href="mailto:jane.doe@example.com">jane.doe@example.com</a></p>
<p>Support: <a href="mailto:hidden.support@example.com?subject=Account%20492">Contact support</a></p>
<ul>
<li>Phone: +1-555-0142</li>
<li>Token: ghp_0123456789abcdefghijklmnopqrstuvwxyz</li>
</ul>
<p>Server 192.0.2.10 answered from 198.51.100.7.</p>
</body>
</html>
"""

CSV = """name,email,phone,card,note
Jane Doe,jane.doe@example.com,+1-555-0142,4111111111111111,synthetic row
John Roe,john.roe@example.com,+1-555-0199,5555555555554444,synthetic row
"""

EML = """\
From: Jane Doe <jane.doe@example.com>
To: John Roe <john.roe@example.com>
Cc: support@example.com
Subject: Synthetic fixture email (fake data only)
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi John,

This is a DocRedact test fixture; every value is fake.

Card on file: 4111111111111111 (Visa test number).
Server: 192.0.2.10

Regards,
Ms. Jane Doe
"""

JSON_FIXTURE = """\
{
  "service": "docredact-fixture",
  "owner": "jane.doe@example.com",
  "aws": {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE"
  },
  "hosts": ["192.0.2.10", "198.51.100.7"],
  "github_token": "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
}
"""

PDF_PAGES: tuple[tuple[str, ...], ...] = (
    (
        "DocRedact synthetic sample PDF (page 1 of 3).",
        "All data in this document is fake test data.",
        "Contact: jane.doe@example.com",
    ),
    (
        "Page 2: support line +1-555-0142.",
        "AWS key sample: AKIAIOSFODNN7EXAMPLE",
    ),
    (
        "Page 3: card 4111111111111111 (Visa test number).",
        "Signed, Mr. John Smith (fictional).",
    ),
)


# Each paragraph is a tuple of runs; text split across runs (like the email
# below) exercises run-joining in the extractor, because Word routinely
# fragments a sentence into many runs.
DOCX_PARAGRAPHS: tuple[tuple[str, ...], ...] = (
    ("DocRedact synthetic DOCX fixture. Everything below is fake test data.",),
    ("Contact jane.doe@", "example.com or call +1-555-0142 for support."),
    ("AWS key sample: AKIAIOSFODNN7EXAMPLE",),
    ("Signed, Mr. John Smith (fictional).",),
)

DOCX_TABLE: tuple[tuple[str, ...], ...] = (
    ("name", "email", "card"),
    ("Jane Doe", "jane.doe@example.com", "4111111111111111"),
    ("John Roe", "john.roe@example.com", "5555555555554444"),
)

# Values planted OUTSIDE the body prove the header/footer/footnote scanning
# path end to end; each is distinct from every body value so a hit cannot be
# a body finding in disguise. All fake by construction (example.com, the
# reserved 555-01xx range, the sequential GitHub-token-shaped string).
DOCX_HEADERS: tuple[str, ...] = (
    "CONFIDENTIAL fixture header - contact header.owner@example.com",
)
DOCX_FOOTERS: tuple[str, ...] = ("Page footer helpline: +1-555-0177 (fake).",)
DOCX_FOOTNOTES: tuple[str, ...] = (
    "Footnote credential sample: ghp_0123456789abcdefghijklmnopqrstuvwxyz (fake).",
)

_XML_DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
_W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CT_HEADER = "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"
_CT_FOOTER = "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"
_CT_FOOTNOTES = "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"
_CT_ENDNOTES = "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml"

_DOCX_RELS = (
    f"{_XML_DECL}"
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    f'<Relationship Id="rId1" Type="{_R_NS}/officeDocument" Target="word/document.xml"/>'
    "</Relationships>"
)


def _docx_paragraph(runs: Sequence[str]) -> str:
    body = "".join(
        f'<w:r><w:t xml:space="preserve">{escape(run)}</w:t></w:r>' for run in runs
    )
    return f"<w:p>{body}</w:p>"


def _docx_notes(kind: str, notes: Sequence[str]) -> str:
    """Render word/footnotes.xml or word/endnotes.xml (kind: footnote|endnote).

    Includes the standard separator/continuationSeparator stub notes (ids -1
    and 0) that Word always writes; they carry no text, so the extractor must
    skip them without emitting empty blocks.
    """
    stubs = (
        f'<w:{kind} w:type="separator" w:id="-1"><w:p><w:r><w:separator/></w:r></w:p></w:{kind}>'
        f'<w:{kind} w:type="continuationSeparator" w:id="0">'
        f"<w:p><w:r><w:continuationSeparator/></w:r></w:p></w:{kind}>"
    )
    body = "".join(
        f'<w:{kind} w:id="{i}">{_docx_paragraph((text,))}</w:{kind}>'
        for i, text in enumerate(notes, start=1)
    )
    return f'{_XML_DECL}<w:{kind}s xmlns:w="{_W_NS}">{stubs}{body}</w:{kind}s>'


def build_docx(
    paragraphs: Sequence[Sequence[str]],
    table: Sequence[Sequence[str]],
    *,
    headers: Sequence[str] = (),
    footers: Sequence[str] = (),
    footnotes: Sequence[str] = (),
    endnotes: Sequence[str] = (),
) -> bytes:
    """Build a minimal, deterministic DOCX (zip of hand-written OOXML parts).

    Each ``headers``/``footers`` entry becomes its own one-paragraph
    word/headerN.xml / word/footerN.xml part (referenced from the section
    properties and the relationship part, as Word writes them); ``footnotes``
    and ``endnotes`` entries become one note each in word/footnotes.xml /
    word/endnotes.xml. Determinism: fixed zip timestamps, fixed
    create_system/permissions, and stored (uncompressed) entries, so output
    is byte-identical between runs and across platforms.
    """
    elements = [_docx_paragraph(runs) for runs in paragraphs]
    rows = "".join(
        "<w:tr>"
        + "".join(f"<w:tc>{_docx_paragraph((cell,))}</w:tc>" for cell in cells)
        + "</w:tr>"
        for cells in table
    )
    elements.append(f"<w:tbl>{rows}</w:tbl>")

    parts: list[tuple[str, str]] = []
    overrides: list[tuple[str, str]] = [
        (
            "/word/document.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        )
    ]
    relationships: list[tuple[str, str, str]] = []  # (rId, type suffix, target)
    references: list[str] = []
    for i, text in enumerate(headers, start=1):
        parts.append(
            (
                f"word/header{i}.xml",
                f'{_XML_DECL}<w:hdr xmlns:w="{_W_NS}">{_docx_paragraph((text,))}</w:hdr>',
            )
        )
        overrides.append((f"/word/header{i}.xml", _CT_HEADER))
        relationships.append((f"rIdHdr{i}", "header", f"header{i}.xml"))
        references.append(f'<w:headerReference w:type="default" r:id="rIdHdr{i}"/>')
    for i, text in enumerate(footers, start=1):
        parts.append(
            (
                f"word/footer{i}.xml",
                f'{_XML_DECL}<w:ftr xmlns:w="{_W_NS}">{_docx_paragraph((text,))}</w:ftr>',
            )
        )
        overrides.append((f"/word/footer{i}.xml", _CT_FOOTER))
        relationships.append((f"rIdFtr{i}", "footer", f"footer{i}.xml"))
        references.append(f'<w:footerReference w:type="default" r:id="rIdFtr{i}"/>')
    if footnotes:
        parts.append(("word/footnotes.xml", _docx_notes("footnote", footnotes)))
        overrides.append(("/word/footnotes.xml", _CT_FOOTNOTES))
        relationships.append(("rIdFtn", "footnotes", "footnotes.xml"))
    if endnotes:
        parts.append(("word/endnotes.xml", _docx_notes("endnote", endnotes)))
        overrides.append(("/word/endnotes.xml", _CT_ENDNOTES))
        relationships.append(("rIdEdn", "endnotes", "endnotes.xml"))
    if references:
        elements.append(f"<w:sectPr>{''.join(references)}</w:sectPr>")

    document = (
        f"{_XML_DECL}"
        f'<w:document xmlns:w="{_W_NS}" xmlns:r="{_R_NS}">'
        f"<w:body>{''.join(elements)}</w:body></w:document>"
    )
    content_types = (
        f"{_XML_DECL}"
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType='
        '"application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(
            f'<Override PartName="{part}" ContentType="{ct}"/>' for part, ct in overrides
        )
        + "</Types>"
    )
    members: list[tuple[str, str]] = [
        ("[Content_Types].xml", content_types),
        ("_rels/.rels", _DOCX_RELS),
        ("word/document.xml", document),
    ]
    if relationships:
        document_rels = (
            f"{_XML_DECL}"
            '<Relationships xmlns='
            '"http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(
                f'<Relationship Id="{rid}" Type="{_R_NS}/{suffix}" Target="{target}"/>'
                for rid, suffix, target in relationships
            )
            + "</Relationships>"
        )
        members.append(("word/_rels/document.xml.rels", document_rels))
    members.extend(parts)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, payload in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 0
            info.external_attr = 0o644 << 16
            archive.writestr(info, payload.encode("utf-8"))
    return buffer.getvalue()


def _pdf_escape(text: str) -> str:
    """Escape characters that are special inside PDF literal strings."""
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def build_pdf(pages: Sequence[Sequence[str]]) -> bytes:
    """Build a minimal, deterministic, uncompressed PDF 1.4 document.

    Object layout: 1 catalog, 2 page tree, then (page, content) pairs,
    and finally one shared Helvetica font object.
    """
    count = len(pages)
    font_obj = 3 + 2 * count
    kids = " ".join(f"{3 + 2 * i} 0 R" for i in range(count))
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {count} >>".encode("ascii"),
    ]
    for i, lines in enumerate(pages):
        objects.append(
            (
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
                f"/Contents {4 + 2 * i} 0 R >>"
            ).encode("ascii")
        )
        text_ops = " T* ".join(f"({_pdf_escape(line)}) Tj" for line in lines)
        stream = f"BT /F1 12 Tf 72 720 Td 16 TL {text_ops} ET".encode("ascii")
        objects.append(
            b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream)
        )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref_at = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref_at,
    )
    return bytes(out)


def main() -> None:
    """Write all six fixtures next to this script."""
    (HERE / "sample.txt").write_bytes(TXT.encode("ascii"))
    (HERE / "sample.md").write_bytes(MD.encode("ascii"))
    (HERE / "sample.html").write_bytes(HTML.encode("ascii"))
    (HERE / "sample.csv").write_bytes(CSV.encode("ascii"))
    (HERE / "sample.pdf").write_bytes(build_pdf(PDF_PAGES))
    (HERE / "sample.docx").write_bytes(
        build_docx(
            DOCX_PARAGRAPHS,
            DOCX_TABLE,
            headers=DOCX_HEADERS,
            footers=DOCX_FOOTERS,
            footnotes=DOCX_FOOTNOTES,
        )
    )
    (HERE / "sample.eml").write_bytes(EML.encode("ascii"))
    (HERE / "sample.json").write_bytes(JSON_FIXTURE.encode("ascii"))
    print("wrote sample.{txt,md,html,csv,pdf,docx,eml,json} into", HERE.name + "/")


if __name__ == "__main__":
    main()
