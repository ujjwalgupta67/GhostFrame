import io
import zipfile

import pikepdf
from PIL import Image, PngImagePlugin

from ghostframe import inspect_file, sanitize_with_verification


def test_png_text_and_transparency_audit():
    image = Image.new("RGBA", (5, 4), (1, 2, 3, 99))
    metadata = PngImagePlugin.PngInfo(); metadata.add_text("Author", "Private Person"); metadata.add_itxt("Description", "Sensitive note")
    source = io.BytesIO(); image.save(source, "PNG", pnginfo=metadata)
    before = inspect_file(source.getvalue(), "image.png", use_exiftool=False)
    assert any(item.source.startswith("PNG/tEXt") for item in before.findings)
    outcome = sanitize_with_verification(source.getvalue(), "image.png", before, use_exiftool=False)
    assert outcome.verification.status == "Verified"
    with Image.open(io.BytesIO(outcome.data)) as cleaned:
        assert cleaned.size == (5, 4) and cleaned.mode == "RGBA" and cleaned.getpixel((0, 0))[3] == 99


def test_jpeg_serial_number_has_high_severity():
    image = Image.new("RGB", (4, 4), "white"); exif = Image.Exif(); exif[0xA431] = "SERIAL-123"; exif[0x010F] = "CameraCo"
    source = io.BytesIO(); image.save(source, "JPEG", exif=exif)
    result = inspect_file(source.getvalue(), "camera.jpg", use_exiftool=False)
    serial = next(item for item in result.findings if "Serial" in item.field_name)
    make = next(item for item in result.findings if item.field_name == "Make")
    assert serial.severity == "High" and serial.source.endswith("0xA431")
    assert make.severity == "Low"


def test_pdf_deep_actions_xmp_attachment_and_page_source():
    source = io.BytesIO()
    with pikepdf.Pdf.new() as pdf:
        page = pdf.add_blank_page(page_size=(100, 100))
        pdf.docinfo["/CreationDate"] = "D:20260920112233+05'30'"
        page["/Annots"] = pikepdf.Array([
            pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=pikepdf.Array([0, 0, 10, 10]), A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI="https://example.invalid/track")),
            pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=pikepdf.Array([0, 0, 10, 10]), A=pikepdf.Dictionary(S=pikepdf.Name.Launch, F="tool.exe")),
            pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=pikepdf.Array([0, 0, 10, 10]), A=pikepdf.Dictionary(S=pikepdf.Name("/SubmitForm"), F="https://example.invalid/submit")),
            pikepdf.Dictionary(Type=pikepdf.Name.Annot, Subtype=pikepdf.Name("/RichMedia"), Rect=pikepdf.Array([0, 0, 10, 10])),
        ])
        pdf.Root["/OpenAction"] = pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS="app.alert('x')")
        pdf.Root["/AcroForm"] = pikepdf.Dictionary(Fields=pikepdf.Array([pikepdf.Dictionary(T="EmailAddress")]))
        pdf.attachments["note.txt"] = b"hidden"
        with pdf.open_metadata(set_pikepdf_as_editor=False) as metadata:
            metadata["dc:title"] = "Private title"
        pdf.docinfo["/CreationDate"] = "D:20260920112233+05'30'"
        pdf.save(source)
    before = inspect_file(source.getvalue(), "active.pdf", use_exiftool=False)
    assert any(item.field_name == "URI" and item.page_number == 1 and "page 1" in item.source for item in before.findings)
    assert any(item.field_name == "JavaScript" for item in before.findings)
    assert any(item.field_name == "Launch" for item in before.findings)
    assert any(item.field_name == "SubmitForm" for item in before.findings)
    assert any(item.field_name == "Attachment" for item in before.findings)
    assert any(item.category == "XMP" for item in before.findings)
    assert any(item.field_name == "AcroForm" for item in before.findings)
    assert any(item.category == "Rich media" for item in before.findings)
    date = next(item for item in before.findings if item.field_name == "CreationDate")
    assert date.normalized_value.endswith("+05:30")
    outcome = sanitize_with_verification(source.getvalue(), "active.pdf", before, use_exiftool=False)
    assert not any(item.field_name in {"URI", "JavaScript", "Launch", "SubmitForm", "Attachment"} for item in outcome.after.findings)
    assert outcome.verification.status == "Verified with residual findings"


def _rich_docx() -> bytes:
    parts = {
        "[Content_Types].xml": b'''<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>''',
        "word/document.xml": b'''<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:hyperlink r:id="rId1"><w:r><w:t>Visible text</w:t></w:r></w:hyperlink></w:p><w:ins w:id="2" w:author="Editor" w:date="2026-09-20T10:00:00Z"><w:r><w:t>Added</w:t></w:r></w:ins><w:del w:id="3" w:author="Editor"><w:r><w:delText>Deleted secret</w:delText></w:r></w:del><w:p><w:r><w:rPr><w:vanish/></w:rPr><w:t>Hidden</w:t></w:r></w:p><w:altChunk r:id="rId2"/></w:body></w:document>''',
        "word/_rels/document.xml.rels": b'''<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.invalid" TargetMode="External"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" Target="altChunk1.html"/></Relationships>''',
        "word/_rels/settings.xml.rels": b'''<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdTemplate" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://example.invalid/template.dotx" TargetMode="External"/></Relationships>''',
        "docProps/core.xml": b'''<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Alice</dc:creator></cp:coreProperties>''',
        "docProps/app.xml": b'''<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Example Ltd</Company><Application>Word</Application></Properties>''',
        "docProps/custom.xml": b'''<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="Case"><value>Private</value></property></Properties>''',
        "word/comments.xml": b'''<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0" w:author="Reviewer" w:initials="R" w:date="2026-09-20T11:00:00Z"><w:p><w:r><w:t>Review note</w:t></w:r></w:p></w:comment></w:comments>''',
        "word/settings.xml": b'''<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docVars><w:docVar w:name="Secret" w:val="Value"/></w:docVars><w:mailMerge/></w:settings>''',
        "customXml/item1.xml": b"<private>value</private>",
        "word/embeddings/object.bin": b"not executed",
        "word/vbaProject.bin": b"not executed",
        "word/activeX/activeX1.bin": b"not executed",
        "word/printerSettings/printerSettings1.bin": b"printer artifact",
        "word/people.xml": b'''<w:people xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:person w:author="Reviewer"/></w:people>''',
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in parts.items(): archive.writestr(name, payload)
    return output.getvalue()


def test_docx_deep_inventory_and_visible_text_preservation():
    data = _rich_docx(); before = inspect_file(data, "review.docx", use_exiftool=False)
    names = {item.field_name for item in before.findings}
    assert {"Creator", "Company", "Comment", "Insertion", "Deletion", "HiddenTextIndicator", "CustomXMLPart", "VBAProject", "CommentPeopleData"}.issubset(names)
    external = next(item for item in before.findings if item.category == "External relationship")
    assert "source=word/document.xml" in external.source
    assert any(item.field_name == "attachedTemplate" and "source=word/settings.xml" in item.source for item in before.findings)
    outcome = sanitize_with_verification(data, "review.docx", before, use_exiftool=False)
    assert outcome.verification.status == "Verified with residual findings"
    with zipfile.ZipFile(io.BytesIO(outcome.data)) as archive:
        document = archive.read("word/document.xml")
        assert b"Visible text" in document and b"Added" in document and b"Deleted secret" not in document
        assert "word/comments.xml" not in archive.namelist()
        assert not any(name.startswith("customXml/") for name in archive.namelist())
