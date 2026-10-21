import io
import zipfile

import pikepdf
from PIL import Image, PngImagePlugin

from ghostframe import inspect_file, sanitize_file


def test_jpeg_metadata_is_removed():
    image = Image.new("RGB", (8, 8), "red")
    exif = Image.Exif()
    exif[0x010F] = "Identifying Camera"
    source = io.BytesIO()
    image.save(source, "JPEG", exif=exif)

    before = inspect_file(source.getvalue(), "photo.jpg")
    cleaned, name = sanitize_file(source.getvalue(), "photo.jpg")
    after = inspect_file(cleaned, name)

    assert before.risk_count >= 1
    assert after.risk_count == 0
    assert name == "photo_sanitized.jpg"


def test_png_transparency_is_preserved_without_metadata():
    image = Image.new("RGBA", (8, 8), (10, 20, 30, 100))
    source = io.BytesIO()
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Author", "Private Author")
    image.save(source, "PNG", pnginfo=metadata)

    before = inspect_file(source.getvalue(), "image.png")
    cleaned, name = sanitize_file(source.getvalue(), "image.png")
    after = inspect_file(cleaned, name)

    assert before.risk_count >= 1
    assert after.risk_count == 0
    with Image.open(io.BytesIO(cleaned)) as result:
        assert result.mode == "RGBA"
        assert result.getpixel((0, 0))[3] == 100


def test_pdf_properties_and_uri_are_removed():
    source = io.BytesIO()
    with pikepdf.Pdf.new() as pdf:
        page = pdf.add_blank_page(page_size=(100, 100))
        pdf.docinfo["/Author"] = "Private Author"
        page["/Annots"] = pikepdf.Array([
            pikepdf.Dictionary(
                Type=pikepdf.Name.Annot,
                Subtype=pikepdf.Name.Link,
                Rect=pikepdf.Array([0, 0, 10, 10]),
                A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI="https://example.com/track"),
            )
        ])
        pdf.save(source)

    before = inspect_file(source.getvalue(), "document.pdf")
    cleaned, name = sanitize_file(source.getvalue(), "document.pdf")
    after = inspect_file(cleaned, name)

    assert before.risk_count >= 2
    assert after.risk_count == 0


def test_docx_properties_comments_and_external_links_are_removed():
    source = io.BytesIO()
    content_types = b'''<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>'''
    document = b'''<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:hyperlink r:id="rId9"><w:r><w:t>Visible text</w:t></w:r></w:hyperlink></w:p></w:body></w:document>'''
    rels = b'''<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://example.com/track" TargetMode="External"/></Relationships>'''
    core = b'''<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Private Author</dc:creator></cp:coreProperties>'''
    comments = b'''<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0" w:author="Reviewer"><w:p><w:r><w:t>Secret note</w:t></w:r></w:p></w:comment></w:comments>'''
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("word/document.xml", document)
        archive.writestr("word/_rels/document.xml.rels", rels)
        archive.writestr("docProps/core.xml", core)
        archive.writestr("word/comments.xml", comments)

    before = inspect_file(source.getvalue(), "report.docx")
    cleaned, name = sanitize_file(source.getvalue(), "report.docx")
    after = inspect_file(cleaned, name)

    assert before.risk_count >= 3
    assert after.risk_count == 0
    with zipfile.ZipFile(io.BytesIO(cleaned)) as archive:
        assert b"Visible text" in archive.read("word/document.xml")
        assert "word/comments.xml" not in archive.namelist()
