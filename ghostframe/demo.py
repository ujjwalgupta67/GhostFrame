from __future__ import annotations

import io
import zipfile


DEMO_FILENAME = "ghostframe_synthetic_demo.docx"
DEMO_NOTICE = "This file is generated locally with fictional demonstration data. It contains no real personal metadata."


def build_synthetic_demo() -> tuple[bytes, str, str]:
    parts = {
        "[Content_Types].xml": b'''<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>''',
        "word/document.xml": b'''<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>GhostFrame synthetic training file. All names and metadata are fictional.</w:t></w:r></w:p><w:p><w:hyperlink r:id="rId1"><w:r><w:t>Harmless reserved-domain example link</w:t></w:r></w:hyperlink></w:p><w:ins w:id="7" w:author="Example Reviewer" w:date="2026-01-15T10:30:00Z"><w:r><w:t>Fictional added text</w:t></w:r></w:ins><w:del w:id="8" w:author="Example Reviewer" w:date="2026-01-15T10:31:00Z"><w:r><w:delText>Fictional deleted draft</w:delText></w:r></w:del></w:body></w:document>''',
        "word/_rels/document.xml.rels": b'''<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://training.example.invalid/open?demo_token=fictional" TargetMode="External"/></Relationships>''',
        "docProps/core.xml": b'''<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:creator>Example Person</dc:creator><cp:lastModifiedBy>Example Reviewer</cp:lastModifiedBy><dcterms:created>2026-01-15T10:00:00Z</dcterms:created><dcterms:modified>2026-01-15T10:35:00Z</dcterms:modified></cp:coreProperties>''',
        "docProps/app.xml": b'''<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Fictional Privacy Lab</Company><Application>Example Editor 1.0</Application></Properties>''',
        "docProps/custom.xml": b'''<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"><property name="GPSLatitudeDecimal"><value>12.345678</value></property><property name="GPSLongitudeDecimal"><value>-98.765432</value></property><property name="CameraSerialNumber"><value>DEMO-SERIAL-0001</value></property><property name="DemoData"><value>Fictional demonstration values only</value></property></Properties>''',
        "word/comments.xml": b'''<?xml version="1.0"?><w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:comment w:id="0" w:author="Example Reviewer" w:initials="ER" w:date="2026-01-15T10:32:00Z"><w:p><w:r><w:t>Fictional internal review comment for training.</w:t></w:r></w:p></w:comment></w:comments>''',
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in parts.items():
            archive.writestr(name, payload)
    return output.getvalue(), DEMO_FILENAME, DEMO_NOTICE
