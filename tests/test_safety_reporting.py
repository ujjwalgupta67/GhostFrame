import io
import subprocess
import zipfile

import pytest
import pikepdf
from PIL import Image

from ghostframe import inspect_file
from ghostframe.models import InspectionResult
from ghostframe.inspectors.common import make_finding
from ghostframe.reporting import html_report, json_report
from ghostframe.security import UnsafeFileError, UnsupportedFileError, run_exiftool, safe_display_name


def _docx(parts: dict[str, bytes]) -> bytes:
    base = {
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/document.xml": b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
    }
    base.update(parts); output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in base.items(): archive.writestr(name, payload)
    return output.getvalue()


def test_wrong_extension_rejected():
    image = Image.new("RGB", (2, 2)); source = io.BytesIO(); image.save(source, "PNG")
    with pytest.raises(UnsupportedFileError): inspect_file(source.getvalue(), "image.jpg", use_exiftool=False)


def test_size_and_zip_limits(monkeypatch):
    import ghostframe.security as security
    image = Image.new("RGB", (2, 2)); source = io.BytesIO(); image.save(source, "PNG")
    monkeypatch.setattr(security, "MAX_FILE_SIZE", 10)
    with pytest.raises(UnsafeFileError, match="larger"):
        inspect_file(source.getvalue(), "image.png", use_exiftool=False)
    monkeypatch.setattr(security, "MAX_FILE_SIZE", 25 * 1024 * 1024)
    monkeypatch.setattr(security, "MAX_DOCX_EXPANDED_SIZE", 20)
    with pytest.raises(UnsafeFileError, match="expands"):
        inspect_file(_docx({"word/large.bin": b"x" * 100}), "large.docx", use_exiftool=False)


def test_unsafe_archive_path_and_excessive_entries(monkeypatch):
    with pytest.raises(UnsafeFileError, match="unsafe internal path"):
        inspect_file(_docx({"../escape.xml": b"x"}), "unsafe.docx", use_exiftool=False)
    with pytest.raises(UnsafeFileError, match="unsafe internal path"):
        inspect_file(_docx({"..\\escape.xml": b"x"}), "unsafe.docx", use_exiftool=False)
    import ghostframe.security as security
    monkeypatch.setattr(security, "MAX_DOCX_FILES", 2)
    with pytest.raises(UnsafeFileError, match="too many"):
        inspect_file(_docx({"extra.xml": b"x"}), "many.docx", use_exiftool=False)


def test_malformed_and_entity_xml_rejected():
    with pytest.raises(UnsafeFileError, match="Invalid XML"):
        inspect_file(_docx({"docProps/core.xml": b"<broken>"}), "broken.docx", use_exiftool=False)
    entity = b'<!DOCTYPE x [<!ENTITY secret "value">]><x>&secret;</x>'
    with pytest.raises(UnsafeFileError, match="Unsafe XML"):
        inspect_file(_docx({"docProps/core.xml": entity}), "entity.docx", use_exiftool=False)


def test_multiframe_png_rejected():
    frames = [Image.new("RGBA", (2, 2), color) for color in ("red", "blue")]
    source = io.BytesIO(); frames[0].save(source, "PNG", save_all=True, append_images=frames[1:], duration=100, loop=0)
    with pytest.raises(UnsafeFileError, match="multi-frame"):
        inspect_file(source.getvalue(), "animated.png", use_exiftool=False)


def test_encrypted_and_malformed_pdf_handling():
    encrypted = io.BytesIO()
    with pikepdf.Pdf.new() as pdf:
        pdf.add_blank_page(page_size=(10, 10))
        pdf.save(encrypted, encryption=pikepdf.Encryption(owner="owner-secret", user="user-secret", R=4))
    with pytest.raises(UnsafeFileError, match="encrypted"):
        inspect_file(encrypted.getvalue(), "locked.pdf", use_exiftool=False)
    with pytest.raises(UnsafeFileError):
        inspect_file(b"%PDF-1.7\nthis is malformed", "broken.pdf", use_exiftool=False)


def test_filename_sanitization():
    assert safe_display_name("../../A<script>.pdf") == "A_script_.pdf"
    assert len(safe_display_name("a" * 200 + ".pdf")) == 120


def test_reports_escape_html_and_are_valid_json():
    author = make_finding("pdf", "Info", "Author", '<img src=x onerror="alert(1)"> Example Person', "info/author", overrides={"severity": "High", "risk_group": "direct_identity", "subcategory": "identity"})
    result = InspectionResult("PDF", [author], file_sha256="abc", file_size=3, limitations=["<b>limit</b>"])
    output = html_report('<img src=x onerror="alert(1)">.pdf', result).decode()
    assert "&lt;b&gt;limit&lt;/b&gt;" in output
    assert "<script" not in output.lower()
    parsed = __import__("json").loads(json_report("safe.pdf", result))
    assert parsed["report_schema_version"] == "2.1"
    assert parsed["masking_status"] == "masked"
    assert "Example Person" not in output
    assert "Example Person" not in parsed["original_inspection"]["findings"][0]["normalized_value"]


def test_full_evidence_report_requires_explicit_option_and_stays_offline():
    author = make_finding("pdf", "Info", "Author", "Example Person", "info/author", overrides={"severity": "High", "risk_group": "direct_identity", "subcategory": "identity"})
    result = InspectionResult("PDF", [author])
    masked = __import__("json").loads(json_report("file.pdf", result))
    full = __import__("json").loads(json_report("file.pdf", result, full_evidence=True))
    assert masked["masking_status"] == "masked" and masked["original_inspection"]["findings"][0]["raw_value"] != "Example Person"
    assert full["masking_status"] == "full evidence" and full["original_inspection"]["findings"][0]["raw_value"] == "Example Person"
    html_output = html_report("file.pdf", result).decode().lower()
    assert "<script" not in html_output and "src=" not in html_output and "href=" not in html_output


def test_exiftool_timeout_and_malformed_output(monkeypatch):
    import ghostframe.security as security
    monkeypatch.setattr(security.shutil, "which", lambda _: "/fake/exiftool")
    monkeypatch.setattr(security.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("exiftool", 6)))
    records, status, detail = run_exiftool(b"data", "jpg")
    assert records == [] and status == "failed" and "timeout" in detail
    class Completed:
        returncode = 0; stdout = b"not json"; stderr = b""
    monkeypatch.setattr(security.subprocess, "run", lambda *a, **k: Completed())
    assert run_exiftool(b"data", "jpg")[1] == "failed"
