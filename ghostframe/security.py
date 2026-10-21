from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree as ET


MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_IMAGE_PIXELS = 50_000_000
MAX_DOCX_FILES = 3_000
MAX_DOCX_EXPANDED_SIZE = 100 * 1024 * 1024
MAX_XML_PART_SIZE = 10 * 1024 * 1024
MAX_EXIFTOOL_OUTPUT = 2 * 1024 * 1024
SUPPORTED_EXTENSIONS = {"jpg", "jpeg", "png", "pdf", "docx"}


class UnsupportedFileError(ValueError):
    pass


class UnsafeFileError(ValueError):
    pass


def safe_display_name(filename: str) -> str:
    name = PurePosixPath(filename.replace("\\", "/")).name
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:120] or "uploaded_file"


def detect_file_type(data: bytes, filename: str) -> str:
    if len(data) > MAX_FILE_SIZE:
        raise UnsafeFileError(f"File is larger than the {MAX_FILE_SIZE // (1024 * 1024)} MB safety limit.")
    if data.startswith(b"\xff\xd8\xff"):
        actual = "jpg"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        actual = "png"
    elif data.startswith(b"%PDF-"):
        actual = "pdf"
    elif data.startswith(b"PK\x03\x04") and looks_like_docx(data):
        actual = "docx"
    else:
        raise UnsupportedFileError("The file content is not a supported JPG, PNG, PDF, or DOCX file.")
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if suffix not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFileError("Use a .jpg, .jpeg, .png, .pdf, or .docx filename.")
    if ("jpg" if suffix == "jpeg" else suffix) != actual:
        raise UnsupportedFileError(f"The filename says {suffix.upper()}, but the content appears to be {actual.upper()}.")
    return actual


def looks_like_docx(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            return "[Content_Types].xml" in names and "word/document.xml" in names
    except (zipfile.BadZipFile, OSError):
        return False


def safe_zip(data: bytes) -> zipfile.ZipFile:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise UnsafeFileError("This DOCX archive is damaged or unreadable.") from exc
    if len(infos) > MAX_DOCX_FILES:
        archive.close(); raise UnsafeFileError("This DOCX contains too many internal files to process safely.")
    if sum(item.file_size for item in infos) > MAX_DOCX_EXPANDED_SIZE:
        archive.close(); raise UnsafeFileError("This DOCX expands beyond the 100 MB safety limit.")
    for item in infos:
        normalized_name = item.filename.replace("\\", "/")
        path = PurePosixPath(normalized_name)
        if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", normalized_name):
            archive.close(); raise UnsafeFileError("This DOCX contains an unsafe internal path.")
    return archive


def parse_safe_xml(raw: bytes, source: str) -> ET.Element:
    if len(raw) > MAX_XML_PART_SIZE:
        raise UnsafeFileError(f"XML part {source} exceeds the safety limit.")
    upper = raw.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise UnsafeFileError(f"Unsafe XML declarations were found inside {source}.")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise UnsafeFileError(f"Invalid XML was found inside {source}.") from exc


def read_xml(archive: zipfile.ZipFile, name: str) -> ET.Element | None:
    try:
        return parse_safe_xml(archive.read(name), name)
    except KeyError:
        return None


def exiftool_status() -> tuple[bool, str, str]:
    executable = shutil.which("exiftool")
    if not executable:
        return False, "", "ExifTool is not installed; built-in inspection remains fully available."
    try:
        completed = subprocess.run([executable, "-ver"], capture_output=True, timeout=3, check=False, shell=False)
        version = completed.stdout[:100].decode("utf-8", "replace").strip()
        return completed.returncode == 0, version, "ExifTool is available for optional enrichment."
    except (OSError, subprocess.TimeoutExpired):
        return False, "", "ExifTool was detected but did not respond safely."


def run_exiftool(data: bytes, extension: str) -> tuple[list[dict[str, object]], str, str]:
    executable = shutil.which("exiftool")
    if not executable:
        return [], "unavailable", "ExifTool is not installed."
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(prefix="ghostframe_", suffix=f".{extension}", delete=False) as handle:
            handle.write(data)
            temp_path = Path(handle.name)
        completed = subprocess.run(
            [executable, "-config", "", "-json", "-G1", "-struct", "-charset", "filename=UTF8", str(temp_path)],
            capture_output=True, timeout=6, check=False, shell=False,
        )
        if len(completed.stdout) > MAX_EXIFTOOL_OUTPUT:
            return [], "failed", "ExifTool output exceeded the 2 MB safety limit."
        if completed.returncode not in {0, 1}:
            return [], "failed", "ExifTool returned an error; built-in findings are still available."
        parsed = json.loads(completed.stdout.decode("utf-8", "replace"))
        if not isinstance(parsed, list) or not parsed or not isinstance(parsed[0], dict):
            return [], "failed", "ExifTool returned malformed structured output."
        return [parsed[0]], "available", "ExifTool enrichment completed."
    except subprocess.TimeoutExpired:
        return [], "failed", "ExifTool exceeded the six-second timeout."
    except (OSError, ValueError, json.JSONDecodeError):
        return [], "failed", "ExifTool output could not be read safely."
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
