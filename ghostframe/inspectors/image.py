from __future__ import annotations

import io
import struct
import zlib
from typing import Any, Iterable

from PIL import ExifTags, Image, ImageCms, IptcImagePlugin

from ..models import Finding, InspectionResult
from ..normalization import compact_text, gps_dms_to_decimal, normalize_datetime
from ..security import MAX_IMAGE_PIXELS, UnsafeFileError
from .common import make_finding


def _decode_exif_value(name: str, value: Any) -> str:
    if name.startswith("XP") and isinstance(value, (bytes, bytearray)):
        return value.decode("utf-16-le", "replace").rstrip("\x00")
    if name == "UserComment" and isinstance(value, (bytes, bytearray)):
        payload = bytes(value)
        for prefix, encoding in ((b"ASCII\x00\x00\x00", "ascii"), (b"UNICODE\x00", "utf-16")):
            if payload.startswith(prefix):
                return payload[len(prefix):].decode(encoding, "replace").rstrip("\x00")
    return compact_text(value)


def _ifd_items(exif: Image.Exif) -> Iterable[tuple[str, int, Any]]:
    seen: set[tuple[str, int]] = set()
    for tag_id, value in exif.items():
        key = ("IFD0", int(tag_id))
        if key not in seen:
            seen.add(key); yield "IFD0", int(tag_id), value
    for label, enum_name in (("ExifIFD", "Exif"), ("GPSIFD", "GPSInfo"), ("InteropIFD", "Interop")):
        try:
            enum_value = getattr(ExifTags.IFD, enum_name)
            values = exif.get_ifd(enum_value)
        except (AttributeError, KeyError, TypeError, ValueError):
            values = {}
        for tag_id, value in values.items():
            key = (label, int(tag_id))
            if key not in seen:
                seen.add(key); yield label, int(tag_id), value


def _jpeg_markers(data: bytes) -> Iterable[tuple[str, int, bytes]]:
    if not data.startswith(b"\xff\xd8"):
        return
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1; continue
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            break
        marker = data[offset]; offset += 1
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xDA:
            break
        if offset + 2 > len(data):
            break
        length = int.from_bytes(data[offset:offset + 2], "big")
        if length < 2 or offset + length > len(data):
            break
        payload = data[offset + 2:offset + length]
        label = "COM" if marker == 0xFE else f"APP{marker - 0xE0}" if 0xE0 <= marker <= 0xEF else f"0x{marker:02X}"
        yield label, offset - 2, payload
        offset += length


def _png_chunks(data: bytes) -> Iterable[tuple[str, int, bytes]]:
    offset = 8
    while offset + 12 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8].decode("ascii", "replace")
        end = offset + 12 + length
        if length > 10 * 1024 * 1024 or end > len(data):
            break
        yield kind, offset, data[offset + 8:offset + 8 + length]
        offset = end
        if kind == "IEND":
            break


def _decode_png_text(kind: str, payload: bytes) -> tuple[str, str] | None:
    try:
        if kind == "tEXt":
            key, value = payload.split(b"\x00", 1)
            return key.decode("latin-1", "replace"), value.decode("latin-1", "replace")
        if kind == "zTXt":
            key, rest = payload.split(b"\x00", 1)
            if not rest or rest[0] != 0:
                return None
            inflater = zlib.decompressobj()
            value = inflater.decompress(rest[1:], 1024 * 1024)
            return key.decode("latin-1", "replace"), value.decode("latin-1", "replace")
        if kind == "iTXt":
            key, rest = payload.split(b"\x00", 1)
            compression_flag, compression_method = rest[0], rest[1]
            rest = rest[2:]
            language, rest = rest.split(b"\x00", 1)
            translated, text = rest.split(b"\x00", 1)
            if compression_flag == 1 and compression_method == 0:
                inflater = zlib.decompressobj()
                text = inflater.decompress(text, 1024 * 1024)
            return key.decode("latin-1", "replace"), text.decode("utf-8", "replace")
    except (ValueError, IndexError, zlib.error):
        return None
    return None


def inspect_image(data: bytes, file_type: str) -> InspectionResult:
    result = InspectionResult(file_type.upper())
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise UnsafeFileError("This image exceeds the 50-megapixel safety limit.")
            if getattr(image, "n_frames", 1) > 1:
                raise UnsafeFileError("Animated or multi-frame images are not supported because frames could be lost.")
            result.findings.extend([
                make_finding(file_type, "Technical", "ImageWidth", image.width, "image header/width", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}),
                make_finding(file_type, "Technical", "ImageHeight", image.height, "image header/height", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}),
                make_finding(file_type, "Technical", "ColorMode", image.mode, "image header/mode", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}),
            ])
            exif = image.getexif()
            gps_values: dict[int, Any] = {}
            for ifd_name, tag_id, value in _ifd_items(exif):
                name = ExifTags.GPSTAGS.get(tag_id, str(tag_id)) if ifd_name == "GPSIFD" else ExifTags.TAGS.get(tag_id, str(tag_id))
                if name in {"ExifOffset", "GPSInfo", "InteropOffset"}:
                    continue
                decoded = _decode_exif_value(name, value)
                normalized = decoded
                if any(word in name.lower() for word in ("date", "time")):
                    normalized = normalize_datetime(decoded)[0]
                result.findings.append(make_finding(file_type, "EXIF", name, value, f"EXIF/{ifd_name}/tag 0x{tag_id:04X}", normalized_value=normalized, sanitization_action="Re-encode the image without EXIF metadata."))
                if ifd_name == "GPSIFD":
                    gps_values[tag_id] = value
            lat, lat_note = gps_dms_to_decimal(gps_values.get(2), gps_values.get(1))
            lon, lon_note = gps_dms_to_decimal(gps_values.get(4), gps_values.get(3))
            if gps_values and (lat is None or lon is None):
                result.notes.append(f"GPS conversion incomplete: {lat_note if lat is None else lon_note}")
            if lat is not None:
                result.findings.append(make_finding(file_type, "Location", "GPSLatitudeDecimal", gps_values.get(2), "EXIF/GPSIFD/derived latitude", normalized_value=f"{lat:.7f}", sanitization_action="Re-encode the image without the GPS IFD.", overrides={"subcategory": "precise location", "severity": "High", "risk_group": "precise_location", "meaning": "Latitude decoded from the recorded GPS degrees, minutes, seconds, and direction.", "privacy_impact": "Can reveal a precise capture location when combined with longitude.", "exposure_scenario": "A recipient could plot the coordinates without contacting any service."}, limitations=lat_note))
            if lon is not None:
                result.findings.append(make_finding(file_type, "Location", "GPSLongitudeDecimal", gps_values.get(4), "EXIF/GPSIFD/derived longitude", normalized_value=f"{lon:.7f}", sanitization_action="Re-encode the image without the GPS IFD.", overrides={"subcategory": "precise location", "severity": "High", "risk_group": "precise_location", "meaning": "Longitude decoded from the recorded GPS degrees, minutes, seconds, and direction.", "privacy_impact": "Can reveal a precise capture location when combined with latitude.", "exposure_scenario": "A recipient could plot the coordinates without contacting any service."}, limitations=lon_note))
            try:
                iptc = IptcImagePlugin.getiptcinfo(image) or {}
            except (OSError, ValueError, TypeError):
                iptc = {}
            for dataset, value in sorted(iptc.items(), key=lambda item: str(item[0])):
                result.findings.append(make_finding(file_type, "IPTC", f"Dataset {dataset}", value, f"IPTC/dataset {dataset}", sanitization_action="Re-encode the image without IPTC metadata."))
            icc = image.info.get("icc_profile")
            if icc:
                try:
                    profile_name = compact_text(ImageCms.getProfileName(ImageCms.ImageCmsProfile(io.BytesIO(icc))))
                except (OSError, TypeError, ValueError):
                    profile_name = "Name unavailable"
                result.findings.append(make_finding(file_type, "Rendering metadata", "ICCProfile", f"{profile_name} ({len(icc)} bytes)", "image/ICC profile", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical", "meaning": "An embedded color profile helps consistent rendering.", "privacy_impact": "Normally harmless; profile bytes may identify a color-management workflow.", "exposure_scenario": "A technical examiner could see that a profile is embedded."}))
    except UnsafeFileError:
        raise
    except (OSError, ValueError) as exc:
        raise UnsafeFileError("The image is damaged or could not be decoded safely.") from exc

    if file_type == "jpg":
        for marker, offset, payload in _jpeg_markers(data):
            if marker == "COM":
                result.findings.append(make_finding(file_type, "JPEG marker", "Comment", payload, f"JPEG/{marker} at byte {offset}", sanitization_action="Re-encode the image without JPEG comments."))
            elif marker == "APP1" and b"http://ns.adobe.com/xap/1.0/" in payload[:100]:
                text = payload.split(b"\x00", 1)[-1]
                result.findings.append(make_finding(file_type, "XMP", "XMPPacket", text, f"JPEG/APP1 at byte {offset}", sanitization_action="Re-encode the image without XMP metadata."))
            elif marker == "APP13" and b"Photoshop 3.0" in payload[:30]:
                result.findings.append(make_finding(file_type, "IPTC", "PhotoshopResourceBlock", f"Present ({len(payload)} bytes)", f"JPEG/APP13 at byte {offset}", sanitization_action="Re-encode the image without application resource blocks."))
    else:
        for chunk, offset, payload in _png_chunks(data):
            decoded = _decode_png_text(chunk, payload)
            if decoded:
                key, value = decoded
                result.findings.append(make_finding(file_type, "PNG text", key, value, f"PNG/{chunk} chunk at byte {offset}", sanitization_action="Re-encode the PNG without textual chunks."))
            elif chunk == "tIME" and len(payload) == 7:
                year, month, day, hour, minute, second = struct.unpack(">H5B", payload)
                raw = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
                result.findings.append(make_finding(file_type, "PNG chunk", "ModificationTime", raw, f"PNG/tIME chunk at byte {offset}", normalized_value=normalize_datetime(raw)[0], sanitization_action="Re-encode the PNG without the tIME chunk."))
            elif chunk == "pHYs" and len(payload) == 9:
                x, y, unit = struct.unpack(">IIB", payload)
                result.findings.append(make_finding(file_type, "Rendering metadata", "PhysicalDimensions", f"x={x}, y={y}, unit={unit}", f"PNG/pHYs chunk at byte {offset}", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}))
            elif chunk == "iCCP":
                name = payload.split(b"\x00", 1)[0].decode("latin-1", "replace")
                result.findings.append(make_finding(file_type, "Rendering metadata", "ICCProfile", f"{name} ({len(payload)} bytes)", f"PNG/iCCP chunk at byte {offset}", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}))
    return result
