from __future__ import annotations

import io
from typing import Iterable

import pikepdf

from ..models import InspectionResult
from ..normalization import compact_text, normalize_datetime
from ..security import UnsafeFileError, parse_safe_xml
from .common import make_finding


ACTIVE_ACTIONS = {"/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToR", "/URI"}


def pdf_scalar(value: object) -> str:
    try:
        return compact_text(value)
    except Exception:
        return "Present"


def object_ref(obj: object) -> str:
    try:
        number, generation = obj.objgen  # type: ignore[attr-defined]
        return f"object {number} {generation}" if number else "direct object"
    except (AttributeError, TypeError, ValueError):
        return "direct object"


def walk_pdf_objects(pdf: pikepdf.Pdf) -> Iterable[pikepdf.Dictionary]:
    stack = list(pdf.objects); seen: set[tuple[object, ...]] = set()
    while stack:
        obj = stack.pop()
        try:
            if isinstance(obj, pikepdf.Dictionary):
                objgen = tuple(obj.objgen)
                # pikepdf may create short-lived Python wrappers for direct PDF
                # dictionaries. Their id() values can be reused while walking,
                # which intermittently skipped an unrelated action dictionary.
                # Indirect objects have stable PDF identities and are the only
                # objects that need cycle de-duplication.
                if objgen != (0, 0):
                    identity = ("indirect", *objgen)
                    if identity in seen:
                        continue
                    seen.add(identity)
                yield obj
                stack.extend(obj[key] for key in list(obj.keys()))
            elif isinstance(obj, pikepdf.Array):
                stack.extend(list(obj))
        except (ValueError, TypeError, pikepdf.PdfError):
            continue


def _action(result: InspectionResult, action: object, source: str, page_number: int | None = None) -> None:
    if not isinstance(action, pikepdf.Dictionary):
        return
    try:
        kind = str(action.get("/S", "/Unknown"))
        if kind not in ACTIVE_ACTIONS and kind not in {"/GoTo", "/Named"}:
            return
        target = action.get("/URI") or action.get("/F") or action.get("/JS") or action.get("/N") or "Present"
        active = kind in ACTIVE_ACTIONS
        result.findings.append(make_finding(
            "pdf", "PDF action", kind.lstrip("/"), target, f"{source}/{object_ref(action)}",
            page_number=page_number, sanitization_action=f"Remove the {kind.lstrip('/')} action dictionary.",
            overrides={
                "subcategory": "active or external behavior" if active else "navigation",
                "severity": "High" if active else "Informational",
                "risk_group": "active_external_behavior" if active else "technical",
                "meaning": f"A PDF {kind.lstrip('/')} action is present; GhostFrame did not execute it.",
                "privacy_impact": "This action may contact, submit to, open, or run an external resource when activated." if active else "Internal navigation normally has little privacy impact.",
                "exposure_scenario": "Opening or interacting with the PDF in a capable viewer could trigger the configured behavior." if active else "A viewer may navigate inside the document.",
            },
        ))
    except (ValueError, TypeError, pikepdf.PdfError):
        return


def _xmp_findings(result: InspectionResult, raw: bytes, source: str) -> None:
    root = parse_safe_xml(raw, source)
    count = 0
    for element in root.iter():
        text = compact_text(element.text or "")
        if not text or len(text) > 800:
            continue
        name = element.tag.rsplit("}", 1)[-1]
        normalized = normalize_datetime(text)[0] if any(key in name.lower() for key in ("date", "time")) else text
        result.findings.append(make_finding("pdf", "XMP", name, text, f"{source}/{element.tag}", normalized_value=normalized, sanitization_action="Remove the PDF XMP metadata stream."))
        count += 1
        if count >= 200:
            result.partial_analysis = True; result.notes.append("XMP field display was capped at 200 entries."); break


def inspect_pdf(data: bytes) -> InspectionResult:
    result = InspectionResult("PDF")
    try:
        with pikepdf.Pdf.open(io.BytesIO(data)) as pdf:
            result.findings.append(make_finding("pdf", "Structure", "PDFVersion", pdf.pdf_version, "PDF header/version", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}))
            result.findings.append(make_finding("pdf", "Structure", "PageCount", len(pdf.pages), "PDF page tree", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}))
            result.findings.append(make_finding("pdf", "Security", "Encrypted", bool(pdf.is_encrypted), "PDF encryption state", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical", "meaning": "Indicates whether the input PDF used encryption.", "privacy_impact": "Encryption state is structural information, not evidence of maliciousness.", "exposure_scenario": "A technical examiner can see whether the source PDF was encrypted."}))
            try:
                permissions = compact_text(pdf.allow)
                result.findings.append(make_finding("pdf", "Security", "Permissions", permissions, "PDF encryption permissions", sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}))
            except (AttributeError, ValueError, pikepdf.PdfError):
                pass
            for key, value in pdf.docinfo.items():
                text = pdf_scalar(value)
                if not text:
                    continue
                name = str(key).lstrip("/")
                normalized = normalize_datetime(text)[0] if "date" in name.lower() else text
                result.findings.append(make_finding("pdf", "Document information", name, text, f"trailer/Info/{key}", normalized_value=normalized, sanitization_action="Delete the PDF document information entry."))
            identifiers = pdf.trailer.get("/ID")
            if identifiers:
                result.findings.append(make_finding("pdf", "Correlation clue", "TrailerIdentifiers", identifiers, "trailer/ID", sanitization_action="Regenerate PDF file identifiers when saving.", overrides={"subcategory": "file correlation", "severity": "Informational", "risk_group": "technical", "meaning": "Opaque file identifiers can help correlate copies or related PDF revisions.", "privacy_impact": "They are not personal identity; only a match across separately compared files creates a correlation clue.", "exposure_scenario": "An examiner comparing files may notice matching identifiers."}, limitations="A matching identifier is a correlation clue, not proof of common ownership."))
            metadata = pdf.Root.get("/Metadata")
            if metadata is not None:
                result.findings.append(make_finding("pdf", "XMP", "MetadataStream", "Present", f"catalog/Metadata/{object_ref(metadata)}", sanitization_action="Remove the PDF XMP metadata stream."))
                try:
                    _xmp_findings(result, metadata.read_bytes(), f"catalog/Metadata/{object_ref(metadata)}")
                except (AttributeError, ValueError, pikepdf.PdfError, UnsafeFileError) as exc:
                    result.partial_analysis = True; result.notes.append(f"XMP packet was present but not fully parsed: {exc}")
            try:
                for name in sorted(pdf.attachments.keys()):
                    spec = pdf.attachments[name]
                    size = "unknown"
                    mime = "not declared"
                    try:
                        attachment = spec.get_file(); size = str(len(attachment.read_bytes())); mime = compact_text(getattr(attachment, "mimetype", mime))
                    except (AttributeError, KeyError, TypeError, ValueError, pikepdf.PdfError):
                        pass
                    result.findings.append(make_finding("pdf", "Embedded content", "Attachment", f"filename={name}; size={size}; type={mime}", f"catalog/Names/EmbeddedFiles/{name}", sanitization_action="Remove the embedded file specification and payload.", overrides={"subcategory": "embedded file", "severity": "High", "risk_group": "hidden_embedded_content", "meaning": "A file is embedded inside the PDF; GhostFrame did not open or execute it.", "privacy_impact": "The attachment can carry hidden or unintended content.", "exposure_scenario": "A recipient can extract the embedded file using a capable PDF tool."}))
            except (AttributeError, KeyError, TypeError):
                pass
            _action(result, pdf.Root.get("/OpenAction"), "catalog/OpenAction")
            aa = pdf.Root.get("/AA")
            if isinstance(aa, pikepdf.Dictionary):
                for key in aa.keys():
                    _action(result, aa[key], f"catalog/AA/{key}")
            form = pdf.Root.get("/AcroForm")
            if isinstance(form, pikepdf.Dictionary):
                fields = form.get("/Fields", [])
                result.findings.append(make_finding("pdf", "Interactive form", "AcroForm", f"Present ({len(fields)} top-level fields)", f"catalog/AcroForm/{object_ref(form)}", sanitizable=False, overrides={"subcategory": "form", "severity": "Medium", "risk_group": "hidden_embedded_content", "meaning": "The PDF contains interactive form structures.", "privacy_impact": "Field names or retained values may reveal workflow or entered information.", "exposure_scenario": "A recipient can inspect or interact with form fields."}, limitations="GhostFrame inventories the form but does not submit or execute it."))
                for index, field in enumerate(list(fields)[:200]):
                    if isinstance(field, pikepdf.Dictionary):
                        result.findings.append(make_finding("pdf", "Interactive form", "FieldName", field.get("/T", f"Field {index + 1}"), f"catalog/AcroForm/Fields[{index}]/{object_ref(field)}", sanitizable=False, overrides={"severity": "Low", "risk_group": "hidden_embedded_content"}))
            for page_number, page in enumerate(pdf.pages, 1):
                annots = page.obj.get("/Annots", [])
                for index, annot in enumerate(list(annots)):
                    if not isinstance(annot, pikepdf.Dictionary):
                        continue
                    subtype = str(annot.get("/Subtype", "/Unknown"))
                    result.findings.append(make_finding("pdf", "Page annotation", subtype.lstrip("/"), "Present", f"page {page_number}/Annots[{index}]/{object_ref(annot)}", page_number=page_number, sanitizable=False, overrides={"severity": "Informational", "risk_group": "technical"}))
                    _action(result, annot.get("/A"), f"page {page_number}/Annots[{index}]/A", page_number)
                    page_aa = annot.get("/AA")
                    if isinstance(page_aa, pikepdf.Dictionary):
                        for key in page_aa.keys():
                            _action(result, page_aa[key], f"page {page_number}/Annots[{index}]/AA/{key}", page_number)
            for obj in walk_pdf_objects(pdf):
                subtype = str(obj.get("/Subtype", ""))
                if subtype in {"/RichMedia", "/Movie", "/Sound", "/Screen", "/3D"} or "/RichMediaContent" in obj:
                    result.findings.append(make_finding("pdf", "Rich media", subtype.lstrip("/") or "RichMediaContent", "Present", object_ref(obj), sanitizable=False, overrides={"subcategory": "rich media", "severity": "High", "risk_group": "hidden_embedded_content", "meaning": "A multimedia or rich-media structure is present; it was not executed.", "privacy_impact": "Interactive media may contain hidden content or external behavior.", "exposure_scenario": "A capable PDF viewer may expose or activate the media."}))
    except (pikepdf.PasswordError, pikepdf.PdfError, OSError, ValueError) as exc:
        raise UnsafeFileError("The PDF is encrypted, damaged, or cannot be processed safely.") from exc
    return result
