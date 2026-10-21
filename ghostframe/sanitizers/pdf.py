from __future__ import annotations

import io

import pikepdf

from ..security import UnsafeFileError
from ..inspectors.pdf import walk_pdf_objects


REMOVED_ACTIONS = {pikepdf.Name(name) for name in ("/URI", "/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToR")}


def sanitize_pdf(data: bytes) -> tuple[bytes, list[str]]:
    output = io.BytesIO(); actions: list[str] = []
    try:
        with pikepdf.Pdf.open(io.BytesIO(data)) as pdf:
            if pdf.docinfo:
                for key in list(pdf.docinfo.keys()):
                    del pdf.docinfo[key]
                actions.append("Cleared PDF document information fields.")
            for key, label in (("/Metadata", "Removed XMP metadata."), ("/OpenAction", "Removed the document open action."), ("/AA", "Removed document additional actions.")):
                if key in pdf.Root:
                    del pdf.Root[key]; actions.append(label)
            try:
                attachment_names = list(pdf.attachments.keys())
                for name in attachment_names:
                    del pdf.attachments[name]
                if attachment_names:
                    actions.append(f"Removed {len(attachment_names)} embedded attachment(s).")
            except (AttributeError, KeyError, TypeError):
                pass
            names = pdf.Root.get("/Names")
            if isinstance(names, pikepdf.Dictionary):
                for key in ("/JavaScript", "/EmbeddedFiles"):
                    if key in names:
                        del names[key]; actions.append(f"Removed the {key.lstrip('/')} name tree.")
            removed_count = 0
            for obj in walk_pdf_objects(pdf):
                try:
                    action = obj.get("/A")
                    if isinstance(action, pikepdf.Dictionary) and action.get("/S") in REMOVED_ACTIONS:
                        del obj["/A"]; removed_count += 1
                    for key in ("/AA", "/JS"):
                        if key in obj:
                            del obj[key]; removed_count += 1
                except (ValueError, KeyError, TypeError, pikepdf.PdfError):
                    continue
            if removed_count:
                actions.append(f"Removed {removed_count} supported action or script reference(s).")
            pdf.save(output, deterministic_id=True, compress_streams=True)
    except (pikepdf.PasswordError, pikepdf.PdfError, OSError, ValueError) as exc:
        raise UnsafeFileError("The PDF could not be sanitized. It may be encrypted or damaged.") from exc
    return output.getvalue(), actions
