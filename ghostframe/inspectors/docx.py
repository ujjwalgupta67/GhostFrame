from __future__ import annotations

import io
from pathlib import PurePosixPath

from ..models import InspectionResult
from ..normalization import compact_text, local_name, normalize_datetime
from ..security import read_xml, safe_zip
from .common import make_finding


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS = {"w": W, "r": R, "pr": REL}
REVISION_TAGS = {"ins": "Insertion", "del": "Deletion", "moveFrom": "MoveFrom", "moveTo": "MoveTo"}


def source_part_for_rels(rels_name: str) -> str:
    path = PurePosixPath(rels_name)
    if path.name == ".rels":
        return "package root"
    if path.parent.name == "_rels" and path.name.endswith(".rels"):
        return str(path.parent.parent / path.name[:-5])
    return rels_name


def _property_findings(result: InspectionResult, archive, part: str, category: str) -> None:
    root = read_xml(archive, part)
    if root is None:
        return
    if part == "docProps/custom.xml":
        for index, prop in enumerate(list(root)):
            name = prop.attrib.get("name", f"CustomProperty{index + 1}")
            text = compact_text(" ".join(child.text or "" for child in prop.iter()))
            if text:
                result.findings.append(make_finding("docx", category, name, text, f"{part}/property[{index}]", sanitization_action=f"Clear properties stored in {part}."))
        return
    canonical_names = {
        "creator": "Creator", "lastModifiedBy": "LastModifiedBy", "created": "Created",
        "modified": "Modified", "lastPrinted": "LastPrinted", "revision": "Revision",
        "title": "Title", "subject": "Subject", "description": "Description", "keywords": "Keywords",
    }
    for index, element in enumerate(root.iter()):
        text = compact_text(element.text or "")
        if not text:
            continue
        raw_name = element.attrib.get("name") or local_name(element.tag)
        name = canonical_names.get(raw_name, raw_name)
        if name in {"Pages", "Words", "Characters", "Lines", "Paragraphs", "Slides", "Notes"}:
            severity = "Informational"
        else:
            severity = None
        normalized = normalize_datetime(text)[0] if any(word in name.lower() for word in ("date", "time", "created", "modified", "printed")) else text
        overrides = {"severity": severity, "risk_group": "technical"} if severity else None
        result.findings.append(make_finding("docx", category, name, text, f"{part}/{element.tag}[{index}]", normalized_value=normalized, sanitization_action=f"Clear properties stored in {part}.", overrides=overrides))


def inspect_docx(data: bytes) -> InspectionResult:
    result = InspectionResult("DOCX")
    with safe_zip(data) as archive:
        names = set(archive.namelist())
        _property_findings(result, archive, "docProps/core.xml", "Core property")
        _property_findings(result, archive, "docProps/app.xml", "Application property")
        _property_findings(result, archive, "docProps/custom.xml", "Custom property")

        comments = read_xml(archive, "word/comments.xml")
        if comments is not None:
            for index, comment in enumerate(comments.findall(f"{{{W}}}comment")):
                text = compact_text("".join(node.text or "" for node in comment.iter() if node.tag == f"{{{W}}}t"), 240)
                author = comment.attrib.get(f"{{{W}}}author", "Unknown")
                initials = comment.attrib.get(f"{{{W}}}initials", "")
                date = comment.attrib.get(f"{{{W}}}date", "")
                value = f"author={author}; initials={initials}; date={date}; preview={text or 'Comment present'}"
                result.findings.append(make_finding("docx", "Review history", "Comment", value, f"word/comments.xml/w:comment[{index}]", sanitization_action="Remove comments and their relationship records.", overrides={"subcategory": "comment", "severity": "High" if author not in {"", "Unknown"} else "Medium", "risk_group": "collaboration_history", "meaning": "A reviewer comment stores identity, time, and discussion context.", "privacy_impact": "Can expose reviewer identities and private review conversations.", "exposure_scenario": "A recipient can inspect comments even when they are not visible in the main page view."}))

        for name in sorted(names):
            if not name.endswith(".rels"):
                continue
            root = read_xml(archive, name)
            if root is None:
                continue
            source_part = source_part_for_rels(name)
            for index, rel in enumerate(root):
                target = rel.attrib.get("Target", "")
                rel_type = rel.attrib.get("Type", "").rsplit("/", 1)[-1]
                rel_id = rel.attrib.get("Id", "")
                mode = rel.attrib.get("TargetMode", "Internal")
                if mode == "External":
                    severity = "High" if rel_type in {"attachedTemplate", "mailMergeSource", "oleObject", "image"} else "Medium"
                    result.findings.append(make_finding("docx", "External relationship", rel_type or "ExternalTarget", target, f"{name}/Relationship[{index}] id={rel_id}; source={source_part}", sanitization_action="Remove the external relationship and its referencing element.", overrides={"subcategory": "external reference", "severity": severity, "risk_group": "active_external_behavior", "meaning": f"The {source_part} part points to an external {rel_type or 'resource'}.", "privacy_impact": "Opening the document may contact or reveal activity to another resource.", "exposure_scenario": "A compatible Word processor may attempt to resolve the linked target."}))
                elif rel_type in {"oleObject", "package", "activeXControl", "vbaProject", "customXml"}:
                    result.findings.append(make_finding("docx", "Embedded relationship", rel_type, target, f"{name}/Relationship[{index}] id={rel_id}; source={source_part}", sanitization_action="Remove the embedded relationship and payload.", overrides={"subcategory": "embedded content", "severity": "High", "risk_group": "hidden_embedded_content", "meaning": f"An internal {rel_type} relationship is present; GhostFrame did not open or execute it.", "privacy_impact": "Embedded or active content can carry hidden information or behavior.", "exposure_scenario": "A compatible application may expose or activate the embedded feature."}))

        word_xml = sorted(name for name in names if name.startswith("word/") and name.endswith(".xml"))
        for part in word_xml:
            root = read_xml(archive, part)
            if root is None:
                continue
            tag_counts: dict[str, int] = {}
            for element in root.iter():
                lname = local_name(element.tag)
                index = tag_counts.get(lname, 0)
                tag_counts[lname] = index + 1
                if lname in REVISION_TAGS:
                    author = element.attrib.get(f"{{{W}}}author", "Unknown")
                    date = element.attrib.get(f"{{{W}}}date", "")
                    revision_id = element.attrib.get(f"{{{W}}}id", "")
                    result.findings.append(make_finding("docx", "Review history", REVISION_TAGS[lname], f"author={author}; date={date}; id={revision_id}", f"{part}/{element.tag}[{index}]", normalized_value=f"author={author}; date={normalize_datetime(date)[0] if date else 'not recorded'}; id={revision_id}", sanitization_action="Accept insertions/moves-to and remove deletions/moves-from to clear tracked-change history.", overrides={"subcategory": "tracked change", "severity": "High" if author not in {"", "Unknown"} else "Medium", "risk_group": "collaboration_history", "meaning": "A tracked revision records editing activity and may identify an editor.", "privacy_impact": "Can expose collaboration identities, deleted text, or editing history.", "exposure_scenario": "A recipient can inspect revision history or recover marked changes."}))
                elif lname == "altChunk":
                    result.findings.append(make_finding("docx", "Included content", "altChunk", element.attrib.get(f"{{{R}}}id", "Present"), f"{part}/{element.tag}[{index}]", sanitization_action="Remove the altChunk reference and related content.", overrides={"subcategory": "included content", "severity": "High", "risk_group": "hidden_embedded_content"}))
                elif lname == "vanish":
                    result.findings.append(make_finding("docx", "Hidden content", "HiddenTextIndicator", "Present", f"{part}/{element.tag}[{index}]", sanitizable=False, sanitization_action="Manual review required.", overrides={"subcategory": "hidden text", "severity": "Medium", "risk_group": "hidden_embedded_content", "meaning": "A run is formatted as hidden text.", "privacy_impact": "Text may be absent from normal view but remain extractable.", "exposure_scenario": "A recipient can reveal hidden formatting or extract the underlying XML."}, limitations="GhostFrame does not automatically delete hidden text because it may be intentional document content."))
                elif lname == "docVar":
                    var_name = element.attrib.get(f"{{{W}}}name", "Unnamed")
                    var_value = element.attrib.get(f"{{{W}}}val", "")
                    result.findings.append(make_finding("docx", "Document variable", var_name, var_value, f"{part}/{element.tag}[{index}]", sanitization_action="Remove document variables from settings.xml.", overrides={"subcategory": "hidden value", "severity": "Medium", "risk_group": "hidden_embedded_content"}))
                elif lname == "mailMerge":
                    result.findings.append(make_finding("docx", "Mail merge", "MailMergeConfiguration", "Present", f"{part}/{element.tag}[{index}]", sanitization_action="Remove mail-merge configuration and external data relationships.", overrides={"subcategory": "external data configuration", "severity": "High", "risk_group": "active_external_behavior"}))

        special_parts = {
            "word/vbaProject.bin": ("VBAProject", "High"),
            "docProps/thumbnail.jpeg": ("Thumbnail", "Low"),
            "docProps/thumbnail.png": ("Thumbnail", "Low"),
        }
        for name, (label, severity) in special_parts.items():
            if name in names:
                result.findings.append(make_finding("docx", "Package part", label, f"Present ({archive.getinfo(name).file_size} bytes)", name, sanitization_action=f"Remove {name} from the sanitized package.", overrides={"subcategory": "active content" if label == "VBAProject" else "preview", "severity": severity, "risk_group": "hidden_embedded_content"}))
        for name in sorted(names):
            if name.startswith(("word/embeddings/", "word/activeX/", "word/printerSettings/")):
                result.findings.append(make_finding("docx", "Package part", "EmbeddedPart", f"Present ({archive.getinfo(name).file_size} bytes)", name, sanitization_action="Remove the embedded package part and relationship.", overrides={"subcategory": "embedded content", "severity": "High" if "printerSettings" not in name else "Low", "risk_group": "hidden_embedded_content"}))
            elif name.startswith("customXml/") and name.endswith(".xml"):
                result.findings.append(make_finding("docx", "Custom XML", "CustomXMLPart", f"Present ({archive.getinfo(name).file_size} bytes)", name, sanitization_action="Remove the custom XML part and relationship.", overrides={"subcategory": "hidden structured data", "severity": "Medium", "risk_group": "hidden_embedded_content"}, limitations="Removing custom XML may affect content controls bound to that data."))
            elif name in {"word/people.xml", "word/commentsExtended.xml", "word/commentsIds.xml"}:
                result.findings.append(make_finding("docx", "Review history", "CommentPeopleData", "Present", name, sanitization_action="Remove comment-person and extended comment data.", overrides={"subcategory": "collaboration metadata", "severity": "High", "risk_group": "collaboration_history"}))
    return result
