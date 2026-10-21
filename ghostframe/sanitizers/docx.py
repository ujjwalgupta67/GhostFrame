from __future__ import annotations

import io
import zipfile
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET

from ..security import read_xml, safe_zip


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
EP = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
REVISION_UNWRAP = {f"{{{W}}}ins", f"{{{W}}}moveTo"}
REVISION_REMOVE = {f"{{{W}}}del", f"{{{W}}}moveFrom"}


def _source_part_for_rels(rels_name: str) -> str | None:
    path = PurePosixPath(rels_name)
    if path.name == ".rels":
        return None
    if path.parent.name != "_rels" or not path.name.endswith(".rels"):
        return None
    return str(path.parent.parent / path.name[:-5])


def _remove_refs(root: ET.Element, relationship_ids: set[str]) -> None:
    parent_map = {child: parent for parent in root.iter() for child in parent}
    attrs = {f"{{{R}}}id", f"{{{R}}}embed", f"{{{R}}}link"}
    for element in list(root.iter()):
        if not any(element.attrib.get(attr) in relationship_ids for attr in attrs):
            continue
        parent = parent_map.get(element)
        if parent is None:
            continue
        if element.tag == f"{{{W}}}hyperlink":
            index = list(parent).index(element); parent.remove(element)
            for child in list(element):
                parent.insert(index, child); index += 1
        else:
            parent.remove(element)


def _clean_word_xml(root: ET.Element) -> None:
    remove_tags = {
        f"{{{W}}}commentRangeStart", f"{{{W}}}commentRangeEnd", f"{{{W}}}commentReference",
        f"{{{W}}}altChunk", f"{{{W}}}mailMerge", f"{{{W}}}docVars",
    }
    for parent in list(root.iter()):
        for child in list(parent):
            if child.tag in remove_tags or child.tag in REVISION_REMOVE:
                parent.remove(child)
            elif child.tag in REVISION_UNWRAP:
                index = list(parent).index(child); parent.remove(child)
                for grandchild in list(child):
                    parent.insert(index, grandchild); index += 1


def sanitize_docx(data: bytes) -> tuple[bytes, list[str]]:
    removed_prefixes = ("word/embeddings/", "word/activeX/", "word/printerSettings/", "word/altChunk", "word/afchunk", "customXml/")
    removed_names = {
        "word/comments.xml", "word/commentsExtended.xml", "word/commentsIds.xml", "word/people.xml",
        "word/vbaProject.bin", "docProps/thumbnail.jpeg", "docProps/thumbnail.png",
    }
    actions: list[str] = []
    output = io.BytesIO()
    with safe_zip(data) as archive:
        names = archive.namelist(); updates: dict[str, bytes] = {}; removed_ids: dict[str, set[str]] = {}
        for name in names:
            if not name.endswith(".rels"):
                continue
            root = read_xml(archive, name)
            if root is None:
                continue
            ids: set[str] = set()
            for rel in list(root):
                target = rel.attrib.get("Target", ""); rel_type = rel.attrib.get("Type", "").lower()
                remove = rel.attrib.get("TargetMode") == "External" or any(marker in rel_type for marker in ("comments", "custom-properties", "customxml", "oleobject", "package", "activex", "vbaproject", "attachedtemplate", "mailmerge", "afchunk")) or target.startswith(("embeddings/", "activeX/", "printerSettings/", "altChunk", "afchunk", "../customXml/"))
                if remove:
                    if rel.attrib.get("Id"): ids.add(rel.attrib["Id"])
                    root.remove(rel)
            source = _source_part_for_rels(name)
            if source and ids: removed_ids[source] = ids
            updates[name] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        for name in names:
            if not name.endswith(".xml") or name in removed_names or name.startswith(removed_prefixes):
                continue
            if name == "docProps/core.xml": root = ET.Element(f"{{{CP}}}coreProperties")
            elif name == "docProps/app.xml": root = ET.Element(f"{{{EP}}}Properties")
            elif name == "docProps/custom.xml": root = ET.Element(f"{{{CUSTOM}}}Properties")
            else:
                root = read_xml(archive, name)
                if root is None: continue
                _clean_word_xml(root); _remove_refs(root, removed_ids.get(name, set()))
                if name == "[Content_Types].xml":
                    for child in list(root):
                        part = child.attrib.get("PartName", "").lstrip("/")
                        if part in removed_names or part.startswith(removed_prefixes): root.remove(child)
            updates[name] = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as cleaned:
            for info in archive.infolist():
                name = info.filename
                if name in removed_names or name.startswith(removed_prefixes): continue
                payload = updates.get(name, archive.read(name))
                safe_info = zipfile.ZipInfo(name); safe_info.compress_type = zipfile.ZIP_DEFLATED; safe_info.external_attr = info.external_attr
                cleaned.writestr(safe_info, payload)
    actions.extend([
        "Cleared core, application, and custom document properties.",
        "Removed comments, comment-person data, and comment markers.",
        "Removed external relationships and supported embedded or active parts.",
        "Accepted visible insertions/moves-to and removed deletions/moves-from to clear tracked-change history.",
        "Removed document variables, mail-merge configuration, custom XML, and altChunk references where present.",
    ])
    return output.getvalue(), actions
