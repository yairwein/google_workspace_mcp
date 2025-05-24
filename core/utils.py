import zipfile, xml.etree.ElementTree as ET

from typing import List, Optional

# -------------------------------------------------------------------------
# Helper: pull raw text from OOXML containers (docx / xlsx / pptx)
# -------------------------------------------------------------------------
def extract_office_xml_text(file_bytes: bytes, mime_type: str) -> Optional[str]:
    """
    Very light-weight XML scraper for Word, Excel, PowerPoint files.
    Returns plain-text if something readable is found, else None.
    No external deps – just std-lib zipfile + ElementTree.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            # Map MIME → iterable of XML files to inspect
            if mime_type == (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ):
                targets = ["word/document.xml"]
            elif mime_type == (
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            ):
                targets = [n for n in zf.namelist() if n.startswith("ppt/slides/slide")]
            elif mime_type == (
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ):
                targets = [n for n in zf.namelist() if n.startswith("xl/worksheets/sheet")]
            else:
                return None

            pieces: List[str] = []
            for member in targets:
                try:
                    xml_root = ET.fromstring(zf.read(member))
                    # In both Word/PowerPoint the text is in <w:t> or <a:t>;
                    # in Excel, cell values are in <v>.
                    for elem in xml_root.iter():
                        tag = elem.tag.split("}")[-1]  # strip namespace
                        if tag in {"t", "v"} and elem.text:
                            pieces.append(elem.text)
                    pieces.append("\n")  # separator per part / sheet / slide
                except Exception:
                    continue  # ignore individual slide/sheet errors
            text = "\n".join(pieces).strip()
            return text or None
    except Exception as e:
        logger.error(f"Failed to extract file content: {e}")
        # Any failure → quietly signal "not handled"
        return None
