"""
Google Docs MCP Tools

This module provides MCP tools for interacting with Google Docs API and managing Google Docs via Drive.
"""
import logging
import asyncio
import io

from googleapiclient.http import MediaIoBaseDownload

# Auth & server utilities
from auth.service_decorator import require_google_service, require_multiple_services
from core.utils import extract_office_xml_text, handle_http_errors
from core.server import server
from core.comments import create_comment_tools

logger = logging.getLogger(__name__)

@server.tool()
@handle_http_errors("search_docs", is_read_only=True, service_type="docs")
@require_google_service("drive", "drive_read")
async def search_docs(
    service,
    user_google_email: str,
    query: str,
    page_size: int = 10,
) -> str:
    """
    Searches for Google Docs by name using Drive API (mimeType filter).

    Returns:
        str: A formatted list of Google Docs matching the search query.
    """
    logger.info(f"[search_docs] Email={user_google_email}, Query='{query}'")

    escaped_query = query.replace("'", "\\'")

    response = await asyncio.to_thread(
        service.files().list(
            q=f"name contains '{escaped_query}' and mimeType='application/vnd.google-apps.document' and trashed=false",
            pageSize=page_size,
            fields="files(id, name, createdTime, modifiedTime, webViewLink)"
        ).execute
    )
    files = response.get('files', [])
    if not files:
        return f"No Google Docs found matching '{query}'."

    output = [f"Found {len(files)} Google Docs matching '{query}':"]
    for f in files:
        output.append(
            f"- {f['name']} (ID: {f['id']}) Modified: {f.get('modifiedTime')} Link: {f.get('webViewLink')}"
        )
    return "\n".join(output)

@server.tool()
@handle_http_errors("get_doc_content", is_read_only=True, service_type="docs")
@require_multiple_services([
    {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"},
    {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"}
])
async def get_doc_content(
    drive_service,
    docs_service,
    user_google_email: str,
    document_id: str,
) -> str:
    """
    Retrieves content of a Google Doc or a Drive file (like .docx) identified by document_id.
    - Native Google Docs: Fetches content via Docs API.
    - Office files (.docx, etc.) stored in Drive: Downloads via Drive API and extracts text.

    Returns:
        str: The document content with metadata header.
    """
    logger.info(f"[get_doc_content] Invoked. Document/File ID: '{document_id}' for user '{user_google_email}'")

    # Step 2: Get file metadata from Drive
    file_metadata = await asyncio.to_thread(
        drive_service.files().get(
            fileId=document_id, fields="id, name, mimeType, webViewLink"
        ).execute
    )
    mime_type = file_metadata.get("mimeType", "")
    file_name = file_metadata.get("name", "Unknown File")
    web_view_link = file_metadata.get("webViewLink", "#")

    logger.info(f"[get_doc_content] File '{file_name}' (ID: {document_id}) has mimeType: '{mime_type}'")

    body_text = "" # Initialize body_text

    # Step 3: Process based on mimeType
    if mime_type == "application/vnd.google-apps.document":
        logger.info("[get_doc_content] Processing as native Google Doc.")
        doc_data = await asyncio.to_thread(
            docs_service.documents().get(
                documentId=document_id,
                includeTabsContent=True
            ).execute
        )
        # Tab header format constant
        TAB_HEADER_FORMAT = "\n--- TAB: {tab_name} ---\n"

        def extract_text_from_elements(elements, tab_name=None, depth=0):
            """Extract text from document elements (paragraphs, tables, etc.)"""
            # Prevent infinite recursion by limiting depth
            if depth > 5:
                return ""
            text_lines = []
            if tab_name:
                text_lines.append(TAB_HEADER_FORMAT.format(tab_name=tab_name))

            for element in elements:
                if 'paragraph' in element:
                    paragraph = element.get('paragraph', {})
                    para_elements = paragraph.get('elements', [])
                    current_line_text = ""
                    for pe in para_elements:
                        text_run = pe.get('textRun', {})
                        if text_run and 'content' in text_run:
                            current_line_text += text_run['content']
                    if current_line_text.strip():
                        text_lines.append(current_line_text)
                elif 'table' in element:
                    # Handle table content
                    table = element.get('table', {})
                    table_rows = table.get('tableRows', [])
                    for row in table_rows:
                        row_cells = row.get('tableCells', [])
                        for cell in row_cells:
                            cell_content = cell.get('content', [])
                            cell_text = extract_text_from_elements(cell_content, depth=depth + 1)
                            if cell_text.strip():
                                text_lines.append(cell_text)
            return "".join(text_lines)

        def process_tab_hierarchy(tab, level=0):
            """Process a tab and its nested child tabs recursively"""
            tab_text = ""

            if 'documentTab' in tab:
                tab_title = tab.get('documentTab', {}).get('title', 'Untitled Tab')
                # Add indentation for nested tabs to show hierarchy
                if level > 0:
                    tab_title = "    " * level + tab_title
                tab_body = tab.get('documentTab', {}).get('body', {}).get('content', [])
                tab_text += extract_text_from_elements(tab_body, tab_title)

            # Process child tabs (nested tabs)
            child_tabs = tab.get('childTabs', [])
            for child_tab in child_tabs:
                tab_text += process_tab_hierarchy(child_tab, level + 1)

            return tab_text

        processed_text_lines = []

        # Process main document body
        body_elements = doc_data.get('body', {}).get('content', [])
        main_content = extract_text_from_elements(body_elements)
        if main_content.strip():
            processed_text_lines.append(main_content)

        # Process all tabs
        tabs = doc_data.get('tabs', [])
        for tab in tabs:
            tab_content = process_tab_hierarchy(tab)
            if tab_content.strip():
                processed_text_lines.append(tab_content)

        body_text = "".join(processed_text_lines)
    else:
        logger.info(f"[get_doc_content] Processing as Drive file (e.g., .docx, other). MimeType: {mime_type}")

        export_mime_type_map = {
                # Example: "application/vnd.google-apps.spreadsheet"z: "text/csv",
                # Native GSuite types that are not Docs would go here if this function
                # was intended to export them. For .docx, direct download is used.
        }
        effective_export_mime = export_mime_type_map.get(mime_type)

        request_obj = (
            drive_service.files().export_media(fileId=document_id, mimeType=effective_export_mime)
            if effective_export_mime
            else drive_service.files().get_media(fileId=document_id)
        )

        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_obj)
        loop = asyncio.get_event_loop()
        done = False
        while not done:
            status, done = await loop.run_in_executor(None, downloader.next_chunk)

        file_content_bytes = fh.getvalue()

        office_text = extract_office_xml_text(file_content_bytes, mime_type)
        if office_text:
            body_text = office_text
        else:
            try:
                body_text = file_content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                body_text = (
                    f"[Binary or unsupported text encoding for mimeType '{mime_type}' - "
                    f"{len(file_content_bytes)} bytes]"
                )

    header = (
        f'File: "{file_name}" (ID: {document_id}, Type: {mime_type})\n'
        f'Link: {web_view_link}\n\n--- CONTENT ---\n'
    )
    return header + body_text

@server.tool()
@handle_http_errors("list_docs_in_folder", is_read_only=True, service_type="docs")
@require_google_service("drive", "drive_read")
async def list_docs_in_folder(
    service,
    user_google_email: str,
    folder_id: str = 'root',
    page_size: int = 100
) -> str:
    """
    Lists Google Docs within a specific Drive folder.

    Returns:
        str: A formatted list of Google Docs in the specified folder.
    """
    logger.info(f"[list_docs_in_folder] Invoked. Email: '{user_google_email}', Folder ID: '{folder_id}'")

    rsp = await asyncio.to_thread(
        service.files().list(
            q=f"'{folder_id}' in parents and mimeType='application/vnd.google-apps.document' and trashed=false",
            pageSize=page_size,
            fields="files(id, name, modifiedTime, webViewLink)"
        ).execute
    )
    items = rsp.get('files', [])
    if not items:
        return f"No Google Docs found in folder '{folder_id}'."
    out = [f"Found {len(items)} Docs in folder '{folder_id}':"]
    for f in items:
        out.append(f"- {f['name']} (ID: {f['id']}) Modified: {f.get('modifiedTime')} Link: {f.get('webViewLink')}")
    return "\n".join(out)

@server.tool()
@handle_http_errors("create_doc", service_type="docs")
@require_google_service("docs", "docs_write")
async def create_doc(
    service,
    user_google_email: str,
    title: str,
    content: str = '',
) -> str:
    """
    Creates a new Google Doc and optionally inserts initial content.

    Returns:
        str: Confirmation message with document ID and link.
    """
    logger.info(f"[create_doc] Invoked. Email: '{user_google_email}', Title='{title}'")

    doc = await asyncio.to_thread(service.documents().create(body={'title': title}).execute)
    doc_id = doc.get('documentId')
    if content:
        requests = [{'insertText': {'location': {'index': 1}, 'text': content}}]
        await asyncio.to_thread(service.documents().batchUpdate(documentId=doc_id, body={'requests': requests}).execute)
    link = f"https://docs.google.com/document/d/{doc_id}/edit"
    msg = f"Created Google Doc '{title}' (ID: {doc_id}) for {user_google_email}. Link: {link}"
    logger.info(f"Successfully created Google Doc '{title}' (ID: {doc_id}) for {user_google_email}. Link: {link}")
    return msg


@server.tool()
@handle_http_errors("update_doc_text", service_type="docs")
@require_google_service("docs", "docs_write")
async def update_doc_text(
    service,
    user_google_email: str,
    document_id: str,
    text: str,
    start_index: int,
    end_index: int = None,
) -> str:
    """
    Updates text at a specific location in a Google Doc.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        text: New text to insert or replace with
        start_index: Start position for text update (0-based)
        end_index: End position for text replacement (if not provided, text is inserted)
    
    Returns:
        str: Confirmation message with update details
    """
    logger.info(f"[update_doc_text] Doc={document_id}, start={start_index}, end={end_index}")
    
    requests = []
    
    if end_index is not None and end_index > start_index:
        # Replace text: delete old text, then insert new text
        requests.extend([
            {
                'deleteContentRange': {
                    'range': {
                        'startIndex': start_index,
                        'endIndex': end_index
                    }
                }
            },
            {
                'insertText': {
                    'location': {'index': start_index},
                    'text': text
                }
            }
        ])
        operation = f"Replaced text from index {start_index} to {end_index}"
    else:
        # Insert text at position
        requests.append({
            'insertText': {
                'location': {'index': start_index},
                'text': text
            }
        })
        operation = f"Inserted text at index {start_index}"
    
    await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': requests}
        ).execute
    )
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"{operation} in document {document_id}. Text length: {len(text)} characters. Link: {link}"

@server.tool()
@handle_http_errors("find_and_replace_doc", service_type="docs")
@require_google_service("docs", "docs_write")
async def find_and_replace_doc(
    service,
    user_google_email: str,
    document_id: str,
    find_text: str,
    replace_text: str,
    match_case: bool = False,
) -> str:
    """
    Finds and replaces text throughout a Google Doc.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        find_text: Text to search for
        replace_text: Text to replace with
        match_case: Whether to match case exactly
    
    Returns:
        str: Confirmation message with replacement count
    """
    logger.info(f"[find_and_replace_doc] Doc={document_id}, find='{find_text}', replace='{replace_text}'")
    
    requests = [{
        'replaceAllText': {
            'containsText': {
                'text': find_text,
                'matchCase': match_case
            },
            'replaceText': replace_text
        }
    }]
    
    result = await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': requests}
        ).execute
    )
    
    # Extract number of replacements from response
    replacements = 0
    if 'replies' in result and result['replies']:
        reply = result['replies'][0]
        if 'replaceAllText' in reply:
            replacements = reply['replaceAllText'].get('occurrencesChanged', 0)
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Replaced {replacements} occurrence(s) of '{find_text}' with '{replace_text}' in document {document_id}. Link: {link}"

@server.tool()
@handle_http_errors("format_doc_text", service_type="docs")
@require_google_service("docs", "docs_write")
async def format_doc_text(
    service,
    user_google_email: str,
    document_id: str,
    start_index: int,
    end_index: int,
    bold: bool = None,
    italic: bool = None,
    underline: bool = None,
    font_size: int = None,
    font_family: str = None,
) -> str:
    """
    Applies text formatting to a specific range in a Google Doc.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        start_index: Start position of text to format (0-based)
        end_index: End position of text to format
        bold: Whether to make text bold (True/False/None to leave unchanged)
        italic: Whether to make text italic (True/False/None to leave unchanged)
        underline: Whether to underline text (True/False/None to leave unchanged)
        font_size: Font size in points
        font_family: Font family name (e.g., "Arial", "Times New Roman")
    
    Returns:
        str: Confirmation message with formatting details
    """
    logger.info(f"[format_doc_text] Doc={document_id}, range={start_index}-{end_index}")
    
    text_style = {}
    format_changes = []
    
    if bold is not None:
        text_style['bold'] = bold
        format_changes.append(f"bold: {bold}")
    
    if italic is not None:
        text_style['italic'] = italic
        format_changes.append(f"italic: {italic}")
    
    if underline is not None:
        text_style['underline'] = underline
        format_changes.append(f"underline: {underline}")
    
    if font_size is not None:
        text_style['fontSize'] = {'magnitude': font_size, 'unit': 'PT'}
        format_changes.append(f"font size: {font_size}pt")
    
    if font_family is not None:
        text_style['fontFamily'] = font_family
        format_changes.append(f"font family: {font_family}")
    
    if not text_style:
        return "No formatting changes specified. Please provide at least one formatting option."
    
    requests = [{
        'updateTextStyle': {
            'range': {
                'startIndex': start_index,
                'endIndex': end_index
            },
            'textStyle': text_style,
            'fields': ','.join(text_style.keys())
        }
    }]
    
    await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': requests}
        ).execute
    )
    
    changes_str = ', '.join(format_changes)
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Applied formatting ({changes_str}) to text from index {start_index} to {end_index} in document {document_id}. Link: {link}"

@server.tool()
@handle_http_errors("insert_doc_elements", service_type="docs")
@require_google_service("docs", "docs_write")
async def insert_doc_elements(
    service,
    user_google_email: str,
    document_id: str,
    element_type: str,
    index: int,
    rows: int = None,
    columns: int = None,
    list_type: str = None,
    text: str = None,
) -> str:
    """
    Inserts structural elements like tables, lists, or page breaks into a Google Doc.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        element_type: Type of element to insert ("table", "list", "page_break")
        index: Position to insert element (0-based)
        rows: Number of rows for table (required for table)
        columns: Number of columns for table (required for table)
        list_type: Type of list ("UNORDERED", "ORDERED") (required for list)
        text: Initial text content for list items
    
    Returns:
        str: Confirmation message with insertion details
    """
    logger.info(f"[insert_doc_elements] Doc={document_id}, type={element_type}, index={index}")
    
    requests = []
    
    if element_type == "table":
        if not rows or not columns:
            return "Error: 'rows' and 'columns' parameters are required for table insertion."
        
        requests.append({
            'insertTable': {
                'location': {'index': index},
                'rows': rows,
                'columns': columns
            }
        })
        description = f"table ({rows}x{columns})"
        
    elif element_type == "list":
        if not list_type:
            return "Error: 'list_type' parameter is required for list insertion ('UNORDERED' or 'ORDERED')."
        
        if not text:
            text = "List item"
        
        # Insert text first, then create list
        requests.extend([
            {
                'insertText': {
                    'location': {'index': index},
                    'text': text + '\n'
                }
            },
            {
                'createParagraphBullets': {
                    'range': {
                        'startIndex': index,
                        'endIndex': index + len(text)
                    },
                    'bulletPreset': f'BULLET_DISC_CIRCLE_SQUARE' if list_type == "UNORDERED" else 'NUMBERED_DECIMAL_ALPHA_ROMAN'
                }
            }
        ])
        description = f"{list_type.lower()} list"
        
    elif element_type == "page_break":
        requests.append({
            'insertPageBreak': {
                'location': {'index': index}
            }
        })
        description = "page break"
        
    else:
        return f"Error: Unsupported element type '{element_type}'. Supported types: 'table', 'list', 'page_break'."
    
    await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': requests}
        ).execute
    )
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Inserted {description} at index {index} in document {document_id}. Link: {link}"

@server.tool()
@handle_http_errors("insert_doc_image", service_type="docs")
@require_multiple_services([
    {"service_type": "docs", "scopes": "docs_write", "param_name": "docs_service"},
    {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"}
])
async def insert_doc_image(
    docs_service,
    drive_service,
    user_google_email: str,
    document_id: str,
    image_source: str,
    index: int,
    width: int = None,
    height: int = None,
) -> str:
    """
    Inserts an image into a Google Doc from Drive or a URL.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        image_source: Drive file ID or public image URL
        index: Position to insert image (0-based)
        width: Image width in points (optional)
        height: Image height in points (optional)
    
    Returns:
        str: Confirmation message with insertion details
    """
    logger.info(f"[insert_doc_image] Doc={document_id}, source={image_source}, index={index}")
    
    # Determine if source is a Drive file ID or URL
    is_drive_file = not (image_source.startswith('http://') or image_source.startswith('https://'))
    
    if is_drive_file:
        # Verify Drive file exists and get metadata
        try:
            file_metadata = await asyncio.to_thread(
                drive_service.files().get(
                    fileId=image_source, 
                    fields="id, name, mimeType"
                ).execute
            )
            mime_type = file_metadata.get('mimeType', '')
            if not mime_type.startswith('image/'):
                return f"Error: File {image_source} is not an image (MIME type: {mime_type})."
            
            image_uri = f"https://drive.google.com/uc?id={image_source}"
            source_description = f"Drive file {file_metadata.get('name', image_source)}"
        except Exception as e:
            return f"Error: Could not access Drive file {image_source}: {str(e)}"
    else:
        image_uri = image_source
        source_description = "URL image"
    
    # Build image properties
    image_properties = {}
    if width is not None:
        image_properties['width'] = {'magnitude': width, 'unit': 'PT'}
    if height is not None:
        image_properties['height'] = {'magnitude': height, 'unit': 'PT'}
    
    requests = [{
        'insertInlineImage': {
            'location': {'index': index},
            'uri': image_uri,
            'objectSize': image_properties if image_properties else None
        }
    }]
    
    # Remove None values
    if requests[0]['insertInlineImage']['objectSize'] is None:
        del requests[0]['insertInlineImage']['objectSize']
    
    await asyncio.to_thread(
        docs_service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': requests}
        ).execute
    )
    
    size_info = ""
    if width or height:
        size_info = f" (size: {width or 'auto'}x{height or 'auto'} points)"
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Inserted {source_description}{size_info} at index {index} in document {document_id}. Link: {link}"

@server.tool()
@handle_http_errors("update_doc_headers_footers", service_type="docs")
@require_google_service("docs", "docs_write")
async def update_doc_headers_footers(
    service,
    user_google_email: str,
    document_id: str,
    section_type: str,
    content: str,
    header_footer_type: str = "DEFAULT",
) -> str:
    """
    Updates headers or footers in a Google Doc.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        section_type: Type of section to update ("header" or "footer")
        content: Text content for the header/footer
        header_footer_type: Type of header/footer ("DEFAULT", "FIRST_PAGE_ONLY", "EVEN_PAGE")
    
    Returns:
        str: Confirmation message with update details
    """
    logger.info(f"[update_doc_headers_footers] Doc={document_id}, type={section_type}")
    
    if section_type not in ["header", "footer"]:
        return "Error: section_type must be 'header' or 'footer'."
    
    if header_footer_type not in ["DEFAULT", "FIRST_PAGE_ONLY", "EVEN_PAGE"]:
        return "Error: header_footer_type must be 'DEFAULT', 'FIRST_PAGE_ONLY', or 'EVEN_PAGE'."
    
    # First, get the document to find existing header/footer
    doc = await asyncio.to_thread(
        service.documents().get(documentId=document_id).execute
    )
    
    # Find the appropriate header or footer
    headers = doc.get('headers', {})
    footers = doc.get('footers', {})
    
    target_section = None
    section_id = None
    
    if section_type == "header":
        # Look for existing header of the specified type
        for hid, header in headers.items():
            target_section = header
            section_id = hid
            break  # Use first available header for now
    else:
        # Look for existing footer of the specified type
        for fid, footer in footers.items():
            target_section = footer
            section_id = fid
            break  # Use first available footer for now
    
    if not target_section:
        return f"Error: No {section_type} found in document. Please create a {section_type} first in Google Docs."
    
    # Clear existing content and insert new content
    content_elements = target_section.get('content', [])
    if content_elements:
        # Find the first paragraph to replace content
        first_para = None
        for element in content_elements:
            if 'paragraph' in element:
                first_para = element
                break
        
        if first_para:
            # Calculate content range to replace
            start_index = first_para.get('startIndex', 0)
            end_index = first_para.get('endIndex', 0)
            
            requests = []
            
            # Delete existing content if any
            if end_index > start_index:
                requests.append({
                    'deleteContentRange': {
                        'range': {
                            'startIndex': start_index,
                            'endIndex': end_index - 1  # Keep the paragraph end
                        }
                    }
                })
            
            # Insert new content
            requests.append({
                'insertText': {
                    'location': {'index': start_index},
                    'text': content
                }
            })
            
            await asyncio.to_thread(
                service.documents().batchUpdate(
                    documentId=document_id,
                    body={'requests': requests}
                ).execute
            )
            
            link = f"https://docs.google.com/document/d/{document_id}/edit"
            return f"Updated {section_type} content in document {document_id}. Link: {link}"
    
    return f"Error: Could not find content structure in {section_type} to update."

@server.tool()
@handle_http_errors("batch_update_doc", service_type="docs")
@require_google_service("docs", "docs_write")
async def batch_update_doc(
    service,
    user_google_email: str,
    document_id: str,
    operations: list,
) -> str:
    """
    Executes multiple document operations in a single atomic batch update.
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        operations: List of operation dictionaries. Each operation should contain:
                   - type: Operation type ('insert_text', 'delete_text', 'replace_text', 'format_text', 'insert_table', 'insert_page_break')
                   - Additional parameters specific to each operation type
    
    Example operations:
        [
            {"type": "insert_text", "index": 1, "text": "Hello World"},
            {"type": "format_text", "start_index": 1, "end_index": 12, "bold": true},
            {"type": "insert_table", "index": 20, "rows": 2, "columns": 3}
        ]
    
    Returns:
        str: Confirmation message with batch operation results
    """
    logger.info(f"[batch_update_doc] Doc={document_id}, operations={len(operations)}")
    
    if not operations:
        return "Error: No operations provided. Please provide at least one operation."
    
    requests = []
    operation_descriptions = []
    
    for i, op in enumerate(operations):
        op_type = op.get('type')
        if not op_type:
            return f"Error: Operation {i+1} missing 'type' field."
        
        try:
            if op_type == 'insert_text':
                requests.append({
                    'insertText': {
                        'location': {'index': op['index']},
                        'text': op['text']
                    }
                })
                operation_descriptions.append(f"insert text at {op['index']}")
                
            elif op_type == 'delete_text':
                requests.append({
                    'deleteContentRange': {
                        'range': {
                            'startIndex': op['start_index'],
                            'endIndex': op['end_index']
                        }
                    }
                })
                operation_descriptions.append(f"delete text {op['start_index']}-{op['end_index']}")
                
            elif op_type == 'replace_text':
                requests.extend([
                    {
                        'deleteContentRange': {
                            'range': {
                                'startIndex': op['start_index'],
                                'endIndex': op['end_index']
                            }
                        }
                    },
                    {
                        'insertText': {
                            'location': {'index': op['start_index']},
                            'text': op['text']
                        }
                    }
                ])
                operation_descriptions.append(f"replace text {op['start_index']}-{op['end_index']}")
                
            elif op_type == 'format_text':
                text_style = {}
                format_changes = []
                
                if op.get('bold') is not None:
                    text_style['bold'] = op['bold']
                    format_changes.append(f"bold: {op['bold']}")
                if op.get('italic') is not None:
                    text_style['italic'] = op['italic']
                    format_changes.append(f"italic: {op['italic']}")
                if op.get('underline') is not None:
                    text_style['underline'] = op['underline']
                    format_changes.append(f"underline: {op['underline']}")
                if op.get('font_size') is not None:
                    text_style['fontSize'] = {'magnitude': op['font_size'], 'unit': 'PT'}
                    format_changes.append(f"font size: {op['font_size']}pt")
                if op.get('font_family') is not None:
                    text_style['fontFamily'] = op['font_family']
                    format_changes.append(f"font family: {op['font_family']}")
                
                if text_style:
                    requests.append({
                        'updateTextStyle': {
                            'range': {
                                'startIndex': op['start_index'],
                                'endIndex': op['end_index']
                            },
                            'textStyle': text_style,
                            'fields': ','.join(text_style.keys())
                        }
                    })
                    operation_descriptions.append(f"format text {op['start_index']}-{op['end_index']} ({', '.join(format_changes)})")
                
            elif op_type == 'insert_table':
                if not op.get('rows') or not op.get('columns'):
                    return f"Error: Operation {i+1} (insert_table) requires 'rows' and 'columns' fields."
                
                requests.append({
                    'insertTable': {
                        'location': {'index': op['index']},
                        'rows': op['rows'],
                        'columns': op['columns']
                    }
                })
                operation_descriptions.append(f"insert {op['rows']}x{op['columns']} table at {op['index']}")
                
            elif op_type == 'insert_page_break':
                requests.append({
                    'insertPageBreak': {
                        'location': {'index': op['index']}
                    }
                })
                operation_descriptions.append(f"insert page break at {op['index']}")
                
            elif op_type == 'find_replace':
                requests.append({
                    'replaceAllText': {
                        'containsText': {
                            'text': op['find_text'],
                            'matchCase': op.get('match_case', False)
                        },
                        'replaceText': op['replace_text']
                    }
                })
                operation_descriptions.append(f"find/replace '{op['find_text']}' → '{op['replace_text']}'")
                
            else:
                return f"Error: Unsupported operation type '{op_type}' in operation {i+1}. Supported types: insert_text, delete_text, replace_text, format_text, insert_table, insert_page_break, find_replace."
                
        except KeyError as e:
            return f"Error: Operation {i+1} ({op_type}) missing required field: {e}"
        except Exception as e:
            return f"Error: Operation {i+1} ({op_type}) failed validation: {str(e)}"
    
    # Execute all operations in a single batch
    result = await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': requests}
        ).execute
    )
    
    # Extract results information
    replies_count = len(result.get('replies', []))
    
    operations_summary = ', '.join(operation_descriptions[:3])  # Show first 3 operations
    if len(operation_descriptions) > 3:
        operations_summary += f" and {len(operation_descriptions) - 3} more"
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Successfully executed {len(operations)} operations ({operations_summary}) on document {document_id}. API replies: {replies_count}. Link: {link}"


# Create comment management tools for documents
_comment_tools = create_comment_tools("document", "document_id")

# Extract and register the functions
read_doc_comments = _comment_tools['read_comments']
create_doc_comment = _comment_tools['create_comment']
reply_to_comment = _comment_tools['reply_to_comment']
resolve_comment = _comment_tools['resolve_comment']
