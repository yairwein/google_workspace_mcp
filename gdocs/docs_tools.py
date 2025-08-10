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

# Import helper functions for document operations
from gdocs.docs_helpers import (
    create_insert_text_request,
    create_delete_range_request,
    create_format_text_request,
    create_find_replace_request,
    create_insert_table_request,
    create_insert_page_break_request,
    create_insert_image_request,
    create_bullet_list_request,
    validate_operation
)

# Import document structure and table utilities
from gdocs.docs_structure import (
    parse_document_structure,
    find_tables,
    get_table_cell_indices,
    find_element_at_index,
    analyze_document_complexity
)
from gdocs.docs_tables import (
    build_table_population_requests,
    format_table_data,
    validate_table_data,
    extract_table_as_data,
    find_table_by_content
)

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
            create_delete_range_request(start_index, end_index),
            create_insert_text_request(start_index, text)
        ])
        operation = f"Replaced text from index {start_index} to {end_index}"
    else:
        # Insert text at position
        requests.append(create_insert_text_request(start_index, text))
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
    
    requests = [create_find_replace_request(find_text, replace_text, match_case)]
    
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
    
    # Use helper to create format request
    format_request = create_format_text_request(
        start_index, end_index, bold, italic, underline, font_size, font_family
    )
    
    if not format_request:
        return "No formatting changes specified. Please provide at least one formatting option."
    
    requests = [format_request]
    
    # Build format_changes list for the return message
    format_changes = []
    if bold is not None:
        format_changes.append(f"bold: {bold}")
    if italic is not None:
        format_changes.append(f"italic: {italic}")
    if underline is not None:
        format_changes.append(f"underline: {underline}")
    if font_size is not None:
        format_changes.append(f"font size: {font_size}pt")
    if font_family is not None:
        format_changes.append(f"font family: {font_family}")
    
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
        
        requests.append(create_insert_table_request(index, rows, columns))
        description = f"table ({rows}x{columns})"
        
    elif element_type == "list":
        if not list_type:
            return "Error: 'list_type' parameter is required for list insertion ('UNORDERED' or 'ORDERED')."
        
        if not text:
            text = "List item"
        
        # Insert text first, then create list
        requests.extend([
            create_insert_text_request(index, text + '\n'),
            create_bullet_list_request(index, index + len(text), list_type)
        ])
        description = f"{list_type.lower()} list"
        
    elif element_type == "page_break":
        requests.append(create_insert_page_break_request(index))
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
    
    # Use helper to create image request
    requests = [create_insert_image_request(index, image_uri, width, height)]
    
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
        # Validate operation first
        is_valid, error_msg = validate_operation(op)
        if not is_valid:
            return f"Error: Operation {i+1}: {error_msg}"
        
        op_type = op.get('type')
        
        try:
            if op_type == 'insert_text':
                requests.append(create_insert_text_request(op['index'], op['text']))
                operation_descriptions.append(f"insert text at {op['index']}")
                
            elif op_type == 'delete_text':
                requests.append(create_delete_range_request(op['start_index'], op['end_index']))
                operation_descriptions.append(f"delete text {op['start_index']}-{op['end_index']}")
                
            elif op_type == 'replace_text':
                requests.extend([
                    create_delete_range_request(op['start_index'], op['end_index']),
                    create_insert_text_request(op['start_index'], op['text'])
                ])
                operation_descriptions.append(f"replace text {op['start_index']}-{op['end_index']}")
                
            elif op_type == 'format_text':
                format_request = create_format_text_request(
                    op['start_index'], op['end_index'],
                    op.get('bold'), op.get('italic'), op.get('underline'),
                    op.get('font_size'), op.get('font_family')
                )
                if format_request:
                    requests.append(format_request)
                    # Build format description
                    format_changes = []
                    if op.get('bold') is not None:
                        format_changes.append(f"bold: {op['bold']}")
                    if op.get('italic') is not None:
                        format_changes.append(f"italic: {op['italic']}")
                    if op.get('underline') is not None:
                        format_changes.append(f"underline: {op['underline']}")
                    if op.get('font_size') is not None:
                        format_changes.append(f"font size: {op['font_size']}pt")
                    if op.get('font_family') is not None:
                        format_changes.append(f"font family: {op['font_family']}")
                    operation_descriptions.append(f"format text {op['start_index']}-{op['end_index']} ({', '.join(format_changes)})")
                
            elif op_type == 'insert_table':
                requests.append(create_insert_table_request(op['index'], op['rows'], op['columns']))
                operation_descriptions.append(f"insert {op['rows']}x{op['columns']} table at {op['index']}")
                
            elif op_type == 'insert_page_break':
                requests.append(create_insert_page_break_request(op['index']))
                operation_descriptions.append(f"insert page break at {op['index']}")
                
            elif op_type == 'find_replace':
                requests.append(create_find_replace_request(
                    op['find_text'], op['replace_text'], op.get('match_case', False)
                ))
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

@server.tool()
@handle_http_errors("inspect_doc_structure", is_read_only=True, service_type="docs")
@require_google_service("docs", "docs_read")
async def inspect_doc_structure(
    service,
    user_google_email: str,
    document_id: str,
    detailed: bool = False,
) -> str:
    """
    Essential tool for finding safe insertion points and understanding document structure.
    
    USE THIS FOR:
    - Finding the correct index for table insertion
    - Understanding document layout before making changes
    - Locating existing tables and their positions
    - Getting document statistics and complexity info
    
    CRITICAL FOR TABLE OPERATIONS:
    ALWAYS call this BEFORE creating tables to get a safe insertion index.
    Look for "total_length" in the output - use values less than this for insertion.
    
    WHAT THE OUTPUT SHOWS:
    - total_elements: Number of document elements
    - total_length: Maximum safe index for insertion
    - tables: Number of existing tables
    - table_details: Position and dimensions of each table
    
    WORKFLOW:
    Step 1: Call this function
    Step 2: Note the "total_length" value
    Step 3: Use an index < total_length for table insertion
    Step 4: Create your table
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to inspect
        detailed: Whether to return detailed structure information
    
    Returns:
        str: JSON string containing document structure and safe insertion indices
    """
    logger.info(f"[inspect_doc_structure] Doc={document_id}, detailed={detailed}")
    
    # Get the document
    doc = await asyncio.to_thread(
        service.documents().get(documentId=document_id).execute
    )
    
    if detailed:
        # Return full parsed structure
        structure = parse_document_structure(doc)
        
        # Simplify for JSON serialization
        result = {
            'title': structure['title'],
            'total_length': structure['total_length'],
            'statistics': {
                'elements': len(structure['body']),
                'tables': len(structure['tables']),
                'paragraphs': sum(1 for e in structure['body'] if e.get('type') == 'paragraph'),
                'has_headers': bool(structure['headers']),
                'has_footers': bool(structure['footers'])
            },
            'elements': []
        }
        
        # Add element summaries
        for element in structure['body']:
            elem_summary = {
                'type': element['type'],
                'start_index': element['start_index'],
                'end_index': element['end_index']
            }
            
            if element['type'] == 'table':
                elem_summary['rows'] = element['rows']
                elem_summary['columns'] = element['columns']
                elem_summary['cell_count'] = len(element.get('cells', []))
            elif element['type'] == 'paragraph':
                elem_summary['text_preview'] = element.get('text', '')[:100]
            
            result['elements'].append(elem_summary)
        
        # Add table details
        if structure['tables']:
            result['tables'] = []
            for i, table in enumerate(structure['tables']):
                table_data = extract_table_as_data(table)
                result['tables'].append({
                    'index': i,
                    'position': {'start': table['start_index'], 'end': table['end_index']},
                    'dimensions': {'rows': table['rows'], 'columns': table['columns']},
                    'preview': table_data[:3] if table_data else []  # First 3 rows
                })
    
    else:
        # Return basic analysis
        result = analyze_document_complexity(doc)
        
        # Add table information
        tables = find_tables(doc)
        if tables:
            result['table_details'] = []
            for i, table in enumerate(tables):
                result['table_details'].append({
                    'index': i,
                    'rows': table['rows'],
                    'columns': table['columns'],
                    'start_index': table['start_index'],
                    'end_index': table['end_index']
                })
    
    import json
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Document structure analysis for {document_id}:\n\n{json.dumps(result, indent=2)}\n\nLink: {link}"

@server.tool()
@handle_http_errors("create_table_with_data", service_type="docs")
@require_google_service("docs", "docs_write")
async def create_table_with_data(
    service,
    user_google_email: str,
    document_id: str,
    table_data: list,
    index: int,
    bold_headers: bool = True,
) -> str:
    """
    Creates a table and populates it with data in one reliable operation.
    
    CRITICAL: YOU MUST CALL inspect_doc_structure FIRST TO GET THE INDEX!
    
    MANDATORY WORKFLOW - DO THESE STEPS IN ORDER:
    
    Step 1: ALWAYS call inspect_doc_structure first
    Step 2: Use the 'total_length' value from inspect_doc_structure as your index
    Step 3: Format data as 2D list: [["col1", "col2"], ["row1col1", "row1col2"]]
    Step 4: Call this function with the correct index and data
    
    EXAMPLE DATA FORMAT:
    table_data = [
        ["Header1", "Header2", "Header3"],    # Row 0 - headers
        ["Data1", "Data2", "Data3"],          # Row 1 - first data row  
        ["Data4", "Data5", "Data6"]           # Row 2 - second data row
    ]
    
    CRITICAL INDEX REQUIREMENTS:
    - NEVER use index values like 1, 2, 10 without calling inspect_doc_structure first
    - ALWAYS get index from inspect_doc_structure 'total_length' field
    - Index must be a valid insertion point in the document
    
    DATA FORMAT REQUIREMENTS:
    - Must be 2D list of strings only
    - Each inner list = one table row
    - All rows MUST have same number of columns
    - Use empty strings "" for empty cells, never None
    
    TROUBLESHOOTING:
    - If data appears concatenated in first cell (like "h1h2h3"), this was a known bug now fixed
    - The function now refreshes document structure after each cell insertion to prevent index shifting
    - If you get errors, verify table_data is properly formatted 2D list
    - Use debug_table_structure after creation to verify results
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update  
        table_data: 2D list of strings - EXACT format: [["col1", "col2"], ["row1col1", "row1col2"]]
        index: Document position (MANDATORY: get from inspect_doc_structure 'total_length')
        bold_headers: Whether to make first row bold (default: true)
    
    Returns:
        str: Confirmation with table details and link
    """
    logger.info(f"[create_table_with_data] Doc={document_id}, index={index}")
    logger.info(f"Received table_data: {table_data}")
    logger.info(f"Bold headers: {bold_headers}")
    
    # Critical validation: Check if index is suspiciously low (common LLM mistake)
    # NOTE: Removed strict validation since index=1 can be valid for simple documents
    if index < 0:
        return f"ERROR: Index {index} is negative. You MUST call inspect_doc_structure first to get the proper insertion index."
    
    # Strict validation with helpful error messages
    is_valid, error_msg = validate_table_data(table_data)
    if not is_valid:
        return f"ERROR: {error_msg}\n\nRequired format: [['col1', 'col2'], ['row2col1', 'row2col2']]"
    
    # Additional debugging: Print the exact structure we received
    logger.info(f"Table data structure validation:")
    for i, row in enumerate(table_data):
        logger.info(f"  Row {i}: {row} (type: {type(row)}, length: {len(row)})")
        for j, cell in enumerate(row):
            logger.info(f"    Cell ({i},{j}): '{cell}' (type: {type(cell)})")
    
    rows = len(table_data)
    cols = len(table_data[0])
    logger.info(f"Table dimensions: {rows}x{cols}")
    
    # Validate all rows have same column count
    for i, row in enumerate(table_data):
        if len(row) != cols:
            return f"ERROR: Row {i} has {len(row)} columns, but first row has {cols} columns. All rows must have the same number of columns."
        # Also validate each cell is a string
        for j, cell in enumerate(row):
            if not isinstance(cell, str):
                return f"ERROR: Cell ({i},{j}) is {type(cell).__name__}, not string. All cells must be strings. Value: {repr(cell)}"
    
    # Step 1: Create empty table
    logger.info(f"Creating {rows}x{cols} table at index {index}")
    logger.info(f"Table data being used: {table_data}")
    create_result = await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': [create_insert_table_request(index, rows, cols)]}
        ).execute
    )
    
    # Step 2: Get fresh document structure to find actual cell positions
    doc = await asyncio.to_thread(
        service.documents().get(documentId=document_id).execute
    )
    
    # Find the table we just created
    tables = find_tables(doc)
    if not tables:
        return f"ERROR: Could not find table after creation in document {document_id}"
    
    # Use the last table (newly created one)
    table_info = tables[-1]
    cells = table_info.get('cells', [])
    logger.info(f"Found table with {len(cells)} rows, cells structure: {[[f'({r},{c})' for c in range(len(row))] for r, row in enumerate(cells)]}")
    
    # Step 3: Populate each cell individually, refreshing indices after each insertion
    population_count = 0
    logger.info(f"Starting cell population for {len(table_data)} rows, {len(table_data[0]) if table_data else 0} columns")
    
    for row_idx, row_data in enumerate(table_data):
        logger.info(f"Processing row {row_idx}: {row_data}")
        for col_idx, cell_text in enumerate(row_data):
            if cell_text:  # Only populate non-empty cells
                logger.info(f"Processing cell ({row_idx},{col_idx}) with text '{cell_text}'")
                
                # CRITICAL: Refresh document structure before each insertion
                # This prevents index shifting issues
                fresh_doc = await asyncio.to_thread(
                    service.documents().get(documentId=document_id).execute
                )
                fresh_tables = find_tables(fresh_doc)
                if not fresh_tables:
                    return f"ERROR: Could not find table after refresh for cell ({row_idx},{col_idx})"
                
                fresh_table = fresh_tables[-1]  # Use the last table (newly created one)
                fresh_cells = fresh_table.get('cells', [])
                
                # Bounds checking with fresh data
                if row_idx >= len(fresh_cells) or col_idx >= len(fresh_cells[row_idx]):
                    logger.error(f"Cell ({row_idx},{col_idx}) out of bounds after refresh")
                    continue
                    
                cell = fresh_cells[row_idx][col_idx] 
                insertion_index = cell.get('insertion_index')
                logger.info(f"Cell ({row_idx},{col_idx}) fresh insertion_index: {insertion_index}")
                
                if insertion_index:
                    try:
                        # Insert text
                        await asyncio.to_thread(
                            service.documents().batchUpdate(
                                documentId=document_id,
                                body={'requests': [{
                                    'insertText': {
                                        'location': {'index': insertion_index},
                                        'text': cell_text
                                    }
                                }]}
                            ).execute
                        )
                        population_count += 1
                        logger.info(f"Successfully inserted '{cell_text}' at index {insertion_index}")
                        
                        # Apply bold to first row if requested
                        if bold_headers and row_idx == 0:
                            # Need to get updated position after text insertion
                            updated_end_index = insertion_index + len(cell_text)
                            await asyncio.to_thread(
                                service.documents().batchUpdate(
                                    documentId=document_id,
                                    body={'requests': [{
                                        'updateTextStyle': {
                                            'range': {
                                                'startIndex': insertion_index,
                                                'endIndex': updated_end_index
                                            },
                                            'textStyle': {'bold': True},
                                            'fields': 'bold'
                                        }
                                    }]}
                                ).execute
                            )
                            logger.info(f"Applied bold formatting to '{cell_text}' from {insertion_index} to {updated_end_index}")
                        
                    except Exception as e:
                        logger.error(f"Failed to populate cell ({row_idx},{col_idx}): {str(e)}")
                        return f"ERROR: Failed to populate cell ({row_idx},{col_idx}) with '{cell_text}': {str(e)}"
                else:
                    logger.warning(f"No insertion_index for cell ({row_idx},{col_idx})")
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    logger.info(f"Completed table creation. Populated {population_count} cells out of expected {sum(1 for row in table_data for cell in row if cell)}")
    return f"SUCCESS: Created {rows}x{cols} table and populated {population_count} cells at index {index}. Bold headers: {bold_headers}. Link: {link}"

@server.tool()
@handle_http_errors("create_empty_table", service_type="docs")
@require_google_service("docs", "docs_write")
async def create_empty_table(
    service,
    user_google_email: str,
    document_id: str,
    rows: int,
    columns: int,
    index: int,
) -> str:
    """
    Creates an empty table with specified dimensions - use when you need precise control.
    
    WHEN TO USE THIS:
    - You want to create table first, then populate later
    - You need to create multiple tables before populating any
    - You want to manually control each step of table creation
    
    RECOMMENDED WORKFLOW:
    Step 1: Call inspect_doc_structure to get safe insertion index
    Step 2: Call this function to create empty table
    Step 3: Call debug_table_structure to verify table was created correctly
    Step 4: Call populate_existing_table to fill with data
    
    ALTERNATIVE: Use create_table_with_data to do steps 2-4 in one operation
    
    VALIDATION RULES:
    - rows: 1-20 (Google Docs limits)
    - columns: 1-10 (Google Docs limits)
    - index: Must be valid insertion point (get from inspect_doc_structure)
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to update
        rows: Number of rows (1-20)
        columns: Number of columns (1-10) 
        index: Document position to insert table (get from inspect_doc_structure)
    
    Returns:
        str: Confirmation with table details and link
    """
    logger.info(f"[create_empty_table] Doc={document_id}, {rows}x{columns} at index {index}")
    
    # Validation
    if rows < 1 or rows > 20:
        return f"ERROR: Rows must be between 1-20, got {rows}"
    if columns < 1 or columns > 10:
        return f"ERROR: Columns must be between 1-10, got {columns}"
    
    # Create table
    result = await asyncio.to_thread(
        service.documents().batchUpdate(
            documentId=document_id,
            body={'requests': [create_insert_table_request(index, rows, columns)]}
        ).execute
    )
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"SUCCESS: Created empty {rows}x{columns} table at index {index}. Link: {link}"

@server.tool()
@handle_http_errors("populate_existing_table", service_type="docs")
@require_google_service("docs", "docs_write")
async def populate_existing_table(
    service,
    user_google_email: str,
    document_id: str,
    table_data: list,
    table_index: int = 0,
    bold_headers: bool = True,
) -> str:
    """
    Populates an existing empty table with data using individual cell updates.
    
    USAGE WORKFLOW - DO THIS STEP BY STEP:
    
    Step 1: Ensure table already exists in document (use create_empty_table first if needed)
    Step 2: ALWAYS call debug_table_structure to verify table layout and dimensions
    Step 3: Format your data to match table dimensions exactly
    Step 4: Call this function
    Step 5: If issues occur, call debug_table_structure again to diagnose
    
    MANDATORY DATA FORMAT:
    table_data = [
        ["Col1", "Col2", "Col3"],       # Row 0 - must match table width
        ["Val1", "Val2", "Val3"],       # Row 1
        ["Val4", "Val5", "Val6"]        # Row 2 - must match table height
    ]
    
    REQUIREMENTS CHECKLIST:
    □ Table already exists in document
    □ Used debug_table_structure to check table dimensions  
    □ Data is 2D list of strings only
    □ Data rows ≤ table rows, Data cols ≤ table cols
    □ All data items are strings (use "" for empty cells)
    □ Verified table_index is correct (0 = first table)
    
    WHEN TO USE THIS vs create_table_with_data:
    - Use create_table_with_data: When you need to create a NEW table
    - Use populate_existing_table: When table already exists and is empty
    - Use debug_table_structure: ALWAYS use this first to understand table layout
    
    TROUBLESHOOTING:
    - Data in wrong cells? → Check debug_table_structure output
    - "Table not found" error? → Verify table_index, use inspect_doc_structure
    - "Dimensions mismatch" error? → Your data array is wrong size for table
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of document containing the table
        table_data: 2D list of strings - EXACT format: [["col1", "col2"], ["row1col1", "row1col2"]]
        table_index: Which table to populate (0 = first table, 1 = second table, etc.)
        bold_headers: Whether to make first row bold
    
    Returns:
        str: Confirmation with population details
    """
    logger.info(f"[populate_existing_table] Doc={document_id}, table_index={table_index}")
    
    # Strict validation with clear error messages
    is_valid, error_msg = validate_table_data(table_data)
    if not is_valid:
        return f"ERROR: {error_msg}\n\nRequired format: [['col1', 'col2'], ['row2col1', 'row2col2']]"
    
    # Get document and find the specified table
    doc = await asyncio.to_thread(
        service.documents().get(documentId=document_id).execute
    )
    
    tables = find_tables(doc)
    if table_index >= len(tables):
        return f"ERROR: Table index {table_index} not found. Document has {len(tables)} table(s). Use debug_table_structure to see available tables."
    
    table_info = tables[table_index]
    cells = table_info.get('cells', [])
    
    # Validate data fits in table
    table_rows = table_info['rows']
    table_cols = table_info['columns']
    data_rows = len(table_data)
    data_cols = len(table_data[0])
    
    if data_rows > table_rows:
        return f"ERROR: Data has {data_rows} rows but table only has {table_rows} rows."
    
    if data_cols > table_cols:
        return f"ERROR: Data has {data_cols} columns but table only has {table_cols} columns."
    
    # Populate each cell individually using the proven working method
    population_count = 0
    for row_idx, row_data in enumerate(table_data):
        for col_idx, cell_text in enumerate(row_data):
            if cell_text:  # Only populate non-empty cells
                cell = cells[row_idx][col_idx]
                insertion_index = cell.get('insertion_index')
                
                if insertion_index:
                    # Use individual insertText operations (the method that worked)
                    await asyncio.to_thread(
                        service.documents().batchUpdate(
                            documentId=document_id,
                            body={'requests': [{
                                'insertText': {
                                    'location': {'index': insertion_index},
                                    'text': cell_text
                                }
                            }]}
                        ).execute
                    )
                    population_count += 1
                    
                    # Apply bold to first row if requested
                    if bold_headers and row_idx == 0:
                        await asyncio.to_thread(
                            service.documents().batchUpdate(
                                documentId=document_id,
                                body={'requests': [{
                                    'updateTextStyle': {
                                        'range': {
                                            'startIndex': insertion_index,
                                            'endIndex': insertion_index + len(cell_text)
                                        },
                                        'textStyle': {'bold': True},
                                        'fields': 'bold'
                                    }
                                }]}
                            ).execute
                        )
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"SUCCESS: Populated {population_count} cells in table {table_index} with {data_rows}x{data_cols} data. Bold headers: {bold_headers}. Link: {link}"

@server.tool()
@handle_http_errors("debug_table_structure", is_read_only=True, service_type="docs")
@require_google_service("docs", "docs_read")
async def debug_table_structure(
    service,
    user_google_email: str,
    document_id: str,
    table_index: int = 0,
) -> str:
    """
    ESSENTIAL DEBUGGING TOOL - Use this whenever tables don't work as expected.
    
    USE THIS IMMEDIATELY WHEN:
    - Table population put data in wrong cells
    - You get "table not found" errors  
    - Data appears concatenated in first cell
    - Need to understand existing table structure
    - Planning to use populate_existing_table
    
    WHAT THIS SHOWS YOU:
    - Exact table dimensions (rows × columns)
    - Each cell's position coordinates (row,col)
    - Current content in each cell
    - Insertion indices for each cell
    - Table boundaries and ranges
    
    HOW TO READ THE OUTPUT:
    - "dimensions": "2x3" = 2 rows, 3 columns
    - "position": "(0,0)" = first row, first column
    - "current_content": What's actually in each cell right now
    - "insertion_index": Where new text would be inserted in that cell
    
    WORKFLOW INTEGRATION:
    1. After creating table → Use this to verify structure
    2. Before populating → Use this to plan your data format
    3. After population fails → Use this to see what went wrong
    4. When debugging → Compare your data array to actual table structure
    
    Args:
        user_google_email: User's Google email address
        document_id: ID of the document to inspect
        table_index: Which table to debug (0 = first table, 1 = second table, etc.)
    
    Returns:
        str: Detailed JSON structure showing table layout, cell positions, and current content
    """
    logger.info(f"[debug_table_structure] Doc={document_id}, table_index={table_index}")
    
    # Get the document
    doc = await asyncio.to_thread(
        service.documents().get(documentId=document_id).execute
    )
    
    # Find tables
    tables = find_tables(doc)
    if table_index >= len(tables):
        return f"Error: Table index {table_index} not found. Document has {len(tables)} table(s)."
    
    table_info = tables[table_index]
    
    import json
    
    # Extract detailed cell information
    debug_info = {
        'table_index': table_index,
        'dimensions': f"{table_info['rows']}x{table_info['columns']}",
        'table_range': f"[{table_info['start_index']}-{table_info['end_index']}]",
        'cells': []
    }
    
    for row_idx, row in enumerate(table_info['cells']):
        row_info = []
        for col_idx, cell in enumerate(row):
            cell_debug = {
                'position': f"({row_idx},{col_idx})",
                'range': f"[{cell['start_index']}-{cell['end_index']}]",
                'insertion_index': cell.get('insertion_index', 'N/A'),
                'current_content': repr(cell.get('content', '')),
                'content_elements_count': len(cell.get('content_elements', []))
            }
            row_info.append(cell_debug)
        debug_info['cells'].append(row_info)
    
    link = f"https://docs.google.com/document/d/{document_id}/edit"
    return f"Table structure debug for table {table_index}:\n\n{json.dumps(debug_info, indent=2)}\n\nLink: {link}"


# Create comment management tools for documents
_comment_tools = create_comment_tools("document", "document_id")

# Extract and register the functions
read_doc_comments = _comment_tools['read_comments']
create_doc_comment = _comment_tools['create_comment']
reply_to_comment = _comment_tools['reply_to_comment']
resolve_comment = _comment_tools['resolve_comment']
