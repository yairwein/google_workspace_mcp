"""
Google Docs MCP Tools

This module provides MCP tools for interacting with Google Docs API and managing Google Docs via Drive.
"""
import logging
import asyncio
import io
from typing import List

from mcp import types
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

# Auth & server utilities
from auth.google_auth import get_authenticated_google_service
from core.utils import extract_office_xml_text
from core.server import (
    server,
    DRIVE_READONLY_SCOPE,
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE,
)

logger = logging.getLogger(__name__)

@server.tool()
async def search_docs(
    user_google_email: str,
    query: str,
    page_size: int = 10,
) -> str:
    """
    Searches for Google Docs by name using Drive API (mimeType filter).
    
    Returns:
        str: A formatted list of Google Docs matching the search query.
    """
    tool_name = "search_docs"
    logger.info(f"[{tool_name}] Email={user_google_email}, Query='{query}'")

    auth_result = await get_authenticated_google_service(
        service_name="drive",
        version="v3",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DRIVE_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
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

    except HttpError as e:
        logger.error(f"API error in search_docs: {e}", exc_info=True)
        raise Exception(f"API error: {e}")

@server.tool()
async def get_doc_content(
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
    tool_name = "get_doc_content"
    logger.info(f"[{tool_name}] Invoked. Document/File ID: '{document_id}' for user '{user_google_email}'")

    # Step 1: Authenticate with Drive API to get metadata
    drive_auth_result = await get_authenticated_google_service(
        service_name="drive",
        version="v3",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DRIVE_READONLY_SCOPE],
    )
    if isinstance(drive_auth_result, types.CallToolResult):
        return drive_auth_result
    drive_service, user_email = drive_auth_result # user_email will be consistent

    try:
        # Step 2: Get file metadata from Drive
        file_metadata = await asyncio.to_thread(
            drive_service.files().get(
                fileId=document_id, fields="id, name, mimeType, webViewLink"
            ).execute
        )
        mime_type = file_metadata.get("mimeType", "")
        file_name = file_metadata.get("name", "Unknown File")
        web_view_link = file_metadata.get("webViewLink", "#")

        logger.info(f"[{tool_name}] File '{file_name}' (ID: {document_id}) has mimeType: '{mime_type}'")

        body_text = "" # Initialize body_text

        # Step 3: Process based on mimeType
        if mime_type == "application/vnd.google-apps.document":
            logger.info(f"[{tool_name}] Processing as native Google Doc.")
            docs_auth_result = await get_authenticated_google_service(
                service_name="docs",
                version="v1",
                tool_name=tool_name,
                user_google_email=user_google_email,
                required_scopes=[DOCS_READONLY_SCOPE],
            )
            if isinstance(docs_auth_result, types.CallToolResult):
                return docs_auth_result
            docs_service, _ = docs_auth_result # user_email already obtained from drive_auth

            doc_data = await asyncio.to_thread(
                docs_service.documents().get(documentId=document_id).execute
            )
            body_elements = doc_data.get('body', {}).get('content', [])

            processed_text_lines: List[str] = []
            for element in body_elements:
                if 'paragraph' in element:
                    paragraph = element.get('paragraph', {})
                    para_elements = paragraph.get('elements', [])
                    current_line_text = ""
                    for pe in para_elements:
                        text_run = pe.get('textRun', {})
                        if text_run and 'content' in text_run:
                            current_line_text += text_run['content']
                    if current_line_text.strip():
                         processed_text_lines.append(current_line_text)
            body_text = "".join(processed_text_lines)
        else:
            logger.info(f"[{tool_name}] Processing as Drive file (e.g., .docx, other). MimeType: {mime_type}")

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

    except HttpError as error:
        logger.error(
            f"[{tool_name}] API error for ID {document_id}: {error}",
            exc_info=True,
        )
        raise Exception(f"API error processing document/file ID {document_id}: {error}")
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error for ID {document_id}: {e}")
        raise Exception(f"Unexpected error processing document/file ID {document_id}: {e}")

@server.tool()
async def list_docs_in_folder(
    user_google_email: str,
    folder_id: str = 'root',
    page_size: int = 100
) -> str:
    """
    Lists Google Docs within a specific Drive folder.
    
    Returns:
        str: A formatted list of Google Docs in the specified folder.
    """
    tool_name = "list_docs_in_folder"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}', Folder ID: '{folder_id}'")

    auth_result = await get_authenticated_google_service(
        service_name="drive",
        version="v3",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DRIVE_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    drive_service, user_email = auth_result # user_email will be consistent

    try:
        rsp = await asyncio.to_thread(
            drive_service.files().list(
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

    except HttpError as e:
        logger.error(f"API error in {tool_name}: {e}", exc_info=True)
        raise Exception(f"API error: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error in {tool_name}: {e}")
        raise Exception(f"Unexpected error: {e}")

@server.tool()
async def create_doc(
    user_google_email: str, # Made user_google_email required
    title: str,
    content: str = '',
) -> str:
    """
    Creates a new Google Doc and optionally inserts initial content.
    
    Returns:
        str: Confirmation message with document ID and link.
    """
    tool_name = "create_doc"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}', Title='{title}'")

    auth_result = await get_authenticated_google_service(
        service_name="docs",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DOCS_WRITE_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    docs_service, user_email = auth_result

    try:
        doc = await asyncio.to_thread(docs_service.documents().create(body={'title': title}).execute)
        doc_id = doc.get('documentId')
        if content:
            requests = [{'insertText': {'location': {'index': 1}, 'text': content}}]
            await asyncio.to_thread(docs_service.documents().batchUpdate(documentId=doc_id, body={'requests': requests}).execute)
        link = f"https://docs.google.com/document/d/{doc_id}/edit"
        msg = f"Created Google Doc '{title}' (ID: {doc_id}) for {user_email}. Link: {link}"
        logger.info(f"Successfully created Google Doc '{title}' (ID: {doc_id}) for {user_email}. Link: {link}")
        return msg

    except HttpError as e:
        logger.error(f"API error in {tool_name}: {e}", exc_info=True)
        raise Exception(f"API error: {e}")
    except Exception as e:
        logger.exception(f"Unexpected error in {tool_name}: {e}")
        raise Exception(f"Unexpected error: {e}")
