"""
Google Drive MCP Tools

This module provides MCP tools for interacting with Google Drive API.
"""
import logging
import asyncio
import re
from typing import List, Optional, Dict, Any

from mcp import types
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import io

from auth.google_auth import get_authenticated_google_service
from core.utils import extract_office_xml_text
from core.server import server
from core.server import (
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE,
)

logger = logging.getLogger(__name__)

# Precompiled regex patterns for Drive query detection
DRIVE_QUERY_PATTERNS = [
    re.compile(r'\b\w+\s*(=|!=|>|<)\s*[\'"].*?[\'"]', re.IGNORECASE),  # field = 'value'
    re.compile(r'\b\w+\s*(=|!=|>|<)\s*\d+', re.IGNORECASE),            # field = number
    re.compile(r'\bcontains\b', re.IGNORECASE),                         # contains operator
    re.compile(r'\bin\s+parents\b', re.IGNORECASE),                     # in parents
    re.compile(r'\bhas\s*\{', re.IGNORECASE),                          # has {properties}
    re.compile(r'\btrashed\s*=\s*(true|false)\b', re.IGNORECASE),      # trashed=true/false
    re.compile(r'\bstarred\s*=\s*(true|false)\b', re.IGNORECASE),      # starred=true/false
    re.compile(r'[\'"][^\'"]+[\'"]\s+in\s+parents', re.IGNORECASE),    # 'parentId' in parents
    re.compile(r'\bfullText\s+contains\b', re.IGNORECASE),             # fullText contains
    re.compile(r'\bname\s*(=|contains)\b', re.IGNORECASE),             # name = or name contains
    re.compile(r'\bmimeType\s*(=|!=)\b', re.IGNORECASE),               # mimeType operators
]


def _build_drive_list_params(
    query: str,
    page_size: int,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Helper function to build common list parameters for Drive API calls.

    Args:
        query: The search query string
        page_size: Maximum number of items to return
        drive_id: Optional shared drive ID
        include_items_from_all_drives: Whether to include items from all drives
        corpora: Optional corpus specification

    Returns:
        Dictionary of parameters for Drive API list calls
    """
    list_params = {
        "q": query,
        "pageSize": page_size,
        "fields": "nextPageToken, files(id, name, mimeType, webViewLink, iconLink, modifiedTime, size)",
        "supportsAllDrives": True,
        "includeItemsFromAllDrives": include_items_from_all_drives,
    }

    if drive_id:
        list_params["driveId"] = drive_id
        if corpora:
            list_params["corpora"] = corpora
        else:
            list_params["corpora"] = "drive"
    elif corpora:
        list_params["corpora"] = corpora

    return list_params

@server.tool()
async def search_drive_files(
    user_google_email: str,
    query: str,
    page_size: int = 10,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
) -> types.CallToolResult:
    """
    Searches for files and folders within a user's Google Drive, including shared drives.

    Args:
        user_google_email (str): The user's Google email address. Required.
        query (str): The search query string. Supports Google Drive search operators.
        page_size (int): The maximum number of files to return. Defaults to 10.
        drive_id (Optional[str]): ID of the shared drive to search. If None, behavior depends on `corpora` and `include_items_from_all_drives`.
        include_items_from_all_drives (bool): Whether shared drive items should be included in results. Defaults to True. This is effective when not specifying a `drive_id`.
        corpora (Optional[str]): Bodies of items to query (e.g., 'user', 'domain', 'drive', 'allDrives').
                                 If 'drive_id' is specified and 'corpora' is None, it defaults to 'drive'.
                                 Otherwise, Drive API default behavior applies. Prefer 'user' or 'drive' over 'allDrives' for efficiency.

    Returns:
        types.CallToolResult: Contains a list of found files/folders with their details (ID, name, type, size, modified time, link),
                               an error message if the API call fails,
                               or an authentication guidance message if credentials are required.
    """
    tool_name = "search_drive_files"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}', Query: '{query}'")

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
        # Check if the query looks like a structured Drive query or free text
        # Look for Drive API operators and structured query patterns
        is_structured_query = any(pattern.search(query) for pattern in DRIVE_QUERY_PATTERNS)

        if is_structured_query:
            final_query = query
            logger.info(f"[search_drive_files] Using structured query as-is: '{final_query}'")
        else:
            # For free text queries, wrap in fullText contains
            escaped_query = query.replace("'", "\\'")
            final_query = f"fullText contains '{escaped_query}'"
            logger.info(f"[search_drive_files] Reformatting free text query '{query}' to '{final_query}'")

        list_params = _build_drive_list_params(
            query=final_query,
            page_size=page_size,
            drive_id=drive_id,
            include_items_from_all_drives=include_items_from_all_drives,
            corpora=corpora,
        )

        results = await asyncio.to_thread(
            service.files().list(**list_params).execute
        )
        files = results.get('files', [])
        if not files:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No files found for '{query}'.")])

        formatted_files_text_parts = [f"Found {len(files)} files for {user_google_email} matching '{query}':"]
        for item in files:
            size_str = f", Size: {item.get('size', 'N/A')}" if 'size' in item else ""
            formatted_files_text_parts.append(
                f"- Name: \"{item['name']}\" (ID: {item['id']}, Type: {item['mimeType']}{size_str}, Modified: {item.get('modifiedTime', 'N/A')}) Link: {item.get('webViewLink', '#')}"
            )
        text_output = "\n".join(formatted_files_text_parts)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text_output)])
    except HttpError as error:
        logger.error(f"API error searching Drive files: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error searching Drive files: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def get_drive_file_content(
    user_google_email: str,
    file_id: str,
) -> types.CallToolResult:
    """
    Retrieves the content of a specific Google Drive file by ID, supporting files in shared drives.

    • Native Google Docs, Sheets, Slides → exported as text / CSV.
    • Office files (.docx, .xlsx, .pptx) → unzipped & parsed with std-lib to
      extract readable text.
    • Any other file → downloaded; tries UTF-8 decode, else notes binary.

    Args:
        user_google_email: The user’s Google email address.
        file_id: Drive file ID.

    Returns:
        types.CallToolResult with plain-text content (or error info).
    """
    tool_name = "get_drive_file_content"
    logger.info(f"[{tool_name}] Invoked. File ID: '{file_id}'")

    auth_result = await get_authenticated_google_service(
        service_name="drive",
        version="v3",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DRIVE_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, _ = auth_result

    try:
        file_metadata = await asyncio.to_thread(
            service.files().get(
                fileId=file_id, fields="id, name, mimeType, webViewLink", supportsAllDrives=True
            ).execute
        )
        mime_type = file_metadata.get("mimeType", "")
        file_name = file_metadata.get("name", "Unknown File")
        export_mime_type = {
            "application/vnd.google-apps.document": "text/plain",
            "application/vnd.google-apps.spreadsheet": "text/csv",
            "application/vnd.google-apps.presentation": "text/plain",
        }.get(mime_type)

        request_obj = (
            service.files().export_media(fileId=file_id, mimeType=export_mime_type)
            if export_mime_type
            else service.files().get_media(fileId=file_id)
        )
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_obj)
        loop = asyncio.get_event_loop()
        done = False
        while not done:
            status, done = await loop.run_in_executor(None, downloader.next_chunk)

        file_content_bytes = fh.getvalue()

        # Attempt Office XML extraction
        office_text = extract_office_xml_text(file_content_bytes, mime_type)
        if office_text:
            body_text = office_text
        else:
            # Fallback: try UTF-8; otherwise flag binary
            try:
                body_text = file_content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                body_text = (
                    f"[Binary or unsupported text encoding for mimeType '{mime_type}' - "
                    f"{len(file_content_bytes)} bytes]"
                )

        # Assemble response
        header = (
            f'File: "{file_name}" (ID: {file_id}, Type: {mime_type})\n'
            f'Link: {file_metadata.get("webViewLink", "#")}\n\n--- CONTENT ---\n'
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=header + body_text)]
        )

    except HttpError as error:
        logger.error(
            f"API error getting Drive file content for {file_id}: {error}",
            exc_info=True,
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"API error: {error}")],
        )
    except Exception as e:
        logger.exception(f"Unexpected error getting Drive file content for {file_id}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def list_drive_items(
    user_google_email: str,
    folder_id: str = 'root',
    page_size: int = 100,
    drive_id: Optional[str] = None,
    include_items_from_all_drives: bool = True,
    corpora: Optional[str] = None,
) -> types.CallToolResult:
    """
    Lists files and folders, supporting shared drives.
    If `drive_id` is specified, lists items within that shared drive. `folder_id` is then relative to that drive (or use drive_id as folder_id for root).
    If `drive_id` is not specified, lists items from user's "My Drive" and accessible shared drives (if `include_items_from_all_drives` is True).

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): The ID of the Google Drive folder. Defaults to 'root'. For a shared drive, this can be the shared drive's ID to list its root, or a folder ID within that shared drive.
        page_size (int): The maximum number of items to return. Defaults to 100.
        drive_id (Optional[str]): ID of the shared drive. If provided, the listing is scoped to this drive.
        include_items_from_all_drives (bool): Whether items from all accessible shared drives should be included if `drive_id` is not set. Defaults to True.
        corpora (Optional[str]): Corpus to query ('user', 'drive', 'allDrives'). If `drive_id` is set and `corpora` is None, 'drive' is used. If None and no `drive_id`, API defaults apply.

    Returns:
        types.CallToolResult: Contains a list of files/folders or an error.
    """
    tool_name = "list_drive_items"
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
    service, user_email = auth_result

    try:
        final_query = f"'{folder_id}' in parents and trashed=false"

        list_params = _build_drive_list_params(
            query=final_query,
            page_size=page_size,
            drive_id=drive_id,
            include_items_from_all_drives=include_items_from_all_drives,
            corpora=corpora,
        )

        results = await asyncio.to_thread(
            service.files().list(**list_params).execute
        )
        files = results.get('files', [])
        if not files:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No items found in folder '{folder_id}'.")])

        formatted_items_text_parts = [f"Found {len(files)} items in folder '{folder_id}' for {user_google_email}:"]
        for item in files:
            size_str = f", Size: {item.get('size', 'N/A')}" if 'size' in item else ""
            formatted_items_text_parts.append(
                f"- Name: \"{item['name']}\" (ID: {item['id']}, Type: {item['mimeType']}{size_str}, Modified: {item.get('modifiedTime', 'N/A')}) Link: {item.get('webViewLink', '#')}"
            )
        text_output = "\n".join(formatted_items_text_parts)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text_output)])
    except HttpError as error:
        logger.error(f"API error listing Drive items in folder {folder_id}: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error listing Drive items in folder {folder_id}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def create_drive_file(
    user_google_email: str,
    file_name: str,
    content: str,
    folder_id: str = 'root',
    mime_type: str = 'text/plain',
) -> types.CallToolResult:
    """
    Creates a new file in Google Drive, supporting creation within shared drives.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name for the new file.
        content (str): The content to write to the file.
        folder_id (str): The ID of the parent folder. Defaults to 'root'. For shared drives, this must be a folder ID within the shared drive.
        mime_type (str): The MIME type of the file. Defaults to 'text/plain'.

    Returns:
        A CallToolResult confirming creation or an error/auth guidance message.
    """
    tool_name = "create_drive_file"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}', File Name: {file_name}, Folder ID: {folder_id}")

    auth_result = await get_authenticated_google_service(
        service_name="drive",
        version="v3",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DRIVE_FILE_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
        file_metadata = {
            'name': file_name,
            'parents': [folder_id],
            'mimeType': mime_type
        }
        media = io.BytesIO(content.encode('utf-8'))

        created_file = await asyncio.to_thread(
            service.files().create(
                body=file_metadata,
                media_body=MediaIoBaseUpload(media, mimetype=mime_type, resumable=True),
                fields='id, name, webViewLink',
                supportsAllDrives=True
            ).execute
        )

        link = created_file.get('webViewLink', 'No link available')
        confirmation_message = f"Successfully created file '{created_file.get('name', file_name)}' (ID: {created_file.get('id', 'N/A')}) in folder '{folder_id}' for {user_email}. Link: {link}"
        logger.info(f"Successfully created file. Link: {link}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=confirmation_message)])

    except HttpError as error:
        logger.error(f"API error creating Drive file '{file_name}': {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error creating Drive file '{file_name}': {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])