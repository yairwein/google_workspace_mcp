"""
Google Drive MCP Tools

This module provides MCP tools for interacting with Google Drive API.
"""
import logging
import asyncio
import re
import os
from typing import List, Optional, Dict, Any

from mcp import types
from fastapi import Header
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload # For file content
import io # For file content

from auth.google_auth import get_authenticated_google_service
from core.utils import extract_office_xml_text
from core.server import server
from core.server import (
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE,
)

logger = logging.getLogger(__name__)

@server.tool()
async def search_drive_files(
    user_google_email: str,
    query: str,
    page_size: int = 10,
) -> types.CallToolResult:
    """
    Searches for files and folders within a user's Google Drive based on a query string.

    Args:
        user_google_email (str): The user's Google email address. Required.
        query (str): The search query string. Supports Google Drive search operators (e.g., 'name contains "report"', 'mimeType="application/vnd.google-apps.document"', 'parents in "folderId"').
        page_size (int): The maximum number of files to return. Defaults to 10.

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
        return auth_result  # Auth error
    service, user_email = auth_result

    try:

        # Check if the query looks like a structured Drive query or free text
        # Basic check for operators or common keywords used in structured queries
        drive_query_pattern = r"(\w+\s*(=|!=|>|<|contains|in|has)\s*['\"]?.+?['\"]?|\w+\s*(=|!=|>|<)\s*\d+|trashed\s*=\s*(true|false)|starred\s*=\s*(true|false)|properties\s+has\s*\{.*?\}|appProperties\s+has\s*\{.*?\}|'[^']+'\s+in\s+parents)"
        is_structured_query = re.search(drive_query_pattern, query, re.IGNORECASE)

        if is_structured_query:
            final_query = query # Use as is
        else:
            # Assume free text search, escape single quotes and wrap
            escaped_query = query.replace("'", "\\'")
            final_query = f"fullText contains '{escaped_query}'"
            logger.info(f"[search_drive_files] Reformatting free text query '{query}' to '{final_query}'")

        results = await asyncio.to_thread(
            service.files().list(
                q=final_query, # Use the potentially modified query
                pageSize=page_size,
                fields="nextPageToken, files(id, name, mimeType, webViewLink, iconLink, modifiedTime, size)"
            ).execute
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
    Retrieves the content of a specific Google Drive file by ID.

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
        return auth_result  # authentication problem
    service, _ = auth_result

    try:
        # ------------------------------------------------------------------
        # Metadata lookup
        # ------------------------------------------------------------------
        file_metadata = await asyncio.to_thread(
            service.files().get(
                fileId=file_id, fields="id, name, mimeType, webViewLink"
            ).execute
        )
        mime_type = file_metadata.get("mimeType", "")
        file_name = file_metadata.get("name", "Unknown File")

        # ------------------------------------------------------------------
        # Decide export vs. direct download
        # ------------------------------------------------------------------
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

        # ------------------------------------------------------------------
        # Download
        # ------------------------------------------------------------------
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_obj)
        loop = asyncio.get_event_loop()
        done = False
        while not done:
            status, done = await loop.run_in_executor(None, downloader.next_chunk)

        file_content_bytes = fh.getvalue()

        # ------------------------------------------------------------------
        # Attempt Office XML extraction
        # ------------------------------------------------------------------
        office_text = extract_office_xml_text(file_content_bytes, mime_type)
        if office_text:
            body_text = office_text
        else:
            # Fallback: try UTF-8; otherwise flag binary
            try:
                body_text = file_content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                body_text = (
                    f"[Binary or unsupported text encoding — "
                    f"{len(file_content_bytes)} bytes]"
                )

        # ------------------------------------------------------------------
        # Assemble response
        # ------------------------------------------------------------------
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
    folder_id: str = 'root', # Default to root folder
    page_size: int = 100, # Default page size for listing
) -> types.CallToolResult:
    """
    Lists files and folders directly within a specified Google Drive folder.
    Defaults to the root folder if `folder_id` is not provided. Does not recurse into subfolders.

    Args:
        user_google_email (str): The user's Google email address. Required.
        folder_id (str): The ID of the Google Drive folder to list items from. Defaults to 'root'.
        page_size (int): The maximum number of items to return per page. Defaults to 100.

    Returns:
        types.CallToolResult: Contains a list of files/folders within the specified folder, including their details (ID, name, type, size, modified time, link),
                               an error message if the API call fails or the folder is not accessible/found,
                               or an authentication guidance message if credentials are required.
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
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        results = await asyncio.to_thread(
            service.files().list(
                q=f"'{folder_id}' in parents and trashed=false", # List items directly in the folder
                pageSize=page_size,
                fields="nextPageToken, files(id, name, mimeType, webViewLink, iconLink, modifiedTime, size)"
            ).execute
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
    folder_id: str = 'root', # Default to root folder
    mime_type: str = 'text/plain', # Default to plain text
) -> types.CallToolResult:
    """
    Creates a new file in Google Drive with the specified name, content, and optional parent folder.

    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name for the new file.
        content (str): The content to write to the file.
        folder_id (str): The ID of the parent folder. Defaults to 'root'.
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
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        file_metadata = {
            'name': file_name,
            'parents': [folder_id],
            'mimeType': mime_type
        }
        media = io.BytesIO(content.encode('utf-8')) # Encode content to bytes

        created_file = await asyncio.to_thread(
            service.files().create(
                body=file_metadata,
                media_body=MediaIoBaseDownload(media, service.files().get_media(fileId='placeholder')), # Placeholder request for MediaIoBaseDownload
                fields='id, name, webViewLink'
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