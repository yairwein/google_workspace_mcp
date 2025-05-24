"""
Google Docs MCP Tools

This module provides MCP tools for interacting with Google Docs API and managing Google Docs via Drive.
"""
import logging
import asyncio
import io
from typing import List, Optional, Dict, Any

from mcp import types
from fastapi import Header
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

# Auth & server utilities
from auth.google_auth import get_authenticated_google_service
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
) -> types.CallToolResult:
    """
    Searches for Google Docs by name using Drive API (mimeType filter).
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
        return auth_result  # Auth error
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
            return types.CallToolResult(content=[types.TextContent(type="text",
                text=f"No Google Docs found matching '{query}'.")])

        output = [f"Found {len(files)} Google Docs matching '{query}':"]
        for f in files:
            output.append(
                f"- {f['name']} (ID: {f['id']}) Modified: {f.get('modifiedTime')} Link: {f.get('webViewLink')}"
            )
        return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(output))])

    except HttpError as e:
        logger.error(f"API error in search_docs: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])

@server.tool()
async def get_doc_content(
    user_google_email: str,
    document_id: str,
) -> types.CallToolResult:
    """
    Retrieves Google Doc content as plain text using Docs API.
    """
    tool_name = "get_doc_content"
    logger.info(f"[{tool_name}] Document ID={document_id}")

    auth_result = await get_authenticated_google_service(
        service_name="docs",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[DOCS_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    docs, user_email = auth_result

    try:
        doc = await asyncio.to_thread(docs.documents().get(documentId=document_id).execute)
        title = doc.get('title', '')
        body = doc.get('body', {}).get('content', [])

        text_lines: List[str] = [f"Document: '{title}' (ID: {document_id})\n"]
        def extract_text(el):
            segs = el.get('paragraph', {}).get('elements', [])
            return ''.join([s.get('textRun', {}).get('content', '') for s in segs])
        for el in body:
            if 'paragraph' in el:
                t = extract_text(el)
                if t.strip():
                    text_lines.append(t)
        content = ''.join(text_lines)
        return types.CallToolResult(content=[types.TextContent(type="text", text=content)])

    except HttpError as e:
        logger.error(f"API error in get_doc_content: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])

@server.tool()
async def list_docs_in_folder(
    user_google_email: str,
    folder_id: str = 'root',
    page_size: int = 100
) -> types.CallToolResult:
    """
    Lists Google Docs within a specific Drive folder.
    """
    logger.info(f"[list_docs_in_folder] Folder ID={folder_id}")
    tool_scopes = [DRIVE_READONLY_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )
    if not credentials or not credentials.valid:
        logger.warning(f"[list_docs_in_folder] Missing credentials.")
        if user_google_email and '@' in user_google_email:
            return await start_auth_flow(
                mcp_session_id=mcp_session_id,
                user_google_email=user_google_email,
                service_name="Google Drive",
                redirect_uri=OAUTH_REDIRECT_URI
            )
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text",
            text="Google Drive Authentication required. LLM: Please ask for Google email and retry, or use the 'start_google_auth' tool with the email and service_name='Google Drive'.")])

    try:
        drive = build('drive', 'v3', credentials=credentials)
        rsp = await asyncio.to_thread(
            drive.files().list(
                q=f"'{folder_id}' in parents and mimeType='application/vnd.google-apps.document' and trashed=false",
                pageSize=page_size,
                fields="files(id, name, modifiedTime, webViewLink)"
            ).execute
        )
        items = rsp.get('files', [])
        if not items:
            return types.CallToolResult(content=[types.TextContent(type="text",
                text=f"No Google Docs found in folder '{folder_id}'.")])
        out = [f"Found {len(items)} Docs in folder '{folder_id}':"]
        for f in items:
            out.append(f"- {f['name']} (ID: {f['id']}) Modified: {f.get('modifiedTime')} Link: {f.get('webViewLink')}")
        return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(out))])

    except HttpError as e:
        logger.error(f"API error in list_docs_in_folder: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])

@server.tool()
async def create_doc(
    title: str,
    content: str = '',
    user_google_email: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Creates a new Google Doc and optionally inserts initial content.
    """
    logger.info(f"[create_doc] Title='{title}'")
    tool_scopes = [DOCS_WRITE_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )
    if not credentials or not credentials.valid:
        logger.warning(f"[create_doc] Missing credentials.")
        if user_google_email and '@' in user_google_email:
            return await start_auth_flow(
                mcp_session_id=mcp_session_id,
                user_google_email=user_google_email,
                service_name="Google Docs",
                redirect_uri=OAUTH_REDIRECT_URI
            )
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text",
            text="Google Docs Authentication required. LLM: Please ask for Google email and retry, or use the 'start_google_auth' tool with the email and service_name='Google Docs'.")])

    try:
        docs = build('docs', 'v1', credentials=credentials)
        doc = await asyncio.to_thread(docs.documents().create(body={'title': title}).execute)
        doc_id = doc.get('documentId')
        if content:
            # Insert content at end
            requests = [{'insertText': {'location': {'index': 1}, 'text': content}}]
            await asyncio.to_thread(docs.documents().batchUpdate(documentId=doc_id, body={'requests': requests}).execute)
        link = f"https://docs.google.com/document/d/{doc_id}/edit"
        msg = f"Created Google Doc '{title}' (ID: {doc_id}). Link: {link}"
        return types.CallToolResult(content=[types.TextContent(type="text", text=msg)])

    except HttpError as e:
        logger.error(f"API error in create_doc: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])
