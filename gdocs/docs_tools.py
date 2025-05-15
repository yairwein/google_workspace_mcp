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
from auth.google_auth import get_credentials, start_auth_flow, CONFIG_CLIENT_SECRETS_PATH
from core.server import (
    server,
    OAUTH_REDIRECT_URI,
    DRIVE_READONLY_SCOPE,
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE,
    SCOPES
)

logger = logging.getLogger(__name__)

@server.tool()
async def search_docs(
    query: str,
    user_google_email: Optional[str] = None,
    page_size: int = 10,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Searches for Google Docs by name using Drive API (mimeType filter).
    """
    logger.info(f"[search_docs] Session={mcp_session_id}, Email={user_google_email}, Query='{query}'")
    tool_scopes = [DRIVE_READONLY_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )
    if not credentials or not credentials.valid:
        logger.warning(f"[search_docs] Missing credentials.")
        if user_google_email and '@' in user_google_email:
            return await start_auth_flow(
                mcp_session_id=mcp_session_id,
                user_google_email=user_google_email,
                service_name="Google Drive",
                redirect_uri=OAUTH_REDIRECT_URI
            )
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text",
            text="Docs Authentication required. LLM: Please ask for Google email.")])

    try:
        drive = build('drive', 'v3', credentials=credentials)
        escaped_query = query.replace("'", "\\'")

        response = await asyncio.to_thread(
            drive.files().list(
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
    document_id: str,
    user_google_email: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Retrieves Google Doc content as plain text using Docs API.
    """
    logger.info(f"[get_doc_content] Document ID={document_id}")
    tool_scopes = [DOCS_READONLY_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )
    if not credentials or not credentials.valid:
        logger.warning(f"[get_doc_content] Missing credentials.")
        if user_google_email and '@' in user_google_email:
            return await start_auth_flow(
                mcp_session_id=mcp_session_id,
                user_google_email=user_google_email,
                service_name="Google Docs",
                redirect_uri=OAUTH_REDIRECT_URI
            )
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text",
            text="Docs Authentication required. LLM: Please ask for Google email.")])

    try:
        docs = build('docs', 'v1', credentials=credentials)
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
    folder_id: str = 'root',
    user_google_email: Optional[str] = None,
    page_size: int = 100,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
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
            text="Docs Authentication required. LLM: Please ask for Google email.")])

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
            text="Docs Authentication required. LLM: Please ask for Google email.")])

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
