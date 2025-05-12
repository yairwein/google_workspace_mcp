"""
Google Gmail MCP Tools

This module provides MCP tools for interacting with the Gmail API.
"""
import logging
import asyncio
import os
import base64
import email
from typing import List, Optional, Any # Keep Any

from mcp import types
from fastapi import Header
# Remove unused Resource import
# from googleapiclient.discovery import Resource as GoogleApiServiceResource
from googleapiclient.errors import HttpError

# Import the decorator, config path, AND the context variable
from auth.auth_flow import require_google_auth, CONFIG_CLIENT_SECRETS_PATH, current_google_service
from core.server import server
from core.server import (
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
)

logger = logging.getLogger(__name__)

@server.tool()
@require_google_auth(
    required_scopes=[GMAIL_READONLY_SCOPE],
    service_name="Gmail",
    api_name="gmail",
    api_version="v1"
)
async def search_gmail_messages( # Signature cleaned - no google_service param
    query: str,
    user_google_email: Optional[str] = None,
    page_size: int = 10,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Searches messages in a user's Gmail account based on a query.
    Authentication and service object are handled by the @require_google_auth decorator using context variables.

    Args:
        query (str): The search query. Supports standard Gmail search operators.
        user_google_email (Optional[str]): The user's Google email address (used for context/logging).
        page_size (int): The maximum number of messages to return. Defaults to 10.
        mcp_session_id (Optional[str]): The active MCP session ID (used for context/logging).

    Returns:
        types.CallToolResult: Contains a list of found message IDs or an error/auth guidance message.
    """
    # *** Add logging and check here ***
    tool_name = "search_gmail_messages"
    logger.debug(f"[{tool_name}] Entered function. Attempting to get service from context var...")
    google_service = current_google_service.get()
    logger.debug(f"[{tool_name}] Service retrieved from context var. Type: {type(google_service)}, id: {id(google_service)}")

    if not google_service:
         logger.error(f"[{tool_name}] Google service retrieved from context is None!")
         return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text="Internal error: Google service unavailable in tool context.")])

    logger.info(f"[{tool_name}] Session: '{mcp_session_id}', Email: '{user_google_email}', Query: '{query}'")
    try:
        # More robust way to extract email from credentials
        id_token = getattr(google_service._http.credentials, 'id_token', None)
        if isinstance(id_token, dict) and 'email' in id_token:
            user_email_from_creds = id_token.get('email')
        else:
            # Fallback to user_google_email parameter or default
            user_email_from_creds = user_google_email or "Unknown (Gmail)"
        logger.info(f"[{tool_name}] Using service for: {user_email_from_creds}")
    except AttributeError as e:
         logger.error(f"[{tool_name}] Error accessing credentials/email from google_service: {e}", exc_info=True)
         user_email_from_creds = user_google_email or "Unknown (Gmail - Error)"


    try:
        response = await asyncio.to_thread(
            google_service.users().messages().list(
                userId='me',
                q=query,
                maxResults=page_size
            ).execute
        )
        messages = response.get('messages', [])
        if not messages:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No messages found for '{query}'.")])

        lines = [f"Found {len(messages)} messages:"]
        for msg in messages:
             lines.append(f"- ID: {msg['id']}") # list doesn't return snippet by default

        return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(lines))])

    except HttpError as e:
        logger.error(f"Gmail API error searching messages: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Gmail API error: {e}")])
    except Exception as e:
        logger.exception(f"Unexpected error searching Gmail messages: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])


@server.tool()
@require_google_auth(
    required_scopes=[GMAIL_READONLY_SCOPE],
    service_name="Gmail",
    api_name="gmail",
    api_version="v1"
)
async def get_gmail_message_content( # Signature cleaned - no google_service param
    message_id: str,
    user_google_email: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Retrieves the full content (subject, sender, plain text body) of a specific Gmail message.
    Authentication and service object are handled by the @require_google_auth decorator using context variables.

    Args:
        message_id (str): The unique ID of the Gmail message to retrieve.
        user_google_email (Optional[str]): The user's Google email address (used for context/logging).
        mcp_session_id (Optional[str]): The active MCP session ID (used for context/logging).

    Returns:
        types.CallToolResult: Contains the message details or an error/auth guidance message.
    """
    # *** Add logging and check here ***
    tool_name = "get_gmail_message_content"
    logger.debug(f"[{tool_name}] Entered function. Attempting to get service from context var...")
    google_service = current_google_service.get()
    logger.debug(f"[{tool_name}] Service retrieved from context var. Type: {type(google_service)}, id: {id(google_service)}")

    if not google_service:
         logger.error(f"[{tool_name}] Google service retrieved from context is None!")
         return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text="Internal error: Google service unavailable in tool context.")])

    logger.info(f"[{tool_name}] Message ID: '{message_id}', Session: '{mcp_session_id}', Email: '{user_google_email}'")
    try:
        # More robust way to extract email from credentials
        id_token = getattr(google_service._http.credentials, 'id_token', None)
        if isinstance(id_token, dict) and 'email' in id_token:
            user_email_from_creds = id_token.get('email')
        else:
            # Fallback to user_google_email parameter or default
            user_email_from_creds = user_google_email or "Unknown (Gmail)"
        logger.info(f"[{tool_name}] Using service for: {user_email_from_creds}")
    except AttributeError as e:
         logger.error(f"[{tool_name}] Error accessing credentials/email from google_service: {e}", exc_info=True)
         user_email_from_creds = user_google_email or "Unknown (Gmail - Error)"


    try:
        # Fetch message metadata first to get headers
        message_metadata = await asyncio.to_thread(
            google_service.users().messages().get(
                userId='me',
                id=message_id,
                format='metadata',
                metadataHeaders=['Subject', 'From']
            ).execute
        )

        headers = {h['name']: h['value'] for h in message_metadata.get('payload', {}).get('headers', [])}
        subject = headers.get('Subject', '(no subject)')
        sender = headers.get('From', '(unknown sender)')

        # Now fetch the full message to get the body parts
        message_full = await asyncio.to_thread(
             google_service.users().messages().get(
                userId='me',
                id=message_id,
                format='full' # Request full payload for body
            ).execute
        )

        # Find the plain text part (more robustly)
        body_data = ""
        payload = message_full.get('payload', {})
        parts = [payload] if 'parts' not in payload else payload.get('parts', [])

        part_queue = list(parts) # Use a queue for BFS traversal of parts
        while part_queue:
            part = part_queue.pop(0)
            if part.get('mimeType') == 'text/plain' and part.get('body', {}).get('data'):
                data = base64.urlsafe_b64decode(part['body']['data'])
                body_data = data.decode('utf-8', errors='ignore')
                break # Found plain text body
            elif part.get('mimeType', '').startswith('multipart/') and 'parts' in part:
                part_queue.extend(part.get('parts', [])) # Add sub-parts to the queue

        # If no plain text found, check the main payload body if it exists
        if not body_data and payload.get('mimeType') == 'text/plain' and payload.get('body', {}).get('data'):
             data = base64.urlsafe_b64decode(payload['body']['data'])
             body_data = data.decode('utf-8', errors='ignore')


        content_text = "\n".join([
            f"Subject: {subject}",
            f"From:    {sender}",
            f"\n--- BODY ---\n{body_data or '[No text/plain body found]'}"
        ])
        return types.CallToolResult(content=[types.TextContent(type="text", text=content_text)])

    except HttpError as e:
        logger.error(f"Gmail API error getting message content: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Gmail API error: {e}")])
    except Exception as e:
        logger.exception(f"Unexpected error getting Gmail message content: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

# Note: send_gmail_message tool would need GMAIL_SEND_SCOPE and similar refactoring if added.