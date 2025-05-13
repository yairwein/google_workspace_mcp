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
from googleapiclient.discovery import build # Import build
from googleapiclient.errors import HttpError

# Use functions directly from google_auth
from auth.google_auth import get_credentials, start_auth_flow, CONFIG_CLIENT_SECRETS_PATH # Import get_credentials, start_auth_flow, CONFIG_CLIENT_SECRETS_PATH
# Remove imports from auth.auth_flow
# from auth.auth_flow import require_google_auth, CONFIG_CLIENT_SECRETS_PATH, current_google_service

from core.server import server, OAUTH_REDIRECT_URI # Import OAUTH_REDIRECT_URI
from core.server import (
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    SCOPES # Import SCOPES for auth flow initiation
)

logger = logging.getLogger(__name__)

# CONFIG_CLIENT_SECRETS_PATH is now imported from auth.google_auth

@server.tool()
# Remove the decorator
# @require_google_auth(
#     required_scopes=[GMAIL_READONLY_SCOPE],
#     service_name="Gmail",
#     api_name="gmail",
#     api_version="v1"
# )
async def search_gmail_messages( # Signature cleaned - no google_service param
    query: str,
    user_google_email: Optional[str] = None,
    page_size: int = 10,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Searches messages in a user's Gmail account based on a query.
    Authentication is handled by get_credentials and start_auth_flow.

    Args:
        query (str): The search query. Supports standard Gmail search operators.
        user_google_email (Optional[str]): The user's Google email address. Required if the MCP session is not already authenticated for Gmail access.
        page_size (int): The maximum number of messages to return. Defaults to 10.
        mcp_session_id (Optional[str]): The active MCP session ID (automatically injected by FastMCP from the Mcp-Session-Id header). Used for session-based authentication.

    Returns:
        types.CallToolResult: Contains a list of found message IDs or an error/auth guidance message.
    """
    tool_name = "search_gmail_messages"
    logger.info(f"[{tool_name}] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', Query: '{query}'")

    # Use get_credentials to fetch credentials
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE], # Specify required scopes for this tool
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH, # Use imported constant
        session_id=mcp_session_id
    )

    # Check if credentials are valid, initiate auth flow if not
    if not credentials or not credentials.valid:
        logger.warning(f"[{tool_name}] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[{tool_name}] Valid email '{user_google_email}' provided, initiating auth flow for this email (requests all SCOPES).")
            # Use the centralized start_auth_flow
            return await start_auth_flow(mcp_session_id=mcp_session_id, user_google_email=user_google_email, service_name="Gmail", redirect_uri=OAUTH_REDIRECT_URI)
        else:
            error_msg = "Gmail Authentication required. No active authenticated session, and no valid 'user_google_email' provided. LLM: Please ask the user for their Google email address and retry, or use the 'start_auth' tool with their email."
            logger.info(f"[{tool_name}] {error_msg}")
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        # Build the service object directly
        service = build('gmail', 'v1', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown (Gmail)'
        logger.info(f"[{tool_name}] Using service for: {user_email_from_creds}")

        response = await asyncio.to_thread(
            service.users().messages().list(
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
        logger.error(f"[{tool_name}] Gmail API error searching messages: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Gmail API error: {e}")])
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error searching Gmail messages: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])


@server.tool()
# Remove the decorator
# @require_google_auth(
#     required_scopes=[GMAIL_READONLY_SCOPE],
#     service_name="Gmail",
#     api_name="gmail",
#     api_version="v1"
# )
async def get_gmail_message_content( # Signature cleaned - no google_service param
    message_id: str,
    user_google_email: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Retrieves the full content (subject, sender, plain text body) of a specific Gmail message.
    Authentication is handled by get_credentials and start_auth_flow.

    Args:
        message_id (str): The unique ID of the Gmail message to retrieve.
        user_google_email (Optional[str]): The user's Google email address. Required if the MCP session is not already authenticated for Gmail access.
        mcp_session_id (Optional[str]): The active MCP session ID (automatically injected by FastMCP from the Mcp-Session-Id header). Used for session-based authentication.

    Returns:
        types.CallToolResult: Contains the message details or an error/auth guidance message.
    """
    tool_name = "get_gmail_message_content"
    logger.info(f"[{tool_name}] Invoked. Message ID: '{message_id}', Session: '{mcp_session_id}', Email: '{user_google_email}'")

    # Use get_credentials to fetch credentials
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE], # Specify required scopes for this tool
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH, # Use imported constant
        session_id=mcp_session_id
    )

    # Check if credentials are valid, initiate auth flow if not
    if not credentials or not credentials.valid:
        logger.warning(f"[{tool_name}] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[{tool_name}] Valid email '{user_google_email}' provided, initiating auth flow for this email (requests all SCOPES).")
            # Use the centralized start_auth_flow
            return await start_auth_flow(mcp_session_id=mcp_session_id, user_google_email=user_google_email, service_name="Gmail", redirect_uri=OAUTH_REDIRECT_URI)
        else:
            error_msg = "Gmail Authentication required. No active authenticated session, and no valid 'user_google_email' provided. LLM: Please ask the user for their Google email address and retry, or use the 'start_auth' tool with their email."
            logger.info(f"[{tool_name}] {error_msg}")
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        # Build the service object directly
        service = build('gmail', 'v1', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown (Gmail)'
        logger.info(f"[{tool_name}] Using service for: {user_email_from_creds}")

        # Fetch message metadata first to get headers
        message_metadata = await asyncio.to_thread(
            service.users().messages().get(
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
             service.users().messages().get(
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
        logger.error(f"[{tool_name}] Gmail API error getting message content: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Gmail API error: {e}")])
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error getting Gmail message content: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

# Note: send_gmail_message tool would need GMAIL_SEND_SCOPE and similar refactoring if added.