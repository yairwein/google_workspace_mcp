"""
Google Gmail MCP Tools

This module provides MCP tools for interacting with the Gmail API.
"""

import logging
import asyncio
import base64
from typing import Optional

from email.mime.text import MIMEText


from mcp import types
from fastapi import Body
from googleapiclient.errors import HttpError

from auth.google_auth import get_authenticated_google_service

from core.server import (
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    server,
)

logger = logging.getLogger(__name__)


def _extract_message_body(payload):
    """
    Helper function to extract plain text body from a Gmail message payload.

    Args:
        payload (dict): The message payload from Gmail API

    Returns:
        str: The plain text body content, or empty string if not found
    """
    body_data = ""
    parts = [payload] if "parts" not in payload else payload.get("parts", [])

    part_queue = list(parts)  # Use a queue for BFS traversal of parts
    while part_queue:
        part = part_queue.pop(0)
        if part.get("mimeType") == "text/plain" and part.get("body", {}).get("data"):
            data = base64.urlsafe_b64decode(part["body"]["data"])
            body_data = data.decode("utf-8", errors="ignore")
            break  # Found plain text body
        elif part.get("mimeType", "").startswith("multipart/") and "parts" in part:
            part_queue.extend(part.get("parts", []))  # Add sub-parts to the queue

    # If no plain text found, check the main payload body if it exists
    if (
        not body_data
        and payload.get("mimeType") == "text/plain"
        and payload.get("body", {}).get("data")
    ):
        data = base64.urlsafe_b64decode(payload["body"]["data"])
        body_data = data.decode("utf-8", errors="ignore")

    return body_data


def _generate_gmail_web_url(item_id: str, account_index: int = 0) -> str:
    """
    Generate Gmail web interface URL for a message or thread ID.
    Uses #all to access messages from any Gmail folder/label (not just inbox).

    Args:
        item_id: Gmail message ID or thread ID
        account_index: Google account index (default 0 for primary account)

    Returns:
        Gmail web interface URL that opens the message/thread in Gmail web interface
    """
    return f"https://mail.google.com/mail/u/{account_index}/#all/{item_id}"


@server.tool()
async def search_gmail_messages(
    query: str,
    user_google_email: str,
    page_size: int = 10,
) -> types.CallToolResult:
    """
    Searches messages in a user's Gmail account based on a query.
    Returns both Message IDs and Thread IDs for each found message, along with Gmail web interface links for manual verification.

    Args:
        query (str): The search query. Supports standard Gmail search operators.
        user_google_email (str): The user's Google email address. Required.
        page_size (int): The maximum number of messages to return. Defaults to 10.

    Returns:
        types.CallToolResult: Contains XML-structured results with Message IDs, Thread IDs, and clickable Gmail web interface URLs for each found message, or an error/auth guidance message.
    """
    tool_name = "search_gmail_messages"
    logger.info(
        f"[{tool_name}] Invoked. Email: '{user_google_email}', Query: '{query}'"
    )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:

        response = await asyncio.to_thread(
            service.users()
            .messages()
            .list(userId="me", q=query, maxResults=page_size)
            .execute
        )
        messages = response.get("messages", [])
        if not messages:
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text", text=f"No messages found for '{query}'."
                    )
                ]
            )

        # Build enhanced output with XML structure and Gmail web links
        lines = [
            f"Found {len(messages)} messages:",
            "",
            "Note: Use Message ID with get_gmail_message_content, Thread ID with get_gmail_thread_content",
            "Click the Gmail links below to view messages/threads directly in your browser:",
            "",
            f'<gmail_results count="{len(messages)}">',
        ]

        for i, msg in enumerate(messages, 1):
            message_url = _generate_gmail_web_url(msg["id"])
            thread_url = _generate_gmail_web_url(msg["threadId"])

            lines.extend(
                [
                    f'    <message index="{i}">',
                    f'        <message_id>{msg["id"]}</message_id>',
                    f"        <message_url>{message_url}</message_url>",
                    f'        <thread_id>{msg["threadId"]}</thread_id>',
                    f"        <thread_url>{thread_url}</thread_url>",
                    f"    </message>",
                ]
            )

        lines.append("</gmail_results>")

        return types.CallToolResult(
            content=[types.TextContent(type="text", text="\n".join(lines))]
        )

    except HttpError as e:
        logger.error(
            f"[{tool_name}] Gmail API error searching messages: {e}", exc_info=True
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(
            f"[{tool_name}] Unexpected error searching Gmail messages: {e}"
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def get_gmail_message_content(
    message_id: str,
    user_google_email: str,
) -> types.CallToolResult:
    """
    Retrieves the full content (subject, sender, plain text body) of a specific Gmail message.

    Args:
        message_id (str): The unique ID of the Gmail message to retrieve.
        user_google_email (str): The user's Google email address. Required.

    Returns:
        types.CallToolResult: Contains the message details or an error/auth guidance message.
    """
    tool_name = "get_gmail_message_content"
    logger.info(
        f"[{tool_name}] Invoked. Message ID: '{message_id}', Email: '{user_google_email}'"
    )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        logger.info(f"[{tool_name}] Using service for: {user_google_email}")

        # Fetch message metadata first to get headers
        message_metadata = await asyncio.to_thread(
            service.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="metadata",
                metadataHeaders=["Subject", "From"],
            )
            .execute
        )

        headers = {
            h["name"]: h["value"]
            for h in message_metadata.get("payload", {}).get("headers", [])
        }
        subject = headers.get("Subject", "(no subject)")
        sender = headers.get("From", "(unknown sender)")

        # Now fetch the full message to get the body parts
        message_full = await asyncio.to_thread(
            service.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="full",  # Request full payload for body
            )
            .execute
        )

        # Extract the plain text body using helper function
        payload = message_full.get("payload", {})
        body_data = _extract_message_body(payload)

        content_text = "\n".join(
            [
                f"Subject: {subject}",
                f"From:    {sender}",
                f"\n--- BODY ---\n{body_data or '[No text/plain body found]'}",
            ]
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=content_text)]
        )

    except HttpError as e:
        logger.error(
            f"[{tool_name}] Gmail API error getting message content: {e}", exc_info=True
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(
            f"[{tool_name}] Unexpected error getting Gmail message content: {e}"
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def send_gmail_message(
    user_google_email: str,
    to: str = Body(..., description="Recipient email address."),
    subject: str = Body(..., description="Email subject."),
    body: str = Body(..., description="Email body (plain text)."),
) -> types.CallToolResult:
    """
    Sends an email using the user's Gmail account.

    Args:
        to (str): Recipient email address.
        subject (str): Email subject.
        body (str): Email body (plain text).
        user_google_email (str): The user's Google email address. Required.

    Returns:
        types.CallToolResult: Contains the message ID of the sent email, or an error/auth guidance message.
    """
    tool_name = "send_gmail_message"

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_SEND_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:

        # Prepare the email
        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        send_body = {"raw": raw_message}

        # Send the message
        sent_message = await asyncio.to_thread(
            service.users().messages().send(userId="me", body=send_body).execute
        )
        message_id = sent_message.get("id")
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text", text=f"Email sent! Message ID: {message_id}"
                )
            ]
        )

    except HttpError as e:
        logger.error(
            f"[{tool_name}] Gmail API error sending message: {e}", exc_info=True
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error sending Gmail message: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def draft_gmail_message(
    user_google_email: str,
    subject: str = Body(..., description="Email subject."),
    body: str = Body(..., description="Email body (plain text)."),
    to: Optional[str] = Body(None, description="Optional recipient email address."),
) -> types.CallToolResult:
    """
    Creates a draft email in the user's Gmail account.

    Args:
        user_google_email (str): The user's Google email address. Required.
        subject (str): Email subject.
        body (str): Email body (plain text).
        to (Optional[str]): Optional recipient email address. Can be left empty for drafts.

    Returns:
        types.CallToolResult: Contains the draft ID of the created email, or an error/auth guidance message.
    """
    tool_name = "draft_gmail_message"
    logger.info(
        f"[{tool_name}] Invoked. Email: '{user_google_email}', Subject: '{subject}'"
    )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_COMPOSE_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:

        # Prepare the email
        message = MIMEText(body)
        message["subject"] = subject

        # Add recipient if provided
        if to:
            message["to"] = to

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        # Create a draft instead of sending
        draft_body = {"message": {"raw": raw_message}}

        # Create the draft
        created_draft = await asyncio.to_thread(
            service.users().drafts().create(userId="me", body=draft_body).execute
        )
        draft_id = created_draft.get("id")
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text", text=f"Draft created! Draft ID: {draft_id}"
                )
            ]
        )

    except HttpError as e:
        logger.error(
            f"[{tool_name}] Gmail API error creating draft: {e}", exc_info=True
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error creating Gmail draft: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def get_gmail_thread_content(
    thread_id: str,
    user_google_email: str,
) -> types.CallToolResult:
    """
    Retrieves the complete content of a Gmail conversation thread, including all messages.

    Args:
        thread_id (str): The unique ID of the Gmail thread to retrieve.
        user_google_email (str): The user's Google email address. Required.

    Returns:
        types.CallToolResult: Contains the complete thread content with all messages or an error/auth guidance message.
    """
    tool_name = "get_gmail_thread_content"
    logger.info(
        f"[{tool_name}] Invoked. Thread ID: '{thread_id}', Email: '{user_google_email}'"
    )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        # Fetch the complete thread with all messages
        thread_response = await asyncio.to_thread(
            service.users()
            .threads()
            .get(userId="me", id=thread_id, format="full")
            .execute
        )

        messages = thread_response.get("messages", [])
        if not messages:
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text", text=f"No messages found in thread '{thread_id}'."
                    )
                ]
            )

        # Extract thread subject from the first message
        first_message = messages[0]
        first_headers = {
            h["name"]: h["value"]
            for h in first_message.get("payload", {}).get("headers", [])
        }
        thread_subject = first_headers.get("Subject", "(no subject)")

        # Build the thread content
        content_lines = [
            f"Thread ID: {thread_id}",
            f"Subject: {thread_subject}",
            f"Messages: {len(messages)}",
            "",
        ]

        # Process each message in the thread
        for i, message in enumerate(messages, 1):
            # Extract headers
            headers = {
                h["name"]: h["value"]
                for h in message.get("payload", {}).get("headers", [])
            }

            sender = headers.get("From", "(unknown sender)")
            date = headers.get("Date", "(unknown date)")
            subject = headers.get("Subject", "(no subject)")

            # Extract message body
            payload = message.get("payload", {})
            body_data = _extract_message_body(payload)

            # Add message to content
            content_lines.extend(
                [
                    f"=== Message {i} ===",
                    f"From: {sender}",
                    f"Date: {date}",
                ]
            )

            # Only show subject if it's different from thread subject
            if subject != thread_subject:
                content_lines.append(f"Subject: {subject}")

            content_lines.extend(
                [
                    "",
                    body_data or "[No text/plain body found]",
                    "",
                ]
            )

        content_text = "\n".join(content_lines)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=content_text)]
        )

    except HttpError as e:
        logger.error(
            f"[{tool_name}] Gmail API error getting thread content: {e}", exc_info=True
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(
            f"[{tool_name}] Unexpected error getting Gmail thread content: {e}"
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )
