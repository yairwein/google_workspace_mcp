"""
Google Gmail MCP Tools

This module provides MCP tools for interacting with the Gmail API.
"""

import logging
import asyncio
import base64
from typing import Optional, List, Dict, Literal

from email.mime.text import MIMEText

from mcp import types
from fastapi import Body
from googleapiclient.errors import HttpError

from auth.google_auth import get_authenticated_google_service

from core.server import (
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_LABELS_SCOPE,
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


def _extract_headers(payload: dict, header_names: List[str]) -> Dict[str, str]:
    """
    Extract specified headers from a Gmail message payload.

    Args:
        payload: The message payload from Gmail API
        header_names: List of header names to extract

    Returns:
        Dict mapping header names to their values
    """
    headers = {}
    for header in payload.get("headers", []):
        if header["name"] in header_names:
            headers[header["name"]] = header["value"]
    return headers


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


def _format_gmail_results_plain(messages: list, query: str) -> str:
    """Format Gmail search results in clean, LLM-friendly plain text."""
    if not messages:
        return f"No messages found for query: '{query}'"

    lines = [
        f"Found {len(messages)} messages matching '{query}':",
        "",
        "📧 MESSAGES:",
    ]

    for i, msg in enumerate(messages, 1):
        message_url = _generate_gmail_web_url(msg["id"])
        thread_url = _generate_gmail_web_url(msg["threadId"])

        lines.extend([
            f"  {i}. Message ID: {msg['id']}",
            f"     Web Link: {message_url}",
            f"     Thread ID: {msg['threadId']}",
            f"     Thread Link: {thread_url}",
            ""
        ])

    lines.extend([
        "💡 USAGE:",
        "  • Pass the Message IDs **as a list** to get_gmail_messages_content_batch()",
        "    e.g. get_gmail_messages_content_batch(message_ids=[...])",
        "  • Pass the Thread IDs to get_gmail_thread_content() (single) _or_",
        "    get_gmail_threads_content_batch() (coming soon)"
    ])

    return "\n".join(lines)


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
        types.CallToolResult: Contains LLM-friendly structured results with Message IDs, Thread IDs, and clickable Gmail web interface URLs for each found message, or an error/auth guidance message.
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
        return auth_result
    service, user_email = auth_result

    try:

        response = await asyncio.to_thread(
            service.users()
            .messages()
            .list(userId="me", q=query, maxResults=page_size)
            .execute
        )
        messages = response.get("messages", [])

        formatted_output = _format_gmail_results_plain(messages, query)

        return types.CallToolResult(
            content=[types.TextContent(type="text", text=formatted_output)]
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
        return auth_result
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
async def get_gmail_messages_content_batch(
    message_ids: List[str],
    user_google_email: str,
    format: Literal["full", "metadata"] = "full",
) -> types.CallToolResult:
    """
    Retrieves the content of multiple Gmail messages in a single batch request.
    Supports up to 100 messages per request using Google's batch API.

    Args:
        message_ids (List[str]): List of Gmail message IDs to retrieve (max 100).
        user_google_email (str): The user's Google email address. Required.
        format (Literal["full", "metadata"]): Message format. "full" includes body, "metadata" only headers.

    Returns:
        types.CallToolResult: Contains a list of message contents or error details.
    """
    tool_name = "get_gmail_messages_content_batch"
    logger.info(
        f"[{tool_name}] Invoked. Message count: {len(message_ids)}, Email: '{user_google_email}'"
    )

    if not message_ids:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="No message IDs provided")]
        )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
        output_messages = []

        # Process in chunks of 100 (Gmail batch limit)
        for chunk_start in range(0, len(message_ids), 100):
            chunk_ids = message_ids[chunk_start:chunk_start + 100]
            results: Dict[str, Dict] = {}

            def _batch_callback(request_id, response, exception):
                """Callback for batch requests"""
                results[request_id] = {"data": response, "error": exception}

            # Try to use batch API
            try:
                batch = service.new_batch_http_request(callback=_batch_callback)

                for mid in chunk_ids:
                    if format == "metadata":
                        req = service.users().messages().get(
                            userId="me",
                            id=mid,
                            format="metadata",
                            metadataHeaders=["Subject", "From"]
                        )
                    else:
                        req = service.users().messages().get(
                            userId="me",
                            id=mid,
                            format="full"
                        )
                    batch.add(req, request_id=mid)

                # Execute batch request
                await asyncio.to_thread(batch.execute)

            except Exception as batch_error:
                # Fallback to asyncio.gather if batch API fails
                logger.warning(
                    f"[{tool_name}] Batch API failed, falling back to asyncio.gather: {batch_error}"
                )

                async def fetch_message(mid: str):
                    try:
                        if format == "metadata":
                            msg = await asyncio.to_thread(
                                service.users().messages().get(
                                    userId="me",
                                    id=mid,
                                    format="metadata",
                                    metadataHeaders=["Subject", "From"]
                                ).execute
                            )
                        else:
                            msg = await asyncio.to_thread(
                                service.users().messages().get(
                                    userId="me",
                                    id=mid,
                                    format="full"
                                ).execute
                            )
                        return mid, msg, None
                    except Exception as e:
                        return mid, None, e

                # Fetch all messages in parallel
                fetch_results = await asyncio.gather(
                    *[fetch_message(mid) for mid in chunk_ids],
                    return_exceptions=False
                )

                # Convert to results format
                for mid, msg, error in fetch_results:
                    results[mid] = {"data": msg, "error": error}

            # Process results for this chunk
            for mid in chunk_ids:
                entry = results.get(mid, {"data": None, "error": "No result"})

                if entry["error"]:
                    output_messages.append(
                        f"⚠️ Message {mid}: {entry['error']}\n"
                    )
                else:
                    message = entry["data"]
                    if not message:
                        output_messages.append(
                            f"⚠️ Message {mid}: No data returned\n"
                        )
                        continue

                    # Extract content based on format
                    payload = message.get("payload", {})

                    if format == "metadata":
                        headers = _extract_headers(payload, ["Subject", "From"])
                        subject = headers.get("Subject", "(no subject)")
                        sender = headers.get("From", "(unknown sender)")

                        output_messages.append(
                            f"Message ID: {mid}\n"
                            f"Subject: {subject}\n"
                            f"From: {sender}\n"
                            f"Web Link: {_generate_gmail_web_url(mid)}\n"
                        )
                    else:
                        # Full format - extract body too
                        headers = _extract_headers(payload, ["Subject", "From"])
                        subject = headers.get("Subject", "(no subject)")
                        sender = headers.get("From", "(unknown sender)")
                        body = _extract_message_body(payload)

                        output_messages.append(
                            f"Message ID: {mid}\n"
                            f"Subject: {subject}\n"
                            f"From: {sender}\n"
                            f"Web Link: {_generate_gmail_web_url(mid)}\n"
                            f"\n{body or '[No text/plain body found]'}\n"
                        )

        # Combine all messages with separators
        final_output = f"Retrieved {len(message_ids)} messages:\n\n"
        final_output += "\n---\n\n".join(output_messages)

        return types.CallToolResult(
            content=[types.TextContent(type="text", text=final_output)]
        )

    except HttpError as e:
        logger.error(
            f"[{tool_name}] Gmail API error in batch retrieval: {e}", exc_info=True
        )
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(
            f"[{tool_name}] Unexpected error in batch retrieval: {e}"
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
        return auth_result
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
        return auth_result
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
        return auth_result
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


@server.tool()
async def list_gmail_labels(
    user_google_email: str,
) -> types.CallToolResult:
    """
    Lists all labels in the user's Gmail account.

    Args:
        user_google_email (str): The user's Google email address. Required.

    Returns:
        types.CallToolResult: Contains a list of all labels with their IDs, names, and types, or an error message.
    """
    tool_name = "list_gmail_labels"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}'")

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
        response = await asyncio.to_thread(
            service.users().labels().list(userId="me").execute
        )
        labels = response.get("labels", [])

        if not labels:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="No labels found.")]
            )

        lines = [f"Found {len(labels)} labels:", ""]

        system_labels = []
        user_labels = []

        for label in labels:
            if label.get("type") == "system":
                system_labels.append(label)
            else:
                user_labels.append(label)

        if system_labels:
            lines.append("📂 SYSTEM LABELS:")
            for label in system_labels:
                lines.append(f"  • {label['name']} (ID: {label['id']})")
            lines.append("")

        if user_labels:
            lines.append("🏷️  USER LABELS:")
            for label in user_labels:
                lines.append(f"  • {label['name']} (ID: {label['id']})")

        return types.CallToolResult(
            content=[types.TextContent(type="text", text="\n".join(lines))]
        )

    except HttpError as e:
        logger.error(f"[{tool_name}] Gmail API error listing labels: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error listing Gmail labels: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def manage_gmail_label(
    user_google_email: str,
    action: Literal["create", "update", "delete"],
    name: Optional[str] = None,
    label_id: Optional[str] = None,
    label_list_visibility: Literal["labelShow", "labelHide"] = "labelShow",
    message_list_visibility: Literal["show", "hide"] = "show",
) -> types.CallToolResult:
    """
    Manages Gmail labels: create, update, or delete labels.

    Args:
        user_google_email (str): The user's Google email address. Required.
        action (Literal["create", "update", "delete"]): Action to perform on the label.
        name (Optional[str]): Label name. Required for create, optional for update.
        label_id (Optional[str]): Label ID. Required for update and delete operations.
        label_list_visibility (Literal["labelShow", "labelHide"]): Whether the label is shown in the label list.
        message_list_visibility (Literal["show", "hide"]): Whether the label is shown in the message list.

    Returns:
        types.CallToolResult: Result of the label operation or an error message.
    """
    tool_name = "manage_gmail_label"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}', Action: '{action}'")

    if action == "create" and not name:
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text="Label name is required for create action.")],
        )

    if action in ["update", "delete"] and not label_id:
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text="Label ID is required for update and delete actions.")],
        )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_LABELS_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
        if action == "create":
            label_object = {
                "name": name,
                "labelListVisibility": label_list_visibility,
                "messageListVisibility": message_list_visibility,
            }
            created_label = await asyncio.to_thread(
                service.users().labels().create(userId="me", body=label_object).execute
            )
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"Label created successfully!\nName: {created_label['name']}\nID: {created_label['id']}"
                    )
                ]
            )

        elif action == "update":
            current_label = await asyncio.to_thread(
                service.users().labels().get(userId="me", id=label_id).execute
            )

            label_object = {
                "id": label_id,
                "name": name if name is not None else current_label["name"],
                "labelListVisibility": label_list_visibility,
                "messageListVisibility": message_list_visibility,
            }

            updated_label = await asyncio.to_thread(
                service.users().labels().update(userId="me", id=label_id, body=label_object).execute
            )
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"Label updated successfully!\nName: {updated_label['name']}\nID: {updated_label['id']}"
                    )
                ]
            )

        elif action == "delete":
            label = await asyncio.to_thread(
                service.users().labels().get(userId="me", id=label_id).execute
            )
            label_name = label["name"]

            await asyncio.to_thread(
                service.users().labels().delete(userId="me", id=label_id).execute
            )
            return types.CallToolResult(
                content=[
                    types.TextContent(
                        type="text",
                        text=f"Label '{label_name}' (ID: {label_id}) deleted successfully!"
                    )
                ]
            )

    except HttpError as e:
        logger.error(f"[{tool_name}] Gmail API error: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )


@server.tool()
async def modify_gmail_message_labels(
    user_google_email: str,
    message_id: str,
    add_label_ids: Optional[List[str]] = None,
    remove_label_ids: Optional[List[str]] = None,
) -> types.CallToolResult:
    """
    Adds or removes labels from a Gmail message.

    Args:
        user_google_email (str): The user's Google email address. Required.
        message_id (str): The ID of the message to modify.
        add_label_ids (Optional[List[str]]): List of label IDs to add to the message.
        remove_label_ids (Optional[List[str]]): List of label IDs to remove from the message.

    Returns:
        types.CallToolResult: Confirmation of label changes or an error message.
    """
    tool_name = "modify_gmail_message_labels"
    logger.info(f"[{tool_name}] Invoked. Email: '{user_google_email}', Message ID: '{message_id}'")

    if not add_label_ids and not remove_label_ids:
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text="At least one of add_label_ids or remove_label_ids must be provided.")],
        )

    auth_result = await get_authenticated_google_service(
        service_name="gmail",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[GMAIL_MODIFY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
        body = {}
        if add_label_ids:
            body["addLabelIds"] = add_label_ids
        if remove_label_ids:
            body["removeLabelIds"] = remove_label_ids

        await asyncio.to_thread(
            service.users().messages().modify(userId="me", id=message_id, body=body).execute
        )

        actions = []
        if add_label_ids:
            actions.append(f"Added labels: {', '.join(add_label_ids)}")
        if remove_label_ids:
            actions.append(f"Removed labels: {', '.join(remove_label_ids)}")

        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=f"Message labels updated successfully!\nMessage ID: {message_id}\n{'; '.join(actions)}"
                )
            ]
        )

    except HttpError as e:
        logger.error(f"[{tool_name}] Gmail API error modifying message labels: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Gmail API error: {e}")],
        )
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error modifying Gmail message labels: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error: {e}")],
        )
