"""
Google Chat MCP Tools

This module provides MCP tools for interacting with Google Chat API.
"""
import logging
import asyncio
from typing import List, Optional, Dict, Any

from mcp import types
from fastapi import Header
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Auth & server utilities
from auth.google_auth import get_authenticated_google_service
from core.server import server
from config.google_config import (
    CHAT_READONLY_SCOPE,
    CHAT_WRITE_SCOPE,
    CHAT_SPACES_SCOPE,
)

logger = logging.getLogger(__name__)

@server.tool()
async def list_spaces(
    user_google_email: str,
    page_size: int = 100,
    space_type: str = "all"  # "all", "room", "dm"
) -> types.CallToolResult:
    """
    Lists Google Chat spaces (rooms and direct messages) accessible to the user.
    """
    tool_name = "list_spaces"
    logger.info(f"[{tool_name}] Email={user_google_email}, Type={space_type}")

    auth_result = await get_authenticated_google_service(
        service_name="chat",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[CHAT_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        # Build filter based on space_type
        filter_param = None
        if space_type == "room":
            filter_param = "spaceType = SPACE"
        elif space_type == "dm":
            filter_param = "spaceType = DIRECT_MESSAGE"

        request_params = {"pageSize": page_size}
        if filter_param:
            request_params["filter"] = filter_param

        response = await asyncio.to_thread(
            service.spaces().list(**request_params).execute
        )
        
        spaces = response.get('spaces', [])
        if not spaces:
            return types.CallToolResult(content=[types.TextContent(type="text",
                text=f"No Chat spaces found for type '{space_type}'.")])

        output = [f"Found {len(spaces)} Chat spaces (type: {space_type}):"]
        for space in spaces:
            space_name = space.get('displayName', 'Unnamed Space')
            space_id = space.get('name', '')
            space_type_actual = space.get('spaceType', 'UNKNOWN')
            output.append(f"- {space_name} (ID: {space_id}, Type: {space_type_actual})")
        
        return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(output))])

    except HttpError as e:
        logger.error(f"API error in {tool_name}: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])
    except Exception as e:
        logger.exception(f"Unexpected error in {tool_name}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def get_messages(
    user_google_email: str,
    space_id: str,
    page_size: int = 50,
    order_by: str = "createTime desc"
) -> types.CallToolResult:
    """
    Retrieves messages from a Google Chat space.
    """
    tool_name = "get_messages"
    logger.info(f"[{tool_name}] Space ID: '{space_id}' for user '{user_google_email}'")

    auth_result = await get_authenticated_google_service(
        service_name="chat",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[CHAT_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result
    service, user_email = auth_result

    try:
        # Get space info first
        space_info = await asyncio.to_thread(
            service.spaces().get(name=space_id).execute
        )
        space_name = space_info.get('displayName', 'Unknown Space')

        # Get messages
        response = await asyncio.to_thread(
            service.spaces().messages().list(
                parent=space_id,
                pageSize=page_size,
                orderBy=order_by
            ).execute
        )
        
        messages = response.get('messages', [])
        if not messages:
            return types.CallToolResult(content=[types.TextContent(type="text",
                text=f"No messages found in space '{space_name}' (ID: {space_id}).")])

        output = [f"Messages from '{space_name}' (ID: {space_id}):\n"]
        for msg in messages:
            sender = msg.get('sender', {}).get('displayName', 'Unknown Sender')
            create_time = msg.get('createTime', 'Unknown Time')
            text_content = msg.get('text', 'No text content')
            msg_name = msg.get('name', '')
            
            output.append(f"[{create_time}] {sender}:")
            output.append(f"  {text_content}")
            output.append(f"  (Message ID: {msg_name})\n")
        
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="\n".join(output))]
        )

    except HttpError as error:
        logger.error(f"[{tool_name}] API error for space {space_id}: {error}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"API error accessing space {space_id}: {error}")],
        )
    except Exception as e:
        logger.exception(f"[{tool_name}] Unexpected error for space {space_id}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=f"Unexpected error accessing space {space_id}: {e}")],
        )

@server.tool()
async def send_message(
    user_google_email: str,
    space_id: str,
    message_text: str,
    thread_key: Optional[str] = None
) -> types.CallToolResult:
    """
    Sends a message to a Google Chat space.
    """
    tool_name = "send_message"
    logger.info(f"[{tool_name}] Email: '{user_google_email}', Space: '{space_id}'")

    auth_result = await get_authenticated_google_service(
        service_name="chat",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[CHAT_WRITE_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        message_body = {
            'text': message_text
        }
        
        # Add thread key if provided (for threaded replies)
        request_params = {
            'parent': space_id,
            'body': message_body
        }
        if thread_key:
            request_params['threadKey'] = thread_key

        message = await asyncio.to_thread(
            service.spaces().messages().create(**request_params).execute
        )
        
        message_name = message.get('name', '')
        create_time = message.get('createTime', '')
        
        msg = f"Message sent to space '{space_id}' by {user_email}. Message ID: {message_name}, Time: {create_time}"
        logger.info(f"Successfully sent message to space '{space_id}' by {user_email}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=msg)])

    except HttpError as e:
        logger.error(f"API error in {tool_name}: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])
    except Exception as e:
        logger.exception(f"Unexpected error in {tool_name}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def search_messages(
    user_google_email: str,
    query: str,
    space_id: Optional[str] = None,
    page_size: int = 25
) -> types.CallToolResult:
    """
    Searches for messages in Google Chat spaces by text content.
    """
    tool_name = "search_messages"
    logger.info(f"[{tool_name}] Email={user_google_email}, Query='{query}'")

    auth_result = await get_authenticated_google_service(
        service_name="chat",
        version="v1",
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=[CHAT_READONLY_SCOPE],
    )
    if isinstance(auth_result, types.CallToolResult):
        return auth_result  # Auth error
    service, user_email = auth_result

    try:
        # If specific space provided, search within that space
        if space_id:
            response = await asyncio.to_thread(
                service.spaces().messages().list(
                    parent=space_id,
                    pageSize=page_size,
                    filter=f'text:"{query}"'
                ).execute
            )
            messages = response.get('messages', [])
            context = f"space '{space_id}'"
        else:
            # Search across all accessible spaces (this may require iterating through spaces)
            # For simplicity, we'll search the user's spaces first
            spaces_response = await asyncio.to_thread(
                service.spaces().list(pageSize=100).execute
            )
            spaces = spaces_response.get('spaces', [])
            
            messages = []
            for space in spaces[:10]:  # Limit to first 10 spaces to avoid timeout
                try:
                    space_messages = await asyncio.to_thread(
                        service.spaces().messages().list(
                            parent=space.get('name'),
                            pageSize=5,
                            filter=f'text:"{query}"'
                        ).execute
                    )
                    space_msgs = space_messages.get('messages', [])
                    for msg in space_msgs:
                        msg['_space_name'] = space.get('displayName', 'Unknown')
                    messages.extend(space_msgs)
                except HttpError:
                    continue  # Skip spaces we can't access
            context = "all accessible spaces"

        if not messages:
            return types.CallToolResult(content=[types.TextContent(type="text",
                text=f"No messages found matching '{query}' in {context}.")])

        output = [f"Found {len(messages)} messages matching '{query}' in {context}:"]
        for msg in messages:
            sender = msg.get('sender', {}).get('displayName', 'Unknown Sender')
            create_time = msg.get('createTime', 'Unknown Time')
            text_content = msg.get('text', 'No text content')
            space_name = msg.get('_space_name', 'Unknown Space')
            
            # Truncate long messages
            if len(text_content) > 100:
                text_content = text_content[:100] + "..."
            
            output.append(f"- [{create_time}] {sender} in '{space_name}': {text_content}")
        
        return types.CallToolResult(content=[types.TextContent(type="text", text="\n".join(output))])

    except HttpError as e:
        logger.error(f"API error in {tool_name}: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {e}")])
    except Exception as e:
        logger.exception(f"Unexpected error in {tool_name}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])