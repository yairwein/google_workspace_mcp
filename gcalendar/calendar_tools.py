"""
Google Calendar MCP Tools

This module provides MCP tools for interacting with Google Calendar API.
"""
import datetime
import logging
import asyncio
import os
import sys
from typing import List, Optional, Dict, Any

# Import MCP types for proper response formatting
from mcp import types
from fastapi import Header # Import Header

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Use functions directly from google_auth
from auth.google_auth import get_credentials, start_auth_flow, CONFIG_CLIENT_SECRETS_PATH # Import start_auth_flow and CONFIG_CLIENT_SECRETS_PATH

# Configure module logger
logger = logging.getLogger(__name__)

# Import the server directly (will be initialized before this module is imported)
# Also import the OAUTH_STATE_TO_SESSION_ID_MAP for linking OAuth state to MCP session
from core.server import server, OAUTH_REDIRECT_URI, OAUTH_STATE_TO_SESSION_ID_MAP

# Import scopes from server
from core.server import (
    SCOPES, # Keep SCOPES for the start_auth tool and auth flow initiation
    CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE
)

# CONFIG_CLIENT_SECRETS_PATH is now imported from auth.google_auth
# CONFIG_REDIRECT_URI is now imported from core.server

# Remove the local _initiate_auth_and_get_message helper function
# async def _initiate_auth_and_get_message(...): ...


# --- Tool Implementations ---

@server.tool()
async def start_auth(user_google_email: str, mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")) -> types.CallToolResult:
    """
    Initiates the Google OAuth 2.0 authentication flow for the specified user email.
    This is the primary method to establish credentials when no valid session exists or when targeting a specific account.
    It generates an authorization URL that the LLM must present to the user.
    The authentication attempt is linked to the current MCP session via `mcp_session_id`.

    LLM Guidance:
    - Use this tool when you need to authenticate a user for Google services and don't have existing valid credentials for the session or specified email.
    - You MUST provide the `user_google_email`. If you don't know it, ask the user first.
    - After calling this tool, present the returned authorization URL clearly to the user and instruct them to:
        1. Click the link and complete the sign-in/consent process in their browser.
        2. Note the authenticated email displayed on the success page.
        3. Provide that email back to you (the LLM).
        4. Retry their original request, including the confirmed `user_google_email`.

    Args:
        user_google_email (str): The user's full Google email address (e.g., 'example@gmail.com'). This is REQUIRED.
        mcp_session_id (Optional[str]): The active MCP session ID (automatically injected by FastMCP from the Mcp-Session-Id header). Links the OAuth flow state to the session.

    Returns:
        types.CallToolResult: An error result (`isError=True`) containing:
                               - A detailed message for the LLM with the authorization URL and instructions to guide the user through the authentication process.
                               - An error message if `user_google_email` is invalid or missing.
                               - An error message if the OAuth flow initiation fails.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[start_auth] {error_msg}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    logger.info(f"Tool 'start_auth' invoked for user_google_email: '{user_google_email}', session: '{mcp_session_id}'.")
    # Use the centralized start_auth_flow from auth.google_auth
    return await start_auth_flow(mcp_session_id=mcp_session_id, user_google_email=user_google_email, service_name="Google Calendar", redirect_uri=OAUTH_REDIRECT_URI)

@server.tool()
async def list_calendars(user_google_email: Optional[str] = None, mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")) -> types.CallToolResult:
    """
    Retrieves a list of calendars accessible to the authenticated user.
    Prioritizes authentication via the active MCP session (`mcp_session_id`).
    If the session isn't authenticated for Calendar, it falls back to using `user_google_email`.
    If neither provides valid credentials, it returns a message guiding the LLM to request the user's email
    or initiate the authentication flow via the `start_auth` tool.

    Args:
        user_google_email (Optional[str]): The user's Google email address. Required if the MCP session is not already authenticated for Calendar access.
        mcp_session_id (Optional[str]): The active MCP session ID (automatically injected by FastMCP from the Mcp-Session-Id header). Used for session-based authentication.

    Returns:
        types.CallToolResult: Contains a list of the user's calendars (summary, ID, primary status),
                               an error message if the API call fails,
                               or an authentication guidance message if credentials are required.
    """
    logger.info(f"[list_calendars] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}'")
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=[CALENDAR_READONLY_SCOPE], # Request only necessary scopes for get_credentials check
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH, # Use imported constant
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[list_calendars] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[list_calendars] Valid email '{user_google_email}' provided, initiating auth flow for this email.")
            # Use the centralized start_auth_flow
            return await start_auth_flow(mcp_session_id=mcp_session_id, user_google_email=user_google_email, service_name="Google Calendar", redirect_uri=OAUTH_REDIRECT_URI)
        else:
            error_msg = "Authentication required. No active authenticated session, and no valid 'user_google_email' provided. LLM: Please ask the user for their Google email address and retry, or use the 'start_auth' tool with their email."
            logger.info(f"[list_calendars] {error_msg}")
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        service = build('calendar', 'v3', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown'
        logger.info(f"Successfully built calendar service. User associated with creds: {user_email_from_creds}")
        calendar_list_response = await asyncio.to_thread(service.calendarList().list().execute)
        items = calendar_list_response.get('items', [])
        if not items:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No calendars found for {user_email_from_creds}.")])

        calendars_summary_list = [f"- \"{cal.get('summary', 'No Summary')}\"{' (Primary)' if cal.get('primary') else ''} (ID: {cal['id']})" for cal in items]
        text_output = f"Successfully listed {len(items)} calendars for {user_email_from_creds}:\n" + "\n".join(calendars_summary_list)
        logger.info(f"Successfully listed {len(items)} calendars.")
        return types.CallToolResult(content=[types.TextContent(type="text", text=text_output)])
    except HttpError as error:
        message = f"API error listing calendars: {error}. You might need to re-authenticate. LLM: Try 'start_auth' with user's email."
        logger.error(message, exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])
    except Exception as e:
        message = f"Unexpected error listing calendars: {e}."
        logger.exception(message)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])

@server.tool()
async def get_events(
    user_google_email: Optional[str] = None,
    calendar_id: str = 'primary',
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
    max_results: int = 25,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Retrieves a list of events from a specified Google Calendar within a given time range.
    Prioritizes authentication via the active MCP session (`mcp_session_id`).
    If the session isn't authenticated for Calendar, it falls back to using `user_google_email`.
    If neither provides valid credentials, it returns a message guiding the LLM to request the user's email
    or initiate the authentication flow via the `start_auth` tool.

    Args:
        user_google_email (Optional[str]): The user's Google email address. Required if the MCP session is not already authenticated for Calendar access.
        calendar_id (str): The ID of the calendar to query. Use 'primary' for the user's primary calendar. Defaults to 'primary'. Calendar IDs can be obtained using `list_calendars`.
        time_min (Optional[str]): The start of the time range (inclusive) in RFC3339 format (e.g., '2024-05-12T10:00:00Z' or '2024-05-12'). If omitted, defaults to the current time.
        time_max (Optional[str]): The end of the time range (exclusive) in RFC3339 format. If omitted, events starting from `time_min` onwards are considered (up to `max_results`).
        max_results (int): The maximum number of events to return. Defaults to 25.
        mcp_session_id (Optional[str]): The active MCP session ID (automatically injected by FastMCP from the Mcp-Session-Id header). Used for session-based authentication.

    Returns:
        types.CallToolResult: Contains a list of events (summary, start time, link) within the specified range,
                               an error message if the API call fails,
                               or an authentication guidance message if credentials are required.
    """
    logger.info(f"[get_events] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', Calendar: {calendar_id}")
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=[CALENDAR_READONLY_SCOPE],
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH, # Use imported constant
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[get_events] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[get_events] Valid email '{user_google_email}' provided, initiating auth flow for this email (requests all SCOPES).")
            # Use the centralized start_auth_flow
            return await start_auth_flow(mcp_session_id=mcp_session_id, user_google_email=user_google_email, service_name="Google Calendar", redirect_uri=OAUTH_REDIRECT_URI)
        else:
            error_msg = "Authentication required. No active authenticated session, and no valid 'user_google_email' provided. LLM: Please ask the user for their Google email address and retry, or use the 'start_auth' tool with their email."
            logger.info(f"[get_events] {error_msg}")
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        service = build('calendar', 'v3', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown'
        logger.info(f"Successfully built calendar service. User associated with creds: {user_email_from_creds}")

        effective_time_min = time_min or (datetime.datetime.utcnow().isoformat() + 'Z')
        if time_min is None: logger.info(f"Defaulting time_min to current time: {effective_time_min}")

        events_result = await asyncio.to_thread(
            service.events().list(
                calendarId=calendar_id, timeMin=effective_time_min, timeMax=time_max,
                maxResults=max_results, singleEvents=True, orderBy='startTime'
            ).execute
        )
        items = events_result.get('items', [])
        if not items:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No events found in calendar '{calendar_id}' for {user_email_from_creds} for the specified time range.")])

        event_details_list = []
        for item in items:
            summary = item.get('summary', 'No Title')
            start = item['start'].get('dateTime', item['start'].get('date'))
            link = item.get('htmlLink', 'No Link')
            event_details_list.append(f"- \"{summary}\" (Starts: {start}) Link: {link}")

        text_output = f"Successfully retrieved {len(items)} events from calendar '{calendar_id}' for {user_email_from_creds}:\n" + "\n".join(event_details_list)
        logger.info(f"Successfully retrieved {len(items)} events.")
        return types.CallToolResult(content=[types.TextContent(type="text", text=text_output)])
    except HttpError as error:
        message = f"API error getting events: {error}. You might need to re-authenticate. LLM: Try 'start_auth' with user's email."
        logger.error(message, exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])
    except Exception as e:
        message = f"Unexpected error getting events: {e}."
        logger.exception(message)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])

@server.tool()
async def create_event(
    summary: str,
    start_time: str,
    end_time: str,
    user_google_email: Optional[str] = None,
    calendar_id: str = 'primary',
    description: Optional[str] = None,
    location: Optional[str] = None,
    attendees: Optional[List[str]] = None,
    timezone: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Creates a new event. Prioritizes authenticated MCP session, then `user_google_email`.
    If no valid authentication is found, guides the LLM to obtain user's email or use `start_auth`.

    Args:
        summary (str): Event title.
        start_time (str): Start time (RFC3339, e.g., "2023-10-27T10:00:00-07:00" or "2023-10-27" for all-day).
        end_time (str): End time (RFC3339, e.g., "2023-10-27T11:00:00-07:00" or "2023-10-28" for all-day).
        user_google_email (Optional[str]): User's Google email. Used if session isn't authenticated.
        calendar_id (str): Calendar ID (default: 'primary').
        description (Optional[str]): Event description.
        location (Optional[str]): Event location.
        attendees (Optional[List[str]]): Attendee email addresses.
        timezone (Optional[str]): Timezone (e.g., "America/New_York").
        mcp_session_id (Optional[str]): Active MCP session ID (injected by FastMCP from Mcp-Session-Id header).

    Returns:
        A CallToolResult confirming creation or an error/auth guidance message.
    """
    logger.info(f"[create_event] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', Summary: {summary}")
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=[CALENDAR_EVENTS_SCOPE],
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH, # Use imported constant
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[create_event] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[create_event] Valid email '{user_google_email}' provided, initiating auth flow for this email (requests all SCOPES).")
            # Use the centralized start_auth_flow
            return await start_auth_flow(mcp_session_id=mcp_session_id, user_google_email=user_google_email, service_name="Google Calendar", redirect_uri=OAUTH_REDIRECT_URI)
        else:
            error_msg = "Authentication required to create event. No active authenticated session, and no valid 'user_google_email' provided. LLM: Please ask the user for their Google email address and retry, or use the 'start_auth' tool with their email."
            logger.info(f"[create_event] {error_msg}")
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        service = build('calendar', 'v3', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown'
        logger.info(f"Successfully built calendar service. User associated with creds: {user_email_from_creds}")

        event_body: Dict[str, Any] = {
            'summary': summary,
            'start': {'date': start_time} if 'T' not in start_time else {'dateTime': start_time},
            'end': {'date': end_time} if 'T' not in end_time else {'dateTime': end_time},
        }
        if location: event_body['location'] = location
        if description: event_body['description'] = description
        if timezone:
            if 'dateTime' in event_body['start']: event_body['start']['timeZone'] = timezone
            if 'dateTime' in event_body['end']: event_body['end']['timeZone'] = timezone
        if attendees: event_body['attendees'] = [{'email': email} for email in attendees]

        created_event = await asyncio.to_thread(
            service.events().insert(calendarId=calendar_id, body=event_body).execute
        )

        link = created_event.get('htmlLink', 'No link available')
        confirmation_message = f"Successfully created event '{created_event.get('summary', summary)}' for {user_email_from_creds}. Link: {link}"
        logger.info(f"Successfully created event. Link: {link}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=confirmation_message)])
    except HttpError as error:
        message = f"API error creating event: {error}. Check event details or re-authenticate. LLM: Try 'start_auth' with user's email."
        logger.error(message, exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])
    except Exception as e:
        message = f"Unexpected error creating event: {e}."
        logger.exception(message)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])