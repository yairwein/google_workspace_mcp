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
from auth.google_auth import get_credentials

# Configure module logger
logger = logging.getLogger(__name__)

# Import the server directly (will be initialized before this module is imported)
# Also import the OAUTH_STATE_TO_SESSION_ID_MAP for linking OAuth state to MCP session
from core.server import server, OAUTH_REDIRECT_URI, OAUTH_STATE_TO_SESSION_ID_MAP

# Import scopes from server
from core.server import (
    SCOPES,
    CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE
)

# --- Configuration Placeholders (should ideally be loaded from a central app config) ---
_client_secrets_env = os.getenv("GOOGLE_CLIENT_SECRETS")
if _client_secrets_env:
    CONFIG_CLIENT_SECRETS_PATH = _client_secrets_env # User provided, assume correct path
else:
    # Default to client_secret.json in the root directory
    CONFIG_CLIENT_SECRETS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'client_secret.json')

# Use MCP server's OAuth callback endpoint
CONFIG_REDIRECT_URI = OAUTH_REDIRECT_URI
# ---

async def _initiate_auth_and_get_message(
    mcp_session_id: Optional[str], 
    scopes: List[str],
    user_google_email: Optional[str] = None
) -> types.CallToolResult:
    """
    Initiates the Google OAuth flow and returns an actionable message for the user.
    The user will be directed to an auth URL. The LLM must guide the user on next steps.
    If mcp_session_id is provided, it's linked to the OAuth state.
    """
    initial_email_provided = bool(user_google_email and user_google_email.strip() and user_google_email.lower() != 'default')

    if initial_email_provided:
        user_display_name = f"Google account for '{user_google_email}'"
    else:
        user_display_name = "your Google account"

    logger.info(f"[_initiate_auth_and_get_message] Initiating auth for {user_display_name} (email provided: {initial_email_provided}, session: {mcp_session_id}) with scopes: {scopes}")

    try:
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ and "localhost" in CONFIG_REDIRECT_URI:
            logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            
        from google_auth_oauthlib.flow import Flow
        oauth_state = os.urandom(16).hex()

        if mcp_session_id:
            OAUTH_STATE_TO_SESSION_ID_MAP[oauth_state] = mcp_session_id
            logger.info(f"[_initiate_auth_and_get_message] Stored mcp_session_id '{mcp_session_id}' for oauth_state '{oauth_state}'.")
        
        flow = Flow.from_client_secrets_file(
            CONFIG_CLIENT_SECRETS_PATH,
            scopes=scopes,
            redirect_uri=CONFIG_REDIRECT_URI,
            state=oauth_state
        )
        
        auth_url, returned_state = flow.authorization_url(
            access_type='offline', prompt='consent'
        )
        
        logger.info(f"Auth flow started for {user_display_name}. State: {returned_state}. Advise user to visit: {auth_url}")
        
        message_lines = [
            f"**ACTION REQUIRED: Google Authentication Needed for {user_display_name}**\n",
            "To proceed, the user must authorize this application.",
            "**LLM, please present this exact authorization URL to the user as a clickable hyperlink:**",
            f"Authorization URL: {auth_url}",
            f"Markdown for hyperlink: [Click here to authorize Google Calendar access]({auth_url})\n",
            "**LLM, after presenting the link, instruct the user as follows:**",
            "1. Click the link and complete the authorization in their browser.",
        ]
        session_info_for_llm = f" (this will link to your current session {mcp_session_id})" if mcp_session_id else ""

        if not initial_email_provided:
            message_lines.extend([
                f"2. After successful authorization{session_info_for_llm}, the browser page will display the authenticated email address.",
                "   **LLM: Instruct the user to provide you with this email address.**",
                "3. Once you have the email, **retry their original command, ensuring you include this `user_google_email`.**"
            ])
        else:
            message_lines.append(f"2. After successful authorization{session_info_for_llm}, **retry their original command**.")

        message_lines.append(f"\nThe application will use the new credentials. If '{user_google_email}' was provided, it must match the authenticated account.")
        message = "\n".join(message_lines)
        
        return types.CallToolResult(
            isError=True, 
            content=[types.TextContent(type="text", text=message)]
        )
    except FileNotFoundError as e:
        error_text = f"OAuth client secrets file not found: {e}. Please ensure '{CONFIG_CLIENT_SECRETS_PATH}' is correctly configured."
        logger.error(error_text, exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_text)])
    except Exception as e:
        error_text = f"Could not initiate authentication for {user_display_name} due to an unexpected error: {str(e)}"
        logger.error(f"Failed to start the OAuth flow for {user_display_name}: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_text)])

# --- Tool Implementations ---

@server.tool()
async def start_auth(user_google_email: str, mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")) -> types.CallToolResult:
    """
    Starts the Google OAuth authentication process for a specific Google email.
    This authentication will be linked to the active MCP session if `mcp_session_id` is available from the header.
    LLM: This tool REQUIRES `user_google_email`. If unknown, ask the user first.

    Args:
        user_google_email (str): The user's Google email address (e.g., 'example@gmail.com'). REQUIRED.
        mcp_session_id (Optional[str]): The active MCP session ID (injected by FastMCP from Mcp-Session-Id header).
                                 
    Returns:
        A CallToolResult (isError=True) with instructions for the user to complete auth.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[start_auth] {error_msg}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    logger.info(f"Tool 'start_auth' invoked for user_google_email: '{user_google_email}', session: '{mcp_session_id}'.")
    auth_scopes = SCOPES
    logger.info(f"[start_auth] Using scopes: {auth_scopes}")
    return await _initiate_auth_and_get_message(mcp_session_id, scopes=auth_scopes, user_google_email=user_google_email)

@server.tool()
async def list_calendars(user_google_email: Optional[str] = None, mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")) -> types.CallToolResult:
    """
    Lists Google Calendars. Prioritizes authenticated MCP session, then `user_google_email`.
    If no valid authentication is found, guides the LLM to obtain user's email or use `start_auth`.
    
    Args:
        user_google_email (Optional[str]): User's Google email. Used if session isn't authenticated.
        mcp_session_id (Optional[str]): Active MCP session ID (injected by FastMCP from Mcp-Session-Id header).
        
    Returns:
        A CallToolResult with the list of calendars or an error/auth guidance message.
    """
    logger.info(f"[list_calendars] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}'")
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=SCOPES,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[list_calendars] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[list_calendars] Valid email '{user_google_email}' provided, initiating auth flow for this email.")
            return await _initiate_auth_and_get_message(mcp_session_id, scopes=SCOPES, user_google_email=user_google_email)
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
    Lists events from a Google Calendar. Prioritizes authenticated MCP session, then `user_google_email`.
    If no valid authentication is found, guides the LLM to obtain user's email or use `start_auth`.
    
    Args:
        user_google_email (Optional[str]): User's Google email. Used if session isn't authenticated.
        calendar_id (str): Calendar ID (default: 'primary').
        time_min (Optional[str]): Start time (RFC3339). Defaults to now if not set.
        time_max (Optional[str]): End time (RFC3339).
        max_results (int): Max events to return.
        mcp_session_id (Optional[str]): Active MCP session ID (injected by FastMCP from Mcp-Session-Id header).
        
    Returns:
        A CallToolResult with the list of events or an error/auth guidance message.
    """
    logger.info(f"[get_events] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', Calendar: {calendar_id}")
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=[CALENDAR_READONLY_SCOPE], 
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[get_events] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[get_events] Valid email '{user_google_email}' provided, initiating auth flow for this email (requests all SCOPES).")
            return await _initiate_auth_and_get_message(mcp_session_id, scopes=SCOPES, user_google_email=user_google_email)
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
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[create_event] No valid credentials. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            logger.info(f"[create_event] Valid email '{user_google_email}' provided, initiating auth flow for this email (requests all SCOPES).")
            return await _initiate_auth_and_get_message(mcp_session_id, scopes=SCOPES, user_google_email=user_google_email)
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