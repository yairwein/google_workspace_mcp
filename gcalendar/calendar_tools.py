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

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Use functions directly from google_auth
from auth.google_auth import get_credentials, handle_auth_callback
from auth.auth_session_manager import auth_session_manager

# Configure module logger
logger = logging.getLogger(__name__)

# Import the server directly (will be initialized before this module is imported)
from core.server import server, OAUTH_REDIRECT_URI

# Import scopes from server
from core.server import (
    SCOPES, BASE_SCOPES, CALENDAR_SCOPES,
    USERINFO_EMAIL_SCOPE, OPENID_SCOPE,
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

async def _initiate_auth_and_get_message(scopes: List[str]) -> types.CallToolResult:
    """
    Initiates the Google OAuth flow using AuthSessionManager and returns a message for the user.
    The MCP server's OAuth resource endpoint handles callback.
    Returns a CallToolResult with auth URL and session ID.
    """
    logger.info(f"[_initiate_auth_and_get_message] Called with scopes: {scopes}")

    try:
        # Create a new authentication session
        auth_session = auth_session_manager.create_session()
        session_id_for_state = auth_session.session_id
        logger.info(f"[_initiate_auth_and_get_message] Created auth session ID (for state): {session_id_for_state}")

        # Ensure OAUTHLIB_INSECURE_TRANSPORT is set
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ:
            logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            
        # Set up the OAuth flow using the MCP server's callback endpoint
        from google_auth_oauthlib.flow import Flow
        flow = Flow.from_client_secrets_file(
            CONFIG_CLIENT_SECRETS_PATH,
            scopes=scopes,
            redirect_uri=CONFIG_REDIRECT_URI,
            state=session_id_for_state # Pass the session_id as state
        )
        
        # Generate the authorization URL
        auth_url, state_from_flow = flow.authorization_url(
            access_type='offline',
            prompt='consent'
        )
        # Verify state consistency (state_from_flow should match session_id_for_state)
        if state_from_flow != session_id_for_state:
            error_message = "OAuth state mismatch during flow generation. This is an internal server error."
            logger.error(f"OAuth state mismatch! Expected {session_id_for_state}, got {state_from_flow}. Aborting auth initiation.")
            auth_session_manager.fail_session(session_id_for_state, "OAuth state mismatch during flow generation.")
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=error_message)]
            )

        logger.info(f"Auth flow started. State: {state_from_flow}. Advise user to visit: {auth_url}")
        
        # Return MCP-formatted response with auth URL and session ID
        instructional_message = (
            f"**ACTION REQUIRED: Authentication Needed**\n\n"
            f"1. To proceed, please [click here to authorize Google Calendar access]({auth_url}).\n\n"
            f"2. After successful authorization in your browser, you will receive an `auth_session_id` (it is: `{session_id_for_state}`).\n\n"
            f"3. Call the `get_auth_result` tool, providing this `auth_session_id`, to obtain your verified `user_id`.\n\n"
            f"4. Once you have your `user_id`, you can retry your original command."
        )
        return types.CallToolResult(
            isError=True, # Indicates an action is required from the user/LLM before proceeding
            content=[
                types.TextContent(
                    type="text",
                    text=instructional_message
                )
            ]
        )
    except Exception as e:
        error_message = f"Could not initiate authentication due to an unexpected error: {str(e)}"
        logger.error(f"Failed to start the OAuth flow: {e}", exc_info=True)
        # If session was created, mark it as failed
        if 'auth_session' in locals() and auth_session: # Check if auth_session was defined
            auth_session_manager.fail_session(auth_session.session_id, f"OAuth flow initiation error: {e}")
        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=error_message
                )
            ]
        )

# --- Tool Implementations ---

@server.tool()
async def start_auth() -> types.CallToolResult:
    """
    Starts the Google OAuth authentication process using a session-based flow.
    The user will be prompted to visit an authorization URL.
    After authorization, they must call 'get_auth_result' with the provided
    'auth_session_id' to obtain their verified user_id for subsequent tool calls.
    
    Returns:
        A CallToolResult with the authentication URL, an auth_session_id, and instructions.
    """
    logger.info(f"Tool 'start_auth' invoked. This will initiate a new session-based OAuth flow.")
    # Define desired scopes for general authentication, including userinfo
    # These are the broadest scopes needed for any calendar operation.
    auth_scopes = SCOPES # Use the comprehensive SCOPES from core.server
    
    logger.info(f"[start_auth] Using scopes: {auth_scopes}")
    # The user_id is not known at this point; it will be determined after OAuth.
    return await _initiate_auth_and_get_message(auth_scopes)


@server.tool()
async def get_auth_result(auth_session_id: str) -> types.CallToolResult:
    """
    Retrieves the result of an authentication attempt using the auth_session_id.
    This tool should be called after the user completes the OAuth flow initiated by 'start_auth'.

    Args:
        auth_session_id (str): The session ID provided by the 'start_auth' tool.

    Returns:
        A CallToolResult containing the verified user_id if authentication was successful,
        or an error message if it failed or is still pending.
    """
    logger.info(f"[get_auth_result] Tool invoked with auth_session_id: '{auth_session_id}'")
    session = auth_session_manager.get_session(auth_session_id)

    if not session:
        message = f"Authentication session ID '{auth_session_id}' not found. Please ensure you are using the correct ID provided by 'start_auth' or restart the authentication process with 'start_auth'."
        logger.warning(f"[get_auth_result] Auth session not found for ID: '{auth_session_id}'")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if session.status == "pending":
        message = "Authentication is still pending. Please ensure you have completed the authorization steps in your browser. Then, call this tool again."
        logger.info(f"[get_auth_result] Auth session '{auth_session_id}' is still pending.")
        return types.CallToolResult(
            isError=True, # Still an error in the sense that the original goal isn't met
            content=[types.TextContent(type="text", text=message)]
        )
    elif session.status == "completed" and session.user_id:
        message = f"Authentication successful. Your verified user_id is: {session.user_id}. You can now use this user_id to retry your original command."
        logger.info(f"[get_auth_result] Auth session '{auth_session_id}' completed. Verified user_id: '{session.user_id}'.")
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=message)
            ]
        )
    elif session.status == "failed":
        message = f"Authentication failed for session '{auth_session_id}'. Error: {session.error_message or 'Unknown reason.'}. Please try running 'start_auth' again."
        logger.warning(f"[get_auth_result] Auth session '{auth_session_id}' failed. Error: {session.error_message}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )
    else: # Should not happen
        message = f"Authentication session '{auth_session_id}' is in an unknown state: {session.status}. This is an internal server error."
        logger.error(f"[get_auth_result] Auth session '{auth_session_id}' is in an unknown state: {session.status}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )


async def list_calendars(user_id: str) -> types.CallToolResult:
    """
    Lists the Google Calendars the user has access to.
    If not authenticated, prompts the user to authenticate and retry.
    
    Args:
        user_id (str): The user identifier to list calendars for
        
    Returns:
        A CallToolResult with TextContent describing the list of calendars or an error message.
    """
    logger.info(f"[list_calendars] Tool invoked for user: {user_id}")
    # Always use full scopes to ensure future operations work
    required_scopes = SCOPES
    
    # If user_id is 'default', try to find existing credentials
    if user_id == 'default':
        creds_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.credentials')
        if os.path.exists(creds_dir):
            for file in os.listdir(creds_dir):
                if file.endswith('.json'):
                    potential_user_id = file[:-5]  # Remove .json extension
                    if '@' in potential_user_id:  # Looks like an email
                        user_id = potential_user_id
                        logger.info(f"Found existing credentials, using user_id: {user_id}")
                        break

    try:
        logger.info(f"[list_calendars] Attempting to get_credentials for user_id: '{user_id}'")
        credentials = await asyncio.to_thread(
            get_credentials,
            user_id,
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH # Use config
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        message = f"Failed to get credentials for user '{user_id}': {e}. This might be an internal issue or the stored credentials might be corrupted. You can try to re-authenticate using the 'start_auth' tool."
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if not credentials or not credentials.valid:
        tool_name = "list_calendars"
        message = (
            f"**Authentication Required for '{tool_name}'**\n\n"
            f"Valid credentials for user '{user_id}' are missing or invalid.\n\n"
            f"Please follow these steps:\n"
            f"1. Call the `start_auth` tool (it takes no arguments). This will provide an authorization URL and an `auth_session_id`.\n"
            f"2. Complete the authorization flow in your browser.\n"
            f"3. Call the `get_auth_result` tool with the `auth_session_id` obtained in step 1. This will return your verified `user_id`.\n"
            f"4. Retry the `{tool_name}` command using the verified `user_id`."
        )
        logger.warning(f"[{tool_name}] Missing or invalid credentials for user '{user_id}'. Instructing LLM to use 'start_auth' and 'get_auth_result'.")
        return types.CallToolResult(
            isError=True, # Action required from user/LLM
            content=[types.TextContent(type="text", text=message)]
        )

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        calendar_list_response = await asyncio.to_thread(service.calendarList().list().execute)
        items = calendar_list_response.get('items', [])

        if not items:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"No calendars found for user '{user_id}'.")]
            )

        calendars_summary_list = []
        for calendar in items:
            summary = calendar.get('summary', 'No Summary')
            cal_id = calendar['id']
            primary_indicator = " (Primary)" if calendar.get('primary') else ""
            calendars_summary_list.append(f"- \"{summary}\"{primary_indicator} (ID: {cal_id})")
        
        calendars_text_output = f"Successfully listed {len(items)} calendars for user '{user_id}':\n" + "\n".join(calendars_summary_list)
        logger.info(f"Successfully listed {len(items)} calendars for user: {user_id}")
        
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=calendars_text_output)
            ]
        )

    except HttpError as error:
        message = f"An API error occurred while listing calendars for user '{user_id}': {error}. This might be due to insufficient permissions or an issue with the Google Calendar API. You might need to re-authenticate using 'start_auth'."
        logger.error(f"An API error occurred for user {user_id} listing calendars: {error}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )
    except Exception as e:
        message = f"An unexpected error occurred while listing calendars for user '{user_id}': {e}."
        logger.exception(f"An unexpected error occurred while listing calendars for {user_id}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

@server.tool()
async def get_events(
    user_id: str,
    calendar_id: str = 'primary',
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
    max_results: int = 25,
) -> types.CallToolResult:
    """
    Lists events from a specified Google Calendar within a given time range.
    If not authenticated, prompts the user to authenticate and retry.
    
    Args:
        user_id (str): The user identifier to get events for
        calendar_id (str): The calendar ID to fetch events from (default: 'primary')
        time_min (Optional[str]): The start time for fetching events (RFC3339 timestamp)
        time_max (Optional[str]): The end time for fetching events (RFC3339 timestamp)
        max_results (int): Maximum number of events to return (default: 25)
        
    Returns:
        A CallToolResult with TextContent describing the list of events or an error message.
    """
    logger.info(f"[get_events] Tool invoked for user: {user_id}, calendar: {calendar_id}")
    required_scopes = [CALENDAR_READONLY_SCOPE]

    try:
        logger.info(f"[get_events] Attempting to get_credentials for user_id: '{user_id}' with scopes: {required_scopes}") # ADDED LOG
        credentials = await asyncio.to_thread(
            get_credentials,
            user_id,
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH # Use config
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        message = f"Failed to get credentials for user '{user_id}': {e}. This might be an internal issue or the stored credentials might be corrupted. You can try to re-authenticate using the 'start_auth' tool."
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if not credentials or not credentials.valid:
        tool_name = "get_events"
        message = (
            f"**Authentication Required for '{tool_name}'**\n\n"
            f"Valid credentials for user '{user_id}' are missing or invalid.\n\n"
            f"Please follow these steps:\n"
            f"1. Call the `start_auth` tool (it takes no arguments). This will provide an authorization URL and an `auth_session_id`.\n"
            f"2. Complete the authorization flow in your browser.\n"
            f"3. Call the `get_auth_result` tool with the `auth_session_id` obtained in step 1. This will return your verified `user_id`.\n"
            f"4. Retry the `{tool_name}` command using the verified `user_id`."
        )
        logger.warning(f"[{tool_name}] Missing or invalid credentials for user '{user_id}'. Instructing LLM to use 'start_auth' and 'get_auth_result'.")
        return types.CallToolResult(
            isError=True, # Action required from user/LLM
            content=[types.TextContent(type="text", text=message)]
        )

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        effective_time_min = time_min
        if effective_time_min is None:
            effective_time_min = datetime.datetime.utcnow().isoformat() + 'Z' # Default to now
            logger.info(f"Defaulting time_min to current time: {effective_time_min}")
        
        time_max_log = f"and {time_max}" if time_max else "indefinitely (no end time specified)"
        logger.info(f"Fetching events for {user_id} from calendar '{calendar_id}' starting {effective_time_min} {time_max_log}, max results: {max_results}")

        events_result = await asyncio.to_thread(
            service.events().list(
                calendarId=calendar_id,
                timeMin=effective_time_min,
                timeMax=time_max, # Can be None
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute
        )
        items = events_result.get('items', [])

        if not items:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"No events found for user '{user_id}' in calendar '{calendar_id}' for the specified time range.")]
            )

        event_summary_list = []
        for event_item in items:
            summary = event_item.get('summary', 'No Title')
            start_obj = event_item['start']
            start_time_str = start_obj.get('dateTime', start_obj.get('date')) # Handles all-day events
            event_id = event_item['id']
            event_link = event_item.get('htmlLink', '')
            
            event_desc = f"- \"{summary}\" starting at {start_time_str} (ID: {event_id})"
            if event_link:
                event_desc += f" [Link: {event_link}]"
            event_summary_list.append(event_desc)
            
        events_text_output = f"Successfully fetched {len(items)} events for user '{user_id}' from calendar '{calendar_id}':\n" + "\n".join(event_summary_list)
        logger.info(f"Successfully retrieved {len(items)} events for user: {user_id}, calendar: {calendar_id}")
        
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=events_text_output)
            ]
        )

    except HttpError as error:
        message = f"An API error occurred while fetching events for user '{user_id}': {error}. This might be due to insufficient permissions or an issue with the Google Calendar API. You might need to re-authenticate using 'start_auth'."
        logger.error(f"An API error occurred for user {user_id} getting events: {error}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )
    except Exception as e:
        message = f"An unexpected error occurred while fetching events for user '{user_id}': {e}."
        logger.exception(f"An unexpected error occurred while getting events for {user_id}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )


@server.tool()
async def create_event(
    user_id: str,
    summary: str,
    start_time: str,
    end_time: str,
    calendar_id: str = 'primary',
    description: Optional[str] = None,
    location: Optional[str] = None,
    attendees: Optional[List[str]] = None,
    timezone: Optional[str] = None,
) -> types.CallToolResult:
    """
    Creates a new event in a specified Google Calendar.
    If not authenticated, prompts the user to authenticate and retry.
    
    Args:
        user_id (str): The user identifier to create the event for
        summary (str): The event title/summary
        start_time (str): The event start time (RFC3339 timestamp)
        end_time (str): The event end time (RFC3339 timestamp)
        calendar_id (str): The calendar ID to create the event in (default: 'primary')
        description (Optional[str]): Event description
        location (Optional[str]): Event location
        attendees (Optional[List[str]]): List of attendee email addresses
        timezone (Optional[str]): Timezone for the event
        
    Returns:
        A CallToolResult with TextContent confirming event creation or an error message.
    """
    logger.info(f"Attempting to create event for user: {user_id}, calendar: {calendar_id}")
    required_scopes = [CALENDAR_EVENTS_SCOPE] # Write scope needed
    logger.info(f"[create_event] Requesting credentials with scopes: {required_scopes}")

    try:
        credentials = await asyncio.to_thread(
            get_credentials,
            user_id,
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH # Use config
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        message = f"Failed to get credentials for user '{user_id}': {e}. This might be an internal issue or the stored credentials might be corrupted. You can try to re-authenticate using the 'start_auth' tool."
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if not credentials or not credentials.valid:
        tool_name = "create_event"
        message = (
            f"**Authentication Required for '{tool_name}'**\n\n"
            f"Valid credentials for user '{user_id}' are missing or invalid.\n\n"
            f"Please follow these steps:\n"
            f"1. Call the `start_auth` tool (it takes no arguments). This will provide an authorization URL and an `auth_session_id`.\n"
            f"2. Complete the authorization flow in your browser.\n"
            f"3. Call the `get_auth_result` tool with the `auth_session_id` obtained in step 1. This will return your verified `user_id`.\n"
            f"4. Retry the `{tool_name}` command using the verified `user_id`."
        )
        logger.warning(f"[{tool_name}] Missing or invalid credentials for user '{user_id}'. Instructing LLM to use 'start_auth' and 'get_auth_result'.")
        return types.CallToolResult(
            isError=True, # Action required from user/LLM
            content=[types.TextContent(type="text", text=message)]
        )

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        event_body: Dict[str, Any] = {
            'summary': summary,
            'start': {'dateTime': start_time}, # Timezone will be added if provided
            'end': {'dateTime': end_time},     # Timezone will be added if provided
        }
        if location:
            event_body['location'] = location
        if description:
            event_body['description'] = description
        if timezone: # Apply timezone to start and end if provided
            event_body['start']['timeZone'] = timezone
            event_body['end']['timeZone'] = timezone
        if attendees:
            event_body['attendees'] = [{'email': email_address} for email_address in attendees]

        logger.debug(f"Creating event with body: {event_body} for calendar: {calendar_id}")

        created_event_details = await asyncio.to_thread(
            service.events().insert(
                calendarId=calendar_id,
                body=event_body
            ).execute
        )
        
        event_summary_text = created_event_details.get('summary', 'No Title')
        event_id_text = created_event_details.get('id')
        event_link_text = created_event_details.get('htmlLink', 'N/A')
        created_time_text = created_event_details.get('created', 'N/A')

        logger.info(f"Successfully created event for user: {user_id}, event ID: {event_id_text}, Link: {event_link_text}")
        
        success_message = (
            f"Successfully created event: \"{event_summary_text}\".\n"
            f"- Event ID: {event_id_text}\n"
            f"- Calendar ID: {calendar_id}\n"
            f"- Link to event: {event_link_text}\n"
            f"- Created at: {created_time_text}"
        )
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=success_message)
            ]
        )

    except HttpError as error:
        message = f"An API error occurred while creating event for user '{user_id}': {error}. This could be due to invalid event details (e.g., time format), insufficient permissions, or an issue with the Google Calendar API. You might need to re-authenticate using 'start_auth'."
        logger.error(f"An API error occurred for user {user_id} creating event: {error}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )
    except Exception as e:
        message = f"An unexpected error occurred while creating event for user '{user_id}': {e}."
        logger.exception(f"An unexpected error occurred while creating event for {user_id}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )