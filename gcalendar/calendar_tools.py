"""
Google Calendar MCP Tools

This module provides MCP tools for interacting with Google Calendar API.
"""
import datetime
import logging
import asyncio
import os
import sys
from typing import List, Optional, Dict, Any, Required

# Import MCP types for proper response formatting
from mcp import types

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Use functions directly from google_auth
from auth.google_auth import get_credentials, handle_auth_callback

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

async def _initiate_auth_and_get_message(scopes: List[str], user_google_email: Optional[str] = None) -> types.CallToolResult:
    """
    Initiates the Google OAuth flow and returns an actionable message for the user.
    The user will be directed to an auth URL. The LLM must guide the user on next steps,
    including providing their email if it wasn't known beforehand.
    """
    initial_email_provided = bool(user_google_email and user_google_email.strip() and user_google_email.lower() != 'default')

    if initial_email_provided:
        user_display_name = f"Google account for '{user_google_email}'"
    else:
        user_display_name = "your Google account"

    logger.info(f"[_initiate_auth_and_get_message] Initiating auth for {user_display_name} (email provided: {initial_email_provided}) with scopes: {scopes}")

    try:
        # Ensure OAUTHLIB_INSECURE_TRANSPORT is set for localhost development
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ and "localhost" in CONFIG_REDIRECT_URI:
            logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            
        # Set up the OAuth flow
        from google_auth_oauthlib.flow import Flow
        # Generate a simple state for CSRF, though the library might do this too.
        # This state isn't used for session tracking anymore in this simplified flow.
        oauth_state = os.urandom(16).hex()
        
        flow = Flow.from_client_secrets_file(
            CONFIG_CLIENT_SECRETS_PATH,
            scopes=scopes,
            redirect_uri=CONFIG_REDIRECT_URI,
            state=oauth_state
        )
        
        auth_url, returned_state = flow.authorization_url(
            access_type='offline', # To get a refresh token
            prompt='consent'       # Ensures user sees consent screen, good for re-auth if needed
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
        if not initial_email_provided:
            message_lines.extend([
                "2. After successful authorization, the browser page will display the authenticated email address.",
                "   **LLM: Instruct the user to provide you with this email address.**",
                "3. Once you have the email, **retry their original command, ensuring you include this `user_google_email`.**"
            ])
        else:
            message_lines.append("2. After successful authorization, **retry their original command**.")

        message_lines.append(f"\nThe application will use the new credentials. If '{user_google_email}' was provided, it must match the authenticated account.")
        message = "\n".join(message_lines)
        
        return types.CallToolResult(
            isError=True, # True because the original action is blocked until auth is complete.
            content=[
                types.TextContent(
                    type="text",
                    text=message
                )
            ]
        )
    except FileNotFoundError as e:
        error_text = f"OAuth client secrets file not found: {e}. Please ensure '{CONFIG_CLIENT_SECRETS_PATH}' is correctly configured."
        logger.error(error_text, exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_text)])
    except Exception as e:
        error_text = f"Could not initiate authentication for {user_display_name} due to an unexpected error: {str(e)}"
        logger.error(f"Failed to start the OAuth flow for {user_display_name}: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[
                types.TextContent(
                    type="text",
                    text=error_text
                )
            ]
        )

# --- Tool Implementations ---

@server.tool()
async def start_auth(user_google_email: str) -> types.CallToolResult:
    """
    Starts the Google OAuth authentication process. Requires the user's Google email.
    If the email is not known, the LLM must ask the user for it before calling this tool.
    This tool is typically called when other tools indicate authentication is required
    and the user's Google email is available.

    The tool will return a message containing a special hyperlink for the user to click.
    **LLM Instructions:**
    - You MUST present the `auth_url` provided in the `TextContent` as a clickable hyperlink.
    - Clearly instruct the user to click the link to authorize the application for the specified `user_google_email`.
    - After they complete authorization, instruct them to **retry their original command**.
    - If the initial attempt to get credentials failed because the email was unknown or not yet authenticated,
      the message from this tool will guide you to ask the user for their email after they complete the browser flow.

    Args:
        user_google_email (str): The user's Google email address (e.g., 'example@gmail.com').
                                 This is REQUIRED. Do not pass an empty string or "default".
    Returns:
        A CallToolResult (with `isError=True` because the original action is blocked)
        containing `TextContent` with a Markdown-formatted hyperlink to the Google
        authorization URL and clear instructions for the user and LLM.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[start_auth] {error_msg}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    logger.info(f"Tool 'start_auth' invoked for user_google_email: '{user_google_email}'. This will initiate a new OAuth flow.")
    
    auth_scopes = SCOPES
    
    logger.info(f"[start_auth] Using scopes: {auth_scopes}")
    return await _initiate_auth_and_get_message(scopes=auth_scopes, user_google_email=user_google_email)

@server.tool()
async def list_calendars(user_google_email: str) -> types.CallToolResult:
    """
    Lists the Google Calendars the user has access to.
    Requires the user's Google email. If not authenticated, prompts for authentication.
    LLM: Ensure `user_google_email` is provided. If auth fails, the response will guide you.
    
    Args:
        user_google_email (str): The user's Google email address (e.g., 'example@gmail.com'). REQUIRED.
        
    Returns:
        A CallToolResult with TextContent describing the list of calendars or an error message.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[list_calendars] {error_msg}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    logger.info(f"[list_calendars] Tool invoked for user_google_email: {user_google_email}")
    required_scopes = SCOPES 
    
    try:
        logger.info(f"[list_calendars] Attempting to get_credentials for user_google_email: '{user_google_email}'")
        credentials = await asyncio.to_thread(
            get_credentials,
            user_google_email, 
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        message = f"Failed to get credentials for user '{user_google_email}': {e}. This might be an internal issue. You can try to re-authenticate using the 'start_auth' tool (ensure you provide the user_google_email)."
        logger.error(f"Error getting credentials for {user_google_email}: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if not credentials or not credentials.valid:
        logger.warning(f"[list_calendars] Missing or invalid credentials for user '{user_google_email}'. Triggering auth flow.")
        return await _initiate_auth_and_get_message(scopes=SCOPES, user_google_email=user_google_email)

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_google_email}")

        calendar_list_response = await asyncio.to_thread(service.calendarList().list().execute)
        items = calendar_list_response.get('items', [])

        if not items:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"No calendars found for user '{user_google_email}'.")]
            )

        calendars_summary_list = []
        for calendar in items:
            summary = calendar.get('summary', 'No Summary')
            cal_id = calendar['id']
            primary_indicator = " (Primary)" if calendar.get('primary') else ""
            calendars_summary_list.append(f"- \"{summary}\"{primary_indicator} (ID: {cal_id})")
        
        calendars_text_output = f"Successfully listed {len(items)} calendars for user '{user_google_email}':\n" + "\n".join(calendars_summary_list)
        logger.info(f"Successfully listed {len(items)} calendars for user: {user_google_email}")
        
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=calendars_text_output)
            ]
        )

    except HttpError as error:
        message = f"An API error occurred while listing calendars for user '{user_google_email}': {error}. This might be due to insufficient permissions or an issue with the Google Calendar API. You might need to re-authenticate using 'start_auth' (ensure you provide the user_google_email)."
        logger.error(f"An API error occurred for user {user_google_email} listing calendars: {error}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )
    except Exception as e:
        message = f"An unexpected error occurred while listing calendars for user '{user_google_email}': {e}."
        logger.exception(f"An unexpected error occurred while listing calendars for {user_google_email}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

@server.tool()
async def get_events(
    user_google_email: str,
    calendar_id: str = 'primary',
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
    max_results: int = 25,
) -> types.CallToolResult:
    """
    Lists events from a specified Google Calendar. Requires the user's Google email.
    If not authenticated, prompts for authentication.
    LLM: Ensure `user_google_email` is provided. If auth fails, the response will guide you.
    
    Args:
        user_google_email (str): The user's Google email address (e.g., 'example@gmail.com'). REQUIRED.
        calendar_id (str): The calendar ID to fetch events from (default: 'primary').
        time_min (Optional[str]): The start time for fetching events (RFC3339 timestamp).
        time_max (Optional[str]): The end time for fetching events (RFC3339 timestamp).
        max_results (int): Maximum number of events to return (default: 25).
        
    Returns:
        A CallToolResult with TextContent describing the list of events or an error message.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[get_events] {error_msg}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    logger.info(f"[get_events] Tool invoked for user_google_email: {user_google_email}, calendar: {calendar_id}")
    required_scopes_for_check = [CALENDAR_READONLY_SCOPE] 

    try:
        logger.info(f"[get_events] Attempting to get_credentials for user_google_email: '{user_google_email}' with specific check for scopes: {required_scopes_for_check}")
        credentials = await asyncio.to_thread(
            get_credentials,
            user_google_email, 
            required_scopes_for_check, 
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        message = f"Failed to get credentials for user '{user_google_email}': {e}. This might be an internal issue. You can try to re-authenticate using the 'start_auth' tool (ensure you provide the user_google_email)."
        logger.error(f"Error getting credentials for {user_google_email}: {e}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if not credentials or not credentials.valid:
        logger.warning(f"[get_events] Missing or invalid credentials for user '{user_google_email}'. Triggering auth flow with full SCOPES.")
        return await _initiate_auth_and_get_message(scopes=SCOPES, user_google_email=user_google_email)

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_google_email}")

        effective_time_min = time_min
        if effective_time_min is None:
            effective_time_min = datetime.datetime.utcnow().isoformat() + 'Z' 
            logger.info(f"Defaulting time_min to current time: {effective_time_min}")
        
        time_max_log = f"and {time_max}" if time_max else "indefinitely (no end time specified)"
        logger.info(f"Fetching events for {user_google_email} from calendar '{calendar_id}' starting {effective_time_min} {time_max_log}, max results: {max_results}")

        events_result = await asyncio.to_thread(
            service.events().list(
                calendarId=calendar_id,
                timeMin=effective_time_min,
                timeMax=time_max, 
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute
        )
        items = events_result.get('items', [])

        if not items:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"No events found for user '{user_google_email}' in calendar '{calendar_id}' for the specified time range.")]
            )

        event_details_list = []
        for event_item in items: 
            summary = event_item.get('summary', 'No Title')
            start_obj = event_item['start']
            start_time_str = start_obj.get('dateTime', start_obj.get('date')) 
            event_id = event_item['id'] 
            event_link = event_item.get('htmlLink', '') 
            
            event_desc = f"- \"{summary}\" starting at {start_time_str} (ID: {event_id})"
            if event_link:
                event_desc += f" [Link: {event_link}]"
            event_details_list.append(event_desc) 
            
        events_text_output = f"Successfully fetched {len(items)} events for user '{user_google_email}' from calendar '{calendar_id}':\n" + "\n".join(event_details_list) 
        logger.info(f"Successfully retrieved {len(items)} events for user: {user_google_email}, calendar: {calendar_id}")
        
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=events_text_output)
            ]
        )

    except HttpError as error:
        message = f"An API error occurred while fetching events for user '{user_google_email}': {error}. This might be due to insufficient permissions or an issue with the Google Calendar API. You might need to re-authenticate using 'start_auth' (ensure you provide the user_google_email)."
        logger.error(f"An API error occurred for user {user_google_email} getting events: {error}", exc_info=True)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )
    except Exception as e:
        message = f"An unexpected error occurred while fetching events for user '{user_google_email}': {e}."
        logger.exception(f"An unexpected error occurred while getting events for {user_google_email}: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )


@server.tool()
async def create_event(
    user_google_email: str,
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
    Creates a new event in a specified Google Calendar. Requires the user's Google email.
    If not authenticated, prompts for authentication.
    LLM: Ensure `user_google_email` is provided. If auth fails, the response will guide you.
    
    Args:
        user_google_email (str): The user's Google email address (e.g., 'example@gmail.com'). REQUIRED.
        summary (str): The event title/summary.
        start_time (str): The event start time (RFC3339 timestamp, e.g., "2023-10-27T10:00:00-07:00" or "2023-10-27" for all-day).
        end_time (str): The event end time (RFC3339 timestamp, e.g., "2023-10-27T11:00:00-07:00" or "2023-10-28" for all-day).
        calendar_id (str): The calendar ID to create the event in (default: 'primary').
        description (Optional[str]): Event description.
        location (Optional[str]): Event location.
        attendees (Optional[List[str]]): List of attendee email addresses.
        timezone (Optional[str]): Timezone for the event (e.g., "America/New_York"). Required if start/end times are not UTC and not all-day.
        
    Returns:
        A CallToolResult with TextContent confirming event creation or an error message.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[create_event] {error_msg}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    logger.info(f"[create_event] Tool invoked for user_google_email: {user_google_email}, summary: {summary}")
    required_scopes_for_check = [CALENDAR_EVENTS_SCOPE] 

    try:
        logger.info(f"[create_event] Attempting to get_credentials for user_google_email: '{user_google_email}' with specific check for scopes: {required_scopes_for_check}")
        credentials = await asyncio.to_thread(
            get_credentials,
            user_google_email, 
            required_scopes_for_check, 
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        message = f"Failed to get credentials for user '{user_google_email}': {e}. This might be an internal issue. You can try to re-authenticate using the 'start_auth' tool (ensure you provide the user_google_email)."
        logger.error(f"Error getting credentials for {user_google_email}: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])

    if not credentials or not credentials.valid:
        logger.warning(f"[create_event] Missing or invalid credentials for user '{user_google_email}'. Triggering auth flow with full SCOPES.")
        return await _initiate_auth_and_get_message(scopes=SCOPES, user_google_email=user_google_email)

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_google_email}")

        event_body: Dict[str, Any] = {
            'summary': summary,
            'start': {'date': start_time} if 'T' not in start_time else {'dateTime': start_time},
            'end': {'date': end_time} if 'T' not in end_time else {'dateTime': end_time},
        }
        if location:
            event_body['location'] = location
        if description:
            event_body['description'] = description
        if timezone: 
            if 'dateTime' in event_body['start']:
                 event_body['start']['timeZone'] = timezone
            if 'dateTime' in event_body['end']:
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

        logger.info(f"Successfully created event for user: {user_google_email}, event ID: {event_id_text}, Link: {event_link_text}")
        
        success_message = (
            f"Successfully created event: \"{event_summary_text}\".\n"
            f"- Event ID: {event_id_text}\n"
            f"- Calendar ID: {calendar_id}\n"
            f"- Link to event: {event_link_text}\n"
            f"- Created at: {created_time_text}"
        )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=success_message)]
        )

    except HttpError as error:
        message = f"An API error occurred while creating event for user '{user_google_email}': {error}. This could be due to invalid event details (e.g., time format), insufficient permissions, or an issue with the Google Calendar API. You might need to re-authenticate using 'start_auth' (ensure you provide the user_google_email)."
        logger.error(f"An API error occurred for user {user_google_email} creating event: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])
    except Exception as e:
        message = f"An unexpected error occurred while creating event for user '{user_google_email}': {e}."
        logger.exception(f"An unexpected error occurred while creating event for {user_google_email}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])