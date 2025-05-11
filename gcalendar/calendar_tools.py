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

# Configure module logger
logger = logging.getLogger(__name__)

# Import the server directly (will be initialized before this module is imported)
from core.server import server, OAUTH_REDIRECT_URI

# Define Google Calendar API Scopes
CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"
CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events"
USERINFO_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email"
OPENID_SCOPE = "openid"

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

async def _initiate_auth_and_get_message(user_id: str, scopes: List[str]) -> types.CallToolResult:
    """
    Initiates the Google OAuth flow and returns a message for the user.
    Uses the MCP server's OAuth resource endpoint for callback handling.
    Returns a CallToolResult with appropriate content types.
    """
    logger.info(f"Initiating auth for user '{user_id}' with scopes: {scopes}")

    try:
        logger.info(f"[_initiate_auth_and_get_message] For user '{user_id}', initiating auth flow with scopes: {scopes}")
 
        # Ensure OAUTHLIB_INSECURE_TRANSPORT is set
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ:
            logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
            
        # Set up the OAuth flow using the MCP server's callback endpoint
        from google_auth_oauthlib.flow import Flow
        flow = Flow.from_client_secrets_file(
            CONFIG_CLIENT_SECRETS_PATH,
            scopes=scopes,
            redirect_uri=CONFIG_REDIRECT_URI
        )
        
        # Generate the authorization URL with offline access and consent prompt
        auth_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent'
        )
        logger.info(f"Auth flow started for user '{user_id}'. State: {state}. Advise user to visit: {auth_url}")
        
        # Return MCP-formatted response with auth URL
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=f"ACTION REQUIRED for user '{user_id}':"
                ),
                types.LinkContent(
                    type="link",
                    url=auth_url,
                    display_text="Click here to authorize Google Calendar access"
                ),
                types.TextContent(
                    type="text",
                    text="After successful authorization, please RETRY your original command."
                )
            ]
        )
    except Exception as e:
        error_message = f"Could not initiate authentication for user '{user_id}'. {str(e)}"
        logger.error(f"Failed to start the OAuth flow: {e}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="auth_initialization_error",
                    message=error_message
                )
            ]
        )

# --- Tool Implementations ---

@server.tool()
async def start_auth(user_id: str) -> types.CallToolResult:
    """
    Starts the Google OAuth authentication process.
    The user will be prompted to visit a URL and then retry their command.
    This tool is useful for pre-authentication or if other tools fail due to auth.
    
    Args:
        user_id (str): The user identifier to authenticate
        
    Returns:
        A CallToolResult with LinkContent for authentication URL and TextContent for instructions
    """
    logger.info(f"Tool 'start_auth' invoked for user: {user_id}")
    # Define desired scopes for general authentication, including userinfo
    auth_scopes = list(set([
        CALENDAR_READONLY_SCOPE, # Default for viewing
        USERINFO_EMAIL_SCOPE,
        OPENID_SCOPE
    ]))
    return await _initiate_auth_and_get_message(user_id, auth_scopes)


@server.tool()
async def list_calendars(user_id: str) -> types.CallToolResult:
    """
    Lists the Google Calendars the user has access to.
    If not authenticated, prompts the user to authenticate and retry.
    
    Args:
        user_id (str): The user identifier to list calendars for
        
    Returns:
        A CallToolResult with either JsonContent containing calendars or ErrorContent
    """
    logger.info(f"[list_calendars] Tool invoked for user: {user_id}") # ADDED LOG
    required_scopes = [CALENDAR_READONLY_SCOPE]
    
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
        logger.info(f"[list_calendars] Attempting to get_credentials for user_id: '{user_id}' with scopes: {required_scopes}") # ADDED LOG
        credentials = await asyncio.to_thread(
            get_credentials,
            user_id,
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH # Use config
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="credential_error",
                    message=f"Failed to get credentials: {e}. You might need to authenticate using the 'start_auth' tool."
                )
            ]
        )

    if not credentials or not credentials.valid:
        logger.warning(f"[list_calendars] Missing or invalid credentials for user '{user_id}'. Initiating auth with scopes: {required_scopes}") # MODIFIED LOG
        return await _initiate_auth_and_get_message(user_id, required_scopes)

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        calendar_list = await asyncio.to_thread(service.calendarList().list().execute)
        items = calendar_list.get('items', [])

        calendars = []
        for calendar in items:
            calendars.append({
                "id": calendar['id'],
                "summary": calendar.get('summary', 'No Summary'),
                "description": calendar.get('description', ''),
                "primary": calendar.get('primary', False),
                "accessRole": calendar.get('accessRole', '')
            })
            
        logger.info(f"Successfully listed {len(items)} calendars for user: {user_id}")
        
        return types.CallToolResult(
            content=[
                types.JsonContent(
                    type="json",
                    json={"calendars": calendars}
                )
            ]
        )

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} listing calendars: {error}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="api_error",
                    message=f"An API error occurred: {error}. You might need to re-authenticate using 'start_auth'."
                )
            ]
        )
    except Exception as e:
        logger.exception(f"An unexpected error occurred while listing calendars for {user_id}: {e}")
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="unexpected_error",
                    message=f"An unexpected error occurred: {e}"
                )
            ]
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
        A CallToolResult with either JsonContent containing events or ErrorContent
    """
    logger.info(f"[get_events] Tool invoked for user: {user_id}, calendar: {calendar_id}") # ADDED LOG
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
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="credential_error",
                    message=f"Failed to get credentials: {e}. You might need to authenticate using the 'start_auth' tool."
                )
            ]
        )

    if not credentials or not credentials.valid:
        logger.warning(f"[get_events] Missing or invalid credentials for user '{user_id}'. Initiating auth with scopes: {required_scopes}") # MODIFIED LOG
        return await _initiate_auth_and_get_message(user_id, required_scopes)

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        if time_min is None:
            now = datetime.datetime.utcnow().isoformat() + 'Z'
            time_min = now
            logger.info(f"Defaulting time_min to current time: {time_min}")

        events_result = await asyncio.to_thread(
            service.events().list(
                calendarId=calendar_id,
                timeMin=time_min,
                timeMax=time_max,
                maxResults=max_results,
                singleEvents=True,
                orderBy='startTime'
            ).execute
        )
        events = events_result.get('items', [])

        parsed_events = []
        for event in events:
            parsed_events.append({
                "id": event['id'],
                "summary": event.get('summary', 'No Title'),
                "start": event['start'].get('dateTime', event['start'].get('date')),
                "end": event['end'].get('dateTime', event['end'].get('date')),
                "location": event.get('location', ''),
                "description": event.get('description', ''),
                "htmlLink": event.get('htmlLink', '')
            })
            
        logger.info(f"Successfully retrieved {len(events)} events for user: {user_id}, calendar: {calendar_id}")
        
        return types.CallToolResult(
            content=[
                types.JsonContent(
                    type="json",
                    json={
                        "calendar_id": calendar_id,
                        "events": parsed_events,
                        "event_count": len(parsed_events)
                    }
                )
            ]
        )

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} getting events: {error}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="api_error",
                    message=f"An API error occurred while fetching events: {error}. You might need to re-authenticate using 'start_auth'."
                )
            ]
        )
    except Exception as e:
        logger.exception(f"An unexpected error occurred while getting events for {user_id}: {e}")
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="unexpected_error",
                    message=f"An unexpected error occurred: {e}"
                )
            ]
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
        A CallToolResult with either JsonContent containing created event details or ErrorContent
    """
    logger.info(f"Attempting to create event for user: {user_id}, calendar: {calendar_id}")
    required_scopes = [CALENDAR_EVENTS_SCOPE] # Write scope needed

    try:
        credentials = await asyncio.to_thread(
            get_credentials,
            user_id,
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH # Use config
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="credential_error",
                    message=f"Failed to get credentials: {e}. You might need to authenticate using the 'start_auth' tool."
                )
            ]
        )

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user '{user_id}' for create_event. Initiating auth.")
        return await _initiate_auth_and_get_message(user_id, required_scopes)

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        event_body = {
            'summary': summary,
            'start': {'dateTime': start_time},
            'end': {'dateTime': end_time},
        }
        if location:
            event_body['location'] = location
        if description:
            event_body['description'] = description
        if timezone: # Apply timezone to start and end if provided
            event_body['start']['timeZone'] = timezone
            event_body['end']['timeZone'] = timezone
        if attendees:
            event_body['attendees'] = [{'email': email} for email in attendees]

        logger.debug(f"Creating event with body: {event_body}")

        created_event = await asyncio.to_thread(
            service.events().insert(
                calendarId=calendar_id,
                body=event_body
            ).execute
        )

        logger.info(f"Successfully created event for user: {user_id}, event ID: {created_event['id']}")
        
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=f"Successfully created event '{created_event.get('summary', '')}'"
                ),
                types.JsonContent(
                    type="json",
                    json={
                        "event_id": created_event['id'],
                        "html_link": created_event.get('htmlLink', ''),
                        "summary": created_event.get('summary', ''),
                        "calendar_id": calendar_id,
                        "created": created_event.get('created', '')
                    }
                )
            ]
        )

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} creating event: {error}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="api_error",
                    message=f"An API error occurred while creating the event: {error}. You might need to re-authenticate using 'start_auth'."
                )
            ]
        )
    except Exception as e:
        logger.exception(f"An unexpected error occurred while creating event for {user_id}: {e}")
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="unexpected_error",
                    message=f"An unexpected error occurred: {e}"
                )
            ]
        )