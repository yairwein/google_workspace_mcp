"""
Google Calendar MCP Tools

This module provides MCP tools for interacting with Google Calendar API.
"""
import datetime
import logging
import asyncio
import os
import sys
from typing import List, Optional, Dict

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Use functions directly from google_auth
from auth.google_auth import get_credentials, start_auth_flow, handle_auth_callback

# Configure module logger
logger = logging.getLogger(__name__)

# Import the server directly (will be initialized before this module is imported)
from core.server import server

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
    # Default to client_secret.json in the same directory as this script (gcalendar_tools.py)
    _current_dir = os.path.dirname(os.path.abspath(__file__))
    CONFIG_CLIENT_SECRETS_PATH = os.path.join(_current_dir, "client_secret.json")

CONFIG_PORT = int(os.getenv("OAUTH_CALLBACK_PORT", 8080))
CONFIG_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", f"http://localhost:{CONFIG_PORT}/callback")
# ---

async def _initiate_auth_and_get_message(user_id: str, scopes: List[str]) -> Dict:
    """
    Initiates the Google OAuth flow and returns a message for the user.
    Handles the callback internally to exchange the code for tokens.
    Returns a standard envelope with status and data/error.
    """
    logger.info(f"Initiating auth for user '{user_id}' with scopes: {scopes}")

    # This inner function is called by OAuthCallbackServer (via start_auth_flow) with code and state
    def _handle_redirect_for_token_exchange(received_code: str, received_state: str):
        # This function runs in the OAuthCallbackServer's thread.
        # It needs access to user_id, scopes, CONFIG_CLIENT_SECRETS_PATH, CONFIG_REDIRECT_URI
        # These are available via closure from the _initiate_auth_and_get_message call.
        current_user_id_for_flow = user_id # Capture user_id for this specific flow instance
        flow_scopes = scopes # Capture scopes for this specific flow instance

        logger.info(f"OAuth callback received for user '{current_user_id_for_flow}', state '{received_state}'. Exchanging code.")
        try:
            full_auth_response_url = f"{CONFIG_REDIRECT_URI}?code={received_code}&state={received_state}"

            authenticated_user_email, credentials = handle_auth_callback(
                client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
                scopes=flow_scopes, # Crucial: these must be the scopes used for auth_url generation
                authorization_response=full_auth_response_url,
                redirect_uri=CONFIG_REDIRECT_URI
            )
            # Credentials are saved by handle_auth_callback under the email
            # Update our reference to use the email as user_id for consistency
            if current_user_id_for_flow == 'default':
                current_user_id_for_flow = authenticated_user_email
                logger.info(f"Updated user_id from 'default' to {authenticated_user_email}")
            
            logger.info(f"Successfully exchanged token and saved credentials for {authenticated_user_email} (flow initiated for '{current_user_id_for_flow}').")

        except Exception as e:
            logger.error(f"Error during token exchange for user '{current_user_id_for_flow}', state '{received_state}': {e}", exc_info=True)
            # Optionally, could signal error if a wait mechanism was in place.

    try:
        # Ensure the callback function uses the specific user_id and scopes for *this* auth attempt
        # by defining it within this scope or ensuring it has access to them.
        # The current closure approach for _handle_redirect_for_token_exchange handles this.

        auth_url, state = await asyncio.to_thread(
            start_auth_flow, # This is now the function from auth.google_auth
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
            scopes=scopes,
            redirect_uri=CONFIG_REDIRECT_URI,
            auto_handle_callback=True, # Server starts, browser opens
            callback_function=_handle_redirect_for_token_exchange, # Receives (code, state)
            port=CONFIG_PORT
        )
        logger.info(f"Auth flow started for user '{user_id}'. State: {state}. Advise user to visit: {auth_url}")

        message = (
            f"ACTION REQUIRED for user '{user_id}':\n"
            f"1. Please visit this URL to authorize access: {auth_url}\n"
            f"2. A browser window should open automatically. Complete the authorization.\n"
            f"3. After successful authorization, please **RETRY** your original command.\n\n"
            f"(OAuth callback server is listening on port {CONFIG_PORT} for the redirect)."
        )
        
        return {
            "status": "ok",
            "data": {
                "auth_required": True,
                "auth_url": auth_url,
                "message": message
            },
            "error": None
        }
    except Exception as e:
        error_message = f"Could not initiate authentication for user '{user_id}'. {str(e)}"
        logger.error(f"Failed to start the OAuth flow: {e}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "auth_initialization_error",
                "message": error_message
            }
        }

# --- Tool Implementations ---

@server.tool()
async def start_auth(user_id: str) -> Dict:
    """
    Starts the Google OAuth authentication process.
    The user will be prompted to visit a URL and then retry their command.
    This tool is useful for pre-authentication or if other tools fail due to auth.
    
    Args:
        user_id (str): The user identifier to authenticate
        
    Returns:
        A JSON envelope with:
        - status: "ok" or "error"
        - data: Contains auth_required (bool), auth_url, and message if status is "ok"
        - error: Error details if status is "error"
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
async def list_calendars(user_id: str) -> Dict:
    """
    Lists the Google Calendars the user has access to.
    If not authenticated, prompts the user to authenticate and retry.
    
    Args:
        user_id (str): The user identifier to list calendars for
        
    Returns:
        A JSON envelope with:
        - status: "ok" or "error"
        - data: Contains calendars list if status is "ok"
        - error: Error details if status is "error"
    """
    logger.info(f"Attempting to list calendars for user: {user_id}")
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
        credentials = await asyncio.to_thread(
            get_credentials,
            user_id,
            required_scopes,
            client_secrets_path=CONFIG_CLIENT_SECRETS_PATH # Use config
        )
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        logger.error(f"Error getting credentials for {user_id}: {e}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "credential_error",
                "message": f"Failed to get credentials: {e}. You might need to authenticate using the 'start_auth' tool."
            }
        }

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user '{user_id}' for list_calendars. Initiating auth.")
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
        
        return {
            "status": "ok",
            "data": {
                "calendars": calendars
            },
            "error": None
        }

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} listing calendars: {error}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "api_error",
                "message": f"An API error occurred: {error}. You might need to re-authenticate using 'start_auth'."
            }
        }
    except Exception as e:
        logger.exception(f"An unexpected error occurred while listing calendars for {user_id}: {e}")
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "unexpected_error",
                "message": f"An unexpected error occurred: {e}"
            }
        }

@server.tool()
async def get_events(
    user_id: str,
    calendar_id: str = 'primary',
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
    max_results: int = 25,
) -> Dict:
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
        A JSON envelope with:
        - status: "ok" or "error"
        - data: Contains events list if status is "ok"
        - error: Error details if status is "error"
    """
    logger.info(f"Attempting to get events for user: {user_id}, calendar: {calendar_id}")
    required_scopes = [CALENDAR_READONLY_SCOPE]

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
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "credential_error",
                "message": f"Failed to get credentials: {e}. You might need to authenticate using the 'start_auth' tool."
            }
        }

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user '{user_id}' for get_events. Initiating auth.")
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
        
        return {
            "status": "ok",
            "data": {
                "calendar_id": calendar_id,
                "events": parsed_events,
                "event_count": len(parsed_events)
            },
            "error": None
        }

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} getting events: {error}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "api_error",
                "message": f"An API error occurred while fetching events: {error}. You might need to re-authenticate using 'start_auth'."
            }
        }
    except Exception as e:
        logger.exception(f"An unexpected error occurred while getting events for {user_id}: {e}")
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "unexpected_error",
                "message": f"An unexpected error occurred: {e}"
            }
        }


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
) -> Dict:
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
        A JSON envelope with:
        - status: "ok" or "error"
        - data: Contains created event details if status is "ok"
        - error: Error details if status is "error"
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
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "credential_error",
                "message": f"Failed to get credentials: {e}. You might need to authenticate using the 'start_auth' tool."
            }
        }

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
        
        return {
            "status": "ok",
            "data": {
                "event_id": created_event['id'],
                "html_link": created_event.get('htmlLink', ''),
                "summary": created_event.get('summary', ''),
                "calendar_id": calendar_id,
                "created": created_event.get('created', '')
            },
            "error": None
        }

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} creating event: {error}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "api_error",
                "message": f"An API error occurred while creating the event: {error}. You might need to re-authenticate using 'start_auth'."
            }
        }
    except Exception as e:
        logger.exception(f"An unexpected error occurred while creating event for {user_id}: {e}")
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "unexpected_error",
                "message": f"An unexpected error occurred: {e}"
            }
        }