"""
Google Calendar MCP Tools

This module provides MCP tools for interacting with Google Calendar API.
"""
import datetime
import logging
import asyncio
import sys
from typing import List, Optional

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from auth.google_auth import get_credentials, start_auth_flow, handle_auth_callback
from auth.oauth_manager import start_oauth_flow, check_auth_status, stop_oauth_flow

# Configure module logger
logger = logging.getLogger(__name__)

# Import the server directly (will be initialized before this module is imported)
from core.server import server

# Define Google Calendar API Scopes
CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"
CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Tool Implementations ---

@server.tool() # Added decorator
async def start_auth(user_id: str) -> str:
    """
    Start the Google OAuth authentication process with automatic callback handling.

    This tool provides a smoother authentication experience by automatically
    opening a browser window and handling the callback process.

    Args:
        user_id: The unique identifier (e.g., email address) for the user.

    Returns:
        Instructions for completing the authentication.
    """
    logger.info(f"Starting OAuth authentication flow for user: {user_id}")

    # Use the Calendar readonly scope by default
    # Request calendar scope, user email scope, AND openid scope
    scopes = [CALENDAR_READONLY_SCOPE, "https://www.googleapis.com/auth/userinfo.email", "openid"]

    try:
        # Start the OAuth flow with automatic callback handling
        # Run synchronous function in a thread
        result = await asyncio.to_thread(start_oauth_flow, user_id, scopes)
        return result
    except Exception as e:
        logger.error(f"Error starting authentication flow: {e}")
        return f"Failed to start authentication: {e}"

@server.tool() # Added decorator
async def auth_status(user_id: str) -> str:
    """
    Check the status of an ongoing authentication process.

    Args:
        user_id: The unique identifier (e.g., email address) for the user.

    Returns:
        A status message about the authentication process.
    """
    logger.info(f"Checking authentication status for user: {user_id}")

    try:
        # Check current status
        # Run synchronous function in a thread
        result = await asyncio.to_thread(check_auth_status, user_id)
        return result
    except Exception as e:
        logger.error(f"Error checking authentication status: {e}")
        return f"Failed to check authentication status: {e}"

@server.tool() # Added decorator
async def complete_auth(user_id: str, authorization_code: str) -> str:
    """
    Completes the OAuth flow by exchanging the authorization code for credentials.

    Args:
        user_id: The unique identifier (e.g., email address) for the user.
        authorization_code: The authorization code received from Google OAuth.

    Returns:
        A string indicating success or failure.
    """
    logger.info(f"Attempting to complete authentication for user: {user_id}")

    try:
        # Get the scopes used during the initial auth request
        scopes = [CALENDAR_READONLY_SCOPE]  # Default to readonly scope

        # Construct the full callback URL
        redirect_uri = "http://localhost:8080/callback"
        full_callback_url = f"{redirect_uri}?code={authorization_code}"

        # Use handle_auth_callback to exchange the code for credentials
        # Run synchronous function in a thread
        user_email, credentials = await asyncio.to_thread(
            handle_auth_callback,
            client_secrets_path='client_secret.json',
            scopes=scopes,
            authorization_response=full_callback_url,
            redirect_uri=redirect_uri
        )

        # Verify the user_id matches the authenticated email
        if user_email.lower() != user_id.lower():
            logger.warning(f"User ID mismatch: provided {user_id}, authenticated as {user_email}")
            return (f"Warning: You authenticated as {user_email}, but requested credentials for {user_id}. "
                   f"Using authenticated email {user_email} for credentials.")

        logger.info(f"Successfully completed authentication for user: {user_email}")
        return f"Authentication successful! You can now use the Google Calendar tools with user: {user_email}"

    except Exception as e:
        logger.error(f"Error completing authentication: {e}", exc_info=True)
        return f"Failed to complete authentication: {e}"

@server.tool() # Added decorator
async def list_calendars(user_id: str) -> str:
    """
    Lists the Google Calendars the user has access to.

    Args:
        user_id: The unique identifier (e.g., email address) for the user.

    Returns:
        A string listing the calendars or an authentication prompt.
    """
    logger.info(f"Attempting to list calendars for user: {user_id}")
    scopes = [CALENDAR_READONLY_SCOPE]
    logger.debug(f"Calling get_credentials with user_id: {user_id}, scopes: {scopes}")
    try:
        # Run synchronous function in a thread
        credentials = await asyncio.to_thread(get_credentials, user_id, scopes, client_secrets_path='client_secret.json')
        logger.debug(f"get_credentials returned: {credentials}")
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return f"Failed to get credentials: {e}"

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user: {user_id}")
        try:
            # Use the automatic flow for better user experience
            # Run synchronous function in a thread
            result = await asyncio.to_thread(start_oauth_flow, user_id, scopes)
            return result
        except Exception as e:
            logger.error(f"Failed to start auth flow: {e}")
            return f"Failed to start authentication flow: {e}"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        calendar_list = service.calendarList().list().execute()
        items = calendar_list.get('items', [])

        if not items:
            return "You don't seem to have access to any calendars."

        output = "Here are the calendars you have access to:\n"
        for calendar in items:
            summary = calendar.get('summary', 'No Summary')
            cal_id = calendar['id']
            output += f"- {summary} (ID: {cal_id})\n"
        logger.info(f"Successfully listed {len(items)} calendars for user: {user_id}")
        return output.strip()

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id}: {error}")
        # TODO: Check error details for specific auth issues (e.g., revoked token)
        return f"An API error occurred: {error}. You might need to re-authenticate."
    except Exception as e:
        logger.exception(f"An unexpected error occurred while listing calendars for {user_id}: {e}")
        return f"An unexpected error occurred: {e}"

@server.tool() # Added decorator
async def get_events(
    user_id: str,
    calendar_id: str = 'primary',
    time_min: Optional[str] = None,
    time_max: Optional[str] = None,
    max_results: int = 25,
) -> str:
    """
    Lists events from a specified Google Calendar within a given time range.

    Args:
        user_id: The unique identifier (e.g., email address) for the user.
        calendar_id: The ID of the calendar to fetch events from. Defaults to 'primary'.
        time_min: The start time for the event query (RFC3339 format, e.g., '2025-04-27T10:00:00-04:00').
                  Defaults to the current time if not provided.
        time_max: The end time for the event query (RFC3339 format). Optional.
        max_results: The maximum number of events to return. Defaults to 25.

    Returns:
        A string listing the events or an authentication prompt.
    """
    logger.info(f"Attempting to get events for user: {user_id}, calendar: {calendar_id}")
    scopes = [CALENDAR_READONLY_SCOPE]
    try:
        # Run synchronous function in a thread
        credentials = await asyncio.to_thread(get_credentials, user_id, scopes, client_secrets_path='client_secret.json')
        logger.debug(f"get_credentials returned: {credentials}")

        if not credentials or not credentials.valid:
            logger.warning(f"Missing or invalid credentials for user: {user_id}")
            try:
                # Use the automatic flow for better user experience
                # Run synchronous function in a thread
                result = await asyncio.to_thread(start_oauth_flow, user_id, scopes)
                return result
            except Exception as e:
                logger.error(f"Failed to start auth flow: {e}")
                return f"Failed to start authentication flow: {e}"
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return f"Failed to get credentials: {e}"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        # Set default time_min to now if not provided
        if time_min is None:
            now = datetime.datetime.utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time
            time_min = now
            logger.info(f"Defaulting time_min to current time: {time_min}")

        events_result = service.events().list(
            calendarId=calendar_id,
            timeMin=time_min,
            timeMax=time_max,
            maxResults=max_results,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        events = events_result.get('items', [])

        if not events:
            return f"No upcoming events found in calendar '{calendar_id}'."

        output = f"Here are the upcoming events for calendar '{calendar_id}':\n"
        for event in events:
            start = event['start'].get('dateTime', event['start'].get('date'))
            end = event['end'].get('dateTime', event['end'].get('date'))
            summary = event.get('summary', 'No Title')
            event_id = event['id']
            location = event.get('location', 'N/A')
            output += f"- {summary} (ID: {event_id})\n"
            output += f"  Start: {start}\n"
            output += f"  End:   {end}\n"
            output += f"  Location: {location}\n"

        logger.info(f"Successfully retrieved {len(events)} events for user: {user_id}, calendar: {calendar_id}")
        return output.strip()

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} getting events: {error}")
        # TODO: Check error details for specific auth issues
        return f"An API error occurred while fetching events: {error}. You might need to re-authenticate."
    except Exception as e:
        logger.exception(f"An unexpected error occurred while getting events for {user_id}: {e}")
        return f"An unexpected error occurred: {e}"


@server.tool() # Added decorator
async def create_event(
    user_id: str,
    summary: str,
    start_time: str,
    end_time: str,
    calendar_id: str = 'primary',
    description: Optional[str] = None,
    location: Optional[str] = None,
    attendees: Optional[List[str]] = None,
    timezone: Optional[str] = None, # e.g., "America/New_York"
) -> str:
    """
    Creates a new event in a specified Google Calendar.

    Args:
        user_id: The unique identifier (e.g., email address) for the user.
        summary: The title of the event.
        start_time: The start time of the event (RFC3339 format, e.g., '2025-04-28T10:00:00-04:00').
        end_time: The end time of the event (RFC3339 format, e.g., '2025-04-28T11:00:00-04:00').
        calendar_id: The ID of the calendar to create the event in. Defaults to 'primary'.
        description: An optional description for the event.
        location: An optional location for the event.
        attendees: An optional list of email addresses for attendees.
        timezone: The timezone for the event start/end times (e.g., "America/New_York").
                  If not provided, the calendar's default timezone might be used.

    Returns:
        A confirmation message or an authentication prompt.
    """
    logger.info(f"Attempting to create event for user: {user_id}, calendar: {calendar_id}")
    # Request write scope for creating events
    scopes = [CALENDAR_EVENTS_SCOPE]
    try:
        # Run synchronous function in a thread
        credentials = await asyncio.to_thread(get_credentials, user_id, scopes, client_secrets_path='client_secret.json')
        logger.debug(f"get_credentials returned: {credentials}")

        if not credentials or not credentials.valid:
            logger.warning(f"Missing or invalid credentials for user: {user_id}")
            try:
                # Use the automatic flow for better user experience
                # Run synchronous function in a thread
                result = await asyncio.to_thread(start_oauth_flow, user_id, scopes)
                return result
            except Exception as e:
                logger.error(f"Failed to start auth flow: {e}")
                return f"Failed to start authentication flow: {e}"
    except Exception as e:
        logger.error(f"Error getting credentials: {e}")
        return f"Failed to get credentials: {e}"

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id}")

        event_body = {
            'summary': summary,
            'location': location,
            'description': description,
            'start': {'dateTime': start_time, 'timeZone': timezone},
            'end': {'dateTime': end_time, 'timeZone': timezone},
            'attendees': [{'email': email} for email in attendees] if attendees else [],
        }
        # Remove None values from the event body
        event_body = {k: v for k, v in event_body.items() if v is not None}
        if 'attendees' in event_body and not event_body['attendees']:
            del event_body['attendees'] # Don't send empty attendees list

        logger.debug(f"Creating event with body: {event_body}")

        created_event = service.events().insert(
            calendarId=calendar_id,
            body=event_body
        ).execute()

        event_link = created_event.get('htmlLink')
        logger.info(f"Successfully created event for user: {user_id}, event ID: {created_event['id']}")
        return f"Event created successfully! View it here: {event_link}"

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} creating event: {error}")
        # TODO: Check error details for specific auth issues
        return f"An API error occurred while creating the event: {error}. You might need to re-authenticate."
    except Exception as e:
        logger.exception(f"An unexpected error occurred while creating event for {user_id}: {e}")
        return f"An unexpected error occurred: {e}"