# calendar/calendar_tools.py
import datetime
import logging
from typing import List, Optional

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from auth.google_auth import get_credentials, start_auth_flow
from core.server import server  # Import the MCP server instance

# Define Google Calendar API Scopes
CALENDAR_READONLY_SCOPE = "https://www.googleapis.com/auth/calendar.readonly"
CALENDAR_EVENTS_SCOPE = "https://www.googleapis.com/auth/calendar.events"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Tool Implementations will go here ---
@server.tool()
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
    credentials = await get_credentials(user_id, scopes)

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user: {user_id}")
        auth_url = await start_auth_flow(user_id, scopes)
        return (
            "Authentication required. Please visit this URL to authorize access: "
            f"{auth_url}\nThen, provide the authorization code using the "
            "'complete_auth' tool (implementation pending)."
        )

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
@server.tool()
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
    credentials = await get_credentials(user_id, scopes)

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user: {user_id}")
        auth_url = await start_auth_flow(user_id, scopes)
        return (
            "Authentication required. Please visit this URL to authorize access: "
            f"{auth_url}\nThen, provide the authorization code using the "
            "'complete_auth' tool (implementation pending)."
        )

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
    credentials = await get_credentials(user_id, scopes)

    if not credentials or not credentials.valid:
        logger.warning(f"Missing or invalid credentials for user: {user_id} (write access needed)")
        # Request the necessary write scope during auth flow
        auth_url = await start_auth_flow(user_id, scopes)
        return (
            "Authentication required for creating events. Please visit this URL to authorize access: "
            f"{auth_url}\nThen, provide the authorization code using the "
            "'complete_auth' tool (implementation pending)."
        )

    try:
        service = build('calendar', 'v3', credentials=credentials)
        logger.info(f"Successfully built calendar service for user: {user_id} (with write access)")

        event_body = {
            'summary': summary,
            'start': {'dateTime': start_time},
            'end': {'dateTime': end_time},
        }
        # Add optional fields if provided
        if description:
            event_body['description'] = description
        if location:
            event_body['location'] = location
        if attendees:
            event_body['attendees'] = [{'email': email} for email in attendees]
        if timezone:
            # Apply timezone to start and end times if provided
            event_body['start']['timeZone'] = timezone
            event_body['end']['timeZone'] = timezone

        logger.debug(f"Creating event with body: {event_body}")

        created_event = service.events().insert(
            calendarId=calendar_id,
            body=event_body
        ).execute()

        event_summary = created_event.get('summary', 'N/A')
        event_link = created_event.get('htmlLink', 'N/A')
        logger.info(f"Successfully created event '{event_summary}' for user: {user_id}")

        return (
            f"Successfully created event: '{event_summary}' in calendar '{calendar_id}'.\n"
            f"Link: {event_link}"
        )

    except HttpError as error:
        logger.error(f"An API error occurred for user {user_id} creating event: {error}")
        # TODO: Check error details for specific auth issues (e.g., insufficient permissions)
        return f"An API error occurred while creating the event: {error}. Ensure you have write permissions for this calendar."
    except Exception as e:
        logger.exception(f"An unexpected error occurred while creating event for {user_id}: {e}")
        return f"An unexpected error occurred: {e}"
        logger.exception(f"An unexpected error occurred while getting events for {user_id}: {e}")
        return f"An unexpected error occurred: {e}"