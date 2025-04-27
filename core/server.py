import logging
import os
from fastmcp import FastMCP
from google.auth.exceptions import RefreshError
from auth.google_auth import handle_auth_callback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Required OAuth scopes
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/calendar.readonly'
]

# Basic MCP server instance
server = FastMCP(name="google_workspace")

# Import specific tool functions
from gcalendar.calendar_tools import (
    start_auth,
    auth_status,
    complete_auth,
    list_calendars,
    get_events,
    create_event
)

# Register calendar tools explicitly
# Assuming server.add_tool(function, name="tool_name") signature
# Using function name as tool name by default
server.add_tool(start_auth, name="start_auth")
server.add_tool(auth_status, name="auth_status")
server.add_tool(complete_auth, name="complete_auth")
server.add_tool(list_calendars, name="list_calendars")
server.add_tool(get_events, name="get_events")
server.add_tool(create_event, name="create_event")


# Define OAuth callback as a tool (already registered via decorator)
@server.tool("oauth2callback")
async def oauth2callback(code: str = None, state: str = None, redirect_uri: str = "http://localhost:8080/callback"):
    """
    Handle OAuth2 callback from Google - for integration with external servers.
    
    Most users should use the complete_auth tool instead.
    """
    if not code:
        logger.error("Authorization code not found in callback request.")
        return {
            "success": False,
            "error": "Authorization code not found"
        }

    try:
        client_secrets_path = os.path.join(os.path.dirname(__file__), '..', 'client_secret.json')
        
        # Construct full authorization response URL
        full_callback_url = f"{redirect_uri}?code={code}"
        if state:
            full_callback_url += f"&state={state}"
            
        # Exchange code for credentials
        user_id, credentials = handle_auth_callback(
            client_secrets_path=client_secrets_path,
            scopes=SCOPES,
            authorization_response=full_callback_url,
            redirect_uri=redirect_uri
        )
        
        logger.info(f"Successfully exchanged code for credentials for user: {user_id}")
        return {
            "success": True,
            "message": f"Authentication successful for user: {user_id}"
        }
    except RefreshError as e:
        logger.error(f"Failed to exchange authorization code for tokens: {e}", exc_info=True)
        return {
            "success": False,
            "error": f"Could not exchange authorization code for tokens: {str(e)}"
        }
    except Exception as e:
        logger.error(f"An unexpected error occurred during OAuth callback: {e}", exc_info=True)
        return {
            "success": False,
            "error": f"An unexpected error occurred: {str(e)}"
        }