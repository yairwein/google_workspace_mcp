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

# Import tool modules to register them
from gcalendar.calendar_tools import *

# Define OAuth callback as a tool
@server.tool("oauth2callback")
async def oauth2callback(code: str = None, state: str = None):
    """Handle OAuth2 callback from Google"""
    if not code:
        logger.error("Authorization code not found in callback request.")
        return {
            "success": False,
            "error": "Authorization code not found"
        }

    try:
        client_secrets_path = os.path.join(os.path.dirname(__file__), '..', 'client_secret.json')
        
        # Exchange code for credentials
        user_id, credentials = handle_auth_callback(
            client_secrets_path=client_secrets_path,
            scopes=SCOPES,
            authorization_response=code  # Pass the code directly
        )
        
        logger.info(f"Successfully exchanged code for credentials for user: {user_id}")
        return {
            "success": True,
            "message": "Authentication successful"
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