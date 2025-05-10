import logging
import os
import sys
from typing import Dict

# Explicitly try both import paths for FastMCP
try:
    # Try the standard import path first
    from mcp.server.fastmcp import FastMCP
except ImportError:
    try:
        # Fall back to the alternative import path
        from fastmcp import FastMCP
    except ImportError:
        logger.error("Could not import FastMCP. Please ensure 'mcp[cli]' and 'fastmcp' are installed.")
        sys.exit(1)

from google.auth.exceptions import RefreshError
from auth.google_auth import handle_auth_callback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Required OAuth scopes
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/calendar.readonly',
    'https://www.googleapis.com/auth/calendar.events' # Added events scope as create_event needs it
]

# Basic MCP server instance
server = FastMCP(name="google_workspace")

# Define OAuth callback as a tool (already registered via decorator)
@server.tool("oauth2callback")
async def oauth2callback(code: str = None, state: str = None, redirect_uri: str = "http://localhost:8080/callback") -> Dict:
    """
    Handle OAuth2 callback from Google - for integration with external servers.

    Most users should use the complete_auth tool instead.
    
    Args:
        code (str, optional): Authorization code from OAuth callback
        state (str, optional): State parameter from OAuth callback
        redirect_uri (str, optional): Redirect URI for OAuth callback

    Returns:
        A JSON envelope with:
        - status: "ok" or "error"
        - data: Contains user_id if status is "ok"
        - error: Error details if status is "error"
    """
    if not code:
        logger.error("Authorization code not found in callback request.")
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "missing_code",
                "message": "Authorization code not found"
            }
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
            scopes=SCOPES, # Use updated SCOPES
            authorization_response=full_callback_url,
            redirect_uri=redirect_uri
        )

        logger.info(f"Successfully exchanged code for credentials for user: {user_id}")
        return {
            "status": "ok",
            "data": {
                "user_id": user_id,
                "message": f"Authentication successful for user: {user_id}"
            },
            "error": None
        }
    except RefreshError as e:
        logger.error(f"Failed to exchange authorization code for tokens: {e}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "refresh_error",
                "message": f"Could not exchange authorization code for tokens: {str(e)}"
            }
        }
    except Exception as e:
        logger.error(f"An unexpected error occurred during OAuth callback: {e}", exc_info=True)
        return {
            "status": "error",
            "data": None,
            "error": {
                "type": "unexpected_error",
                "message": f"An unexpected error occurred: {str(e)}"
            }
        }