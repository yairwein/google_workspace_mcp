import logging
import os
import sys
from typing import Dict, Any

from fastapi import Request
from fastapi.responses import HTMLResponse

# Import MCP types for proper response formatting
from mcp import types

from mcp.server.fastmcp import FastMCP

from google.auth.exceptions import RefreshError
from auth.google_auth import handle_auth_callback, load_client_secrets
from auth.auth_session_manager import auth_session_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Individual OAuth Scope Constants
USERINFO_EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'
OPENID_SCOPE = 'openid'
CALENDAR_READONLY_SCOPE = 'https://www.googleapis.com/auth/calendar.readonly'
CALENDAR_EVENTS_SCOPE = 'https://www.googleapis.com/auth/calendar.events'

# Base OAuth scopes required for user identification
BASE_SCOPES = [
    USERINFO_EMAIL_SCOPE,
    OPENID_SCOPE
]

# Calendar-specific scopes
CALENDAR_SCOPES = [
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE
]

# Combined scopes for calendar operations
SCOPES = BASE_SCOPES + CALENDAR_SCOPES

DEFAULT_PORT = 8000
# Basic MCP server instance
server = FastMCP(
    name="google_workspace",
    server_url=f"http://localhost:{DEFAULT_PORT}/gworkspace",  # Add absolute URL for Gemini native function calling
    host="0.0.0.0",      # Listen on all interfaces
    port=DEFAULT_PORT,   # Default port for HTTP server
    stateless_http=False # Enable stateful sessions (default)
)

# Configure OAuth redirect URI to use the MCP server's port
OAUTH_REDIRECT_URI = f"http://localhost:{DEFAULT_PORT}/oauth2callback"

# Register OAuth callback as a custom route
@server.custom_route("/oauth2callback", methods=["GET"])
async def oauth2_callback(request: Request) -> HTMLResponse:
    """
    Handle OAuth2 callback from Google via a custom route.
    Updates the AuthSessionManager with the result.
    """
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if not state:
        logger.error("OAuth callback missing 'state' parameter.")
        # Cannot update session manager without state
        return HTMLResponse(content="Authentication Error: Critical 'state' parameter missing from callback.", status_code=400)

    if error:
        error_message = f"OAuth provider returned an error: {error}"
        logger.error(f"OAuth callback error for state '{state}': {error_message}")
        auth_session_manager.fail_session(state, error_message)
        return HTMLResponse(content=f"""
            <html><head><title>Authentication Error</title></head>
            <body><h2>Authentication Error</h2><p>{error_message}</p><p>You can close this window.</p></body></html>
        """, status_code=400)

    if not code:
        error_message = "Missing authorization code in OAuth callback."
        logger.error(f"OAuth callback error for state '{state}': {error_message}")
        auth_session_manager.fail_session(state, error_message)
        return HTMLResponse(content=f"""
            <html><head><title>Authentication Error</title></head>
            <body><h2>Authentication Error</h2><p>{error_message}</p><p>You can close this window.</p></body></html>
        """, status_code=400)

    try:
        client_secrets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'client_secret.json')
        if not os.path.exists(client_secrets_path):
            logger.error(f"Client secrets file not found at {client_secrets_path}")
            raise FileNotFoundError("Client secrets configuration is missing.")

        logger.info(f"OAuth callback for state '{state}': Received code. Attempting to exchange for tokens.")
        
        # Exchange code for credentials using full scopes
        user_id, credentials = handle_auth_callback(
            client_secrets_path=client_secrets_path,
            scopes=SCOPES,
            authorization_response=str(request.url), # handle_auth_callback expects the full URL
            redirect_uri=OAUTH_REDIRECT_URI # This should match what was used to generate auth_url
        )
        
        logger.info(f"Successfully exchanged code for credentials for state '{state}'. User ID: {user_id}")
        auth_session_manager.complete_session(state, user_id)
        
        # Return success page to the user
        return HTMLResponse(content="""
            <html>
            <head>
                <title>Authentication Successful</title>
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 500px; margin: 40px auto; padding: 20px; text-align: center; color: #333; }
                    .status { color: #4CAF50; font-size: 24px; margin-bottom: 20px; }
                    .message { margin-bottom: 30px; line-height: 1.5; }
                    .button { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
                </style>
                <script> setTimeout(function() { window.close(); }, 5000); </script>
            </head>
            <body>
                <div class="status">Authentication Successful</div>
                <div class="message">You have successfully authenticated. You can now close this window and return to your application.</div>
                <button class="button" onclick="window.close()">Close Window</button>
            </body>
            </html>
        """)
        
    except Exception as e:
        error_message_detail = f"Error processing OAuth callback for state '{state}': {str(e)}"
        logger.error(error_message_detail, exc_info=True)
        auth_session_manager.fail_session(state, error_message_detail)
        return HTMLResponse(content=f"""
            <html>
            <head><title>Authentication Error</title></head>
            <body>
                <h2 style="color: #d32f2f;">Authentication Processing Error</h2>
                <p>An error occurred while processing your authentication: {str(e)}</p>
                <p>You can close this window and try again.</p>
            </body>
            </html>
        """, status_code=500)

# Define OAuth callback as a tool (already registered via decorator)
@server.tool("oauth2callback")
async def oauth2callback(code: str = None, state: str = None, redirect_uri: str = f"http://localhost:{DEFAULT_PORT}/oauth2callback") -> types.CallToolResult:
    """
    Handle OAuth2 callback from Google - for integration with external servers.
    
    Args:
        code (str, optional): Authorization code from OAuth callback
        state (str, optional): State parameter from OAuth callback
        redirect_uri (str, optional): Redirect URI for OAuth callback

    Returns:
        A CallToolResult with TextContent indicating success or failure of the callback processing.
    """
    if not state:
        message = "OAuth callback tool error: 'state' parameter is missing. Cannot process this callback."
        logger.error(message)
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    if not code:
        message = f"OAuth callback tool error for state '{state}': Authorization code not found in callback request."
        logger.error(message)
        auth_session_manager.fail_session(state, "Authorization code not provided to callback tool.")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=message)]
        )

    try:
        client_secrets_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'client_secret.json')
        if not os.path.exists(client_secrets_path):
            logger.error(f"Client secrets file not found at {client_secrets_path} for oauth2callback tool.")
            raise FileNotFoundError("Client secrets configuration is missing for oauth2callback tool.")

        # Construct full authorization response URL as expected by handle_auth_callback
        # The redirect_uri here should be the one this tool itself is "simulating" or was configured with.
        # It might differ from OAUTH_REDIRECT_URI if this tool is called by an external system with a different callback.
        full_callback_url = f"{redirect_uri}?code={code}&state={state}"
        
        logger.info(f"OAuth2Callback Tool: Processing for state '{state}'. Attempting to exchange code.")
        user_id, credentials = handle_auth_callback(
            client_secrets_path=client_secrets_path,
            scopes=SCOPES,
            authorization_response=full_callback_url, # Pass the constructed full URL
            redirect_uri=redirect_uri # The redirect_uri used in this specific flow
        )

        logger.info(f"OAuth2Callback Tool: Successfully exchanged code for state '{state}'. User ID: {user_id}")
        auth_session_manager.complete_session(state, user_id)
        
        success_message = f"OAuth callback processed successfully for session '{state}'. User identified as: {user_id}. You can now use 'get_auth_result' with this session ID if needed, or proceed with operations requiring this user_id."
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text=success_message)
            ]
        )
    except RefreshError as e:
        error_message = f"OAuth callback tool error for state '{state}': Could not exchange authorization code for tokens. {str(e)}"
        logger.error(error_message, exc_info=True)
        auth_session_manager.fail_session(state, f"Token refresh/exchange error: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=error_message)]
        )
    except Exception as e:
        error_message = f"OAuth callback tool error for state '{state}': An unexpected error occurred. {str(e)}"
        logger.error(error_message, exc_info=True)
        auth_session_manager.fail_session(state, f"Unexpected callback processing error: {e}")
        return types.CallToolResult(
            isError=True,
            content=[types.TextContent(type="text", text=error_message)]
        )