import logging
import os
import sys
from typing import Dict, Any, Optional

from fastapi import Request
from fastapi.responses import HTMLResponse

# Import MCP types for proper response formatting
from mcp import types

from mcp.server.fastmcp import FastMCP

from google.auth.exceptions import RefreshError
from auth.google_auth import handle_auth_callback, CONFIG_CLIENT_SECRETS_PATH # Import handle_auth_callback and CONFIG_CLIENT_SECRETS_PATH
# auth_session_manager is no longer used here with the simplified flow

# Import shared configuration
from config.google_config import (
    OAUTH_STATE_TO_SESSION_ID_MAP,
    USERINFO_EMAIL_SCOPE,
    OPENID_SCOPE,
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE,
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE,
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    BASE_SCOPES,
    CALENDAR_SCOPES,
    DRIVE_SCOPES,
    GMAIL_SCOPES,
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE,
    SCOPES
)

# Configure logging
logging.basicConfig(level=logging.INFO)
# OAUTH_STATE_TO_SESSION_ID_MAP is now imported from config.google_config
logger = logging.getLogger(__name__)

# Individual OAuth Scope Constants are now imported from config.google_config
# USERINFO_EMAIL_SCOPE = ...
# OPENID_SCOPE = ...
# CALENDAR_READONLY_SCOPE = ...
# CALENDAR_EVENTS_SCOPE = ...

# Google Drive scopes are now imported from config.google_config
# DRIVE_READONLY_SCOPE = ...
# DRIVE_METADATA_READONLY_SCOPE = ...
# DRIVE_FILE_SCOPE = ...

# Gmail API scopes are now imported from config.google_config
# GMAIL_READONLY_SCOPE   = ...
# GMAIL_SEND_SCOPE       = ...
# GMAIL_LABELS_SCOPE     = ...

# Base OAuth scopes required for user identification are now imported from config.google_config
# BASE_SCOPES = [...]

# Calendar-specific scopes are now imported from config.google_config
# CALENDAR_SCOPES = [...]

# Drive-specific scopes are now imported from config.google_config
# DRIVE_SCOPES = [...]

# Gmail-specific scopes are now imported from config.google_config
# GMAIL_SCOPES = [...]

# Combined scopes for all supported Google Workspace operations are now imported from config.google_config
# SCOPES = [...]

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
    This endpoint exchanges the authorization code for credentials and saves them.
    It then displays a success or error page to the user.
    """
    # State is used by google-auth-library for CSRF protection and should be present.
    # We don't need to track it ourselves in this simplified flow.
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error:
        error_message = f"Authentication failed: Google returned an error: {error}. State: {state}."
        logger.error(error_message)
        return HTMLResponse(content=f"""
            <html><head><title>Authentication Error</title></head>
            <body><h2>Authentication Error</h2><p>{error_message}</p>
            <p>Please ensure you grant the requested permissions. You can close this window and try again.</p></body></html>
        """, status_code=400)

    if not code:
        error_message = "Authentication failed: No authorization code received from Google."
        logger.error(error_message)
        return HTMLResponse(content=f"""
            <html><head><title>Authentication Error</title></head>
            <body><h2>Authentication Error</h2><p>{error_message}</p><p>You can close this window and try again.</p></body></html>
        """, status_code=400)

    try:
        # Use the centralized CONFIG_CLIENT_SECRETS_PATH
        client_secrets_path = CONFIG_CLIENT_SECRETS_PATH
        if not os.path.exists(client_secrets_path):
            logger.error(f"OAuth client secrets file not found at {client_secrets_path}")
            # This is a server configuration error, should not happen in a deployed environment.
            return HTMLResponse(content="Server Configuration Error: Client secrets not found.", status_code=500)

        logger.info(f"OAuth callback: Received code (state: {state}). Attempting to exchange for tokens.")

        mcp_session_id: Optional[str] = OAUTH_STATE_TO_SESSION_ID_MAP.pop(state, None)
        if mcp_session_id:
            logger.info(f"OAuth callback: Retrieved MCP session ID '{mcp_session_id}' for state '{state}'.")
        else:
            logger.warning(f"OAuth callback: No MCP session ID found for state '{state}'. Auth will not be tied to a specific session directly via this callback.")

        # Exchange code for credentials. handle_auth_callback will save them.
        # The user_id returned here is the Google-verified email.
        verified_user_id, credentials = handle_auth_callback(
            client_secrets_path=client_secrets_path,
            scopes=SCOPES, # Ensure all necessary scopes are requested
            authorization_response=str(request.url),
            redirect_uri=OAUTH_REDIRECT_URI,
            session_id=mcp_session_id # Pass session_id if available
        )

        log_session_part = f" (linked to session: {mcp_session_id})" if mcp_session_id else ""
        logger.info(f"OAuth callback: Successfully authenticated user: {verified_user_id} (state: {state}){log_session_part}.")

        # Return a more informative success page
        success_page_content = f"""
            <html>
            <head>
                <title>Authentication Successful</title>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 600px; margin: 40px auto; padding: 20px; text-align: center; color: #333; border: 1px solid #ddd; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    .status {{ color: #4CAF50; font-size: 24px; margin-bottom: 15px; }}
                    .message {{ margin-bottom: 20px; line-height: 1.6; }}
                    .user-id {{ font-weight: bold; color: #2a2a2a; }}
                    .button {{ background-color: #4CAF50; color: white; padding: 12px 25px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; text-decoration: none; display: inline-block; margin-top: 10px; }}
                    .note {{ font-size: 0.9em; color: #555; margin-top: 25px; }}
                </style>
                <script> setTimeout(function() {{ window.close(); }}, 10000); </script>
            </head>
            <body>
                <div class="status">✅ Authentication Successful</div>
                <div class="message">
                    You have successfully authenticated as <span class="user-id">{verified_user_id}</span>.
                    Credentials have been saved.
                </div>
                <div class="message">
                    You can now close this window and **retry your original command** in the application.
                </div>
                <button class="button" onclick="window.close()">Close Window</button>
                <div class="note">This window will close automatically in 10 seconds.</div>
            </body>
            </html>
        """
        return HTMLResponse(content=success_page_content)

    except Exception as e:
        error_message_detail = f"Error processing OAuth callback (state: {state}): {str(e)}"
        logger.error(error_message_detail, exc_info=True)
        # Generic error page for any other issues during token exchange or credential saving
        return HTMLResponse(content=f"""
            <html>
            <head><title>Authentication Processing Error</title></head>
            <body>
                <h2 style="color: #d32f2f;">Authentication Processing Error</h2>
                <p>An unexpected error occurred while processing your authentication: {str(e)}</p>
                <p>Please try again. You can close this window.</p>
            </body>
            </html>
        """, status_code=500)

# The @server.tool("oauth2callback") is removed as it's redundant with the custom HTTP route
# and the simplified "authorize and retry" flow.