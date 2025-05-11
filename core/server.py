import logging
import os
import sys
from typing import Dict, Any

# Import MCP types for proper response formatting
from mcp import types, Resource # Corrected import from 'resources' to 'Resource'

from mcp.server.fastmcp import FastMCP

from google.auth.exceptions import RefreshError
from auth.google_auth import handle_auth_callback, load_client_secrets

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
server = FastMCP(
    name="google_workspace",
    server_url="http://localhost:8000/gworkspace",  # Add absolute URL for Gemini native function calling
    host="0.0.0.0",      # Listen on all interfaces
    port=8000,           # Default port for HTTP server
    stateless_http=False # Enable stateful sessions (default)
)

# Configure OAuth redirect URI to use the MCP server's port
OAUTH_REDIRECT_URI = "http://localhost:8000/oauth2callback"

# Register OAuth callback as a resource
@server.resource("/oauth2callback") # This decorator should work if 'Resource' is the correct base or mechanism
async def oauth2_callback_resource(request, response):
    """Handle OAuth2 callback from Google via an MCP resource endpoint."""
    try:
        # Extract code and state from query parameters
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        
        if not code:
            logger.error("Authorization code not found in callback request")
            await response.send_html("""
                <html>
                <head><title>Authentication Failed</title></head>
                <body>
                    <h2 style="color: #d32f2f;">Authentication Failed</h2>
                    <p>Authorization code missing from the callback request.</p>
                    <p>You can close this window and try again.</p>
                </body>
                </html>
            """)
            return
            
        # Process the authorization code
        client_secrets_path = os.path.join(os.path.dirname(__file__), '..', 'client_secret.json')
        
        # Exchange code for credentials
        user_id, credentials = handle_auth_callback(
            client_secrets_path=client_secrets_path,
            scopes=SCOPES,
            authorization_response=f"{OAUTH_REDIRECT_URI}?code={code}&state={state}",
            redirect_uri=OAUTH_REDIRECT_URI
        )
        
        logger.info(f"Successfully exchanged code for credentials for user: {user_id}")
        
        # Return success page to the user
        await response.send_html("""
            <html>
            <head>
                <title>Authentication Successful</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        max-width: 500px;
                        margin: 40px auto;
                        padding: 20px;
                        text-align: center;
                        color: #333;
                    }
                    .status {
                        color: #4CAF50;
                        font-size: 24px;
                        margin-bottom: 20px;
                    }
                    .message {
                        margin-bottom: 30px;
                        line-height: 1.5;
                    }
                    .button {
                        background-color: #4CAF50;
                        color: white;
                        padding: 10px 20px;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                        font-size: 16px;
                    }
                </style>
                <script>
                    // Auto-close window after 10 seconds
                    setTimeout(function() { window.close(); }, 10000);
                </script>
            </head>
            <body>
                <div class="status">Authentication Successful</div>
                <div class="message">
                    You have successfully authenticated with Google.
                    You can now close this window and return to your application.
                </div>
                <button class="button" onclick="window.close()">Close Window</button>
            </body>
            </html>
        """)
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {e}", exc_info=True)
        await response.send_html(f"""
            <html>
            <head><title>Authentication Error</title></head>
            <body>
                <h2 style="color: #d32f2f;">Authentication Error</h2>
                <p>An error occurred during authentication: {str(e)}</p>
                <p>You can close this window and try again.</p>
            </body>
            </html>
        """)

# Define OAuth callback as a tool (already registered via decorator)
@server.tool("oauth2callback")
async def oauth2callback(code: str = None, state: str = None, redirect_uri: str = "http://localhost:8080/callback") -> types.CallToolResult:
    """
    Handle OAuth2 callback from Google - for integration with external servers.

    Most users should use the complete_auth tool instead.
    
    Args:
        code (str, optional): Authorization code from OAuth callback
        state (str, optional): State parameter from OAuth callback
        redirect_uri (str, optional): Redirect URI for OAuth callback

    Returns:
        A CallToolResult with appropriate content types based on success or failure
    """
    if not code:
        logger.error("Authorization code not found in callback request.")
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="missing_code",
                    message="Authorization code not found"
                )
            ]
        )

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
        return types.CallToolResult(
            content=[
                types.TextContent(
                    type="text",
                    text=f"Authentication successful for user: {user_id}"
                ),
                types.JsonContent(
                    type="json",
                    json={"user_id": user_id}
                )
            ]
        )
    except RefreshError as e:
        logger.error(f"Failed to exchange authorization code for tokens: {e}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="refresh_error",
                    message=f"Could not exchange authorization code for tokens: {str(e)}"
                )
            ]
        )
    except Exception as e:
        logger.error(f"An unexpected error occurred during OAuth callback: {e}", exc_info=True)
        return types.CallToolResult(
            content=[
                types.ErrorContent(
                    type="error",
                    error_type="unexpected_error",
                    message=f"An unexpected error occurred: {str(e)}"
                )
            ]
        )