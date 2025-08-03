import logging
import os
from contextlib import asynccontextmanager

from typing import Optional
from importlib import metadata

from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware

from auth.oauth21_session_store import get_oauth21_session_store
from auth.google_auth import handle_auth_callback, start_auth_flow, check_client_secrets
from auth.mcp_session_middleware import MCPSessionMiddleware
from auth.oauth_responses import create_error_response, create_success_response, create_server_error_response

# FastMCP OAuth imports
from auth.fastmcp_google_auth import GoogleWorkspaceAuthProvider
from auth.oauth21_session_store import set_auth_provider

# Import shared configuration
from auth.scopes import SCOPES
from core.config import (
    WORKSPACE_MCP_PORT,
    WORKSPACE_MCP_BASE_URI,
    USER_GOOGLE_EMAIL,
    get_transport_mode,
    set_transport_mode as _set_transport_mode,
    get_oauth_redirect_uri as get_oauth_redirect_uri_for_current_mode,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastMCP authentication provider instance
_auth_provider: Optional[GoogleWorkspaceAuthProvider] = None

# Create middleware configuration

cors_middleware = Middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

session_middleware = Middleware(MCPSessionMiddleware)

# Custom FastMCP that adds CORS to streamable HTTP
class CORSEnabledFastMCP(FastMCP):
    def streamable_http_app(self) -> "Starlette":
        """Override to add CORS and session middleware to the app."""
        app = super().streamable_http_app()
        # Add session middleware first (to set context before other middleware)
        app.user_middleware.insert(0, session_middleware)
        # Add CORS as the second middleware
        app.user_middleware.insert(1, cors_middleware)
        # Rebuild middleware stack
        app.middleware_stack = app.build_middleware_stack()
        logger.info("Added session and CORS middleware to streamable HTTP app")
        return app


# Basic MCP server instance - auth will be set based on transport mode
server = CORSEnabledFastMCP(
    name="google_workspace",
    port=WORKSPACE_MCP_PORT,
    host="0.0.0.0",
    auth=None  # Will be set in initialize_auth() if needed
)

# Add startup and shutdown event handlers to the underlying FastAPI app
def add_lifecycle_events():
    """Add lifecycle events after server creation."""
    # Get the FastAPI app from streamable HTTP
    app = server.streamable_http_app()
    
    @asynccontextmanager
    async def lifespan(app):
        # Startup
        global _auth_provider
        try:
            _auth_provider = await initialize_auth()
            if _auth_provider:
                logger.info("OAuth 2.1 authentication initialized on startup")
            else:
                logger.info("OAuth authentication not configured or not available")
        except Exception as e:
            logger.error(f"Failed to initialize authentication on startup: {e}")
        
        yield
        
        # Shutdown
        await shutdown_auth()
    
    # Set the lifespan if it's not already set
    if not hasattr(app, 'lifespan') or app.lifespan is None:
        app.router.lifespan_context = lifespan

def set_transport_mode(mode: str):
    """Set the current transport mode for OAuth callback handling."""
    _set_transport_mode(mode)
    logger.info(f"Transport mode set to: {mode}")
    
    # Initialize lifecycle events for HTTP transport after mode is set
    if mode == "streamable-http":
        add_lifecycle_events()

async def initialize_auth() -> Optional[GoogleWorkspaceAuthProvider]:
    """Initialize FastMCP authentication if available and configured."""
    global _auth_provider

    # Only initialize auth for HTTP transport
    if get_transport_mode() != "streamable-http":
        logger.info("Authentication not available in stdio mode")
        return None

    # Check if OAuth is configured
    if not os.getenv("GOOGLE_OAUTH_CLIENT_ID"):
        logger.info("OAuth not configured (GOOGLE_OAUTH_CLIENT_ID not set)")
        return None

    try:
        # Create and configure auth provider
        _auth_provider = GoogleWorkspaceAuthProvider()

        # Set up the bridge for Google credentials
        set_auth_provider(_auth_provider)

        # Update server auth
        server.auth = _auth_provider

        logger.info("FastMCP authentication initialized with Google Workspace provider")
        return _auth_provider
    except Exception as e:
        logger.error(f"Failed to initialize authentication: {e}")
        return None

async def shutdown_auth():
    """Shutdown authentication provider."""
    global _auth_provider
    if _auth_provider:
        try:
            # FastMCP auth providers don't need explicit shutdown
            logger.info("Authentication provider stopped")
        except Exception as e:
            logger.error(f"Error stopping authentication: {e}")
        finally:
            _auth_provider = None
            server.auth = None

def get_auth_provider() -> Optional[GoogleWorkspaceAuthProvider]:
    """Get the global authentication provider instance."""
    return _auth_provider


# Health check endpoint
@server.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """Health check endpoint for container orchestration."""
    try:
        version = metadata.version("workspace-mcp")
    except metadata.PackageNotFoundError:
        version = "dev"
    return JSONResponse({
        "status": "healthy",
        "service": "workspace-mcp",
        "version": version,
        "transport": get_transport_mode()
    })


@server.custom_route("/oauth2callback", methods=["GET"])
async def oauth2_callback(request: Request) -> HTMLResponse:
    """
    Handle OAuth2 callback from Google via a custom route.
    This endpoint exchanges the authorization code for credentials and saves them.
    It then displays a success or error page to the user.
    """
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error:
        error_message = f"Authentication failed: Google returned an error: {error}. State: {state}."
        logger.error(error_message)
        return create_error_response(error_message)

    if not code:
        error_message = "Authentication failed: No authorization code received from Google."
        logger.error(error_message)
        return create_error_response(error_message)

    try:
        # Check if we have credentials available (environment variables or file)
        error_message = check_client_secrets()
        if error_message:
            return create_server_error_response(error_message)

        logger.info(f"OAuth callback: Received code (state: {state}). Attempting to exchange for tokens.")

        # Exchange code for credentials. handle_auth_callback will save them.
        # The user_id returned here is the Google-verified email.
        verified_user_id, credentials = handle_auth_callback(
            scopes=SCOPES, # Ensure all necessary scopes are requested
            authorization_response=str(request.url),
            redirect_uri=get_oauth_redirect_uri_for_current_mode(),
            session_id=None # Session ID tracking removed
        )

        logger.info(f"OAuth callback: Successfully authenticated user: {verified_user_id} (state: {state}).")

        # Store Google credentials in OAuth 2.1 session store
        try:
            store = get_oauth21_session_store()
            store.store_session(
                user_email=verified_user_id,
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_uri=credentials.token_uri,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                scopes=credentials.scopes,
                expiry=credentials.expiry,
                session_id=f"google-{state}",  # Use state as a pseudo session ID
            )
            logger.info(f"Stored Google credentials in OAuth 2.1 session store for {verified_user_id}")
        except Exception as e:
            logger.error(f"Failed to store Google credentials in OAuth 2.1 store: {e}")

        # Return success page using shared template
        return create_success_response(verified_user_id)

    except Exception as e:
        error_message_detail = f"Error processing OAuth callback (state: {state}): {str(e)}"
        logger.error(error_message_detail, exc_info=True)
        # Generic error page for any other issues during token exchange or credential saving
        return create_server_error_response(str(e))

@server.tool()
async def start_google_auth(
    service_name: str,
    user_google_email: str = USER_GOOGLE_EMAIL
) -> str:
    """
    Initiates the Google OAuth 2.0 authentication flow for the specified user email and service.
    This is the primary method to establish credentials when no valid session exists or when targeting a specific account for a particular service.
    It generates an authorization URL that the LLM must present to the user.
    This initiates a new authentication flow for the specified user and service.

    LLM Guidance:
    - Use this tool when you need to authenticate a user for a specific Google service (e.g., "Google Calendar", "Google Docs", "Gmail", "Google Drive")
      and don't have existing valid credentials for the session or specified email.
    - You MUST provide the `user_google_email` and the `service_name`. If you don't know the email, ask the user first.
    - Valid `service_name` values typically include "Google Calendar", "Google Docs", "Gmail", "Google Drive".
    - After calling this tool, present the returned authorization URL clearly to the user and instruct them to:
        1. Click the link and complete the sign-in/consent process in their browser.
        2. Note the authenticated email displayed on the success page.
        3. Provide that email back to you (the LLM).
        4. Retry their original request, including the confirmed `user_google_email`.

    Args:
        user_google_email (str): The user's full Google email address (e.g., 'example@gmail.com'). This is REQUIRED.
        service_name (str): The name of the Google service for which authentication is being requested (e.g., "Google Calendar", "Google Docs"). This is REQUIRED.

    Returns:
        str: A detailed message for the LLM with the authorization URL and instructions to guide the user through the authentication process.
    """
    if not user_google_email or not isinstance(user_google_email, str) or '@' not in user_google_email:
        error_msg = "Invalid or missing 'user_google_email'. This parameter is required and must be a valid email address. LLM, please ask the user for their Google email address."
        logger.error(f"[start_google_auth] {error_msg}")
        raise Exception(error_msg)

    if not service_name or not isinstance(service_name, str):
        error_msg = "Invalid or missing 'service_name'. This parameter is required (e.g., 'Google Calendar', 'Google Docs'). LLM, please specify the service name."
        logger.error(f"[start_google_auth] {error_msg}")
        raise Exception(error_msg)

    logger.info(f"Tool 'start_google_auth' invoked for user_google_email: '{user_google_email}', service: '{service_name}'.")

    # Ensure OAuth callback is available for current transport mode
    from auth.oauth_callback_server import ensure_oauth_callback_available
    redirect_uri = get_oauth_redirect_uri_for_current_mode()
    success, error_msg = ensure_oauth_callback_available(get_transport_mode(), WORKSPACE_MCP_PORT, WORKSPACE_MCP_BASE_URI)
    if not success:
        if error_msg:
            raise Exception(f"Failed to start OAuth callback server: {error_msg}")
        else:
            raise Exception("Failed to start OAuth callback server. Please try again.")

    auth_result = await start_auth_flow(
        user_google_email=user_google_email,
        service_name=service_name,
        redirect_uri=redirect_uri
    )
    return auth_result



