import logging
import os
from typing import Optional, Union
from importlib import metadata

from fastapi.responses import HTMLResponse, JSONResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.middleware import Middleware

from fastmcp import FastMCP

from auth.oauth21_session_store import get_oauth21_session_store, set_auth_provider
from auth.google_auth import handle_auth_callback, start_auth_flow, check_client_secrets
from auth.mcp_session_middleware import MCPSessionMiddleware
from auth.oauth_responses import create_error_response, create_success_response, create_server_error_response
from auth.auth_info_middleware import AuthInfoMiddleware
from auth.fastmcp_google_auth import GoogleWorkspaceAuthProvider
from auth.vscode_compatibility_middleware import VSCodePathNormalizationMiddleware
from auth.cors_security_middleware import CORSSecurityMiddleware
from auth.scopes import SCOPES
from core.config import (
    USER_GOOGLE_EMAIL,
    get_transport_mode,
    set_transport_mode as _set_transport_mode,
    get_oauth_redirect_uri as get_oauth_redirect_uri_for_current_mode,
)

# Try to import GoogleRemoteAuthProvider for FastMCP 2.11.1+
try:
    from auth.google_remote_auth_provider import GoogleRemoteAuthProvider
    GOOGLE_REMOTE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_REMOTE_AUTH_AVAILABLE = False
    GoogleRemoteAuthProvider = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_auth_provider: Optional[Union[GoogleWorkspaceAuthProvider, GoogleRemoteAuthProvider]] = None

# --- Middleware Definitions ---
# Note: The old wildcard CORS middleware is replaced with secure CORS middleware
session_middleware = Middleware(MCPSessionMiddleware)
vscode_middleware = Middleware(VSCodePathNormalizationMiddleware, debug=False)
cors_security_middleware = Middleware(CORSSecurityMiddleware, debug=True)

# Custom FastMCP that adds secure middleware stack for OAuth 2.1
class SecureFastMCP(FastMCP):
    def streamable_http_app(self) -> "Starlette":
        """Override to add secure middleware stack for OAuth 2.1."""
        app = super().streamable_http_app()
        
        # Add middleware in order (first added = outermost layer)
        # 1. CORS Security - handles CORS with proper origin validation
        app.user_middleware.insert(0, cors_security_middleware)
        # 2. VS Code Path Normalization - rewrites VS Code paths transparently  
        app.user_middleware.insert(1, vscode_middleware)
        # 3. Session Management - extracts session info for MCP context
        app.user_middleware.insert(2, session_middleware)
        
        # Rebuild middleware stack
        app.middleware_stack = app.build_middleware_stack()
        logger.info("Added secure middleware stack: CORS Security, VS Code Compatibility, Session Management")
        return app

# --- Server Instance ---
server = SecureFastMCP(
    name="google_workspace", 
    auth=None,
)

# Add the AuthInfo middleware to inject authentication into FastMCP context
auth_info_middleware = AuthInfoMiddleware()
server.add_middleware(auth_info_middleware)


def set_transport_mode(mode: str):
    """Sets the transport mode for the server."""
    _set_transport_mode(mode)
    logger.info(f"🔌 Transport: {mode}")

def configure_server_for_http():
    """
    Configures the authentication provider for HTTP transport.
    This must be called BEFORE server.run().
    """
    global _auth_provider
    transport_mode = get_transport_mode()

    if transport_mode != "streamable-http":
        return

    oauth21_enabled = os.getenv("MCP_ENABLE_OAUTH21", "false").lower() == "true"

    if oauth21_enabled:
        if not os.getenv("GOOGLE_OAUTH_CLIENT_ID"):
            logger.warning("⚠️  OAuth 2.1 enabled but GOOGLE_OAUTH_CLIENT_ID not set")
            return

        if GOOGLE_REMOTE_AUTH_AVAILABLE:
            logger.info("🔐 OAuth 2.1 enabled")
            try:
                _auth_provider = GoogleRemoteAuthProvider()
                server.auth = _auth_provider
                set_auth_provider(_auth_provider)
                from auth.oauth21_integration import enable_oauth21
                enable_oauth21()
            except Exception as e:
                logger.error(f"Failed to initialize GoogleRemoteAuthProvider: {e}", exc_info=True)
        else:
            logger.error("OAuth 2.1 is enabled, but GoogleRemoteAuthProvider is not available.")
    else:
        logger.info("OAuth 2.1 is DISABLED. Server will use legacy tool-based authentication.")
        server.auth = None

def get_auth_provider() -> Optional[Union[GoogleWorkspaceAuthProvider, GoogleRemoteAuthProvider]]:
    """Gets the global authentication provider instance."""
    return _auth_provider

# --- Custom Routes ---
@server.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
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
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error:
        msg = f"Authentication failed: Google returned an error: {error}. State: {state}."
        logger.error(msg)
        return create_error_response(msg)

    if not code:
        msg = "Authentication failed: No authorization code received from Google."
        logger.error(msg)
        return create_error_response(msg)

    try:
        error_message = check_client_secrets()
        if error_message:
            return create_server_error_response(error_message)

        logger.info(f"OAuth callback: Received code (state: {state}).")

        verified_user_id, credentials = handle_auth_callback(
            scopes=SCOPES,
            authorization_response=str(request.url),
            redirect_uri=get_oauth_redirect_uri_for_current_mode(),
            session_id=None
        )

        logger.info(f"OAuth callback: Successfully authenticated user: {verified_user_id}.")

        try:
            store = get_oauth21_session_store()
            mcp_session_id = None
            if hasattr(request, 'state') and hasattr(request.state, 'session_id'):
                mcp_session_id = request.state.session_id

            store.store_session(
                user_email=verified_user_id,
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_uri=credentials.token_uri,
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                scopes=credentials.scopes,
                expiry=credentials.expiry,
                session_id=f"google-{state}",
                mcp_session_id=mcp_session_id,
            )
            logger.info(f"Stored Google credentials in OAuth 2.1 session store for {verified_user_id}")
        except Exception as e:
            logger.error(f"Failed to store credentials in OAuth 2.1 store: {e}")

        return create_success_response(verified_user_id)
    except Exception as e:
        logger.error(f"Error processing OAuth callback: {str(e)}", exc_info=True)
        return create_server_error_response(str(e))

# --- Tools ---
@server.tool()
async def start_google_auth(service_name: str, user_google_email: str = USER_GOOGLE_EMAIL) -> str:
    if not user_google_email:
        raise ValueError("user_google_email must be provided.")

    error_message = check_client_secrets()
    if error_message:
        return f"**Authentication Error:** {error_message}"

    try:
        auth_message = await start_auth_flow(
            user_google_email=user_google_email,
            service_name=service_name,
            redirect_uri=get_oauth_redirect_uri_for_current_mode()
        )
        return auth_message
    except Exception as e:
        logger.error(f"Failed to start Google authentication flow: {e}", exc_info=True)
        return f"**Error:** An unexpected error occurred: {e}"

# OAuth 2.1 Discovery Endpoints - register manually when OAuth 2.1 is enabled but GoogleRemoteAuthProvider is not available
# These will only be registered if MCP_ENABLE_OAUTH21=true and we're in fallback mode
if os.getenv("MCP_ENABLE_OAUTH21", "false").lower() == "true" and not GOOGLE_REMOTE_AUTH_AVAILABLE:
    from auth.oauth_common_handlers import (
        handle_oauth_authorize,
        handle_proxy_token_exchange,
        handle_oauth_protected_resource,
        handle_oauth_authorization_server,
        handle_oauth_client_config,
        handle_oauth_register
    )
    
    server.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])(handle_oauth_protected_resource)
    server.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])(handle_oauth_authorization_server)
    server.custom_route("/.well-known/oauth-client", methods=["GET", "OPTIONS"])(handle_oauth_client_config)
    server.custom_route("/oauth2/authorize", methods=["GET", "OPTIONS"])(handle_oauth_authorize)
    server.custom_route("/oauth2/token", methods=["POST", "OPTIONS"])(handle_proxy_token_exchange)
    server.custom_route("/oauth2/register", methods=["POST", "OPTIONS"])(handle_oauth_register)
