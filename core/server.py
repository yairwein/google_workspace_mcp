import logging
import os
from typing import Optional
from importlib import metadata

from fastapi import Header
from fastapi.responses import HTMLResponse


from mcp.server.fastmcp import FastMCP
from starlette.requests import Request

from auth.google_auth import handle_auth_callback, start_auth_flow, check_client_secrets
from auth.oauth_callback_server import get_oauth_redirect_uri, ensure_oauth_callback_available
from auth.oauth_responses import create_error_response, create_success_response, create_server_error_response

# OAuth 2.1 imports (optional)
try:
    from auth.oauth21.config import AuthConfig, create_default_oauth2_config
    from auth.oauth21.compat import AuthCompatibilityLayer
    OAUTH21_AVAILABLE = True
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.debug(f"OAuth 2.1 not available: {e}")
    OAUTH21_AVAILABLE = False
    AuthCompatibilityLayer = None
    AuthConfig = None

# Import shared configuration
from auth.scopes import (
    SCOPES,
    USERINFO_EMAIL_SCOPE,  # noqa: F401
    OPENID_SCOPE,  # noqa: F401
    CALENDAR_READONLY_SCOPE,  # noqa: F401
    CALENDAR_EVENTS_SCOPE,  # noqa: F401
    DRIVE_READONLY_SCOPE,  # noqa: F401
    DRIVE_FILE_SCOPE,  # noqa: F401
    GMAIL_READONLY_SCOPE,  # noqa: F401
    GMAIL_SEND_SCOPE,  # noqa: F401
    GMAIL_COMPOSE_SCOPE,  # noqa: F401
    GMAIL_MODIFY_SCOPE,  # noqa: F401
    GMAIL_LABELS_SCOPE,  # noqa: F401
    BASE_SCOPES,  # noqa: F401
    CALENDAR_SCOPES,  # noqa: F401
    DRIVE_SCOPES,  # noqa: F401
    GMAIL_SCOPES,  # noqa: F401
    DOCS_READONLY_SCOPE,  # noqa: F401
    DOCS_WRITE_SCOPE,  # noqa: F401
    CHAT_READONLY_SCOPE,  # noqa: F401
    CHAT_WRITE_SCOPE,  # noqa: F401
    CHAT_SPACES_SCOPE,  # noqa: F401
    CHAT_SCOPES,  # noqa: F401
    SHEETS_READONLY_SCOPE,  # noqa: F401
    SHEETS_WRITE_SCOPE,  # noqa: F401
    SHEETS_SCOPES,  # noqa: F401
    FORMS_BODY_SCOPE,  # noqa: F401
    FORMS_BODY_READONLY_SCOPE,  # noqa: F401
    FORMS_RESPONSES_READONLY_SCOPE,  # noqa: F401
    FORMS_SCOPES,  # noqa: F401
    SLIDES_SCOPE,  # noqa: F401
    SLIDES_READONLY_SCOPE,  # noqa: F401
    SLIDES_SCOPES,  # noqa: F401
    TASKS_SCOPE,  # noqa: F401
    TASKS_READONLY_SCOPE,  # noqa: F401
    TASKS_SCOPES,  # noqa: F401
    CUSTOM_SEARCH_SCOPE,  # noqa: F401
    CUSTOM_SEARCH_SCOPES,  # noqa: F401
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WORKSPACE_MCP_PORT = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", 8000)))
WORKSPACE_MCP_BASE_URI = os.getenv("WORKSPACE_MCP_BASE_URI", "http://localhost")
USER_GOOGLE_EMAIL = os.getenv("USER_GOOGLE_EMAIL", None)

# Transport mode detection (will be set by main.py)
_current_transport_mode = "stdio"  # Default to stdio

# Basic MCP server instance
server = FastMCP(
    name="google_workspace",
    port=WORKSPACE_MCP_PORT,
    host="0.0.0.0"
)

def set_transport_mode(mode: str):
    """Set the current transport mode for OAuth callback handling."""
    global _current_transport_mode
    _current_transport_mode = mode
    logger.info(f"Transport mode set to: {mode}")

def get_oauth_redirect_uri_for_current_mode() -> str:
    """Get OAuth redirect URI based on current transport mode."""
    return get_oauth_redirect_uri(WORKSPACE_MCP_PORT, WORKSPACE_MCP_BASE_URI)

async def initialize_oauth21_auth() -> Optional[AuthCompatibilityLayer]:
    """Initialize OAuth 2.1 authentication layer if available and configured."""
    global _auth_layer
    
    if not OAUTH21_AVAILABLE:
        logger.info("OAuth 2.1 not available (dependencies not installed)")
        return None
    
    try:
        # Create authentication configuration
        auth_config = AuthConfig()
        
        if auth_config.is_oauth2_enabled():
            logger.info(f"Initializing OAuth 2.1 authentication: {auth_config.get_effective_auth_mode()}")
            _auth_layer = AuthCompatibilityLayer(auth_config)
            await _auth_layer.start()
            
            # Add middleware if HTTP transport is being used
            if _current_transport_mode == "http" or _current_transport_mode == "streamable-http":
                middleware = _auth_layer.create_enhanced_middleware()
                if middleware and hasattr(server, 'app'):
                    server.app.add_middleware(type(middleware), **middleware.__dict__)
                    logger.info("Added OAuth 2.1 middleware to FastAPI app")
            
            logger.info("OAuth 2.1 authentication initialized successfully")
        else:
            logger.info("OAuth 2.1 not configured, using legacy authentication only")
        
        return _auth_layer
        
    except Exception as e:
        logger.error(f"Failed to initialize OAuth 2.1 authentication: {e}")
        return None

async def shutdown_oauth21_auth():
    """Shutdown OAuth 2.1 authentication layer."""
    global _auth_layer
    
    if _auth_layer:
        try:
            await _auth_layer.stop()
            logger.info("OAuth 2.1 authentication stopped")
        except Exception as e:
            logger.error(f"Error stopping OAuth 2.1 authentication: {e}")
        finally:
            _auth_layer = None

def get_auth_layer() -> Optional[AuthCompatibilityLayer]:
    """Get the global authentication layer instance."""
    return _auth_layer

# Health check endpoint
@server.custom_route("/health", methods=["GET"])
async def health_check(request: Request):
    """Health check endpoint for container orchestration."""
    from fastapi.responses import JSONResponse
    try:
        version = metadata.version("workspace-mcp")
    except metadata.PackageNotFoundError:
        version = "dev"
    return JSONResponse({
        "status": "healthy",
        "service": "workspace-mcp",
        "version": version,
        "transport": _current_transport_mode
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
    redirect_uri = get_oauth_redirect_uri_for_current_mode()
    success, error_msg = ensure_oauth_callback_available(_current_transport_mode, WORKSPACE_MCP_PORT, WORKSPACE_MCP_BASE_URI)
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


# OAuth 2.1 Discovery Endpoints
@server.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource(request: Request):
    """
    OAuth 2.1 Protected Resource Metadata endpoint per RFC9728.
    Returns metadata about this protected resource including authorization servers.
    """
    from fastapi.responses import JSONResponse
    
    auth_layer = get_auth_layer()
    if not auth_layer or not auth_layer.config.is_oauth2_enabled():
        return JSONResponse(
            status_code=404,
            content={"error": "OAuth 2.1 not configured"}
        )
    
    try:
        discovery_service = auth_layer.oauth2_handler.discovery
        metadata = await discovery_service.get_protected_resource_metadata()
        
        return JSONResponse(
            content=metadata,
            headers={
                "Content-Type": "application/json",
                "Cache-Control": "public, max-age=3600",
            }
        )
    except Exception as e:
        logger.error(f"Error serving protected resource metadata: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"}
        )


@server.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server(request: Request):
    """
    OAuth 2.1 Authorization Server Metadata endpoint per RFC8414.
    Returns metadata about the authorization server for this resource.
    """
    from fastapi.responses import JSONResponse
    
    auth_layer = get_auth_layer()
    if not auth_layer or not auth_layer.config.is_oauth2_enabled():
        return JSONResponse(
            status_code=404,
            content={"error": "OAuth 2.1 not configured"}
        )
    
    try:
        discovery_service = auth_layer.oauth2_handler.discovery
        auth_server_url = auth_layer.config.oauth2.authorization_server_url
        
        if not auth_server_url:
            return JSONResponse(
                status_code=404,
                content={"error": "No authorization server configured"}
            )
        
        metadata = await discovery_service.get_authorization_server_metadata(auth_server_url)
        
        # Override issuer to point to this server for MCP-specific metadata
        base_url = f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}"
        metadata["issuer"] = base_url
        metadata["authorization_endpoint"] = f"{auth_server_url}/o/oauth2/v2/auth"
        metadata["token_endpoint"] = f"{auth_server_url}/token"
        
        return JSONResponse(
            content=metadata,
            headers={
                "Content-Type": "application/json", 
                "Cache-Control": "public, max-age=3600",
            }
        )
    except Exception as e:
        logger.error(f"Error serving authorization server metadata: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error"}
        )


@server.custom_route("/oauth2/authorize", methods=["GET"])
async def oauth2_authorize(request: Request):
    """
    OAuth 2.1 authorization endpoint for MCP clients.
    Redirects to the configured authorization server with proper parameters.
    """
    from fastapi.responses import RedirectResponse
    from urllib.parse import urlencode
    
    auth_layer = get_auth_layer()
    if not auth_layer or not auth_layer.config.is_oauth2_enabled():
        return create_error_response("OAuth 2.1 not configured")
    
    try:
        # Extract authorization parameters
        params = dict(request.query_params)
        
        # Validate required parameters
        required_params = ["client_id", "redirect_uri", "response_type", "code_challenge", "code_challenge_method"]
        missing_params = [p for p in required_params if p not in params]
        
        if missing_params:
            return create_error_response(f"Missing required parameters: {', '.join(missing_params)}")
        
        # Build authorization URL
        auth_server_url = auth_layer.config.oauth2.authorization_server_url
        auth_url, state, code_verifier = await auth_layer.oauth2_handler.create_authorization_url(
            redirect_uri=params["redirect_uri"],
            scopes=params.get("scope", "").split(),
            state=params.get("state"),
            additional_params={k: v for k, v in params.items() if k not in ["scope", "state"]}
        )
        
        return RedirectResponse(url=auth_url)
        
    except Exception as e:
        logger.error(f"Error in OAuth 2.1 authorize endpoint: {e}")
        return create_error_response(f"Authorization failed: {str(e)}")


@server.custom_route("/oauth2/token", methods=["POST"])
async def oauth2_token(request: Request):
    """
    OAuth 2.1 token endpoint for MCP clients.
    Exchanges authorization codes for access tokens.
    """
    from fastapi.responses import JSONResponse
    
    auth_layer = get_auth_layer()
    if not auth_layer or not auth_layer.config.is_oauth2_enabled():
        return JSONResponse(
            status_code=404,
            content={"error": "OAuth 2.1 not configured"}
        )
    
    try:
        # Parse form data
        form_data = await request.form()
        grant_type = form_data.get("grant_type")
        
        if grant_type == "authorization_code":
            # Handle authorization code exchange
            code = form_data.get("code")
            code_verifier = form_data.get("code_verifier") 
            redirect_uri = form_data.get("redirect_uri")
            
            if not all([code, code_verifier, redirect_uri]):
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_request", "error_description": "Missing required parameters"}
                )
            
            session_id, session = await auth_layer.oauth2_handler.exchange_code_for_session(
                authorization_code=code,
                code_verifier=code_verifier,
                redirect_uri=redirect_uri
            )
            
            # Return token response
            token_response = {
                "access_token": session.token_info["access_token"],
                "token_type": "Bearer",
                "expires_in": 3600,  # 1 hour
                "scope": " ".join(session.scopes),
                "session_id": session_id,
            }
            
            if "refresh_token" in session.token_info:
                token_response["refresh_token"] = session.token_info["refresh_token"]
            
            return JSONResponse(content=token_response)
            
        elif grant_type == "refresh_token":
            # Handle token refresh
            refresh_token = form_data.get("refresh_token")
            if not refresh_token:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_request", "error_description": "Missing refresh_token"}
                )
            
            # Find session by refresh token (simplified implementation)
            # In production, you'd want a more robust refresh token lookup
            return JSONResponse(
                status_code=501,
                content={"error": "unsupported_grant_type", "error_description": "Refresh token flow not yet implemented"}
            )
        
        else:
            return JSONResponse(
                status_code=400,
                content={"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' not supported"}
            )
    
    except Exception as e:
        logger.error(f"Error in OAuth 2.1 token endpoint: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": "Internal server error"}
        )
