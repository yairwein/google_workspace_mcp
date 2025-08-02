import aiohttp
import logging
import os
from typing import Any, Optional
from importlib import metadata

from fastapi import Header
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware

from auth.google_auth import handle_auth_callback, start_auth_flow, check_client_secrets
from auth.oauth_callback_server import get_oauth_redirect_uri, ensure_oauth_callback_available
from auth.oauth_responses import create_error_response, create_success_response, create_server_error_response

# FastMCP OAuth imports
from auth.fastmcp_google_auth import GoogleWorkspaceAuthProvider
from auth.oauth21_google_bridge import set_auth_provider

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

# FastMCP authentication provider instance
_auth_provider: Optional[GoogleWorkspaceAuthProvider] = None

# Create middleware configuration
from starlette.middleware import Middleware

cors_middleware = Middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom FastMCP that adds CORS to streamable HTTP
class CORSEnabledFastMCP(FastMCP):
    def streamable_http_app(self) -> "Starlette":
        """Override to add CORS middleware to the app."""
        app = super().streamable_http_app()
        # Add CORS as the first middleware
        app.user_middleware.insert(0, cors_middleware)
        # Rebuild middleware stack
        app.middleware_stack = app.build_middleware_stack()
        logger.info("Added CORS middleware to streamable HTTP app")
        return app

# Initialize auth provider for HTTP transport
def create_auth_provider() -> Optional[GoogleWorkspaceAuthProvider]:
    """Create auth provider if OAuth credentials are configured."""
    if os.getenv("GOOGLE_OAUTH_CLIENT_ID") and _current_transport_mode == "streamable-http":
        return GoogleWorkspaceAuthProvider()
    return None

# Basic MCP server instance - auth will be set based on transport mode
server = CORSEnabledFastMCP(
    name="google_workspace",
    port=WORKSPACE_MCP_PORT,
    host="0.0.0.0",
    auth=None  # Will be set in initialize_auth() if needed
)

def set_transport_mode(mode: str):
    """Set the current transport mode for OAuth callback handling."""
    global _current_transport_mode
    _current_transport_mode = mode
    logger.info(f"Transport mode set to: {mode}")

def get_oauth_redirect_uri_for_current_mode() -> str:
    """Get OAuth redirect URI based on current transport mode."""
    return get_oauth_redirect_uri(WORKSPACE_MCP_PORT, WORKSPACE_MCP_BASE_URI)

async def initialize_auth() -> Optional[GoogleWorkspaceAuthProvider]:
    """Initialize FastMCP authentication if available and configured."""
    global _auth_provider

    # Only initialize auth for HTTP transport
    if _current_transport_mode != "streamable-http":
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

        # Store Google credentials in OAuth 2.1 session store
        try:
            from auth.oauth21_session_store import get_oauth21_session_store
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
@server.custom_route("/.well-known/oauth-protected-resource", methods=["GET", "OPTIONS"])
async def oauth_protected_resource(request: Request):
    """OAuth 2.1 Protected Resource Metadata endpoint."""
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )

    metadata = {
        "resource": f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}",
        "authorization_servers": [
            f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}"
        ],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/gmail.modify",
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/presentations",
            "https://www.googleapis.com/auth/chat.spaces",
            "https://www.googleapis.com/auth/forms",
            "https://www.googleapis.com/auth/tasks"
        ],
        "resource_documentation": "https://developers.google.com/workspace",
        "client_registration_required": True,
        "client_configuration_endpoint": f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/.well-known/oauth-client",
    }

    return JSONResponse(
        content=metadata,
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    )


@server.custom_route("/.well-known/oauth-authorization-server", methods=["GET", "OPTIONS"])
async def oauth_authorization_server(request: Request):
    """OAuth 2.1 Authorization Server Metadata endpoint."""
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )

    try:
        # Fetch metadata from Google
        async with aiohttp.ClientSession() as session:
            url = "https://accounts.google.com/.well-known/openid-configuration"
            async with session.get(url) as response:
                if response.status == 200:
                    metadata = await response.json()

                    # Add OAuth 2.1 required fields
                    metadata.setdefault("code_challenge_methods_supported", ["S256"])
                    metadata.setdefault("pkce_required", True)

                    # Override endpoints to use our proxies
                    metadata["token_endpoint"] = f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2/token"
                    metadata["authorization_endpoint"] = f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2/authorize"
                    metadata["enable_dynamic_registration"] = True
                    metadata["registration_endpoint"] = f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2/register"
                    return JSONResponse(
                        content=metadata,
                        headers={
                            "Content-Type": "application/json",
                            "Access-Control-Allow-Origin": "*"
                        }
                    )

        # Fallback metadata
        return JSONResponse(
            content={
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2/authorize",
                "token_endpoint": f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2/token",
                "userinfo_endpoint": "https://www.googleapis.com/oauth2/v2/userinfo",
                "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "pkce_required": True,
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "scopes_supported": ["openid", "email", "profile"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]
            },
            headers={
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            }
        )

    except Exception as e:
        logger.error(f"Error fetching auth server metadata: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to fetch authorization server metadata"},
            headers={"Access-Control-Allow-Origin": "*"}
        )

# OAuth client configuration endpoint
@server.custom_route("/.well-known/oauth-client", methods=["GET", "OPTIONS"])
async def oauth_client_config(request: Request):
    """Return OAuth client configuration."""
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )

    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    if not client_id:
        return JSONResponse(
            status_code=404,
            content={"error": "OAuth not configured"},
            headers={"Access-Control-Allow-Origin": "*"}
        )

    return JSONResponse(
        content={
            "client_id": client_id,
            "client_name": "Google Workspace MCP Server",
            "client_uri": f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}",
            "redirect_uris": [
                f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2callback",
                "http://localhost:5173/auth/callback"
            ],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid email profile https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.modify",
            "token_endpoint_auth_method": "client_secret_basic",
            "code_challenge_methods": ["S256"]
        },
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    )

# OAuth authorization endpoint (redirect to Google)
@server.custom_route("/oauth2/authorize", methods=["GET", "OPTIONS"])
async def oauth_authorize(request: Request):
    """Redirect to Google's authorization endpoint."""
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            }
        )

    from urllib.parse import urlencode

    # Get query parameters
    params = dict(request.query_params)

    # Add our client ID if not provided
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    if "client_id" not in params and client_id:
        params["client_id"] = client_id

    # Ensure response_type is code
    params["response_type"] = "code"

    # Build Google authorization URL
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

    # Return redirect
    return RedirectResponse(
        url=google_auth_url,
        status_code=302,
        headers={
            "Access-Control-Allow-Origin": "*"
        }
    )

# Token exchange proxy endpoint
@server.custom_route("/oauth2/token", methods=["POST", "OPTIONS"])
async def proxy_token_exchange(request: Request):
    """Proxy token exchange to Google to avoid CORS issues."""
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization"
            }
        )

    import aiohttp

    try:
        # Get form data
        body = await request.body()
        content_type = request.headers.get("content-type", "application/x-www-form-urlencoded")

        # Forward request to Google
        async with aiohttp.ClientSession() as session:
            headers = {"Content-Type": content_type}

            async with session.post("https://oauth2.googleapis.com/token", data=body, headers=headers) as response:
                response_data = await response.json()

                # Log for debugging
                if response.status != 200:
                    logger.error(f"Token exchange failed: {response.status} - {response_data}")
                else:
                    logger.info("Token exchange successful")

                return JSONResponse(
                    status_code=response.status,
                    content=response_data,
                    headers={
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*",
                        "Cache-Control": "no-store"
                    }
                )

    except Exception as e:
        logger.error(f"Error in token proxy: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": str(e)},
            headers={"Access-Control-Allow-Origin": "*"}
        )


# OAuth 2.1 Dynamic Client Registration endpoint
@server.custom_route("/oauth2/register", methods=["POST", "OPTIONS"])
async def oauth_register(request: Request):
    """
    Dynamic client registration workaround endpoint.
    
    Google doesn't support OAuth 2.1 dynamic client registration, so this endpoint
    accepts any registration request and returns our pre-configured Google OAuth
    credentials, allowing standards-compliant clients to work seamlessly.
    """
    if request.method == "OPTIONS":
        return JSONResponse(
            content={},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization"
            }
        )
    
    client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
    
    if not client_id or not client_secret:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "OAuth not configured"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    
    try:
        # Parse the registration request
        body = await request.json()
        logger.info(f"Dynamic client registration request received: {body}")
        
        # Extract redirect URIs from the request or use defaults
        redirect_uris = body.get("redirect_uris", [])
        if not redirect_uris:
            redirect_uris = [
                f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2callback",
                "http://localhost:5173/auth/callback"
            ]
        
        # Build the registration response with our pre-configured credentials
        import time
        response_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_name": body.get("client_name", "Google Workspace MCP Server"),
            "client_uri": body.get("client_uri", f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}"),
            "redirect_uris": redirect_uris,
            "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
            "response_types": body.get("response_types", ["code"]),
            "scope": body.get("scope", "openid email profile https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.modify"),
            "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_basic"),
            "code_challenge_methods": ["S256"],
            # Additional OAuth 2.1 fields
            "client_id_issued_at": int(time.time()),
            "registration_access_token": "not-required",  # We don't implement client management
            "registration_client_uri": f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2/register/{client_id}"
        }
        
        logger.info("Dynamic client registration successful - returning pre-configured Google credentials")
        
        return JSONResponse(
            status_code=201,
            content=response_data,
            headers={
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store"
            }
        )
        
    except Exception as e:
        logger.error(f"Error in dynamic client registration: {e}")
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": str(e)},
            headers={"Access-Control-Allow-Origin": "*"}
        )
