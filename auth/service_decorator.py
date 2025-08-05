import inspect
import logging
from functools import wraps
from typing import Dict, List, Optional, Any, Callable, Union
from datetime import datetime, timedelta

from google.auth.exceptions import RefreshError
from auth.google_auth import get_authenticated_google_service, GoogleAuthenticationError
from auth.scopes import (
    GMAIL_READONLY_SCOPE, GMAIL_SEND_SCOPE, GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE, GMAIL_LABELS_SCOPE,
    DRIVE_READONLY_SCOPE, DRIVE_FILE_SCOPE,
    DOCS_READONLY_SCOPE, DOCS_WRITE_SCOPE,
    CALENDAR_READONLY_SCOPE, CALENDAR_EVENTS_SCOPE,
    SHEETS_READONLY_SCOPE, SHEETS_WRITE_SCOPE,
    CHAT_READONLY_SCOPE, CHAT_WRITE_SCOPE, CHAT_SPACES_SCOPE,
    FORMS_BODY_SCOPE, FORMS_BODY_READONLY_SCOPE, FORMS_RESPONSES_READONLY_SCOPE,
    SLIDES_SCOPE, SLIDES_READONLY_SCOPE,
    TASKS_SCOPE, TASKS_READONLY_SCOPE,
    CUSTOM_SEARCH_SCOPE
)
from auth.oauth21_session_store import get_session_context

# OAuth 2.1 integration is now handled by FastMCP auth
OAUTH21_INTEGRATION_AVAILABLE = True


async def _extract_and_verify_bearer_token() -> tuple[Optional[str], Optional[str]]:
    """
    Extract and verify bearer token from HTTP headers.
    
    Returns:
        Tuple of (user_email, verified_token) if valid, (None, None) if invalid or not found
    """
    try:
        from fastmcp.server.dependencies import get_http_headers
        headers = get_http_headers()
        
        if not headers:
            logger.debug("No HTTP headers available for bearer token extraction")
            return None, None
            
        # Look for Authorization header (Google OAuth token)
        auth_header = headers.get("authorization") or headers.get("Authorization")
        
        if not auth_header:
            logger.debug("No Authorization header found in request")
            return None, None
            
        if not auth_header.lower().startswith("bearer "):
            logger.debug(f"Authorization header present but not Bearer token: {auth_header[:20]}...")
            return None, None
            
        # Extract token
        token = auth_header[7:]  # Remove "Bearer " prefix
        if not token:
            logger.debug("Empty bearer token found")
            return None, None
        
        logger.info(f"Found bearer token in Authorization header: {token[:20]}...")
        
        # Verify token using GoogleWorkspaceAuthProvider
        try:
            from core.server import get_auth_provider
            auth_provider = get_auth_provider()
            if not auth_provider:
                logger.error("No auth provider available for token verification")
                return None, None
                
            logger.debug(f"Auth provider type: {type(auth_provider).__name__}")
            
            # Verify the token
            access_token = await auth_provider.verify_token(token)
            if not access_token:
                logger.error("Bearer token verification failed")
                return None, None
                
            logger.debug(f"Token verified, access_token type: {type(access_token).__name__}")
            
            # Extract user email from verified token
            if hasattr(access_token, 'claims'):
                user_email = access_token.claims.get("email")
            else:
                logger.error(f"Access token has no claims attribute: {dir(access_token)}")
                return None, None
                
            if not user_email:
                logger.error(f"No email claim found in verified token. Available claims: {list(access_token.claims.keys()) if hasattr(access_token, 'claims') else 'N/A'}")
                return None, None
                
            logger.info(f"Successfully verified bearer token for user: {user_email}")
            return user_email, token
            
        except Exception as e:
            logger.error(f"Error verifying bearer token: {e}")
            return None, None
            
    except Exception as e:
        logger.debug(f"Error extracting bearer token from headers: {e}")
        return None, None

async def get_authenticated_google_service_oauth21(
    service_name: str,
    version: str,
    tool_name: str,
    user_google_email: str,
    required_scopes: List[str],
    session_id: Optional[str] = None,
    auth_token_email: Optional[str] = None,
    allow_recent_auth: bool = False,
) -> tuple[Any, str]:
    """
    OAuth 2.1 authentication using the session store with security validation.
    """
    from auth.oauth21_session_store import get_oauth21_session_store
    from googleapiclient.discovery import build
    
    store = get_oauth21_session_store()
    
    # Use the new validation method to ensure session can only access its own credentials
    credentials = store.get_credentials_with_validation(
        requested_user_email=user_google_email,
        session_id=session_id,
        auth_token_email=auth_token_email,
        allow_recent_auth=allow_recent_auth
    )
    
    if not credentials:
        from auth.google_auth import GoogleAuthenticationError
        raise GoogleAuthenticationError(
            f"Access denied: Cannot retrieve credentials for {user_google_email}. "
            f"You can only access credentials for your authenticated account."
        )
    
    # Check scopes
    if not all(scope in credentials.scopes for scope in required_scopes):
        from auth.google_auth import GoogleAuthenticationError
        raise GoogleAuthenticationError(f"OAuth 2.1 credentials lack required scopes. Need: {required_scopes}, Have: {credentials.scopes}")
    
    # Build service
    service = build(service_name, version, credentials=credentials)
    logger.info(f"[{tool_name}] Successfully authenticated {service_name} service using OAuth 2.1 for user: {user_google_email}")
    
    return service, user_google_email

logger = logging.getLogger(__name__)

# Service configuration mapping
SERVICE_CONFIGS = {
    "gmail": {"service": "gmail", "version": "v1"},
    "drive": {"service": "drive", "version": "v3"},
    "calendar": {"service": "calendar", "version": "v3"},
    "docs": {"service": "docs", "version": "v1"},
    "sheets": {"service": "sheets", "version": "v4"},
    "chat": {"service": "chat", "version": "v1"},
    "forms": {"service": "forms", "version": "v1"},
    "slides": {"service": "slides", "version": "v1"},
    "tasks": {"service": "tasks", "version": "v1"},
    "customsearch": {"service": "customsearch", "version": "v1"}
}


# Scope group definitions for easy reference
SCOPE_GROUPS = {
    # Gmail scopes
    "gmail_read": GMAIL_READONLY_SCOPE,
    "gmail_send": GMAIL_SEND_SCOPE,
    "gmail_compose": GMAIL_COMPOSE_SCOPE,
    "gmail_modify": GMAIL_MODIFY_SCOPE,
    "gmail_labels": GMAIL_LABELS_SCOPE,

    # Drive scopes
    "drive_read": DRIVE_READONLY_SCOPE,
    "drive_file": DRIVE_FILE_SCOPE,

    # Docs scopes
    "docs_read": DOCS_READONLY_SCOPE,
    "docs_write": DOCS_WRITE_SCOPE,

    # Calendar scopes
    "calendar_read": CALENDAR_READONLY_SCOPE,
    "calendar_events": CALENDAR_EVENTS_SCOPE,

    # Sheets scopes
    "sheets_read": SHEETS_READONLY_SCOPE,
    "sheets_write": SHEETS_WRITE_SCOPE,

    # Chat scopes
    "chat_read": CHAT_READONLY_SCOPE,
    "chat_write": CHAT_WRITE_SCOPE,
    "chat_spaces": CHAT_SPACES_SCOPE,

    # Forms scopes
    "forms": FORMS_BODY_SCOPE,
    "forms_read": FORMS_BODY_READONLY_SCOPE,
    "forms_responses_read": FORMS_RESPONSES_READONLY_SCOPE,

    # Slides scopes
    "slides": SLIDES_SCOPE,
    "slides_read": SLIDES_READONLY_SCOPE,

    # Tasks scopes
    "tasks": TASKS_SCOPE,
    "tasks_read": TASKS_READONLY_SCOPE,
    
    # Custom Search scope
    "customsearch": CUSTOM_SEARCH_SCOPE,
}

# Service cache: {cache_key: (service, cached_time, user_email)}
_service_cache: Dict[str, tuple[Any, datetime, str]] = {}
_cache_ttl = timedelta(minutes=30)  # Cache services for 30 minutes


def _get_cache_key(user_email: str, service_name: str, version: str, scopes: List[str]) -> str:
    """Generate a cache key for service instances."""
    sorted_scopes = sorted(scopes)
    return f"{user_email}:{service_name}:{version}:{':'.join(sorted_scopes)}"


def _is_cache_valid(cached_time: datetime) -> bool:
    """Check if cached service is still valid."""
    return datetime.now() - cached_time < _cache_ttl


def _get_cached_service(cache_key: str) -> Optional[tuple[Any, str]]:
    """Retrieve cached service if valid."""
    if cache_key in _service_cache:
        service, cached_time, user_email = _service_cache[cache_key]
        if _is_cache_valid(cached_time):
            logger.debug(f"Using cached service for key: {cache_key}")
            return service, user_email
        else:
            # Remove expired cache entry
            del _service_cache[cache_key]
            logger.debug(f"Removed expired cache entry: {cache_key}")
    return None


def _cache_service(cache_key: str, service: Any, user_email: str) -> None:
    """Cache a service instance."""
    _service_cache[cache_key] = (service, datetime.now(), user_email)
    logger.debug(f"Cached service for key: {cache_key}")


def _resolve_scopes(scopes: Union[str, List[str]]) -> List[str]:
    """Resolve scope names to actual scope URLs."""
    if isinstance(scopes, str):
        if scopes in SCOPE_GROUPS:
            return [SCOPE_GROUPS[scopes]]
        else:
            return [scopes]

    resolved = []
    for scope in scopes:
        if scope in SCOPE_GROUPS:
            resolved.append(SCOPE_GROUPS[scope])
        else:
            resolved.append(scope)
    return resolved


def _handle_token_refresh_error(error: RefreshError, user_email: str, service_name: str) -> str:
    """
    Handle token refresh errors gracefully, particularly expired/revoked tokens.

    Args:
        error: The RefreshError that occurred
        user_email: User's email address
        service_name: Name of the Google service

    Returns:
        A user-friendly error message with instructions for reauthentication
    """
    error_str = str(error)

    if 'invalid_grant' in error_str.lower() or 'expired or revoked' in error_str.lower():
        logger.warning(f"Token expired or revoked for user {user_email} accessing {service_name}")

        # Clear any cached service for this user to force fresh authentication
        clear_service_cache(user_email)

        service_display_name = f"Google {service_name.title()}"

        return (
            f"**Authentication Required: Token Expired/Revoked for {service_display_name}**\n\n"
            f"Your Google authentication token for {user_email} has expired or been revoked. "
            f"This commonly happens when:\n"
            f"- The token has been unused for an extended period\n"
            f"- You've changed your Google account password\n"
            f"- You've revoked access to the application\n\n"
            f"**To resolve this, please:**\n"
            f"1. Run `start_google_auth` with your email ({user_email}) and service_name='{service_display_name}'\n"
            f"2. Complete the authentication flow in your browser\n"
            f"3. Retry your original command\n\n"
            f"The application will automatically use the new credentials once authentication is complete."
        )
    else:
        # Handle other types of refresh errors
        logger.error(f"Unexpected refresh error for user {user_email}: {error}")
        return (
            f"Authentication error occurred for {user_email}. "
            f"Please try running `start_google_auth` with your email and the appropriate service name to reauthenticate."
        )


def require_google_service(
    service_type: str,
    scopes: Union[str, List[str]],
    version: Optional[str] = None,
    cache_enabled: bool = True
):
    """
    Decorator that automatically handles Google service authentication and injection.

    Args:
        service_type: Type of Google service ("gmail", "drive", "calendar", etc.)
        scopes: Required scopes (can be scope group names or actual URLs)
        version: Service version (defaults to standard version for service type)
        cache_enabled: Whether to use service caching (default: True)

    Usage:
        @require_google_service("gmail", "gmail_read")
        async def search_messages(service, user_google_email: str, query: str):
            # service parameter is automatically injected
            # Original authentication logic is handled automatically
    """
    def decorator(func: Callable) -> Callable:
        # Inspect the original function signature
        original_sig = inspect.signature(func)
        params = list(original_sig.parameters.values())

        # The decorated function must have 'service' as its first parameter.
        if not params or params[0].name != 'service':
            raise TypeError(
                f"Function '{func.__name__}' decorated with @require_google_service "
                "must have 'service' as its first parameter."
            )

        # Create a new signature for the wrapper that excludes the 'service' parameter.
        # This is the signature that FastMCP will see.
        wrapper_sig = original_sig.replace(parameters=params[1:])

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Note: `args` and `kwargs` are now the arguments for the *wrapper*,
            # which does not include 'service'.

            # Extract user_google_email from the arguments passed to the wrapper
            bound_args = wrapper_sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            user_google_email = bound_args.arguments.get('user_google_email')

            if not user_google_email:
                # This should ideally not be reached if 'user_google_email' is a required parameter
                # in the function signature, but it's a good safeguard.
                raise Exception("'user_google_email' parameter is required but was not found.")

            # Get service configuration from the decorator's arguments
            if service_type not in SERVICE_CONFIGS:
                raise Exception(f"Unknown service type: {service_type}")

            config = SERVICE_CONFIGS[service_type]
            service_name = config["service"]
            service_version = version or config["version"]

            # Resolve scopes
            resolved_scopes = _resolve_scopes(scopes)

            # --- Service Caching and Authentication Logic (largely unchanged) ---
            service = None
            actual_user_email = user_google_email

            if cache_enabled:
                cache_key = _get_cache_key(user_google_email, service_name, service_version, resolved_scopes)
                cached_result = _get_cached_service(cache_key)
                if cached_result:
                    service, actual_user_email = cached_result

            if service is None:
                try:
                    tool_name = func.__name__
                    
                    # Check if we have OAuth 2.1 credentials for this user
                    session_ctx = None
                    auth_token_email = None
                    
                    # Try to get FastMCP session ID and auth info
                    mcp_session_id = None
                    session_ctx = None
                    try:
                        from fastmcp.server.dependencies import get_context
                        fastmcp_ctx = get_context()
                        if fastmcp_ctx and hasattr(fastmcp_ctx, 'session_id'):
                            mcp_session_id = fastmcp_ctx.session_id
                            logger.debug(f"[{tool_name}] Got FastMCP session ID: {mcp_session_id}")
                            
                            # Set FastMCP session ID in context variable for propagation
                            from core.context import set_fastmcp_session_id
                            set_fastmcp_session_id(mcp_session_id)
                            
                            # Extract authenticated email from auth context if available
                            if hasattr(fastmcp_ctx, 'auth') and fastmcp_ctx.auth:
                                if hasattr(fastmcp_ctx.auth, 'claims') and fastmcp_ctx.auth.claims:
                                    auth_token_email = fastmcp_ctx.auth.claims.get('email')
                                    logger.debug(f"[{tool_name}] Got authenticated email from token: {auth_token_email}")
                            
                            # Create session context using FastMCP session ID
                            from auth.oauth21_session_store import SessionContext
                            session_ctx = SessionContext(
                                session_id=mcp_session_id,
                                user_id=auth_token_email or user_google_email,
                                metadata={"fastmcp_session_id": mcp_session_id, "user_email": user_google_email, "auth_email": auth_token_email}
                            )
                    except Exception as e:
                        logger.debug(f"[{tool_name}] Could not get FastMCP context: {e}")
                    
                    # Fallback to legacy session context if available
                    if not session_ctx and OAUTH21_INTEGRATION_AVAILABLE:
                        session_ctx = get_session_context()
                    
                    # Check if the CURRENT REQUEST is authenticated
                    is_authenticated_request = False
                    authenticated_user = None
                    bearer_token = None
                    
                    if OAUTH21_INTEGRATION_AVAILABLE:
                        # Check if we have an authenticated FastMCP context
                        try:
                            from fastmcp.server.dependencies import get_context
                            ctx = get_context()
                            if ctx:
                                # Check if AuthInfoMiddleware has stored the access token
                                access_token = ctx.get_state("access_token")
                                if access_token:
                                    # We have authentication info from the middleware
                                    is_authenticated_request = True
                                    authenticated_user = ctx.get_state("username") or ctx.get_state("user_email")
                                    bearer_token = access_token.token if hasattr(access_token, 'token') else str(access_token)
                                    logger.info(f"[{tool_name}] Authenticated via FastMCP context state: {authenticated_user}")
                                    
                                    # Store auth info for later use
                                    auth_token_email = authenticated_user
                                else:
                                    # Check legacy auth field
                                    if hasattr(ctx, 'auth') and ctx.auth:
                                        is_authenticated_request = True
                                        if hasattr(ctx.auth, 'claims'):
                                            authenticated_user = ctx.auth.claims.get('email')
                                        logger.debug(f"[{tool_name}] Authenticated via legacy FastMCP auth: {authenticated_user}")
                        except Exception as e:
                            logger.debug(f"[{tool_name}] Error checking FastMCP context: {e}")
                        
                        # If FastMCP context didn't provide authentication, check HTTP headers directly
                        if not is_authenticated_request:
                            logger.debug(f"[{tool_name}] FastMCP context has no auth, checking HTTP headers for bearer token")
                            header_user, header_token = await _extract_and_verify_bearer_token()
                            if header_user and header_token:
                                is_authenticated_request = True
                                authenticated_user = header_user
                                bearer_token = header_token
                                logger.info(f"[{tool_name}] Authenticated via HTTP bearer token: {authenticated_user}")
                                
                                # Create session binding for this bearer token authenticated request
                                try:
                                    from auth.oauth21_session_store import get_oauth21_session_store
                                    store = get_oauth21_session_store()
                                    # Create a session for this bearer token authentication
                                    session_id = f"bearer_{authenticated_user}_{header_token[:8]}"
                                    store.store_session(
                                        user_email=authenticated_user,
                                        access_token=header_token,
                                        session_id=session_id,
                                        mcp_session_id=mcp_session_id
                                    )
                                    logger.debug(f"[{tool_name}] Created session binding for bearer token auth: {session_id}")
                                except Exception as e:
                                    logger.warning(f"[{tool_name}] Could not create session binding for bearer token: {e}")
                            else:
                                logger.debug(f"[{tool_name}] No valid bearer token found in HTTP headers")
                        
                        # Fallback: Check other authentication indicators
                        if not is_authenticated_request:
                            # Check if MCP session is bound to a user
                            mcp_user = None
                            if mcp_session_id:
                                try:
                                    from auth.oauth21_session_store import get_oauth21_session_store
                                    store = get_oauth21_session_store()
                                    mcp_user = store.get_user_by_mcp_session(mcp_session_id)
                                except Exception:
                                    pass
                            
                            # TEMPORARY: Check if user has recently authenticated (for clients that don't send bearer tokens)
                            # This still enforces that users can only access their own credentials
                            has_recent_auth = False
                            try:
                                from auth.oauth21_session_store import get_oauth21_session_store
                                store = get_oauth21_session_store()
                                has_recent_auth = store.has_session(user_google_email)
                                if has_recent_auth:
                                    logger.info(f"[{tool_name}] User {user_google_email} has recent auth session (client not sending bearer token)")
                            except Exception:
                                pass
                            
                            is_authenticated_request = (
                                auth_token_email is not None or 
                                (session_ctx is not None and session_ctx.user_id) or
                                mcp_user is not None or
                                has_recent_auth  # Allow if user has authenticated (still validates in OAuth21SessionStore)
                            )
                    
                    session_id_for_log = mcp_session_id if mcp_session_id else (session_ctx.session_id if session_ctx else 'None')
                    auth_method = "none"
                    if authenticated_user:
                        if bearer_token:
                            auth_method = "bearer_token"
                        elif auth_token_email:
                            auth_method = "fastmcp_context"
                        else:
                            auth_method = "session"
                    
                    logger.info(f"[{tool_name}] Authentication Status:"
                              f" Method={auth_method},"
                              f" OAuth21={OAUTH21_INTEGRATION_AVAILABLE},"
                              f" Authenticated={is_authenticated_request},"
                              f" User={authenticated_user or 'none'},"
                              f" SessionID={session_id_for_log},"
                              f" MCPSessionID={mcp_session_id or 'none'}")
                    
                    # CRITICAL SECURITY: Check if OAuth 2.1 is enabled AND we're in HTTP mode
                    from core.config import get_transport_mode
                    transport_mode = get_transport_mode()
                    
                    # Check if OAuth 2.1 provider is configured (not just transport mode)
                    oauth21_enabled = False
                    try:
                        from core.server import get_auth_provider
                        auth_provider = get_auth_provider()
                        oauth21_enabled = auth_provider is not None
                    except Exception:
                        pass
                    
                    if transport_mode == "streamable-http" and oauth21_enabled:
                        # OAuth 2.1 is enabled - REQUIRE authentication, no fallback to files
                        if not is_authenticated_request:
                            logger.error(f"[{tool_name}] SECURITY: Unauthenticated request denied in OAuth 2.1 mode")
                            raise Exception(
                                "Authentication required. This server is configured with OAuth 2.1 authentication. "
                                "Please authenticate first using the OAuth flow before accessing resources."
                            )
                        
                        # Additional security: Verify the authenticated user matches the requested user
                        # Only enforce this if we have a verified authenticated user from a token
                        if authenticated_user and authenticated_user != user_google_email:
                            logger.warning(
                                f"[{tool_name}] User mismatch - token authenticated as {authenticated_user} "
                                f"but requesting resources for {user_google_email}"
                            )
                            # The OAuth21SessionStore will handle the actual validation
                        
                        # Must use OAuth 2.1 authentication
                        logger.info(f"[{tool_name}] Using OAuth 2.1 authentication (required for OAuth 2.1 mode)")
                        
                        # CRITICAL SECURITY: Never use allow_recent_auth in OAuth 2.1 mode
                        # This should always be False in streamable-http mode
                        allow_recent = False  # Explicitly disable for OAuth 2.1 mode
                        
                        service, actual_user_email = await get_authenticated_google_service_oauth21(
                            service_name=service_name,
                            version=service_version,
                            tool_name=tool_name,
                            user_google_email=user_google_email,
                            required_scopes=resolved_scopes,
                            session_id=mcp_session_id or (session_ctx.session_id if session_ctx else None),
                            auth_token_email=auth_token_email or authenticated_user,  # Pass authenticated user
                            allow_recent_auth=allow_recent,  # Allow recent auth for clients that don't send tokens
                        )
                    elif OAUTH21_INTEGRATION_AVAILABLE and is_authenticated_request:
                        # In other modes, use OAuth 2.1 if available
                        logger.info(f"[{tool_name}] Using OAuth 2.1 authentication")
                        service, actual_user_email = await get_authenticated_google_service_oauth21(
                            service_name=service_name,
                            version=service_version,
                            tool_name=tool_name,
                            user_google_email=user_google_email,
                            required_scopes=resolved_scopes,
                            session_id=mcp_session_id or (session_ctx.session_id if session_ctx else None),
                            auth_token_email=auth_token_email,
                        )
                    else:
                        # Fall back to legacy authentication ONLY in stdio mode
                        if transport_mode == "stdio":
                            session_id_for_legacy = mcp_session_id if mcp_session_id else (session_ctx.session_id if session_ctx else None)
                            logger.info(f"[{tool_name}] Using legacy authentication (stdio mode)")
                            
                            # In stdio mode, first try to get credentials from OAuth21 store with allow_recent_auth
                            # This handles the case where user just completed OAuth flow
                            # CRITICAL SECURITY: allow_recent_auth=True is ONLY safe in stdio mode because:
                            # 1. Stdio mode is single-user by design
                            # 2. No bearer tokens are available in stdio mode
                            # 3. This allows access immediately after OAuth callback
                            # NEVER use allow_recent_auth=True in multi-user OAuth 2.1 mode!
                            if OAUTH21_INTEGRATION_AVAILABLE:
                                try:
                                    service, actual_user_email = await get_authenticated_google_service_oauth21(
                                        service_name=service_name,
                                        version=service_version,
                                        tool_name=tool_name,
                                        user_google_email=user_google_email,
                                        required_scopes=resolved_scopes,
                                        session_id=session_id_for_legacy,
                                        auth_token_email=None,
                                        allow_recent_auth=True,  # ONLY safe in stdio single-user mode!
                                    )
                                    logger.info(f"[{tool_name}] Successfully used OAuth21 store in stdio mode")
                                except Exception as oauth_error:
                                    logger.debug(f"[{tool_name}] OAuth21 store failed in stdio mode, falling back to legacy: {oauth_error}")
                                    # Fall back to traditional file-based auth
                                    service, actual_user_email = await get_authenticated_google_service(
                                        service_name=service_name,
                                        version=service_version,
                                        tool_name=tool_name,
                                        user_google_email=user_google_email,
                                        required_scopes=resolved_scopes,
                                        session_id=session_id_for_legacy,
                                    )
                            else:
                                # No OAuth21 integration, use legacy directly
                                service, actual_user_email = await get_authenticated_google_service(
                                    service_name=service_name,
                                    version=service_version,
                                    tool_name=tool_name,
                                    user_google_email=user_google_email,
                                    required_scopes=resolved_scopes,
                                    session_id=session_id_for_legacy,
                                )
                        else:
                            logger.error(f"[{tool_name}] No authentication available in {transport_mode} mode")
                            raise Exception(f"Authentication not available in {transport_mode} mode")
                    
                    if cache_enabled:
                        cache_key = _get_cache_key(user_google_email, service_name, service_version, resolved_scopes)
                        _cache_service(cache_key, service, actual_user_email)
                except GoogleAuthenticationError as e:
                    raise Exception(str(e))

            # --- Call the original function with the service object injected ---
            try:
                # Prepend the fetched service object to the original arguments
                return await func(service, *args, **kwargs)
            except RefreshError as e:
                error_message = _handle_token_refresh_error(e, actual_user_email, service_name)
                raise Exception(error_message)

        # Set the wrapper's signature to the one without 'service'
        wrapper.__signature__ = wrapper_sig
        return wrapper
    return decorator


def require_multiple_services(service_configs: List[Dict[str, Any]]):
    """
    Decorator for functions that need multiple Google services.

    Args:
        service_configs: List of service configurations, each containing:
            - service_type: Type of service
            - scopes: Required scopes
            - param_name: Name to inject service as (e.g., 'drive_service', 'docs_service')
            - version: Optional version override

    Usage:
        @require_multiple_services([
            {"service_type": "drive", "scopes": "drive_read", "param_name": "drive_service"},
            {"service_type": "docs", "scopes": "docs_read", "param_name": "docs_service"}
        ])
        async def get_doc_with_metadata(drive_service, docs_service, user_google_email: str, doc_id: str):
            # Both services are automatically injected
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract user_google_email
            sig = inspect.signature(func)
            param_names = list(sig.parameters.keys())

            user_google_email = None
            if 'user_google_email' in kwargs:
                user_google_email = kwargs['user_google_email']
            else:
                try:
                    user_email_index = param_names.index('user_google_email')
                    if user_email_index < len(args):
                        user_google_email = args[user_email_index]
                except ValueError:
                    pass

            if not user_google_email:
                raise Exception("user_google_email parameter is required but not found")

            # Authenticate all services
            for config in service_configs:
                service_type = config["service_type"]
                scopes = config["scopes"]
                param_name = config["param_name"]
                version = config.get("version")

                if service_type not in SERVICE_CONFIGS:
                    raise Exception(f"Unknown service type: {service_type}")

                service_config = SERVICE_CONFIGS[service_type]
                service_name = service_config["service"]
                service_version = version or service_config["version"]
                resolved_scopes = _resolve_scopes(scopes)

                try:
                    tool_name = func.__name__
                    
                    # Check if OAuth 2.1 is enabled AND we're in HTTP mode
                    from core.config import get_transport_mode
                    transport_mode = get_transport_mode()
                    
                    # Check if OAuth 2.1 provider is configured
                    oauth21_enabled = False
                    try:
                        from core.server import get_auth_provider
                        auth_provider = get_auth_provider()
                        oauth21_enabled = auth_provider is not None
                    except Exception:
                        pass
                    
                    # In OAuth 2.1 mode, require authentication
                    if transport_mode == "streamable-http" and oauth21_enabled:
                        if not (OAUTH21_INTEGRATION_AVAILABLE and get_session_context()):
                            logger.error(f"[{tool_name}] SECURITY: Unauthenticated request denied in OAuth 2.1 mode")
                            raise Exception(
                                "Authentication required. This server is configured with OAuth 2.1 authentication. "
                                "Please authenticate first using the OAuth flow before accessing resources."
                            )
                        
                        logger.debug(f"OAuth 2.1 authentication for {tool_name} ({service_type})")
                        service, _ = await get_authenticated_google_service_oauth21(
                            service_name=service_name,
                            version=service_version,
                            tool_name=tool_name,
                            user_google_email=user_google_email,
                            required_scopes=resolved_scopes,
                        )
                    elif OAUTH21_INTEGRATION_AVAILABLE and get_session_context():
                        logger.debug(f"Attempting OAuth 2.1 authentication for {tool_name} ({service_type})")
                        service, _ = await get_authenticated_google_service_oauth21(
                            service_name=service_name,
                            version=service_version,
                            tool_name=tool_name,
                            user_google_email=user_google_email,
                            required_scopes=resolved_scopes,
                        )
                    else:
                        # Fall back to legacy authentication ONLY in stdio mode
                        if transport_mode == "stdio":
                            service, _ = await get_authenticated_google_service(
                                service_name=service_name,
                                version=service_version,
                                tool_name=tool_name,
                                user_google_email=user_google_email,
                                required_scopes=resolved_scopes,
                            )
                        else:
                            logger.error(f"[{tool_name}] No authentication available in {transport_mode} mode")
                            raise Exception(f"Authentication not available in {transport_mode} mode")

                    # Inject service with specified parameter name
                    kwargs[param_name] = service

                except GoogleAuthenticationError as e:
                    raise Exception(str(e))

            # Call the original function with refresh error handling
            try:
                return await func(*args, **kwargs)
            except RefreshError as e:
                # Handle token refresh errors gracefully
                error_message = _handle_token_refresh_error(e, user_google_email, "Multiple Services")
                raise Exception(error_message)

        return wrapper
    return decorator


def clear_service_cache(user_email: Optional[str] = None) -> int:
    """
    Clear service cache entries.

    Args:
        user_email: If provided, only clear cache for this user. If None, clear all.

    Returns:
        Number of cache entries cleared.
    """
    global _service_cache

    if user_email is None:
        count = len(_service_cache)
        _service_cache.clear()
        logger.info(f"Cleared all {count} service cache entries")
        return count

    keys_to_remove = [key for key in _service_cache.keys() if key.startswith(f"{user_email}:")]
    for key in keys_to_remove:
        del _service_cache[key]

    logger.info(f"Cleared {len(keys_to_remove)} service cache entries for user {user_email}")
    return len(keys_to_remove)


def get_cache_stats() -> Dict[str, Any]:
    """Get service cache statistics."""
    valid_entries = 0
    expired_entries = 0

    for _, (_, cached_time, _) in _service_cache.items():
        if _is_cache_valid(cached_time):
            valid_entries += 1
        else:
            expired_entries += 1

    return {
        "total_entries": len(_service_cache),
        "valid_entries": valid_entries,
        "expired_entries": expired_entries,
        "cache_ttl_minutes": _cache_ttl.total_seconds() / 60
    }