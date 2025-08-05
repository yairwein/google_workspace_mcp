"""
Authentication middleware to populate context state with user information
"""
import jwt
import logging
import os
import time
from types import SimpleNamespace
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers

# Configure logging
logger = logging.getLogger(__name__)


class AuthInfoMiddleware(Middleware):
    """
    Middleware to extract authentication information from JWT tokens
    and populate the FastMCP context state for use in tools and prompts.
    """
    
    def __init__(self):
        super().__init__()
        self.auth_provider_type = "Unknown"
    
    async def _process_request_for_auth(self, context: MiddlewareContext):
        """Helper to extract, verify, and store auth info from a request."""
        if not context.fastmcp_context:
            logger.warning("No fastmcp_context available")
            return

        # Return early if authentication state is already set
        if context.fastmcp_context.get_state("authenticated_user_email"):
            logger.info("Authentication state already set.")
            return

        # Try to get the HTTP request to extract Authorization header
        try:
            # Use the new FastMCP method to get HTTP headers
            headers = get_http_headers()
            if headers:
                logger.info(f"Got HTTP headers: {type(headers)}")
                
                # Get the Authorization header
                auth_header = headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    token_str = auth_header[7:]  # Remove "Bearer " prefix
                    logger.info("Found Bearer token in HTTP request")
                    
                    # For Google OAuth tokens (ya29.*), we need to verify them differently
                    if token_str.startswith("ya29."):
                        logger.info("Detected Google OAuth access token")
                        
                        # Verify the token to get user info
                        from core.server import get_auth_provider
                        auth_provider = get_auth_provider()
                        
                        if auth_provider:
                            try:
                                # Verify the token
                                verified_auth = await auth_provider.verify_token(token_str)
                                if verified_auth:
                                    # Extract user info from verified token
                                    user_email = None
                                    if hasattr(verified_auth, 'claims'):
                                        user_email = verified_auth.claims.get("email")
                                    
                                    # Get expires_at, defaulting to 1 hour from now if not available
                                    if hasattr(verified_auth, 'expires_at'):
                                        expires_at = verified_auth.expires_at
                                    else:
                                        expires_at = int(time.time()) + 3600  # Default to 1 hour
                                    
                                    # Get client_id from verified auth or use default
                                    client_id = getattr(verified_auth, 'client_id', None) or "google"
                                    
                                    access_token = SimpleNamespace(
                                        token=token_str,
                                        client_id=client_id,
                                        scopes=verified_auth.scopes if hasattr(verified_auth, 'scopes') else [],
                                        session_id=f"google_oauth_{token_str[:8]}",
                                        expires_at=expires_at,
                                        # Add other fields that might be needed
                                        sub=verified_auth.sub if hasattr(verified_auth, 'sub') else user_email,
                                        email=user_email
                                    )
                                    
                                    # Store in context state - this is the authoritative authentication state
                                    context.fastmcp_context.set_state("access_token", access_token)
                                    context.fastmcp_context.set_state("auth_provider_type", self.auth_provider_type)
                                    context.fastmcp_context.set_state("token_type", "google_oauth")
                                    context.fastmcp_context.set_state("user_email", user_email)
                                    context.fastmcp_context.set_state("username", user_email)
                                    # Set the definitive authentication state
                                    context.fastmcp_context.set_state("authenticated_user_email", user_email)
                                    context.fastmcp_context.set_state("authenticated_via", "bearer_token")
                                    
                                    logger.info(f"Stored verified Google OAuth token for user: {user_email}")
                                else:
                                    logger.error("Failed to verify Google OAuth token")
                                # Don't set authenticated_user_email if verification failed
                            except Exception as e:
                                logger.error(f"Error verifying Google OAuth token: {e}")
                                # Still store the unverified token - service decorator will handle verification
                                access_token = SimpleNamespace(
                                    token=token_str,
                                    client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID", "google"),
                                    scopes=[],
                                    session_id=f"google_oauth_{token_str[:8]}",
                                    expires_at=int(time.time()) + 3600,  # Default to 1 hour
                                    sub="unknown",
                                    email=""
                                )
                                context.fastmcp_context.set_state("access_token", access_token)
                                context.fastmcp_context.set_state("auth_provider_type", self.auth_provider_type)
                                context.fastmcp_context.set_state("token_type", "google_oauth")
                        else:
                            logger.warning("No auth provider available to verify Google token")
                            # Store unverified token
                            access_token = SimpleNamespace(
                                token=token_str,
                                client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID", "google"),
                                scopes=[],
                                session_id=f"google_oauth_{token_str[:8]}",
                                expires_at=int(time.time()) + 3600,  # Default to 1 hour
                                sub="unknown",
                                email=""
                            )
                            context.fastmcp_context.set_state("access_token", access_token)
                            context.fastmcp_context.set_state("auth_provider_type", self.auth_provider_type)
                            context.fastmcp_context.set_state("token_type", "google_oauth")
                        
                    else:
                        # Decode JWT to get user info
                        try:
                            token_payload = jwt.decode(
                                token_str,
                                options={"verify_signature": False}
                            )
                            logger.debug(f"JWT payload decoded: {list(token_payload.keys())}")
                            
                            # Create an AccessToken-like object
                            access_token = SimpleNamespace(
                                token=token_str,
                                client_id=token_payload.get("client_id", "unknown"),
                                scopes=token_payload.get("scope", "").split() if token_payload.get("scope") else [],
                                session_id=token_payload.get("sid", token_payload.get("jti", token_payload.get("session_id", "unknown"))),
                                expires_at=token_payload.get("exp", 0)
                            )
                            
                            # Store in context state
                            context.fastmcp_context.set_state("access_token", access_token)
                            
                            # Store additional user info
                            context.fastmcp_context.set_state("user_id", token_payload.get("sub"))
                            context.fastmcp_context.set_state("username", token_payload.get("username", token_payload.get("email")))
                            context.fastmcp_context.set_state("name", token_payload.get("name"))
                            context.fastmcp_context.set_state("auth_time", token_payload.get("auth_time"))
                            context.fastmcp_context.set_state("issuer", token_payload.get("iss"))
                            context.fastmcp_context.set_state("audience", token_payload.get("aud"))
                            context.fastmcp_context.set_state("jti", token_payload.get("jti"))
                            context.fastmcp_context.set_state("auth_provider_type", self.auth_provider_type)
                            
                            # Set the definitive authentication state for JWT tokens
                            user_email = token_payload.get("email", token_payload.get("username"))
                            if user_email:
                                context.fastmcp_context.set_state("authenticated_user_email", user_email)
                                context.fastmcp_context.set_state("authenticated_via", "jwt_token")
                            
                            logger.info("Successfully extracted and stored auth info from HTTP request")
                            
                        except jwt.DecodeError as e:
                            logger.error(f"Failed to decode JWT: {e}")
                        except Exception as e:
                            logger.error(f"Error processing JWT: {e}")
                else:
                    logger.debug("No Bearer token in Authorization header")
            else:
                logger.debug("No HTTP headers available (might be using stdio transport)")
        except Exception as e:
            logger.debug(f"Could not get HTTP request: {e}")
        
        # After trying HTTP headers, check for other authentication methods
        # This consolidates all authentication logic in the middleware
        if not context.fastmcp_context.get_state("authenticated_user_email"):
            logger.debug("No authentication found via bearer token, checking other methods")
            
            # Check transport mode
            from core.config import get_transport_mode
            transport_mode = get_transport_mode()
            
            if transport_mode == "stdio":
                # In stdio mode, check if there's a session with credentials
                # This is ONLY safe in stdio mode because it's single-user
                logger.debug("Checking for stdio mode authentication")
                
                # Get the requested user from the context if available
                requested_user = None
                if hasattr(context, 'request') and hasattr(context.request, 'params'):
                    requested_user = context.request.params.get('user_google_email')
                elif hasattr(context, 'arguments'):
                    # FastMCP may store arguments differently
                    requested_user = context.arguments.get('user_google_email')
                
                if requested_user:
                    try:
                        from auth.oauth21_session_store import get_oauth21_session_store
                        store = get_oauth21_session_store()
                        
                        # Check if user has a recent session
                        if store.has_session(requested_user):
                            logger.info(f"User {requested_user} has recent auth session in stdio mode")
                            # In stdio mode, we can trust the user has authenticated recently
                            context.fastmcp_context.set_state("authenticated_user_email", requested_user)
                            context.fastmcp_context.set_state("authenticated_via", "stdio_session")
                            context.fastmcp_context.set_state("auth_provider_type", "oauth21_stdio")
                    except Exception as e:
                        logger.debug(f"Error checking stdio session: {e}")
            
            # Check for MCP session binding
            if not context.fastmcp_context.get_state("authenticated_user_email") and hasattr(context.fastmcp_context, 'session_id'):
                mcp_session_id = context.fastmcp_context.session_id
                if mcp_session_id:
                    try:
                        from auth.oauth21_session_store import get_oauth21_session_store
                        store = get_oauth21_session_store()
                        
                        # Check if this MCP session is bound to a user
                        bound_user = store.get_user_by_mcp_session(mcp_session_id)
                        if bound_user:
                            logger.info(f"MCP session {mcp_session_id} is bound to user {bound_user}")
                            context.fastmcp_context.set_state("authenticated_user_email", bound_user)
                            context.fastmcp_context.set_state("authenticated_via", "mcp_session_binding")
                            context.fastmcp_context.set_state("auth_provider_type", "oauth21_session")
                    except Exception as e:
                        logger.debug(f"Error checking MCP session binding: {e}")
    
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Extract auth info from token and set in context state"""
        logger.info("on_call_tool called")
        
        try:
            await self._process_request_for_auth(context)
            
            logger.info("Calling next middleware/handler")
            result = await call_next(context)
            logger.info("Successfully completed call_next()")
            return result
            
        except Exception as e:
            # Check if this is an authentication error - don't log traceback for these
            if "GoogleAuthenticationError" in str(type(e)) or "Access denied: Cannot retrieve credentials" in str(e):
                logger.info(f"Authentication check failed: {e}")
            else:
                logger.error(f"Error in on_call_tool middleware: {e}", exc_info=True)
            raise
    
    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        """Extract auth info for prompt requests too"""
        logger.info("on_get_prompt called")
        
        try:
            await self._process_request_for_auth(context)
            
            logger.info("Calling next middleware/handler for prompt")
            result = await call_next(context)
            logger.info("Successfully completed prompt call_next()")
            return result
            
        except Exception as e:
            # Check if this is an authentication error - don't log traceback for these
            if "GoogleAuthenticationError" in str(type(e)) or "Access denied: Cannot retrieve credentials" in str(e):
                logger.info(f"Authentication check failed in prompt: {e}")
            else:
                logger.error(f"Error in on_get_prompt middleware: {e}", exc_info=True)
            raise