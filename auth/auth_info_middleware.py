"""
Authentication middleware to populate context state with user information
"""
import jwt
import logging
import os
import time
from types import SimpleNamespace
from typing import Any, Dict
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

        # Return early if token is already in state
        if context.fastmcp_context.get_state("access_token"):
            logger.info("Access token already in state.")
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
                                    
                                    # Store in context state
                                    context.fastmcp_context.set_state("access_token", access_token)
                                    context.fastmcp_context.set_state("auth_provider_type", self.auth_provider_type)
                                    context.fastmcp_context.set_state("token_type", "google_oauth")
                                    context.fastmcp_context.set_state("user_email", user_email)
                                    context.fastmcp_context.set_state("username", user_email)
                                    
                                    logger.info(f"Stored verified Google OAuth token for user: {user_email}")
                                else:
                                    logger.error("Failed to verify Google OAuth token")
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