"""
Authentication Middleware

Middleware to bind requests to sessions and handle OAuth 2.1 authentication.
Integrates token validation, session management, and request context.
"""

import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Callable

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .discovery import AuthorizationServerDiscovery
from .tokens import TokenValidator, TokenValidationError
from .sessions import SessionStore, Session
from .http import HTTPAuthHandler

logger = logging.getLogger(__name__)


@dataclass
class AuthContext:
    """Authentication context attached to requests."""
    
    authenticated: bool = False
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    session: Optional[Session] = None
    token_info: Optional[Dict[str, Any]] = None
    scopes: List[str] = None
    error: Optional[str] = None
    error_description: Optional[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware to bind requests to sessions and handle authentication."""

    def __init__(
        self,
        app,
        session_store: SessionStore,
        token_validator: Optional[TokenValidator] = None,
        discovery_service: Optional[AuthorizationServerDiscovery] = None,
        http_auth_handler: Optional[HTTPAuthHandler] = None,
        required_scopes: Optional[List[str]] = None,
        exempt_paths: Optional[List[str]] = None,
        authorization_server_url: Optional[str] = None,
        expected_audience: Optional[str] = None,
        enable_bearer_passthrough: bool = True,
    ):
        """
        Initialize authentication middleware.

        Args:
            app: FastAPI application
            session_store: Session store instance
            token_validator: Token validator instance
            discovery_service: Authorization server discovery service
            http_auth_handler: HTTP authentication handler
            required_scopes: Default required scopes
            exempt_paths: Paths exempt from authentication
            authorization_server_url: Default authorization server URL
            expected_audience: Expected token audience
            enable_bearer_passthrough: Enable Bearer token passthrough mode
        """
        super().__init__(app)
        
        self.session_store = session_store
        self.token_validator = token_validator or TokenValidator(discovery_service)
        self.discovery = discovery_service or AuthorizationServerDiscovery()
        self.http_auth = http_auth_handler or HTTPAuthHandler()
        self.required_scopes = required_scopes or []
        self.exempt_paths = set(exempt_paths or ["/health", "/oauth2callback", "/.well-known/"])
        self.authorization_server_url = authorization_server_url
        self.expected_audience = expected_audience
        self.enable_bearer_passthrough = enable_bearer_passthrough

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        """Process request through authentication middleware."""
        
        # Check if path is exempt from authentication
        if self._is_exempt_path(request.url.path):
            request.state.auth = AuthContext()
            return await call_next(request)

        # Perform authentication
        auth_context = await self.authenticate_request(request)
        
        # Attach authentication context to request
        request.state.auth = auth_context
        
        # Handle authentication failures
        if not auth_context.authenticated and self._requires_authentication(request):
            return self._create_auth_error_response(auth_context)
        
        # Continue with request processing
        return await call_next(request)

    async def authenticate_request(self, request: Request) -> AuthContext:
        """
        Validate token and resolve session for request.

        Args:
            request: HTTP request

        Returns:
            Authentication context
        """
        auth_context = AuthContext()
        
        try:
            # Extract token information
            token_info = self.http_auth.get_token_info_from_headers(dict(request.headers))
            
            if not token_info["has_bearer_token"]:
                auth_context.error = "missing_token"
                auth_context.error_description = "No Bearer token provided"
                return auth_context
            
            if not token_info["valid_format"]:
                auth_context.error = "invalid_token"
                auth_context.error_description = "Invalid Bearer token format"
                return auth_context
            
            token = token_info["token"]
            
            # Try session-based authentication first
            session_id = self._extract_session_id(request)
            if session_id:
                session = self.session_store.get_session(session_id)
                if session:
                    # Validate that token matches session
                    if await self._validate_session_token(session, token):
                        auth_context = self._create_session_auth_context(session)
                        return auth_context
                    else:
                        logger.warning(f"Token mismatch for session {session_id}")
            
            # Fall back to direct token validation
            if self.enable_bearer_passthrough:
                auth_context = await self._validate_bearer_token(token, request)
                
                # Create session if token is valid and no session exists
                if auth_context.authenticated and not session_id:
                    session_id = self._create_session_from_token(auth_context)
                    auth_context.session_id = session_id
                
                return auth_context
            else:
                auth_context.error = "invalid_session"
                auth_context.error_description = "Valid session required"
                return auth_context
                
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            auth_context.error = "server_error"
            auth_context.error_description = "Internal authentication error"
            return auth_context

    async def _validate_bearer_token(self, token: str, request: Request) -> AuthContext:
        """Validate Bearer token directly."""
        auth_context = AuthContext()
        
        try:
            # Validate token
            token_result = await self.token_validator.validate_token(
                token=token,
                expected_audience=self.expected_audience,
                required_scopes=self.required_scopes,
                authorization_server_url=self.authorization_server_url,
            )
            
            if token_result["valid"]:
                auth_context.authenticated = True
                auth_context.user_id = token_result["user_identity"]
                auth_context.token_info = token_result
                auth_context.scopes = token_result.get("scopes", [])
                
                logger.debug(f"Successfully validated Bearer token for user {auth_context.user_id}")
            else:
                auth_context.error = "invalid_token"
                auth_context.error_description = "Token validation failed"
                
        except TokenValidationError as e:
            auth_context.error = e.error_code
            auth_context.error_description = str(e)
            logger.warning(f"Token validation failed: {e}")
        except Exception as e:
            auth_context.error = "server_error"
            auth_context.error_description = "Token validation error"
            logger.error(f"Token validation error: {e}")
        
        return auth_context

    async def _validate_session_token(self, session: Session, token: str) -> bool:
        """Validate that token matches session."""
        try:
            # Compare token with session token info
            session_token = session.token_info.get("access_token")
            if not session_token:
                return False
            
            # Direct token comparison
            if session_token == token:
                return True
            
            # For JWT tokens, compare claims
            if self.token_validator._is_jwt_format(token):
                try:
                    token_payload = self.token_validator.decode_jwt_payload(token)
                    session_payload = session.token_info.get("claims", {})
                    
                    # Compare key claims
                    key_claims = ["sub", "email", "aud", "iss"]
                    for claim in key_claims:
                        if claim in token_payload and claim in session_payload:
                            if token_payload[claim] != session_payload[claim]:
                                return False
                    
                    return True
                except Exception:
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Session token validation error: {e}")
            return False

    def _create_session_auth_context(self, session: Session) -> AuthContext:
        """Create authentication context from session."""
        return AuthContext(
            authenticated=True,
            user_id=session.user_id,
            session_id=session.session_id,
            session=session,
            token_info=session.token_info,
            scopes=session.scopes,
        )

    def _create_session_from_token(self, auth_context: AuthContext) -> Optional[str]:
        """Create new session from validated token."""
        if not auth_context.authenticated or not auth_context.user_id:
            return None
        
        try:
            session_id = self.session_store.create_session(
                user_id=auth_context.user_id,
                token_info=auth_context.token_info,
                scopes=auth_context.scopes,
                authorization_server=auth_context.token_info.get("issuer"),
                metadata={
                    "created_via": "bearer_token",
                    "token_type": auth_context.token_info.get("token_type"),
                }
            )
            
            logger.info(f"Created session {session_id} for user {auth_context.user_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None

    def _extract_session_id(self, request: Request) -> Optional[str]:
        """Extract session ID from request."""
        # Try different sources for session ID
        
        # 1. MCP-Session-Id header (primary)
        session_id = request.headers.get("mcp-session-id") or request.headers.get("Mcp-Session-Id")
        if session_id:
            return session_id
        
        # 2. X-Session-ID header (alternative)
        session_id = request.headers.get("x-session-id") or request.headers.get("X-Session-ID")
        if session_id:
            return session_id
        
        # 3. Query parameter
        session_id = request.query_params.get("session_id")
        if session_id:
            return session_id
        
        return None

    def _is_exempt_path(self, path: str) -> bool:
        """Check if path is exempt from authentication."""
        for exempt_path in self.exempt_paths:
            if path.startswith(exempt_path):
                return True
        return False

    def _requires_authentication(self, request: Request) -> bool:
        """Check if request requires authentication."""
        # For now, all non-exempt paths require authentication
        # This could be extended with more sophisticated rules
        return True

    def _create_auth_error_response(self, auth_context: AuthContext) -> JSONResponse:
        """Create authentication error response."""
        
        # Determine status code
        if auth_context.error == "missing_token":
            status_code = 401
        elif auth_context.error in ["invalid_token", "invalid_session"]:
            status_code = 401
        elif auth_context.error == "insufficient_scope":
            status_code = 403
        else:
            status_code = 401
        
        # Build error response
        error_data = {
            "error": auth_context.error or "unauthorized",
            "error_description": auth_context.error_description or "Authentication required",
        }
        
        # Build WWW-Authenticate header
        www_auth_header = self.http_auth.build_www_authenticate_header(
            realm="mcp-server",
            error=auth_context.error,
            error_description=auth_context.error_description,
            scope=" ".join(self.required_scopes) if self.required_scopes else None,
        )
        
        headers = {
            "WWW-Authenticate": www_auth_header,
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        
        return JSONResponse(
            status_code=status_code,
            content=error_data,
            headers=headers,
        )

    def attach_session_to_request(self, request: Request, session: Session) -> None:
        """
        Attach session context to request.

        Args:
            request: HTTP request
            session: Session to attach
        """
        auth_context = self._create_session_auth_context(session)
        request.state.auth = auth_context

    async def close(self):
        """Clean up middleware resources."""
        await self.token_validator.close()
        await self.discovery.close()


def get_auth_context(request: Request) -> AuthContext:
    """
    Get authentication context from request.

    Args:
        request: HTTP request

    Returns:
        Authentication context
    """
    return getattr(request.state, "auth", AuthContext())


def require_auth(request: Request) -> AuthContext:
    """
    Require authentication and return context.

    Args:
        request: HTTP request

    Returns:
        Authentication context

    Raises:
        HTTPException: If not authenticated
    """
    auth_context = get_auth_context(request)
    
    if not auth_context.authenticated:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return auth_context


def require_scopes(request: Request, required_scopes: List[str]) -> AuthContext:
    """
    Require specific scopes and return context.

    Args:
        request: HTTP request
        required_scopes: Required OAuth scopes

    Returns:
        Authentication context

    Raises:
        HTTPException: If scopes insufficient
    """
    auth_context = require_auth(request)
    
    missing_scopes = set(required_scopes) - set(auth_context.scopes)
    if missing_scopes:
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient scope. Missing: {', '.join(missing_scopes)}",
            headers={
                "WWW-Authenticate": f'Bearer scope="{" ".join(required_scopes)}", error="insufficient_scope"'
            },
        )
    
    return auth_context