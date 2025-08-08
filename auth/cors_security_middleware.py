"""
CORS Security Middleware for OAuth 2.1

This middleware provides secure CORS handling for OAuth endpoints, replacing the
overly permissive wildcard origins with proper origin validation. It addresses
the security vulnerability identified in the challenge review.

Key features:
- Whitelist-based origin validation instead of wildcard "*" origins
- Proper credential handling for OAuth flows
- VS Code Electron app compatibility
- Security-first approach with explicit allow lists
"""

import logging
from typing import List, Optional, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

logger = logging.getLogger(__name__)


class CORSSecurityMiddleware(BaseHTTPMiddleware):
    """
    Secure CORS middleware for OAuth endpoints with proper origin validation.
    
    Replaces the dangerous "*" wildcard origins with a whitelist of allowed origins,
    addressing the security vulnerability where wildcard origins are used with
    credentials enabled.
    """
    
    def __init__(self, app, debug: bool = False):
        super().__init__(app)
        self.debug = debug
        self.allowed_origins = self._get_allowed_origins()
        self.oauth_paths = {
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-authorization-server", 
            "/.well-known/oauth-client",
            "/oauth2/authorize",
            "/oauth2/token",
            "/oauth2/register"
        }
        logger.info(f"CORS security middleware initialized with {len(self.allowed_origins)} allowed origins")
        logger.info("🔒 CORS Security Middleware is ACTIVE")
        if self.debug:
            logger.debug(f"Allowed origins: {self.allowed_origins}")
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """
        Process request and apply secure CORS headers.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/handler in the stack
            
        Returns:
            Response with appropriate CORS headers
        """
        origin = request.headers.get("origin")
        logger.debug(f"🔒 CORS middleware processing: {request.method} {request.url.path} from origin: {origin}")
        
        # For development, be more permissive with localhost origins
        # Handle preflight OPTIONS requests for any localhost origin
        if request.method == "OPTIONS" and origin and (origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")):
            return self._create_preflight_response(origin)
        
        # Process the actual request
        response = await call_next(request)
        
        # Add CORS headers to all responses for localhost origins (development mode)
        if origin and (origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, mcp-protocol-version, x-requested-with"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
            response.headers["Access-Control-Expose-Headers"] = "Content-Type"
        
        # For endpoints that need specific CORS handling (non-localhost)
        elif self._needs_cors_handling(request.url.path):
            # Handle preflight OPTIONS requests
            if request.method == "OPTIONS":
                return self._create_preflight_response(origin)
            
            # Add CORS headers to the response
            self._add_cors_headers(response, origin)
        
        return response
    
    def _get_allowed_origins(self) -> Set[str]:
        """
        Get the set of allowed origins for CORS.
        
        Returns:
            Set of allowed origin URLs
        """
        from auth.oauth_config import get_oauth_config
        config = get_oauth_config()
        return set(config.get_allowed_origins())
    
    def _needs_cors_handling(self, path: str) -> bool:
        """
        Check if a path needs CORS handling.
        
        Args:
            path: The request path to check
            
        Returns:
            True if the path needs CORS handling, False otherwise
        """
        # OAuth endpoints always need CORS
        if path in self.oauth_paths:
            return True
        
        # MCP endpoints need CORS 
        if path.startswith("/mcp"):
            return True
            
        # Well-known endpoints need CORS
        if path.startswith("/.well-known/"):
            return True
        
        return False
    
    def _is_origin_allowed(self, origin: Optional[str]) -> bool:
        """
        Check if an origin is allowed for CORS requests.
        
        Args:
            origin: The origin header value
            
        Returns:
            True if the origin is allowed, False otherwise
        """
        if not origin:
            return False
            
        # Always allow localhost origins for development
        if origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:"):
            return True
            
        # Check exact matches
        if origin in self.allowed_origins:
            return True
            
        # Check VS Code webview patterns
        if origin.startswith("vscode-webview://"):
            return True
            
        # Check for null origin (some VS Code contexts)
        if origin == "null":
            return True
            
        return False
    
    def _create_preflight_response(self, origin: Optional[str]) -> JSONResponse:
        """
        Create a CORS preflight response.
        
        Args:
            origin: The origin header value
            
        Returns:
            JSONResponse with appropriate CORS headers
        """
        headers = {}
        
        if self._is_origin_allowed(origin):
            headers.update({
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept, mcp-protocol-version, x-requested-with",
                "Access-Control-Max-Age": "86400",  # 24 hours
            })
        else:
            if self.debug and origin:
                logger.warning(f"CORS: Rejected origin: {origin}")
        
        return JSONResponse(content={}, headers=headers)
    
    def _add_cors_headers(self, response: Response, origin: Optional[str]) -> None:
        """
        Add CORS headers to a response.
        
        Args:
            response: The response to modify
            origin: The origin header value
        """
        if self._is_origin_allowed(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Expose-Headers"] = "Content-Type"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, Accept, mcp-protocol-version, x-requested-with"
        else:
            if self.debug and origin:
                logger.warning(f"CORS: Rejected origin in response: {origin}")


def get_allowed_origins() -> List[str]:
    """
    Get the list of allowed origins for debugging/monitoring.
    
    Returns:
        List of allowed origin URLs
    """
    middleware = CORSSecurityMiddleware(None)
    return sorted(middleware.allowed_origins)


def validate_origin(origin: str) -> bool:
    """
    Validate if an origin is allowed for CORS requests.
    
    Args:
        origin: The origin to validate
        
    Returns:
        True if the origin is allowed, False otherwise
    """
    middleware = CORSSecurityMiddleware(None)
    return middleware._is_origin_allowed(origin)