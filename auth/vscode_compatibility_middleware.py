"""
VS Code Compatibility Middleware for OAuth 2.1

This middleware provides transparent path normalization to support VS Code's MCP client
OAuth behavior without requiring redirects. It rewrites VS Code's non-standard paths
to canonical OAuth 2.1 discovery endpoints.

Key features:
- Transparent path rewriting from /mcp/.well-known/* to /.well-known/*
- VS Code client detection utilities
- No performance overhead from HTTP redirects
- Maintains OAuth 2.1 compliance while accommodating VS Code quirks
"""

import logging
from typing import Callable, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class VSCodePathNormalizationMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware to normalize VS Code's OAuth discovery paths.
    
    VS Code's MCP client requests OAuth discovery endpoints with a /mcp prefix:
    - /mcp/.well-known/oauth-protected-resource
    - /mcp/.well-known/oauth-authorization-server  
    - /mcp/.well-known/oauth-client
    
    This middleware transparently rewrites these paths to their canonical locations
    without requiring HTTP redirects, improving performance and maintaining
    OAuth 2.1 compliance.
    """
    
    def __init__(self, app, debug: bool = False):
        super().__init__(app)
        self.debug = debug
        logger.info("VSCode path normalization middleware initialized")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request and normalize VS Code paths transparently.
        
        Args:
            request: The incoming HTTP request
            call_next: The next middleware/handler in the stack
            
        Returns:
            Response from the normalized request
        """
        original_path = request.url.path
        
        # Check if this is a VS Code OAuth discovery request
        if self._should_normalize_path(original_path):
            # Normalize the path in-place
            normalized_path = self._normalize_vscode_path(original_path)
            
            # Modify the request scope to use the normalized path
            request.scope["path"] = normalized_path
            request.scope["raw_path"] = normalized_path.encode("utf-8")
            
            # Log the path normalization for debugging
            if self.debug or self._is_vscode_client(request):
                logger.info(f"VS Code path normalization: {original_path} → {normalized_path}")
                user_agent = request.headers.get("user-agent", "unknown")
                logger.debug(f"User agent: {user_agent}")
        
        # Continue with the request (using normalized path if modified)
        response = await call_next(request)
        return response
    
    def _should_normalize_path(self, path: str) -> bool:
        """
        Determine if a path should be normalized for VS Code compatibility.
        
        Args:
            path: The request path to check
            
        Returns:
            True if the path needs normalization, False otherwise
        """
        return (
            path.startswith("/mcp/.well-known/") and
            path in [
                "/mcp/.well-known/oauth-protected-resource",
                "/mcp/.well-known/oauth-authorization-server", 
                "/mcp/.well-known/oauth-client"
            ]
        )
    
    def _normalize_vscode_path(self, path: str) -> str:
        """
        Normalize a VS Code path to its canonical OAuth 2.1 location.
        
        Args:
            path: The VS Code path to normalize
            
        Returns:
            The canonical OAuth 2.1 path
        """
        if path.startswith("/mcp/.well-known/"):
            # Remove the /mcp prefix to get canonical path
            return path.replace("/mcp", "", 1)
        return path
    
    def _is_vscode_client(self, request: Request) -> bool:
        """
        Detect if the request is from VS Code's MCP client.
        
        Args:
            request: The HTTP request to analyze
            
        Returns:
            True if the request appears to be from VS Code, False otherwise
        """
        user_agent = request.headers.get("user-agent", "").lower()
        return any(indicator in user_agent for indicator in ["vscode", "electron", "code"])


def is_vscode_client(request: Request) -> bool:
    """
    Utility function to detect VS Code MCP client requests.
    
    This function can be used by other components that need to adapt
    behavior for VS Code clients.
    
    Args:
        request: The HTTP request to analyze
        
    Returns:
        True if the request appears to be from VS Code, False otherwise
    """
    user_agent = request.headers.get("user-agent", "").lower()
    return any(indicator in user_agent for indicator in ["vscode", "electron", "code"])


def get_vscode_client_info(request: Request) -> Optional[dict]:
    """
    Extract VS Code client information from request headers.
    
    Args:
        request: The HTTP request to analyze
        
    Returns:
        Dictionary with client info if VS Code detected, None otherwise
    """
    if not is_vscode_client(request):
        return None
    
    user_agent = request.headers.get("user-agent", "")
    return {
        "is_vscode": True,
        "user_agent": user_agent,
        "client_type": "vscode-mcp",
        "headers": dict(request.headers)
    }