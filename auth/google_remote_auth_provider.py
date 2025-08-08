"""
Google Workspace RemoteAuthProvider for FastMCP v2.11.1+

This module implements OAuth 2.1 authentication for Google Workspace using FastMCP's
RemoteAuthProvider pattern. It provides:

- JWT token verification using Google's public keys
- OAuth proxy endpoints to work around CORS restrictions
- Dynamic client registration workaround
- Session bridging to Google credentials for API access

This provider is used only in streamable-http transport mode with FastMCP v2.11.1+.
For earlier versions or other transport modes, the legacy GoogleWorkspaceAuthProvider is used.
"""

import os
import logging
import aiohttp
from typing import Optional, List

from starlette.routing import Route
from starlette.responses import RedirectResponse, JSONResponse
from starlette.requests import Request
from pydantic import AnyHttpUrl

try:
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    REMOTEAUTHPROVIDER_AVAILABLE = True
except ImportError:
    REMOTEAUTHPROVIDER_AVAILABLE = False
    RemoteAuthProvider = object  # Fallback for type hints
    JWTVerifier = object


# Import common OAuth handlers
from auth.oauth_common_handlers import (
    handle_oauth_authorize,
    handle_proxy_token_exchange,
    handle_oauth_protected_resource,
    handle_oauth_authorization_server,
    handle_oauth_client_config,
    handle_oauth_register
)

logger = logging.getLogger(__name__)


class GoogleRemoteAuthProvider(RemoteAuthProvider):
    """
    RemoteAuthProvider implementation for Google Workspace with VS Code compatibility.
    
    This provider extends RemoteAuthProvider to add:
    - OAuth proxy endpoints for CORS workaround
    - Dynamic client registration support
    - VS Code MCP client compatibility via path redirects
    - Enhanced session management with issuer tracking
    """
    
    def __init__(self):
        """Initialize the Google RemoteAuthProvider."""
        if not REMOTEAUTHPROVIDER_AVAILABLE:
            raise ImportError("FastMCP v2.11.1+ required for RemoteAuthProvider")
        
        # Get configuration from environment
        self.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
        self.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
        self.base_url = os.getenv("WORKSPACE_MCP_BASE_URI", "http://localhost")
        self.port = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", 8000)))
        
        if not self.client_id:
            logger.error("GOOGLE_OAUTH_CLIENT_ID not set - OAuth 2.1 authentication will not work")
            raise ValueError("GOOGLE_OAUTH_CLIENT_ID environment variable is required for OAuth 2.1 authentication")
        
        # Configure JWT verifier for Google tokens
        token_verifier = JWTVerifier(
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
            issuer="https://accounts.google.com",
            audience=self.client_id,  # Always use actual client_id
            algorithm="RS256"
        )
        
        # Initialize RemoteAuthProvider with correct resource URL (no /mcp suffix)
        super().__init__(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(f"{self.base_url}:{self.port}")],
            resource_server_url=f"{self.base_url}:{self.port}"  # Correct: identifies the actual server
        )
        
        logger.debug("GoogleRemoteAuthProvider initialized with VS Code compatibility")
    
    def get_routes(self) -> List[Route]:
        """
        Add OAuth routes with VS Code compatibility redirects.
        """
        # Get the standard OAuth protected resource routes from RemoteAuthProvider
        routes = super().get_routes()
        
        # Add standard OAuth discovery endpoints at canonical locations
        routes.append(Route(
            "/.well-known/oauth-protected-resource",
            self._handle_discovery_with_logging,
            methods=["GET", "OPTIONS"]
        ))
        
        routes.append(Route(
            "/.well-known/oauth-authorization-server",
            handle_oauth_authorization_server,
            methods=["GET", "OPTIONS"]
        ))
        
        routes.append(Route(
            "/.well-known/oauth-client",
            handle_oauth_client_config,
            methods=["GET", "OPTIONS"]
        ))
        
        # VS Code Compatibility: Redirect /mcp/.well-known/* to canonical locations
        routes.append(Route(
            "/mcp/.well-known/oauth-protected-resource",
            self._redirect_to_canonical_discovery,
            methods=["GET", "OPTIONS"]
        ))
        
        routes.append(Route(
            "/mcp/.well-known/oauth-authorization-server",
            self._redirect_to_canonical_discovery,
            methods=["GET", "OPTIONS"]
        ))
        
        routes.append(Route(
            "/mcp/.well-known/oauth-client",
            self._redirect_to_canonical_discovery,
            methods=["GET", "OPTIONS"]
        ))
        
        # Add OAuth flow endpoints
        routes.append(Route("/oauth2/authorize", handle_oauth_authorize, methods=["GET", "OPTIONS"]))
        routes.append(Route("/oauth2/token", handle_proxy_token_exchange, methods=["POST", "OPTIONS"]))
        routes.append(Route("/oauth2/register", handle_oauth_register, methods=["POST", "OPTIONS"]))
        
        logger.info(f"Registered {len(routes)} OAuth routes with VS Code compatibility")
        return routes
    
    async def _handle_discovery_with_logging(self, request: Request):
        """
        Handle discovery requests with enhanced logging for debugging VS Code integration.
        """
        # Log request details for debugging
        user_agent = request.headers.get("user-agent", "unknown")
        logger.info(f"Discovery request from: {user_agent}")
        logger.info(f"Request path: {request.url.path}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        
        # Detect VS Code client
        if self._is_vscode_client(request):
            logger.info("VS Code MCP client detected")
        
        # Return standard OAuth discovery response
        return await handle_oauth_protected_resource(request)
    
    async def _redirect_to_canonical_discovery(self, request: Request):
        """
        Redirect VS Code's /mcp/.well-known/* requests to canonical locations.
        
        This maintains OAuth 2.1 compliance while accommodating VS Code's path behavior.
        """
        # Handle OPTIONS for CORS preflight
        if request.method == "OPTIONS":
            return JSONResponse(
                content={},
                headers=self._get_cors_headers()
            )
        
        # Extract the discovery endpoint from the path
        path = request.url.path
        canonical_path = path.replace("/mcp/", "/", 1)
        
        logger.info(f"Redirecting VS Code discovery request from {path} to {canonical_path}")
        
        # Use 301 Permanent Redirect to help VS Code cache the correct location
        return RedirectResponse(
            url=canonical_path,
            status_code=301,
            headers=self._get_cors_headers()
        )
    
    def _is_vscode_client(self, request: Request) -> bool:
        """
        Detect if the request is from VS Code's MCP client.
        """
        user_agent = request.headers.get("user-agent", "").lower()
        return "vscode" in user_agent or "electron" in user_agent or "code" in user_agent
    
    def _get_cors_headers(self) -> dict:
        """
        Get CORS headers for VS Code's Electron app.
        """
        return {
            "Access-Control-Allow-Origin": "*",  # VS Code may use various origins
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Authorization, Content-Type, Accept",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "3600"
        }
    
    async def verify_token(self, token: str) -> Optional[object]:
        """
        Verify OAuth tokens with enhanced logging for VS Code debugging.
        """
        logger.debug(f"Verifying token: {token[:10]}..." if token else "No token provided")
        
        # Check if this is a Google OAuth access token (starts with ya29.)
        if token.startswith("ya29."):
            logger.debug("Detected Google OAuth access token, using tokeninfo verification")
            
            try:
                # Verify the access token using Google's tokeninfo endpoint
                async with aiohttp.ClientSession() as session:
                    url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
                    async with session.get(url) as response:
                        if response.status != 200:
                            logger.error(f"Token verification failed: {response.status}")
                            return None
                        
                        token_info = await response.json()
                        
                        # Verify the token is for our client
                        if token_info.get("aud") != self.client_id:
                            logger.error(f"Token audience mismatch: expected {self.client_id}, got {token_info.get('aud')}")
                            return None
                        
                        # Check if token is expired
                        expires_in = token_info.get("expires_in", 0)
                        if int(expires_in) <= 0:
                            logger.error("Token is expired")
                            return None
                        
                        # Create an access token object that matches the expected interface
                        from types import SimpleNamespace
                        import time
                        
                        # Calculate expires_at timestamp
                        expires_in = int(token_info.get("expires_in", 0))
                        expires_at = int(time.time()) + expires_in if expires_in > 0 else 0
                        
                        access_token = SimpleNamespace(
                            claims={
                                "email": token_info.get("email"),
                                "sub": token_info.get("sub"),
                                "aud": token_info.get("aud"),
                                "scope": token_info.get("scope", ""),
                            },
                            scopes=token_info.get("scope", "").split(),
                            token=token,
                            expires_at=expires_at,  # Add the expires_at attribute
                            client_id=self.client_id,  # Add client_id at top level
                            # Add other required fields
                            sub=token_info.get("sub", ""),
                            email=token_info.get("email", "")
                        )
                        
                        user_email = token_info.get("email")
                        if user_email:
                            from auth.oauth21_session_store import get_oauth21_session_store
                            store = get_oauth21_session_store()
                            session_id = f"google_{token_info.get('sub', 'unknown')}"
                            
                            # Try to get FastMCP session ID for binding
                            mcp_session_id = None
                            try:
                                from fastmcp.server.dependencies import get_context
                                ctx = get_context()
                                if ctx and hasattr(ctx, 'session_id'):
                                    mcp_session_id = ctx.session_id
                                    logger.debug(f"Binding MCP session {mcp_session_id} to user {user_email}")
                            except Exception:
                                pass
                            
                            # Store session with issuer information
                            store.store_session(
                                user_email=user_email,
                                access_token=token,
                                scopes=access_token.scopes,
                                session_id=session_id,
                                mcp_session_id=mcp_session_id,
                                issuer="https://accounts.google.com"
                            )
                            
                            logger.info(f"Verified OAuth token: {user_email}")
                        
                        return access_token
                        
            except Exception as e:
                logger.error(f"Error verifying Google OAuth token: {e}")
                return None
        
        else:
            # For JWT tokens, use parent's JWT verification
            logger.debug("Using JWT verification for non-OAuth token")
            access_token = await super().verify_token(token)
            
            if access_token and self.client_id:
                # Extract user information from token claims
                user_email = access_token.claims.get("email")
                if user_email:
                    from auth.oauth21_session_store import get_oauth21_session_store
                    store = get_oauth21_session_store()
                    session_id = f"google_{access_token.claims.get('sub', 'unknown')}"
                    
                    # Store session with issuer information
                    store.store_session(
                        user_email=user_email,
                        access_token=token,
                        scopes=access_token.scopes or [],
                        session_id=session_id,
                        issuer="https://accounts.google.com"
                    )
                    
                    logger.debug(f"Successfully verified JWT token for user: {user_email}")
            
            return access_token