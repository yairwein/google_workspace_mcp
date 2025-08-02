"""
Google Workspace Authentication Provider for FastMCP

This module implements OAuth 2.1 authentication for Google Workspace using FastMCP's
built-in authentication patterns. It acts as a Resource Server (RS) that trusts
Google as the Authorization Server (AS).

Key features:
- JWT token verification using Google's public keys
- Discovery metadata endpoints for MCP protocol compliance
- CORS proxy endpoints to work around Google's CORS limitations
- Session bridging to Google credentials for API access
"""

import os
import logging
import json
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode

import aiohttp
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.requests import Request

from fastmcp.server.auth.auth import AuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)


class GoogleWorkspaceAuthProvider(AuthProvider):
    """
    Authentication provider for Google Workspace integration.
    
    This provider implements the Remote Authentication pattern where:
    - Google acts as the Authorization Server (AS)
    - This MCP server acts as a Resource Server (RS)
    - Tokens are verified using Google's public keys
    """
    
    def __init__(self):
        """Initialize the Google Workspace auth provider."""
        super().__init__()
        
        # Get configuration from environment
        self.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
        self.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
        self.base_url = os.getenv("WORKSPACE_MCP_BASE_URI", "http://localhost")
        self.port = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", 8000)))
        
        if not self.client_id:
            logger.warning("GOOGLE_OAUTH_CLIENT_ID not set - OAuth 2.1 authentication will not work")
            return
            
        # Initialize JWT verifier for Google tokens
        self.jwt_verifier = JWTVerifier(
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
            issuer="https://accounts.google.com",
            audience=self.client_id,
            algorithm="RS256"
        )
        
        # Session store for bridging to Google credentials
        self._sessions: Dict[str, Dict[str, Any]] = {}
        
    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Verify a bearer token issued by Google.
        
        Args:
            token: The bearer token to verify
            
        Returns:
            AccessToken object if valid, None otherwise
        """
        if not self.client_id:
            return None
            
        try:
            # Use FastMCP's JWT verifier
            access_token = await self.jwt_verifier.verify_token(token)
            
            if access_token:
                # Store session info for credential bridging
                session_id = f"google_{access_token.claims.get('sub', 'unknown')}"
                self._sessions[session_id] = {
                    "access_token": token,
                    "user_email": access_token.claims.get("email"),
                    "claims": access_token.claims,
                    "scopes": access_token.scopes or []
                }
                
                logger.debug(f"Successfully verified Google token for user: {access_token.claims.get('email')}")
                
            return access_token
            
        except Exception as e:
            logger.error(f"Failed to verify Google token: {e}")
            return None
    
    def customize_auth_routes(self, routes: List[Route]) -> List[Route]:
        """
        Add custom routes for OAuth discovery and CORS proxy.
        
        This implements:
        1. Protected resource metadata endpoint (RFC9728)
        2. Authorization server discovery proxy (to avoid CORS)
        3. Token exchange proxy (to avoid CORS)
        4. Client configuration endpoint
        """
        
        # Protected Resource Metadata endpoint
        async def protected_resource_metadata(request: Request):
            """Return metadata about this protected resource."""
            metadata = {
                "resource": f"{self.base_url}:{self.port}",
                "authorization_servers": [
                    # Point to the standard well-known endpoint
                    f"{self.base_url}:{self.port}"
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
                "client_configuration_endpoint": f"{self.base_url}:{self.port}/.well-known/oauth-client"
            }
            
            return JSONResponse(
                content=metadata,
                headers={"Content-Type": "application/json"}
            )
        
        routes.append(Route("/.well-known/oauth-protected-resource", protected_resource_metadata))
        
        # OAuth authorization server metadata endpoint
        async def authorization_server_metadata(request: Request):
            """Forward authorization server metadata from Google."""
            try:
                async with aiohttp.ClientSession() as session:
                    # Try OpenID configuration first
                    url = "https://accounts.google.com/.well-known/openid-configuration"
                    async with session.get(url) as response:
                        if response.status == 200:
                            metadata = await response.json()
                            
                            # Add OAuth 2.1 required fields
                            metadata.setdefault("code_challenge_methods_supported", ["S256"])
                            metadata.setdefault("pkce_required", True)
                            
                            # Override token endpoint to use our proxy
                            metadata["token_endpoint"] = f"{self.base_url}:{self.port}/oauth2/token"
                            metadata["authorization_endpoint"] = f"{self.base_url}:{self.port}/oauth2/authorize"
                            
                            return JSONResponse(
                                content=metadata,
                                headers={
                                    "Content-Type": "application/json",
                                    "Access-Control-Allow-Origin": "*",
                                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                                }
                            )
                
                # Fallback to default Google OAuth metadata
                return JSONResponse(
                    content={
                        "issuer": "https://accounts.google.com",
                        "authorization_endpoint": f"{self.base_url}:{self.port}/oauth2/authorize",
                        "token_endpoint": f"{self.base_url}:{self.port}/oauth2/token",
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
                    content={"error": "Failed to fetch authorization server metadata"}
                )
        
        routes.append(Route("/.well-known/oauth-authorization-server", authorization_server_metadata))
        
        # Authorization server discovery proxy
        async def proxy_auth_server_discovery(request: Request):
            """Proxy authorization server metadata to avoid CORS issues."""
            server_host = request.path_params.get("server_host", "accounts.google.com")
            
            # Only allow known Google OAuth endpoints
            allowed_hosts = ["accounts.google.com", "oauth2.googleapis.com"]
            if server_host not in allowed_hosts:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid authorization server"}
                )
            
            try:
                # Fetch metadata from Google
                async with aiohttp.ClientSession() as session:
                    # Try OpenID configuration first
                    url = f"https://{server_host}/.well-known/openid-configuration"
                    async with session.get(url) as response:
                        if response.status == 200:
                            metadata = await response.json()
                            
                            # Add OAuth 2.1 required fields
                            metadata.setdefault("code_challenge_methods_supported", ["S256"])
                            metadata.setdefault("pkce_required", True)
                            
                            return JSONResponse(
                                content=metadata,
                                headers={
                                    "Content-Type": "application/json",
                                    "Access-Control-Allow-Origin": "*",
                                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                                    "Access-Control-Allow-Headers": "Content-Type, Authorization"
                                }
                            )
                
                # Fallback to default Google OAuth metadata
                return JSONResponse(
                    content={
                        "issuer": f"https://{server_host}",
                        "authorization_endpoint": f"https://{server_host}/o/oauth2/v2/auth",
                        "token_endpoint": f"https://{server_host}/token",
                        "userinfo_endpoint": "https://www.googleapis.com/oauth2/v2/userinfo",
                        "revocation_endpoint": f"https://{server_host}/revoke",
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
                logger.error(f"Error proxying auth server discovery: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"error": "Failed to fetch authorization server metadata"}
                )
        
        routes.append(Route("/auth/discovery/authorization-server/{server_host:path}", proxy_auth_server_discovery))
        
        # Token exchange proxy endpoint
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
            
            try:
                # Get form data
                body = await request.body()
                content_type = request.headers.get("content-type", "application/x-www-form-urlencoded")
                
                # Determine which Google token endpoint to use
                token_endpoint = "https://oauth2.googleapis.com/token"
                
                # Forward request to Google
                async with aiohttp.ClientSession() as session:
                    headers = {"Content-Type": content_type}
                    
                    async with session.post(token_endpoint, data=body, headers=headers) as response:
                        response_data = await response.json()
                        
                        # Log for debugging
                        if response.status != 200:
                            logger.error(f"Token exchange failed: {response.status} - {response_data}")
                        else:
                            logger.info("Token exchange successful")
                            
                            # Store session for credential bridging
                            if "access_token" in response_data:
                                # Try to decode the token to get user info
                                try:
                                    access_token = await self.verify_token(response_data["access_token"])
                                    if access_token:
                                        session_id = f"google_{access_token.claims.get('sub', 'unknown')}"
                                        self._sessions[session_id] = {
                                            "token_response": response_data,
                                            "user_email": access_token.claims.get("email"),
                                            "claims": access_token.claims
                                        }
                                except Exception as e:
                                    logger.debug(f"Could not verify token for session storage: {e}")
                        
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
        
        routes.append(Route("/oauth2/token", proxy_token_exchange, methods=["POST", "OPTIONS"]))
        
        # OAuth client configuration endpoint
        async def oauth_client_config(request: Request):
            """Return OAuth client configuration for dynamic registration workaround."""
            if not self.client_id:
                return JSONResponse(
                    status_code=404,
                    content={"error": "OAuth not configured"}
                )
            
            return JSONResponse(
                content={
                    "client_id": self.client_id,
                    "client_name": "Google Workspace MCP Server",
                    "client_uri": f"{self.base_url}:{self.port}",
                    "redirect_uris": [
                        f"{self.base_url}:{self.port}/oauth2callback",
                        "http://localhost:5173/auth/callback"  # Common dev callback
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
        
        routes.append(Route("/.well-known/oauth-client", oauth_client_config))
        
        # OAuth authorization endpoint (redirect to Google)
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
            
            # Get query parameters
            params = dict(request.query_params)
            
            # Add our client ID if not provided
            if "client_id" not in params and self.client_id:
                params["client_id"] = self.client_id
            
            # Ensure response_type is code
            params["response_type"] = "code"
            
            # Build Google authorization URL
            google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
            
            # Return redirect
            return JSONResponse(
                status_code=302,
                headers={
                    "Location": google_auth_url,
                    "Access-Control-Allow-Origin": "*"
                }
            )
        
        routes.append(Route("/oauth2/authorize", oauth_authorize, methods=["GET", "OPTIONS"]))
        
        return routes
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session information for credential bridging.
        
        Args:
            session_id: The session identifier
            
        Returns:
            Session information if found
        """
        return self._sessions.get(session_id)
    
    def create_session_from_token(self, token: str, user_email: str) -> str:
        """
        Create a session from an access token for credential bridging.
        
        Args:
            token: The access token
            user_email: The user's email address
            
        Returns:
            Session ID
        """
        session_id = f"google_{user_email}"
        self._sessions[session_id] = {
            "access_token": token,
            "user_email": user_email,
            "created_at": "now"  # You could use datetime here
        }
        return session_id