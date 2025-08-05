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
import jwt
import time
from typing import Optional, List
from datetime import datetime, timedelta
from urllib.parse import urlencode

from starlette.routing import Route
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from google.oauth2.credentials import Credentials
from jwt import PyJWKClient
from pydantic import AnyHttpUrl

try:
    from fastmcp.server.auth import RemoteAuthProvider
    from fastmcp.server.auth.providers.jwt import JWTVerifier
    REMOTEAUTHPROVIDER_AVAILABLE = True
except ImportError:
    REMOTEAUTHPROVIDER_AVAILABLE = False
    RemoteAuthProvider = object  # Fallback for type hints
    JWTVerifier = object

from auth.oauth21_session_store import get_oauth21_session_store, store_token_session
from auth.google_auth import save_credentials_to_file
from auth.scopes import SCOPES
from core.config import (
    WORKSPACE_MCP_PORT,
    WORKSPACE_MCP_BASE_URI,
)

logger = logging.getLogger(__name__)


class GoogleRemoteAuthProvider(RemoteAuthProvider):
    """
    RemoteAuthProvider implementation for Google Workspace using FastMCP v2.11.1+.
    
    This provider extends RemoteAuthProvider to add:
    - OAuth proxy endpoints for CORS workaround
    - Dynamic client registration support
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
            logger.warning("GOOGLE_OAUTH_CLIENT_ID not set - OAuth 2.1 authentication will not work")
            # Still initialize to avoid errors, but auth won't work
        
        # Configure JWT verifier for Google tokens
        token_verifier = JWTVerifier(
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
            issuer="https://accounts.google.com",
            audience=self.client_id or "placeholder",  # Use placeholder if not configured
            algorithm="RS256"
        )
        
        # Initialize RemoteAuthProvider with local server as the authorization server
        # This ensures OAuth discovery points to our proxy endpoints instead of Google directly
        super().__init__(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(f"{self.base_url}:{self.port}")],
            resource_server_url=f"{self.base_url}:{self.port}"
        )
        
        logger.info("GoogleRemoteAuthProvider initialized with RemoteAuthProvider pattern")
    
    def get_routes(self) -> List[Route]:
        """
        Add custom OAuth proxy endpoints to the standard protected resource routes.
        
        These endpoints work around Google's CORS restrictions and provide
        dynamic client registration support.
        """
        # Get the standard OAuth protected resource routes from RemoteAuthProvider
        routes = super().get_routes()
        
        # Log what routes we're getting from the parent
        logger.info(f"GoogleRemoteAuthProvider: Parent provided {len(routes)} routes")
        for route in routes:
            logger.info(f"  - {route.path} ({', '.join(route.methods)})")
        
        # Add our custom proxy endpoints
        
        # OAuth authorization proxy endpoint
        async def oauth_authorize(request: Request):
            """Redirect to Google's authorization endpoint with CORS support."""
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
            
            # Merge client scopes with our full SCOPES list
            client_scopes = params.get("scope", "").split() if params.get("scope") else []
            # Always include all Google Workspace scopes for full functionality
            all_scopes = set(client_scopes) | set(SCOPES)
            params["scope"] = " ".join(sorted(all_scopes))
            logger.info(f"OAuth 2.1 authorization: Requesting scopes: {params['scope']}")
            
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
        
        routes.append(Route("/oauth2/authorize", oauth_authorize, methods=["GET", "OPTIONS"]))
        
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
                
                # Parse form data to add missing client credentials
                from urllib.parse import parse_qs, urlencode
                
                if content_type and "application/x-www-form-urlencoded" in content_type:
                    form_data = parse_qs(body.decode('utf-8'))
                    
                    # Check if client_id is missing (public client)
                    if 'client_id' not in form_data or not form_data['client_id'][0]:
                        if self.client_id:
                            form_data['client_id'] = [self.client_id]
                            logger.debug(f"Added missing client_id to token request")
                    
                    # Check if client_secret is missing (public client using PKCE)
                    if 'client_secret' not in form_data:
                        if self.client_secret:
                            form_data['client_secret'] = [self.client_secret]
                            logger.debug(f"Added missing client_secret to token request")
                    
                    # Reconstruct body with added credentials
                    body = urlencode(form_data, doseq=True).encode('utf-8')
                
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
                            
                            # Store the token session for credential bridging
                            if "access_token" in response_data:
                                try:
                                    # Extract user email from ID token if present
                                    if "id_token" in response_data:
                                        # Verify ID token using Google's public keys for security
                                        try:
                                            # Get Google's public keys for verification
                                            jwks_client = PyJWKClient("https://www.googleapis.com/oauth2/v3/certs")
                                            
                                            # Get signing key from JWT header
                                            signing_key = jwks_client.get_signing_key_from_jwt(response_data["id_token"])
                                            
                                            # Verify and decode the ID token
                                            id_token_claims = jwt.decode(
                                                response_data["id_token"],
                                                signing_key.key,
                                                algorithms=["RS256"],
                                                audience=self.client_id,
                                                issuer="https://accounts.google.com"
                                            )
                                            user_email = id_token_claims.get("email")
                                            
                                            if user_email:
                                                # Try to get FastMCP session ID from request context for binding
                                                mcp_session_id = None
                                                try:
                                                    # Check if this is a streamable HTTP request with session
                                                    if hasattr(request, 'state') and hasattr(request.state, 'session_id'):
                                                        mcp_session_id = request.state.session_id
                                                        logger.info(f"Found MCP session ID for binding: {mcp_session_id}")
                                                except Exception as e:
                                                    logger.debug(f"Could not get MCP session ID: {e}")
                                                
                                                # Store the token session with MCP session binding and issuer
                                                session_id = store_token_session(response_data, user_email, mcp_session_id)
                                                logger.info(f"Stored OAuth session for {user_email} (session: {session_id}, mcp: {mcp_session_id})")
                                                
                                                # Also create and store Google credentials
                                                expiry = None
                                                if "expires_in" in response_data:
                                                    # Google auth library expects timezone-naive datetime
                                                    expiry = datetime.utcnow() + timedelta(seconds=response_data["expires_in"])
                                                
                                                credentials = Credentials(
                                                    token=response_data["access_token"],
                                                    refresh_token=response_data.get("refresh_token"),
                                                    token_uri="https://oauth2.googleapis.com/token",
                                                    client_id=self.client_id,
                                                    client_secret=self.client_secret,
                                                    scopes=response_data.get("scope", "").split() if response_data.get("scope") else None,
                                                    expiry=expiry
                                                )
                                                
                                                # Save credentials to file for legacy auth
                                                save_credentials_to_file(user_email, credentials)
                                                logger.info(f"Saved Google credentials for {user_email}")
                                        except jwt.ExpiredSignatureError:
                                            logger.error("ID token has expired - cannot extract user email")
                                        except jwt.InvalidTokenError as e:
                                            logger.error(f"Invalid ID token - cannot extract user email: {e}")
                                        except Exception as e:
                                            logger.error(f"Failed to verify ID token - cannot extract user email: {e}")
                                
                                except Exception as e:
                                    logger.error(f"Failed to store OAuth session: {e}")
                        
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
        
        # Dynamic client registration endpoint
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
            
            if not self.client_id or not self.client_secret:
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
                        f"{self.base_url}:{self.port}/oauth2callback",
                        "http://localhost:5173/auth/callback"
                    ]
                
                # Build the registration response with our pre-configured credentials
                response_data = {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "client_name": body.get("client_name", "Google Workspace MCP Server"),
                    "client_uri": body.get("client_uri", f"{self.base_url}:{self.port}"),
                    "redirect_uris": redirect_uris,
                    "grant_types": body.get("grant_types", ["authorization_code", "refresh_token"]),
                    "response_types": body.get("response_types", ["code"]),
                    "scope": body.get("scope", " ".join(SCOPES)),
                    "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_basic"),
                    "code_challenge_methods": ["S256"],
                    # Additional OAuth 2.1 fields
                    "client_id_issued_at": int(time.time()),
                    "registration_access_token": "not-required",  # We don't implement client management
                    "registration_client_uri": f"{self.base_url}:{self.port}/oauth2/register/{self.client_id}"
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
        
        routes.append(Route("/oauth2/register", oauth_register, methods=["POST", "OPTIONS"]))
        
        # Authorization server metadata proxy
        async def oauth_authorization_server(request: Request):
            """OAuth 2.1 Authorization Server Metadata endpoint proxy."""
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
                            metadata["token_endpoint"] = f"{self.base_url}:{self.port}/oauth2/token"
                            metadata["authorization_endpoint"] = f"{self.base_url}:{self.port}/oauth2/authorize"
                            metadata["enable_dynamic_registration"] = True
                            metadata["registration_endpoint"] = f"{self.base_url}:{self.port}/oauth2/register"
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
                        "authorization_endpoint": f"{self.base_url}:{self.port}/oauth2/authorize",
                        "token_endpoint": f"{self.base_url}:{self.port}/oauth2/token",
                        "userinfo_endpoint": "https://www.googleapis.com/oauth2/v2/userinfo",
                        "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
                        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
                        "response_types_supported": ["code"],
                        "code_challenge_methods_supported": ["S256"],
                        "pkce_required": True,
                        "grant_types_supported": ["authorization_code", "refresh_token"],
                        "scopes_supported": SCOPES,
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
        
        routes.append(Route("/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET", "OPTIONS"]))
        
        # OAuth client configuration endpoint
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
            
            if not self.client_id:
                return JSONResponse(
                    status_code=404,
                    content={"error": "OAuth not configured"},
                    headers={"Access-Control-Allow-Origin": "*"}
                )
            
            return JSONResponse(
                content={
                    "client_id": self.client_id,
                    "client_name": "Google Workspace MCP Server",
                    "client_uri": f"{self.base_url}:{self.port}",
                    "redirect_uris": [
                        f"{self.base_url}:{self.port}/oauth2callback",
                        "http://localhost:5173/auth/callback"
                    ],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "scope": " ".join(SCOPES),
                    "token_endpoint_auth_method": "client_secret_basic",
                    "code_challenge_methods": ["S256"]
                },
                headers={
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "*"
                }
            )
        
        routes.append(Route("/.well-known/oauth-client", oauth_client_config, methods=["GET", "OPTIONS"]))
        
        return routes
    
    async def verify_token(self, token: str) -> Optional[object]:
        """
        Override verify_token to handle Google OAuth access tokens.
        
        Google OAuth access tokens (ya29.*) are opaque tokens that need to be
        verified using the tokeninfo endpoint, not JWT verification.
        """
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
                            
                            logger.info(f"Successfully verified Google OAuth token for user: {user_email}")
                        
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