"""
OAuth 2.1 Authorization Flow Handler

Implements OAuth 2.1 authorization flow with PKCE (RFC7636) and Resource Indicators (RFC8707)
for secure authorization code exchange.
"""

import base64
import logging
import secrets
from typing import Dict, Any, Optional, Tuple, List
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .discovery import AuthorizationServerDiscovery

logger = logging.getLogger(__name__)


class OAuth2AuthorizationFlow:
    """Handles OAuth 2.1 authorization flow with PKCE."""

    def __init__(
        self,
        client_id: str,
        client_secret: Optional[str] = None,
        discovery_service: Optional[AuthorizationServerDiscovery] = None,
    ):
        """
        Initialize the OAuth 2.1 flow handler.

        Args:
            client_id: OAuth 2.0 client identifier
            client_secret: OAuth 2.0 client secret (optional for public clients)
            discovery_service: Authorization server discovery service
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.discovery = discovery_service or AuthorizationServerDiscovery()
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "MCP-OAuth2.1-Client/1.0"},
            )
        return self._session

    async def close(self):
        """Clean up resources."""
        if self._session and not self._session.closed:
            await self._session.close()
        await self.discovery.close()

    def generate_pkce_parameters(self) -> Tuple[str, str]:
        """
        Generate PKCE code_verifier and code_challenge per RFC7636.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate cryptographically secure random code_verifier
        # Must be 43-128 characters long
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Create SHA256 hash of the code_verifier for code_challenge
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(code_verifier.encode('utf-8'))
        code_challenge = base64.urlsafe_b64encode(digest.finalize()).decode('utf-8').rstrip('=')
        
        logger.debug("Generated PKCE parameters")
        return code_verifier, code_challenge

    def generate_state(self) -> str:
        """
        Generate a cryptographically secure state parameter.

        Returns:
            Random state string
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

    async def build_authorization_url(
        self,
        authorization_server_url: str,
        redirect_uri: str,
        scopes: List[str],
        state: Optional[str] = None,
        resource: Optional[str] = None,
        additional_params: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, str, str]:
        """
        Build OAuth 2.1 authorization URL with PKCE.

        Args:
            authorization_server_url: Authorization server base URL
            redirect_uri: Client redirect URI
            scopes: List of requested scopes
            state: State parameter (generated if not provided)
            resource: Resource indicator per RFC8707
            additional_params: Additional query parameters

        Returns:
            Tuple of (authorization_url, state, code_verifier)

        Raises:
            ValueError: If authorization server metadata is invalid
            aiohttp.ClientError: If metadata cannot be fetched
        """
        # Fetch authorization server metadata
        as_metadata = await self.discovery.get_authorization_server_metadata(authorization_server_url)
        auth_endpoint = as_metadata.get("authorization_endpoint")
        
        if not auth_endpoint:
            raise ValueError(f"No authorization_endpoint in metadata for {authorization_server_url}")

        # Verify PKCE support
        code_challenge_methods = as_metadata.get("code_challenge_methods_supported", [])
        if "S256" not in code_challenge_methods:
            logger.warning(f"Authorization server {authorization_server_url} may not support PKCE S256")

        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_parameters()
        
        # Generate state if not provided
        if state is None:
            state = self.generate_state()

        # Build authorization parameters
        auth_params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        # Add resource indicator if provided (RFC8707)
        if resource:
            auth_params["resource"] = resource

        # Add any additional parameters
        if additional_params:
            auth_params.update(additional_params)

        # Build the complete authorization URL
        authorization_url = f"{auth_endpoint}?{urlencode(auth_params)}"
        
        logger.info(f"Built authorization URL for {authorization_server_url}")
        logger.debug(f"Authorization URL: {authorization_url}")
        
        return authorization_url, state, code_verifier

    async def exchange_code_for_token(
        self,
        authorization_server_url: str,
        authorization_code: str,
        code_verifier: str,
        redirect_uri: str,
        resource: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Exchange authorization code for access token using PKCE.

        Args:
            authorization_server_url: Authorization server base URL
            authorization_code: Authorization code from callback
            code_verifier: PKCE code verifier
            redirect_uri: Client redirect URI (must match authorization request)
            resource: Resource indicator per RFC8707

        Returns:
            Token response dictionary

        Raises:
            ValueError: If token exchange fails or response is invalid
            aiohttp.ClientError: If HTTP request fails
        """
        # Fetch authorization server metadata
        as_metadata = await self.discovery.get_authorization_server_metadata(authorization_server_url)
        token_endpoint = as_metadata.get("token_endpoint")
        
        if not token_endpoint:
            raise ValueError(f"No token_endpoint in metadata for {authorization_server_url}")

        # Prepare token request data
        token_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": redirect_uri,
            "client_id": self.client_id,
            "code_verifier": code_verifier,
        }

        # Add resource indicator if provided
        if resource:
            token_data["resource"] = resource

        # Prepare headers
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        # Add client authentication if client_secret is available
        if self.client_secret:
            # Use client_secret_post method
            token_data["client_secret"] = self.client_secret
        
        session = await self._get_session()
        
        try:
            logger.debug(f"Exchanging authorization code at {token_endpoint}")
            async with session.post(token_endpoint, data=token_data, headers=headers) as response:
                response_text = await response.text()
                
                if response.status != 200:
                    logger.error(f"Token exchange failed: {response.status} {response_text}")
                    raise ValueError(f"Token exchange failed: {response.status} {response_text}")
                
                try:
                    token_response = await response.json()
                except Exception as e:
                    logger.error(f"Failed to parse token response: {e}")
                    raise ValueError(f"Invalid token response format: {e}")
                
                # Validate required fields in token response
                if "access_token" not in token_response:
                    raise ValueError("Token response missing access_token")
                
                if "token_type" not in token_response:
                    raise ValueError("Token response missing token_type")
                
                # Ensure token_type is Bearer (case-insensitive)
                if token_response["token_type"].lower() != "bearer":
                    logger.warning(f"Unexpected token_type: {token_response['token_type']}")
                
                logger.info("Successfully exchanged authorization code for tokens")
                return token_response
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during token exchange: {e}")
            raise

    async def refresh_access_token(
        self,
        authorization_server_url: str,
        refresh_token: str,
        scopes: Optional[List[str]] = None,
        resource: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.

        Args:
            authorization_server_url: Authorization server base URL
            refresh_token: Refresh token
            scopes: Optional scope restriction
            resource: Resource indicator per RFC8707

        Returns:
            Token response dictionary

        Raises:
            ValueError: If token refresh fails
            aiohttp.ClientError: If HTTP request fails
        """
        # Fetch authorization server metadata
        as_metadata = await self.discovery.get_authorization_server_metadata(authorization_server_url)
        token_endpoint = as_metadata.get("token_endpoint")
        
        if not token_endpoint:
            raise ValueError(f"No token_endpoint in metadata for {authorization_server_url}")

        # Prepare refresh request data
        refresh_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
        }

        # Add optional scope restriction
        if scopes:
            refresh_data["scope"] = " ".join(scopes)

        # Add resource indicator if provided
        if resource:
            refresh_data["resource"] = resource

        # Add client authentication if available
        if self.client_secret:
            refresh_data["client_secret"] = self.client_secret

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        session = await self._get_session()
        
        try:
            logger.debug(f"Refreshing access token at {token_endpoint}")
            async with session.post(token_endpoint, data=refresh_data, headers=headers) as response:
                response_text = await response.text()
                
                if response.status != 200:
                    logger.error(f"Token refresh failed: {response.status} {response_text}")
                    raise ValueError(f"Token refresh failed: {response.status} {response_text}")
                
                token_response = await response.json()
                
                # Validate required fields
                if "access_token" not in token_response:
                    raise ValueError("Refresh response missing access_token")
                
                logger.info("Successfully refreshed access token")
                return token_response
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error during token refresh: {e}")
            raise

    def parse_authorization_response(self, authorization_response_url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Parse authorization response URL to extract code, state, and error.

        Args:
            authorization_response_url: Complete callback URL

        Returns:
            Tuple of (code, state, error)
        """
        parsed_url = urlparse(authorization_response_url)
        query_params = parse_qs(parsed_url.query)
        
        code = query_params.get("code", [None])[0]
        state = query_params.get("state", [None])[0]
        error = query_params.get("error", [None])[0]
        
        if error:
            error_description = query_params.get("error_description", [None])[0]
            full_error = f"{error}: {error_description}" if error_description else error
            logger.error(f"Authorization error: {full_error}")
            return None, state, full_error
        
        return code, state, None