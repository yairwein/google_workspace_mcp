"""
Authorization Server Discovery Module

Implements RFC9728 Protected Resource Metadata and RFC8414 Authorization Server Metadata discovery
for OAuth 2.1 compliance.
"""

import logging
from typing import Dict, Any, Optional, List

import aiohttp
from cachetools import TTLCache

logger = logging.getLogger(__name__)


class AuthorizationServerDiscovery:
    """Implements RFC9728 Protected Resource Metadata and RFC8414 AS Metadata discovery."""

    def __init__(
        self,
        resource_url: Optional[str] = None,
        cache_ttl: int = 3600,
        max_cache_size: int = 100,
        proxy_base_url: Optional[str] = None,
    ):
        """
        Initialize the discovery service.

        Args:
            resource_url: The protected resource URL for this server
            cache_ttl: Cache time-to-live in seconds
            max_cache_size: Maximum number of cached entries
            proxy_base_url: Base URL for proxying discovery requests
        """
        self.resource_url = resource_url
        if not self.resource_url:
            raise ValueError("resource_url is required for AuthorizationServerDiscovery")
        self.cache = TTLCache(maxsize=max_cache_size, ttl=cache_ttl)
        self._session: Optional[aiohttp.ClientSession] = None
        self.proxy_base_url = proxy_base_url

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

    async def get_protected_resource_metadata(self) -> Dict[str, Any]:
        """
        Return Protected Resource Metadata per RFC9728.

        Returns:
            Protected resource metadata including authorization_servers list
        """
        cache_key = f"prm:{self.resource_url}"
        if cache_key in self.cache:
            logger.debug(f"Using cached protected resource metadata for {self.resource_url}")
            return self.cache[cache_key]

        # Generate authorization server URLs - use proxy if configured
        auth_servers = []
        google_servers = ["accounts.google.com", "oauth2.googleapis.com"]
        
        if self.proxy_base_url:
            # Use proxy URLs to avoid CORS issues
            for server in google_servers:
                auth_servers.append(f"{self.proxy_base_url}/auth/discovery/authorization-server/{server}")
        else:
            # Direct URLs (will have CORS issues in browsers)
            auth_servers = [f"https://{server}" for server in google_servers]
        
        metadata = {
            "resource": self.resource_url,
            "authorization_servers": auth_servers,
            "scopes_supported": [
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/calendar",
                "https://www.googleapis.com/auth/calendar.readonly",
                "https://www.googleapis.com/auth/drive",
                "https://www.googleapis.com/auth/drive.readonly", 
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.modify",
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/documents",
                "https://www.googleapis.com/auth/documents.readonly",
                "https://www.googleapis.com/auth/spreadsheets",
                "https://www.googleapis.com/auth/spreadsheets.readonly",
                "https://www.googleapis.com/auth/presentations",
                "https://www.googleapis.com/auth/presentations.readonly",
                "https://www.googleapis.com/auth/chat.spaces",
                "https://www.googleapis.com/auth/chat.messages",
                "https://www.googleapis.com/auth/forms.body",
                "https://www.googleapis.com/auth/forms.responses.readonly",
                "https://www.googleapis.com/auth/tasks",
                "https://www.googleapis.com/auth/tasks.readonly",
            ],
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://developers.google.com/workspace",
            "client_registration_required": True,
            "client_configuration_endpoint": f"{self.proxy_base_url}/.well-known/oauth-client" if self.proxy_base_url else None,
        }

        self.cache[cache_key] = metadata
        logger.info(f"Generated protected resource metadata for {self.resource_url}")
        return metadata

    async def get_authorization_server_metadata(self, as_url: str) -> Dict[str, Any]:
        """
        Fetch and cache Authorization Server metadata per RFC8414.

        Args:
            as_url: Authorization server URL

        Returns:
            Authorization server metadata dictionary

        Raises:
            aiohttp.ClientError: If the metadata cannot be fetched
        """
        cache_key = f"asm:{as_url}"
        if cache_key in self.cache:
            logger.debug(f"Using cached authorization server metadata for {as_url}")
            return self.cache[cache_key]

        # Try standard discovery endpoints
        discovery_urls = [
            f"{as_url}/.well-known/oauth-authorization-server",
            f"{as_url}/.well-known/openid_configuration",
        ]

        session = await self._get_session()
        
        for discovery_url in discovery_urls:
            try:
                logger.debug(f"Attempting to fetch metadata from {discovery_url}")
                async with session.get(discovery_url) as response:
                    if response.status == 200:
                        metadata = await response.json()
                        
                        # Validate required fields per RFC8414
                        required_fields = ["issuer", "authorization_endpoint"]
                        if all(field in metadata for field in required_fields):
                            # Ensure OAuth 2.1 compliance fields
                            metadata.setdefault("code_challenge_methods_supported", ["S256"])
                            metadata.setdefault("pkce_required", True)
                            
                            self.cache[cache_key] = metadata
                            logger.info(f"Fetched authorization server metadata from {discovery_url}")
                            return metadata
                        else:
                            logger.warning(f"Invalid metadata from {discovery_url}: missing required fields")
                            
            except Exception as e:
                logger.debug(f"Failed to fetch from {discovery_url}: {e}")
                continue

        # If discovery fails, return default Google metadata
        logger.warning(f"Could not discover metadata for {as_url}, using defaults")
        default_metadata = self._get_default_google_metadata(as_url)
        self.cache[cache_key] = default_metadata
        return default_metadata

    def _get_default_google_metadata(self, as_url: str) -> Dict[str, Any]:
        """Return default Google OAuth 2.0 metadata."""
        return {
            "issuer": as_url,
            "authorization_endpoint": f"{as_url}/o/oauth2/v2/auth",
            "token_endpoint": f"{as_url}/token",
            "userinfo_endpoint": f"{as_url}/oauth2/v2/userinfo",
            "revocation_endpoint": f"{as_url}/revoke",
            "jwks_uri": f"{as_url}/oauth2/v3/certs",
            "introspection_endpoint": f"{as_url}/introspect",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query", "fragment"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "pkce_required": True,
            "scopes_supported": [
                "openid",
                "email", 
                "profile",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "claims_supported": ["iss", "sub", "aud", "exp", "iat", "email", "email_verified"],
            "request_uri_parameter_supported": False,
            "require_request_uri_registration": False,
        }

    async def discover_authorization_servers(self) -> List[Dict[str, Any]]:
        """
        Discover all authorization servers for this protected resource.

        Returns:
            List of authorization server metadata dictionaries
        """
        prm = await self.get_protected_resource_metadata()
        servers = []
        
        for as_url in prm.get("authorization_servers", []):
            try:
                as_metadata = await self.get_authorization_server_metadata(as_url)
                servers.append(as_metadata)
            except Exception as e:
                logger.error(f"Failed to discover authorization server {as_url}: {e}")
                continue
                
        return servers

    def is_valid_authorization_server(self, as_url: str) -> bool:
        """
        Check if the given URL is a valid authorization server for this resource.

        Args:
            as_url: Authorization server URL to validate

        Returns:
            True if the server is valid for this resource
        """
        try:
            # Get cached metadata without making network calls
            cache_key = f"prm:{self.resource_url}"
            if cache_key in self.cache:
                prm = self.cache[cache_key]
                return as_url in prm.get("authorization_servers", [])
        except Exception:
            pass
            
        # Default to allowing Google servers
        google_servers = [
            "https://accounts.google.com",
            "https://oauth2.googleapis.com",
        ]
        return as_url in google_servers