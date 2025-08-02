"""
HTTP Authentication Handler

Handles HTTP authentication headers and responses per RFC6750 (Bearer Token Usage)
and OAuth 2.1 specifications.
"""

import logging
import re
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class HTTPAuthHandler:
    """Handles HTTP authentication headers and responses."""

    def __init__(self, resource_metadata_url: Optional[str] = None):
        """
        Initialize the HTTP authentication handler.

        Args:
            resource_metadata_url: URL for protected resource metadata discovery
        """
        self.resource_metadata_url = resource_metadata_url or "/.well-known/oauth-authorization-server"

    def parse_authorization_header(self, header: str) -> Optional[str]:
        """
        Extract Bearer token from Authorization header per RFC6750.

        Args:
            header: Authorization header value

        Returns:
            Bearer token string or None if not found/invalid

        Examples:
            >>> handler = HTTPAuthHandler()
            >>> handler.parse_authorization_header("Bearer abc123")
            'abc123'
            >>> handler.parse_authorization_header("Basic abc123")
            None
        """
        if not header:
            return None

        # RFC6750 Section 2.1: Authorization Request Header Field
        # Authorization: Bearer <token>
        bearer_pattern = re.compile(r'^Bearer\s+([^\s]+)$', re.IGNORECASE)
        match = bearer_pattern.match(header.strip())
        
        if match:
            token = match.group(1)
            # Basic validation - token should not be empty
            if token:
                logger.debug("Successfully extracted Bearer token from Authorization header")
                return token
            else:
                logger.warning("Empty Bearer token in Authorization header")
                return None
        else:
            logger.debug(f"Authorization header does not contain valid Bearer token: {header[:20]}...")
            return None

    def build_www_authenticate_header(
        self,
        realm: Optional[str] = None,
        scope: Optional[str] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
        error_uri: Optional[str] = None,
    ) -> str:
        """
        Build WWW-Authenticate header for 401 responses per RFC6750.

        Args:
            realm: Authentication realm
            scope: Required scope(s)
            error: Error code (invalid_request, invalid_token, insufficient_scope)
            error_description: Human-readable error description
            error_uri: URI with error information

        Returns:
            WWW-Authenticate header value

        Examples:
            >>> handler = HTTPAuthHandler()
            >>> handler.build_www_authenticate_header(realm="api")
            'Bearer realm="api"'
            >>> handler.build_www_authenticate_header(error="invalid_token")
            'Bearer error="invalid_token"'
        """
        # Start with Bearer scheme
        parts = ["Bearer"]
        
        # Add realm if provided
        if realm:
            parts.append(f'realm="{self._quote_attribute_value(realm)}"')
        
        # Add scope if provided
        if scope:
            parts.append(f'scope="{self._quote_attribute_value(scope)}"')
        
        # Add error information if provided
        if error:
            parts.append(f'error="{self._quote_attribute_value(error)}"')
        
        if error_description:
            parts.append(f'error_description="{self._quote_attribute_value(error_description)}"')
        
        if error_uri:
            parts.append(f'error_uri="{self._quote_attribute_value(error_uri)}"')

        return " ".join(parts)

    def build_resource_metadata_header(self) -> str:
        """
        Build WWW-Authenticate header with resource metadata URL for discovery.

        Returns:
            WWW-Authenticate header with AS_metadata_url parameter
        """
        return f'Bearer AS_metadata_url="{self.resource_metadata_url}"'

    def _quote_attribute_value(self, value: str) -> str:
        """
        Quote attribute value for use in HTTP header per RFC7235.

        Args:
            value: Attribute value to quote

        Returns:
            Properly quoted value
        """
        # Escape quotes and backslashes
        escaped = value.replace('\\', '\\\\').replace('"', '\\"')
        return escaped

    def extract_bearer_token_from_request(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extract Bearer token from HTTP request headers.

        Args:
            headers: HTTP request headers (case-insensitive dict)

        Returns:
            Bearer token or None
        """
        # Look for Authorization header (case-insensitive)
        authorization = None
        for key, value in headers.items():
            if key.lower() == "authorization":
                authorization = value
                break
        
        if authorization:
            return self.parse_authorization_header(authorization)
        
        return None

    def is_bearer_token_request(self, headers: Dict[str, str]) -> bool:
        """
        Check if request contains Bearer token authentication.

        Args:
            headers: HTTP request headers

        Returns:
            True if request has Bearer token
        """
        token = self.extract_bearer_token_from_request(headers)
        return token is not None

    def build_error_response_headers(
        self,
        error: str,
        error_description: Optional[str] = None,
        realm: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Build complete error response headers for 401/403 responses.

        Args:
            error: OAuth error code
            error_description: Human-readable error description
            realm: Authentication realm
            scope: Required scope

        Returns:
            Dictionary of response headers
        """
        headers = {
            "WWW-Authenticate": self.build_www_authenticate_header(
                realm=realm,
                scope=scope,
                error=error,
                error_description=error_description,
            ),
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        }
        
        return headers

    def validate_token_format(self, token: str) -> bool:
        """
        Validate Bearer token format per RFC6750.

        Args:
            token: Bearer token to validate

        Returns:
            True if token format is valid
        """
        if not token:
            return False
        
        # RFC6750 - token should be ASCII and not contain certain characters
        try:
            # Check if token contains only valid characters
            # Avoid control characters and certain special characters
            invalid_chars = set('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
                              '\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
                              '\x20\x7f"\\')
            
            if any(char in invalid_chars for char in token):
                logger.warning("Bearer token contains invalid characters")
                return False
            
            # Token should be ASCII
            token.encode('ascii')
            
            return True
            
        except UnicodeEncodeError:
            logger.warning("Bearer token contains non-ASCII characters")
            return False

    def get_token_info_from_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Extract and validate token information from request headers.

        Args:
            headers: HTTP request headers

        Returns:
            Dictionary with token information
        """
        result = {
            "has_bearer_token": False,
            "token": None,
            "valid_format": False,
            "error": None,
        }
        
        # Extract token
        token = self.extract_bearer_token_from_request(headers)
        
        if token:
            result["has_bearer_token"] = True
            result["token"] = token
            result["valid_format"] = self.validate_token_format(token)
            
            if not result["valid_format"]:
                result["error"] = "invalid_token"
        else:
            result["error"] = "missing_token"
        
        return result