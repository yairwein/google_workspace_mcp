"""
Token Validator

Validates and parses Bearer tokens, supporting both JWT and opaque token formats.
Implements token introspection per RFC7662 for opaque tokens.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

import aiohttp
import jwt
from cachetools import TTLCache

from .discovery import AuthorizationServerDiscovery

logger = logging.getLogger(__name__)


class TokenValidationError(Exception):
    """Exception raised when token validation fails."""
    
    def __init__(self, message: str, error_code: str = "invalid_token"):
        super().__init__(message)
        self.error_code = error_code


class TokenValidator:
    """Validates and parses Bearer tokens."""

    def __init__(
        self,
        discovery_service: Optional[AuthorizationServerDiscovery] = None,
        cache_ttl: int = 300,  # 5 minutes
        max_cache_size: int = 1000,
    ):
        """
        Initialize the token validator.

        Args:
            discovery_service: Authorization server discovery service
            cache_ttl: Token validation cache TTL in seconds
            max_cache_size: Maximum number of cached validations
        """
        self.discovery = discovery_service or AuthorizationServerDiscovery()
        self.validation_cache = TTLCache(maxsize=max_cache_size, ttl=cache_ttl)
        self.jwks_cache = TTLCache(maxsize=10, ttl=3600)  # 1 hour for JWKS
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

    def _is_jwt_format(self, token: str) -> bool:
        """
        Check if token appears to be in JWT format.

        Args:
            token: Token to check

        Returns:
            True if token appears to be JWT
        """
        # JWT has 3 parts separated by dots
        parts = token.split('.')
        return len(parts) == 3

    async def validate_token(
        self,
        token: str,
        expected_audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        authorization_server_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate token and extract claims.

        Args:
            token: Bearer token to validate
            expected_audience: Expected audience claim
            required_scopes: Required scopes
            authorization_server_url: Authorization server URL for introspection

        Returns:
            Dictionary containing validated token information

        Raises:
            TokenValidationError: If token validation fails
        """
        # Check cache first
        cache_key = f"token:{hash(token)}:{expected_audience}:{','.join(required_scopes or [])}"
        if cache_key in self.validation_cache:
            logger.debug("Using cached token validation result")
            return self.validation_cache[cache_key]

        try:
            if self._is_jwt_format(token):
                result = await self._validate_jwt_token(token, expected_audience, required_scopes)
            else:
                result = await self._validate_opaque_token(
                    token, expected_audience, required_scopes, authorization_server_url
                )
            
            # Cache successful validation
            self.validation_cache[cache_key] = result
            return result
            
        except Exception as e:
            if isinstance(e, TokenValidationError):
                raise
            else:
                logger.error(f"Unexpected error validating token: {e}")
                raise TokenValidationError(f"Token validation failed: {str(e)}")

    async def _validate_jwt_token(
        self,
        token: str,
        expected_audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Validate JWT token."""
        try:
            # First decode without verification to get issuer and key ID
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            issuer = unverified_payload.get("iss")
            
            if not issuer:
                raise TokenValidationError("JWT missing issuer claim")

            # Get JWKS for signature verification
            jwks = await self._fetch_jwks(issuer)
            
            # Decode and verify the JWT
            payload = jwt.decode(
                token,
                key=jwks,
                algorithms=["RS256", "ES256"],
                audience=expected_audience,
                issuer=issuer,
                options={
                    "verify_exp": True,
                    "verify_aud": expected_audience is not None,
                    "verify_iss": True,
                }
            )
            
            # Extract user identity
            user_identity = self.extract_user_identity(payload)
            
            # Validate scopes if required
            if required_scopes:
                token_scopes = self._extract_scopes_from_jwt(payload)
                if not self._validate_scopes(token_scopes, required_scopes):
                    raise TokenValidationError(
                        f"Insufficient scope. Required: {required_scopes}, Got: {token_scopes}",
                        error_code="insufficient_scope"
                    )
            
            return {
                "valid": True,
                "token_type": "jwt",
                "user_identity": user_identity,
                "scopes": self._extract_scopes_from_jwt(payload),
                "expires_at": payload.get("exp"),
                "issuer": issuer,
                "audience": payload.get("aud"),
                "claims": payload,
            }
            
        except jwt.ExpiredSignatureError:
            raise TokenValidationError("JWT token has expired", error_code="invalid_token")
        except jwt.InvalidAudienceError:
            raise TokenValidationError("JWT audience mismatch", error_code="invalid_token")
        except jwt.InvalidIssuerError:
            raise TokenValidationError("JWT issuer invalid", error_code="invalid_token")
        except jwt.InvalidSignatureError:
            raise TokenValidationError("JWT signature verification failed", error_code="invalid_token")
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(f"Invalid JWT token: {str(e)}", error_code="invalid_token")

    async def _validate_opaque_token(
        self,
        token: str,
        expected_audience: Optional[str] = None,
        required_scopes: Optional[List[str]] = None,
        authorization_server_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate opaque token via introspection."""
        if not authorization_server_url:
            # Try to determine from discovery
            servers = await self.discovery.discover_authorization_servers()
            if servers:
                authorization_server_url = servers[0].get("issuer")
            
            if not authorization_server_url:
                raise TokenValidationError("No authorization server URL for token introspection")

        introspection_result = await self.introspect_opaque_token(token, authorization_server_url)
        
        if not introspection_result.get("active", False):
            raise TokenValidationError("Token is not active", error_code="invalid_token")

        # Validate audience if provided
        if expected_audience:
            token_audience = introspection_result.get("aud")
            if token_audience and token_audience != expected_audience:
                raise TokenValidationError("Token audience mismatch", error_code="invalid_token")

        # Validate scopes if required
        if required_scopes:
            token_scopes = introspection_result.get("scope", "").split()
            if not self._validate_scopes(token_scopes, required_scopes):
                raise TokenValidationError(
                    f"Insufficient scope. Required: {required_scopes}, Got: {token_scopes}",
                    error_code="insufficient_scope"
                )

        # Extract user identity
        user_identity = self.extract_user_identity(introspection_result)

        return {
            "valid": True,
            "token_type": "opaque",
            "user_identity": user_identity,
            "scopes": token_scopes if required_scopes else introspection_result.get("scope", "").split(),
            "expires_at": introspection_result.get("exp"),
            "issuer": introspection_result.get("iss"),
            "audience": introspection_result.get("aud"),
            "claims": introspection_result,
        }

    async def introspect_opaque_token(
        self,
        token: str,
        authorization_server_url: str,
    ) -> Dict[str, Any]:
        """
        Query authorization server for opaque token details per RFC7662.

        Args:
            token: Opaque token to introspect
            authorization_server_url: Authorization server URL

        Returns:
            Token introspection response

        Raises:
            TokenValidationError: If introspection fails
        """
        # Get authorization server metadata
        as_metadata = await self.discovery.get_authorization_server_metadata(authorization_server_url)
        introspection_endpoint = as_metadata.get("introspection_endpoint")
        
        if not introspection_endpoint:
            raise TokenValidationError("Authorization server does not support token introspection")

        session = await self._get_session()
        
        try:
            # Prepare introspection request
            data = {"token": token}
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }

            async with session.post(introspection_endpoint, data=data, headers=headers) as response:
                if response.status != 200:
                    raise TokenValidationError(f"Token introspection failed: {response.status}")
                
                result = await response.json()
                logger.debug("Token introspection completed")
                return result
                
        except aiohttp.ClientError as e:
            raise TokenValidationError(f"Failed to introspect token: {str(e)}")

    def extract_user_identity(self, token_payload: Dict[str, Any]) -> str:
        """
        Extract user email/identity from validated token.

        Args:
            token_payload: Validated token payload/claims

        Returns:
            User email or identifier

        Raises:
            TokenValidationError: If no user identity found
        """
        # Try different claim names for user identity
        identity_claims = ["email", "sub", "preferred_username", "upn", "unique_name"]
        
        for claim in identity_claims:
            value = token_payload.get(claim)
            if value:
                # Prefer email-like identities
                if "@" in str(value):
                    return str(value)
                elif claim == "email":  # Email claim should be email
                    return str(value)
        
        # Fallback to first available identity claim
        for claim in identity_claims:
            value = token_payload.get(claim)
            if value:
                return str(value)
        
        raise TokenValidationError("No user identity found in token", error_code="invalid_token")

    async def _fetch_jwks(self, issuer: str) -> Dict[str, Any]:
        """Fetch and cache JWKS from authorization server."""
        cache_key = f"jwks:{issuer}"
        if cache_key in self.jwks_cache:
            return self.jwks_cache[cache_key]

        # Get JWKS URI from metadata
        as_metadata = await self.discovery.get_authorization_server_metadata(issuer)
        jwks_uri = as_metadata.get("jwks_uri")
        
        if not jwks_uri:
            raise TokenValidationError(f"No JWKS URI found for issuer {issuer}")

        session = await self._get_session()
        
        try:
            async with session.get(jwks_uri) as response:
                if response.status != 200:
                    raise TokenValidationError(f"Failed to fetch JWKS: {response.status}")
                
                jwks = await response.json()
                self.jwks_cache[cache_key] = jwks
                logger.debug(f"Fetched JWKS from {jwks_uri}")
                return jwks
                
        except aiohttp.ClientError as e:
            raise TokenValidationError(f"Failed to fetch JWKS: {str(e)}")

    def _extract_scopes_from_jwt(self, payload: Dict[str, Any]) -> List[str]:
        """Extract scopes from JWT payload."""
        # Try different scope claim formats
        scope_claim = payload.get("scope") or payload.get("scp")
        
        if isinstance(scope_claim, str):
            return scope_claim.split()
        elif isinstance(scope_claim, list):
            return scope_claim
        else:
            return []

    def _validate_scopes(self, token_scopes: List[str], required_scopes: List[str]) -> bool:
        """Check if token has all required scopes."""
        token_scope_set = set(token_scopes)
        required_scope_set = set(required_scopes)
        return required_scope_set.issubset(token_scope_set)

    def is_token_expired(self, token_info: Dict[str, Any]) -> bool:
        """
        Check if token is expired.

        Args:
            token_info: Token information from validation

        Returns:
            True if token is expired
        """
        exp = token_info.get("expires_at")
        if not exp:
            return False  # No expiration info
        
        try:
            if isinstance(exp, (int, float)):
                exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
            else:
                exp_time = datetime.fromisoformat(str(exp))
            
            return datetime.now(timezone.utc) >= exp_time
        except (ValueError, TypeError):
            logger.warning(f"Invalid expiration time format: {exp}")
            return False