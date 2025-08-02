"""
JWT Handler

Specialized JWT parsing and validation functionality with JWKS support.
Complements the token validator with JWT-specific features.
"""

import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

import aiohttp
import jwt
from cachetools import TTLCache

logger = logging.getLogger(__name__)


class JWTHandler:
    """Handles JWT parsing and validation with JWKS support."""

    def __init__(
        self,
        jwks_cache_ttl: int = 3600,  # 1 hour
        max_jwks_cache_size: int = 50,
    ):
        """
        Initialize the JWT handler.

        Args:
            jwks_cache_ttl: JWKS cache TTL in seconds
            max_jwks_cache_size: Maximum number of cached JWKS entries
        """
        self.jwks_cache = TTLCache(maxsize=max_jwks_cache_size, ttl=jwks_cache_ttl)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "MCP-JWT-Handler/1.0"},
            )
        return self._session

    async def close(self):
        """Clean up resources."""
        if self._session and not self._session.closed:
            await self._session.close()

    def decode_jwt_header(self, token: str) -> Dict[str, Any]:
        """
        Decode JWT header without verification.

        Args:
            token: JWT token

        Returns:
            JWT header dictionary

        Raises:
            jwt.InvalidTokenError: If token format is invalid
        """
        try:
            return jwt.get_unverified_header(token)
        except Exception as e:
            logger.error(f"Failed to decode JWT header: {e}")
            raise jwt.InvalidTokenError(f"Invalid JWT header: {str(e)}")

    def decode_jwt_payload(self, token: str) -> Dict[str, Any]:
        """
        Decode JWT payload without verification.

        Args:
            token: JWT token

        Returns:
            JWT payload dictionary

        Raises:
            jwt.InvalidTokenError: If token format is invalid
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            logger.error(f"Failed to decode JWT payload: {e}")
            raise jwt.InvalidTokenError(f"Invalid JWT payload: {str(e)}")

    async def decode_jwt(
        self,
        token: str,
        jwks_uri: Optional[str] = None,
        audience: Optional[Union[str, List[str]]] = None,
        issuer: Optional[str] = None,
        algorithms: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Decode and verify JWT signature with JWKS.

        Args:
            token: JWT token to decode
            jwks_uri: JWKS endpoint URI
            audience: Expected audience(s)
            issuer: Expected issuer
            algorithms: Allowed signing algorithms

        Returns:
            Verified JWT payload

        Raises:
            jwt.InvalidTokenError: If JWT verification fails
        """
        if algorithms is None:
            algorithms = ["RS256", "ES256", "HS256"]

        # Get JWT header to find key ID
        header = self.decode_jwt_header(token)
        kid = header.get("kid")
        alg = header.get("alg")

        if alg not in algorithms:
            raise jwt.InvalidTokenError(f"Algorithm {alg} not allowed")

        # Fetch JWKS if URI provided
        verification_key = None
        if jwks_uri:
            jwks = await self.fetch_jwks(jwks_uri)
            verification_key = self._find_key_in_jwks(jwks, kid, alg)

        if not verification_key:
            raise jwt.InvalidTokenError("No valid verification key found")

        # Verify and decode JWT
        try:
            payload = jwt.decode(
                token,
                key=verification_key,
                algorithms=[alg] if alg else algorithms,
                audience=audience,
                issuer=issuer,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": audience is not None,
                    "verify_iss": issuer is not None,
                }
            )
            
            logger.debug("Successfully decoded and verified JWT")
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            raise
        except jwt.InvalidAudienceError:
            logger.warning("JWT audience validation failed")
            raise
        except jwt.InvalidIssuerError:
            logger.warning("JWT issuer validation failed")
            raise
        except jwt.InvalidSignatureError:
            logger.warning("JWT signature verification failed")
            raise
        except Exception as e:
            logger.error(f"JWT verification failed: {e}")
            raise jwt.InvalidTokenError(f"JWT verification failed: {str(e)}")

    async def fetch_jwks(self, jwks_uri: str) -> Dict[str, Any]:
        """
        Fetch and cache JWKS from URI.

        Args:
            jwks_uri: JWKS endpoint URI

        Returns:
            JWKS dictionary

        Raises:
            aiohttp.ClientError: If JWKS cannot be fetched
        """
        # Check cache first
        if jwks_uri in self.jwks_cache:
            logger.debug(f"Using cached JWKS for {jwks_uri}")
            return self.jwks_cache[jwks_uri]

        session = await self._get_session()
        
        try:
            logger.debug(f"Fetching JWKS from {jwks_uri}")
            async with session.get(jwks_uri) as response:
                if response.status != 200:
                    raise aiohttp.ClientError(f"JWKS fetch failed: {response.status}")
                
                jwks = await response.json()
                
                # Validate JWKS format
                if not isinstance(jwks, dict) or "keys" not in jwks:
                    raise ValueError("Invalid JWKS format")
                
                self.jwks_cache[jwks_uri] = jwks
                logger.info(f"Successfully fetched and cached JWKS from {jwks_uri}")
                return jwks
                
        except aiohttp.ClientError:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch JWKS from {jwks_uri}: {e}")
            raise aiohttp.ClientError(f"JWKS fetch failed: {str(e)}")

    def _find_key_in_jwks(
        self,
        jwks: Dict[str, Any],
        kid: Optional[str] = None,
        alg: Optional[str] = None,
    ) -> Optional[Any]:
        """
        Find appropriate key in JWKS for token verification.

        Args:
            jwks: JWKS dictionary
            kid: Key ID from JWT header
            alg: Algorithm from JWT header

        Returns:
            Verification key or None if not found
        """
        keys = jwks.get("keys", [])
        
        for key_data in keys:
            # Match by key ID if provided
            if kid and key_data.get("kid") != kid:
                continue
            
            # Match by algorithm if provided
            if alg and key_data.get("alg") and key_data.get("alg") != alg:
                continue
            
            # Convert JWK to key object
            try:
                key = self._jwk_to_key(key_data)
                if key:
                    logger.debug(f"Found matching key in JWKS: kid={key_data.get('kid')}")
                    return key
            except Exception as e:
                logger.warning(f"Failed to convert JWK to key: {e}")
                continue
        
        logger.warning(f"No matching key found in JWKS for kid={kid}, alg={alg}")
        return None

    def _jwk_to_key(self, jwk: Dict[str, Any]) -> Optional[Any]:
        """
        Convert JWK (JSON Web Key) to cryptographic key object.

        Args:
            jwk: JWK dictionary

        Returns:
            Key object for verification
        """
        kty = jwk.get("kty")
        use = jwk.get("use")
        
        # Skip keys not for signature verification
        if use and use != "sig":
            return None
        
        try:
            if kty == "RSA":
                return self._jwk_to_rsa_key(jwk)
            elif kty == "EC":
                return self._jwk_to_ec_key(jwk)
            elif kty == "oct":
                return self._jwk_to_symmetric_key(jwk)
            else:
                logger.warning(f"Unsupported key type: {kty}")
                return None
        except Exception as e:
            logger.error(f"Failed to convert {kty} JWK to key: {e}")
            return None

    def _jwk_to_rsa_key(self, jwk: Dict[str, Any]) -> rsa.RSAPublicKey:
        """Convert RSA JWK to RSA public key."""
        import base64
        
        n = jwk.get("n")
        e = jwk.get("e")
        
        if not n or not e:
            raise ValueError("RSA JWK missing n or e parameter")
        
        # Decode base64url
        n_bytes = base64.urlsafe_b64decode(n + "==")
        e_bytes = base64.urlsafe_b64decode(e + "==")
        
        # Convert to integers
        n_int = int.from_bytes(n_bytes, byteorder="big")
        e_int = int.from_bytes(e_bytes, byteorder="big")
        
        # Create RSA public key
        public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())
        return public_key

    def _jwk_to_ec_key(self, jwk: Dict[str, Any]) -> ec.EllipticCurvePublicKey:
        """Convert EC JWK to EC public key."""
        import base64
        
        crv = jwk.get("crv")
        x = jwk.get("x")
        y = jwk.get("y")
        
        if not all([crv, x, y]):
            raise ValueError("EC JWK missing required parameters")
        
        # Map curve names
        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
        }
        
        curve = curve_map.get(crv)
        if not curve:
            raise ValueError(f"Unsupported EC curve: {crv}")
        
        # Decode coordinates
        x_bytes = base64.urlsafe_b64decode(x + "==")
        y_bytes = base64.urlsafe_b64decode(y + "==")
        
        x_int = int.from_bytes(x_bytes, byteorder="big")
        y_int = int.from_bytes(y_bytes, byteorder="big")
        
        # Create EC public key
        public_key = ec.EllipticCurvePublicNumbers(x_int, y_int, curve).public_key(default_backend())
        return public_key

    def _jwk_to_symmetric_key(self, jwk: Dict[str, Any]) -> bytes:
        """Convert symmetric JWK to key bytes."""
        import base64
        
        k = jwk.get("k")
        if not k:
            raise ValueError("Symmetric JWK missing k parameter")
        
        return base64.urlsafe_b64decode(k + "==")

    def extract_claims(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and normalize standard JWT claims.

        Args:
            payload: JWT payload

        Returns:
            Dictionary of normalized claims
        """
        claims = {}
        
        # Standard claims with normalization
        claim_mapping = {
            "iss": "issuer",
            "sub": "subject",
            "aud": "audience", 
            "exp": "expires_at",
            "nbf": "not_before",
            "iat": "issued_at",
            "jti": "jwt_id",
        }
        
        for jwt_claim, normalized_name in claim_mapping.items():
            if jwt_claim in payload:
                claims[normalized_name] = payload[jwt_claim]
        
        # Convert timestamps
        for time_claim in ["expires_at", "not_before", "issued_at"]:
            if time_claim in claims:
                claims[time_claim] = self._timestamp_to_datetime(claims[time_claim])
        
        # Additional common claims
        for claim in ["email", "email_verified", "name", "preferred_username", "scope", "scp"]:
            if claim in payload:
                claims[claim] = payload[claim]
        
        return claims

    def _timestamp_to_datetime(self, timestamp: Union[int, float]) -> datetime:
        """Convert Unix timestamp to datetime object."""
        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid timestamp: {timestamp}: {e}")
            return datetime.now(timezone.utc)

    def is_jwt_expired(self, payload: Dict[str, Any]) -> bool:
        """
        Check if JWT is expired based on exp claim.

        Args:
            payload: JWT payload

        Returns:
            True if JWT is expired
        """
        exp = payload.get("exp")
        if not exp:
            return False
        
        exp_time = self._timestamp_to_datetime(exp)
        return datetime.now(timezone.utc) >= exp_time

    def get_jwt_info(self, token: str) -> Dict[str, Any]:
        """
        Extract JWT information without verification.

        Args:
            token: JWT token

        Returns:
            Dictionary with JWT information
        """
        try:
            header = self.decode_jwt_header(token)
            payload = self.decode_jwt_payload(token)
            
            return {
                "header": header,
                "payload": payload,
                "claims": self.extract_claims(payload),
                "expired": self.is_jwt_expired(payload),
                "algorithm": header.get("alg"),
                "key_id": header.get("kid"),
                "token_type": header.get("typ", "JWT"),
            }
        except Exception as e:
            logger.error(f"Failed to extract JWT info: {e}")
            return {"error": str(e)}