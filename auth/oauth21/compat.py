"""
Backward Compatibility Layer

Maintains compatibility with existing authentication methods while providing
access to OAuth 2.1 features. Bridges legacy and modern authentication.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from google.oauth2.credentials import Credentials

from .config import AuthConfig
from .handler import OAuth2Handler
from .middleware import AuthContext
from ..google_auth import (
    get_credentials as legacy_get_credentials,
)

logger = logging.getLogger(__name__)


class AuthCompatibilityLayer:
    """Maintains compatibility with existing auth methods."""

    def __init__(self, auth_config: AuthConfig):
        """
        Initialize compatibility layer.

        Args:
            auth_config: Complete authentication configuration
        """
        self.config = auth_config
        self.oauth2_handler: Optional[OAuth2Handler] = None
        
        # Initialize OAuth 2.1 handler if enabled
        if self.config.is_oauth2_enabled():
            self.oauth2_handler = OAuth2Handler(self.config.oauth2)

    async def start(self):
        """Start the compatibility layer."""
        if self.oauth2_handler:
            await self.oauth2_handler.start()
        logger.info("Authentication compatibility layer started")

    async def stop(self):
        """Stop the compatibility layer."""
        if self.oauth2_handler:
            await self.oauth2_handler.stop()
        logger.info("Authentication compatibility layer stopped")

    def supports_legacy_auth(self, request: Optional[Any] = None) -> bool:
        """
        Check if request uses legacy authentication.

        Args:
            request: HTTP request (optional)

        Returns:
            True if legacy authentication should be used
        """
        # Always support legacy auth if enabled
        if not self.config.enable_legacy_auth:
            return False
        
        # In single user mode, prefer legacy
        if self.config.single_user_mode:
            return True
        
        # If OAuth 2.1 is not configured, use legacy
        if not self.config.is_oauth2_enabled():
            return True
        
        # Check if request has Bearer token (suggesting OAuth 2.1)
        if request and hasattr(request, 'headers'):
            auth_header = request.headers.get('authorization', '')
            if auth_header.lower().startswith('bearer '):
                return False
        
        # Default to supporting legacy for backward compatibility
        return True

    async def handle_legacy_auth(
        self,
        user_google_email: Optional[str],
        required_scopes: List[str],
        session_id: Optional[str] = None,
        client_secrets_path: Optional[str] = None,
        credentials_base_dir: Optional[str] = None,
    ) -> Optional[Credentials]:
        """
        Process legacy authentication.

        Args:
            user_google_email: User's Google email
            required_scopes: Required OAuth scopes
            session_id: Session identifier
            client_secrets_path: Path to client secrets file
            credentials_base_dir: Base directory for credentials

        Returns:
            Google credentials or None if authentication fails
        """
        try:
            credentials = await asyncio.to_thread(
                legacy_get_credentials,
                user_google_email=user_google_email,
                required_scopes=required_scopes,
                client_secrets_path=client_secrets_path,
                credentials_base_dir=credentials_base_dir or self.config.legacy_credentials_dir,
                session_id=session_id,
            )
            
            if credentials:
                logger.debug(f"Legacy authentication successful for {user_google_email}")
                
                # Bridge to OAuth 2.1 session if available
                if self.oauth2_handler and session_id:
                    await self._bridge_legacy_to_oauth2(
                        credentials, user_google_email, session_id, required_scopes
                    )
            
            return credentials
            
        except Exception as e:
            logger.error(f"Legacy authentication failed: {e}")
            return None

    async def get_unified_credentials(
        self,
        user_google_email: Optional[str],
        required_scopes: List[str],
        session_id: Optional[str] = None,
        request: Optional[Any] = None,
        prefer_oauth2: bool = False,
    ) -> Optional[Credentials]:
        """
        Get credentials using unified authentication approach.

        Args:
            user_google_email: User's Google email
            required_scopes: Required OAuth scopes
            session_id: Session identifier
            request: HTTP request object
            prefer_oauth2: Whether to prefer OAuth 2.1 over legacy

        Returns:
            Google credentials or None
        """
        # Determine authentication method
        use_oauth2 = (
            self.config.is_oauth2_enabled() and 
            (prefer_oauth2 or not self.supports_legacy_auth(request))
        )
        
        if use_oauth2:
            # Try OAuth 2.1 authentication first
            credentials = await self._get_oauth2_credentials(
                user_google_email, required_scopes, session_id, request
            )
            
            # Fallback to legacy if OAuth 2.1 fails and legacy is enabled
            if not credentials and self.config.enable_legacy_auth:
                logger.debug("OAuth 2.1 authentication failed, falling back to legacy")
                credentials = await self.handle_legacy_auth(
                    user_google_email, required_scopes, session_id
                )
        else:
            # Use legacy authentication
            credentials = await self.handle_legacy_auth(
                user_google_email, required_scopes, session_id
            )
        
        return credentials

    async def _get_oauth2_credentials(
        self,
        user_google_email: Optional[str],
        required_scopes: List[str],
        session_id: Optional[str],
        request: Optional[Any],
    ) -> Optional[Credentials]:
        """Get credentials using OAuth 2.1."""
        if not self.oauth2_handler:
            return None
        
        try:
            # Extract Bearer token from request if available
            bearer_token = None
            if request and hasattr(request, 'headers'):
                auth_header = request.headers.get('authorization', '')
                if auth_header.lower().startswith('bearer '):
                    bearer_token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Try session-based authentication first
            if session_id:
                session_info = self.oauth2_handler.get_session_info(session_id)
                if session_info:
                    return self._convert_oauth2_to_credentials(session_info)
            
            # Try Bearer token authentication
            if bearer_token:
                auth_context = await self.oauth2_handler.authenticate_bearer_token(
                    token=bearer_token,
                    required_scopes=required_scopes,
                    create_session=bool(session_id),
                )
                
                if auth_context.authenticated:
                    return self._convert_oauth2_to_credentials(auth_context.token_info)
            
            return None
            
        except Exception as e:
            logger.error(f"OAuth 2.1 credential retrieval failed: {e}")
            return None

    def _convert_oauth2_to_credentials(self, token_info: Dict[str, Any]) -> Optional[Credentials]:
        """Convert OAuth 2.1 token info to Google Credentials."""
        try:
            # Extract token information
            access_token = token_info.get("access_token")
            refresh_token = token_info.get("refresh_token")
            token_uri = token_info.get("token_uri") or "https://oauth2.googleapis.com/token"
            client_id = token_info.get("client_id") or self.config.oauth2.client_id
            client_secret = token_info.get("client_secret") or self.config.oauth2.client_secret
            scopes = token_info.get("scopes", [])
            
            if not access_token:
                return None
            
            # Parse expiry
            expiry = None
            if "expires_at" in token_info:
                exp_timestamp = token_info["expires_at"]
                if isinstance(exp_timestamp, (int, float)):
                    expiry = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
            
            # Create Google Credentials object
            credentials = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri=token_uri,
                client_id=client_id,
                client_secret=client_secret,
                scopes=scopes,
                expiry=expiry,
            )
            
            logger.debug("Successfully converted OAuth 2.1 token to Google Credentials")
            return credentials
            
        except Exception as e:
            logger.error(f"Failed to convert OAuth 2.1 token to credentials: {e}")
            return None

    async def _bridge_legacy_to_oauth2(
        self,
        credentials: Credentials,
        user_email: str,
        session_id: str,
        scopes: List[str],
    ):
        """Bridge legacy credentials to OAuth 2.1 session."""
        if not self.oauth2_handler:
            return
        
        try:
            # Convert legacy credentials to OAuth 2.1 token format
            token_info = {
                "access_token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes or scopes,
                "expires_at": credentials.expiry.timestamp() if credentials.expiry else None,
                "token_type": "Bearer",
            }
            
            # Create OAuth 2.1 session
            oauth2_session_id = self.oauth2_handler.session_store.create_session(
                user_id=user_email,
                token_info=token_info,
                scopes=scopes,
                metadata={
                    "bridged_from": "legacy_auth",
                    "legacy_session_id": session_id,
                }
            )
            
            logger.debug(f"Bridged legacy credentials to OAuth 2.1 session {oauth2_session_id}")
            
        except Exception as e:
            logger.error(f"Failed to bridge legacy credentials to OAuth 2.1: {e}")

    def create_enhanced_middleware(self):
        """Create middleware that supports both OAuth 2.1 and legacy auth."""
        if not self.oauth2_handler:
            return None
        
        # Get base OAuth 2.1 middleware
        middleware = self.oauth2_handler.create_middleware()
        
        # Enhance it with legacy support
        original_authenticate = middleware.authenticate_request
        
        async def enhanced_authenticate(request):
            """Enhanced authentication that supports legacy fallback."""
            # Try OAuth 2.1 first
            auth_context = await original_authenticate(request)
            
            # If OAuth 2.1 fails and legacy is supported, try legacy
            if (not auth_context.authenticated and 
                self.supports_legacy_auth(request) and
                self.config.enable_legacy_auth):
                
                # Extract session ID for legacy auth
                session_id = middleware._extract_session_id(request)
                
                # Try to get user email (this is a limitation of legacy auth)
                user_email = self.config.default_user_email
                if not user_email:
                    # Could extract from request parameters or headers
                    user_email = request.query_params.get('user_google_email')
                
                if user_email:
                    try:
                        credentials = await self.handle_legacy_auth(
                            user_google_email=user_email,
                            required_scopes=self.config.oauth2.required_scopes,
                            session_id=session_id,
                        )
                        
                        if credentials:
                            # Create auth context from legacy credentials
                            auth_context = AuthContext(
                                authenticated=True,
                                user_id=user_email,
                                session_id=session_id,
                                token_info={
                                    "access_token": credentials.token,
                                    "scopes": credentials.scopes or [],
                                    "auth_method": "legacy",
                                },
                                scopes=credentials.scopes or [],
                            )
                    except Exception as e:
                        logger.error(f"Legacy auth fallback failed: {e}")
            
            return auth_context
        
        # Replace the authenticate method
        middleware.authenticate_request = enhanced_authenticate
        return middleware

    def get_auth_mode_info(self) -> Dict[str, Any]:
        """Get information about current authentication mode."""
        return {
            "mode": self.config.get_effective_auth_mode(),
            "oauth2_enabled": self.config.is_oauth2_enabled(),
            "legacy_enabled": self.config.enable_legacy_auth,
            "single_user_mode": self.config.single_user_mode,
            "default_user_email": self.config.default_user_email,
            "oauth2_config": self.config.oauth2.to_dict() if self.config.oauth2 else None,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()


# Legacy compatibility functions
async def get_enhanced_credentials(
    user_google_email: Optional[str],
    required_scopes: List[str],
    session_id: Optional[str] = None,
    request: Optional[Any] = None,
    auth_config: Optional[AuthConfig] = None,
    **kwargs
) -> Optional[Credentials]:
    """
    Enhanced version of get_credentials that supports OAuth 2.1.
    
    This function maintains backward compatibility while adding OAuth 2.1 support.
    """
    if not auth_config:
        # Create default config that tries to enable OAuth 2.1
        auth_config = AuthConfig()
    
    compat_layer = AuthCompatibilityLayer(auth_config)
    
    async with compat_layer:
        return await compat_layer.get_unified_credentials(
            user_google_email=user_google_email,
            required_scopes=required_scopes,
            session_id=session_id,
            request=request,
        )


def create_compatible_auth_handler(auth_config: Optional[AuthConfig] = None) -> AuthCompatibilityLayer:
    """
    Create a compatible authentication handler.
    
    Args:
        auth_config: Authentication configuration
        
    Returns:
        Authentication compatibility layer
    """
    if not auth_config:
        auth_config = AuthConfig()
    
    return AuthCompatibilityLayer(auth_config)