"""
OAuth 2.1 Handler

Main OAuth 2.1 authentication handler that integrates all components.
Provides a unified interface for OAuth 2.1 functionality.
"""

import logging
from typing import Dict, Any, Optional, List, Tuple

from .config import OAuth2Config
from .discovery import AuthorizationServerDiscovery
from .oauth2 import OAuth2AuthorizationFlow
from .tokens import TokenValidator, TokenValidationError
from .sessions import SessionStore, Session
from .middleware import AuthenticationMiddleware, AuthContext
from .http import HTTPAuthHandler

logger = logging.getLogger(__name__)


class OAuth2Handler:
    """Main OAuth 2.1 authentication handler."""

    def __init__(self, config: OAuth2Config):
        """
        Initialize OAuth 2.1 handler.

        Args:
            config: OAuth 2.1 configuration
        """
        self.config = config
        
        # Initialize components
        self.discovery = AuthorizationServerDiscovery(
            resource_url=config.resource_url,
            cache_ttl=config.discovery_cache_ttl,
            proxy_base_url=config.proxy_base_url,
        )
        
        self.flow_handler = OAuth2AuthorizationFlow(
            client_id=config.client_id,
            client_secret=config.client_secret,
            discovery_service=self.discovery,
        )
        
        self.token_validator = TokenValidator(
            discovery_service=self.discovery,
            cache_ttl=config.jwks_cache_ttl,
        )
        
        self.session_store = SessionStore(
            default_session_timeout=config.session_timeout,
            max_sessions_per_user=config.max_sessions_per_user,
            cleanup_interval=config.session_cleanup_interval,
            enable_persistence=config.enable_session_persistence,
            persistence_file=str(config.get_session_persistence_path()) if config.get_session_persistence_path() else None,
        )
        
        self.http_auth = HTTPAuthHandler()
        
        # Setup debug logging if enabled
        if config.enable_debug_logging:
            logging.getLogger("auth.oauth21").setLevel(logging.DEBUG)

    async def start(self):
        """Start the OAuth 2.1 handler and background tasks."""
        await self.session_store.start_cleanup_task()
        logger.info("OAuth 2.1 handler started")

    async def stop(self):
        """Stop the OAuth 2.1 handler and clean up resources."""
        await self.session_store.stop_cleanup_task()
        await self.flow_handler.close()
        await self.token_validator.close()
        logger.info("OAuth 2.1 handler stopped")

    async def create_authorization_url(
        self,
        redirect_uri: str,
        scopes: List[str],
        state: Optional[str] = None,
        session_id: Optional[str] = None,
        additional_params: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, str, str]:
        """
        Create OAuth 2.1 authorization URL.

        Args:
            redirect_uri: OAuth redirect URI
            scopes: Requested scopes
            state: State parameter (generated if not provided)
            session_id: Optional session ID to associate
            additional_params: Additional authorization parameters

        Returns:
            Tuple of (authorization_url, state, code_verifier)

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.config.authorization_server_url:
            raise ValueError("Authorization server URL not configured")

        # Build authorization URL
        auth_url, final_state, code_verifier = await self.flow_handler.build_authorization_url(
            authorization_server_url=self.config.authorization_server_url,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            resource=self.config.resource_url,
            additional_params=additional_params,
        )

        # Store session association if provided
        if session_id:
            self._store_authorization_state(final_state, session_id, code_verifier)

        logger.info(f"Created authorization URL for scopes: {scopes}")
        return auth_url, final_state, code_verifier

    async def exchange_code_for_session(
        self,
        authorization_code: str,
        code_verifier: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> Tuple[str, Session]:
        """
        Exchange authorization code for session.

        Args:
            authorization_code: Authorization code from callback
            code_verifier: PKCE code verifier
            redirect_uri: OAuth redirect URI
            state: State parameter from authorization

        Returns:
            Tuple of (session_id, session)

        Raises:
            ValueError: If code exchange fails
            TokenValidationError: If token validation fails
        """
        # Exchange code for tokens
        token_response = await self.flow_handler.exchange_code_for_token(
            authorization_server_url=self.config.authorization_server_url,
            authorization_code=authorization_code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            resource=self.config.resource_url,
        )

        # Validate the received token
        access_token = token_response["access_token"]
        token_info = await self.token_validator.validate_token(
            token=access_token,
            expected_audience=self.config.expected_audience,
            required_scopes=self.config.required_scopes,
            authorization_server_url=self.config.authorization_server_url,
        )

        if not token_info["valid"]:
            raise TokenValidationError("Received token is invalid")

        # Extract user identity
        user_id = token_info["user_identity"]

        # Create session
        session_id = self.session_store.create_session(
            user_id=user_id,
            token_info={
                **token_response,
                "validation_info": token_info,
                "claims": token_info.get("claims", {}),
            },
            scopes=token_info.get("scopes", []),
            authorization_server=self.config.authorization_server_url,
            client_id=self.config.client_id,
            metadata={
                "auth_method": "oauth2_authorization_code",
                "token_type": token_info.get("token_type"),
                "created_via": "code_exchange",
            }
        )

        session = self.session_store.get_session(session_id)
        logger.info(f"Created session {session_id} for user {user_id}")
        
        # Store in global OAuth 2.1 session store for Google services
        try:
            from auth.oauth21_session_store import get_oauth21_session_store
            store = get_oauth21_session_store()
            store.store_session(
                user_email=user_id,
                access_token=access_token,
                refresh_token=token_response.get("refresh_token"),
                token_uri=token_response.get("token_uri", "https://oauth2.googleapis.com/token"),
                client_id=self.config.client_id,
                client_secret=self.config.client_secret,
                scopes=token_info.get("scopes", []),
                expiry=token_info.get("expires_at"),
                session_id=session_id,
            )
        except Exception as e:
            logger.error(f"Failed to store session in global store: {e}")

        return session_id, session

    async def authenticate_bearer_token(
        self,
        token: str,
        required_scopes: Optional[List[str]] = None,
        create_session: bool = True,
    ) -> AuthContext:
        """
        Authenticate Bearer token and optionally create session.

        Args:
            token: Bearer token to authenticate
            required_scopes: Required scopes (uses config default if not provided)
            create_session: Whether to create a session for valid tokens

        Returns:
            Authentication context

        Raises:
            TokenValidationError: If token validation fails
        """
        auth_context = AuthContext()

        try:
            # Validate token
            scopes_to_check = required_scopes or self.config.required_scopes
            token_info = await self.token_validator.validate_token(
                token=token,
                expected_audience=self.config.expected_audience,
                required_scopes=scopes_to_check,
                authorization_server_url=self.config.authorization_server_url,
            )

            if token_info["valid"]:
                auth_context.authenticated = True
                auth_context.user_id = token_info["user_identity"]
                auth_context.token_info = token_info
                auth_context.scopes = token_info.get("scopes", [])

                # Create session if requested
                if create_session:
                    session_id = self.session_store.create_session(
                        user_id=auth_context.user_id,
                        token_info=token_info,
                        scopes=auth_context.scopes,
                        authorization_server=self.config.authorization_server_url,
                        client_id=self.config.client_id,
                        metadata={
                            "auth_method": "bearer_token",
                            "created_via": "token_passthrough",
                        }
                    )
                    
                    auth_context.session_id = session_id
                    auth_context.session = self.session_store.get_session(session_id)

                logger.debug(f"Authenticated Bearer token for user {auth_context.user_id}")
            else:
                auth_context.error = "invalid_token"
                auth_context.error_description = "Token validation failed"

        except TokenValidationError as e:
            auth_context.error = e.error_code
            auth_context.error_description = str(e)
            logger.warning(f"Bearer token validation failed: {e}")

        return auth_context

    async def refresh_session_token(self, session_id: str) -> bool:
        """
        Refresh tokens for a session.

        Args:
            session_id: Session identifier

        Returns:
            True if refresh was successful

        Raises:
            ValueError: If session not found or refresh fails
        """
        session = self.session_store.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")

        refresh_token = session.token_info.get("refresh_token")
        if not refresh_token:
            raise ValueError("Session has no refresh token")

        try:
            # Refresh the token
            token_response = await self.flow_handler.refresh_access_token(
                authorization_server_url=self.config.authorization_server_url,
                refresh_token=refresh_token,
                scopes=session.scopes,
                resource=self.config.resource_url,
            )

            # Update session with new tokens
            updated_token_info = {**session.token_info, **token_response}
            success = self.session_store.update_session(
                session_id=session_id,
                token_info=updated_token_info,
                extend_expiration=True,
            )

            if success:
                logger.info(f"Refreshed tokens for session {session_id}")
            
            return success

        except Exception as e:
            logger.error(f"Failed to refresh token for session {session_id}: {e}")
            raise ValueError(f"Token refresh failed: {str(e)}")

    def create_middleware(self) -> AuthenticationMiddleware:
        """
        Create authentication middleware.

        Returns:
            Configured authentication middleware
        """
        return AuthenticationMiddleware(
            app=None,  # Will be set when middleware is added to app
            session_store=self.session_store,
            token_validator=self.token_validator,
            discovery_service=self.discovery,
            http_auth_handler=self.http_auth,
            required_scopes=self.config.required_scopes,
            exempt_paths=self.config.exempt_paths,
            authorization_server_url=self.config.authorization_server_url,
            expected_audience=self.config.expected_audience,
            enable_bearer_passthrough=self.config.enable_bearer_passthrough,
        )

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get session information.

        Args:
            session_id: Session identifier

        Returns:
            Session information dictionary or None
        """
        session = self.session_store.get_session(session_id)
        if not session:
            return None

        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "scopes": session.scopes,
            "created_at": session.created_at.isoformat(),
            "last_accessed": session.last_accessed.isoformat(),
            "expires_at": session.expires_at.isoformat() if session.expires_at else None,
            "authorization_server": session.authorization_server,
            "metadata": session.metadata,
            "has_refresh_token": "refresh_token" in session.token_info,
        }

    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            List of session information
        """
        sessions = self.session_store.get_user_sessions(user_id)
        return [
            {
                "session_id": session.session_id,
                "created_at": session.created_at.isoformat(),
                "last_accessed": session.last_accessed.isoformat(),
                "expires_at": session.expires_at.isoformat() if session.expires_at else None,
                "scopes": session.scopes,
                "metadata": session.metadata,
            }
            for session in sessions
        ]

    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session.

        Args:
            session_id: Session identifier

        Returns:
            True if session was revoked
        """
        success = self.session_store.remove_session(session_id)
        if success:
            logger.info(f"Revoked session {session_id}")
        return success

    def revoke_user_sessions(self, user_id: str) -> int:
        """
        Revoke all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            Number of sessions revoked
        """
        count = self.session_store.remove_user_sessions(user_id)
        logger.info(f"Revoked {count} sessions for user {user_id}")
        return count

    def get_handler_stats(self) -> Dict[str, Any]:
        """
        Get OAuth 2.1 handler statistics.

        Returns:
            Handler statistics
        """
        session_stats = self.session_store.get_session_stats()
        
        return {
            "config": {
                "authorization_server": self.config.authorization_server_url,
                "client_id": self.config.client_id,
                "session_timeout": self.config.session_timeout,
                "bearer_passthrough": self.config.enable_bearer_passthrough,
            },
            "sessions": session_stats,
            "components": {
                "discovery_cache_size": len(self.discovery.cache),
                "token_validation_cache_size": len(self.token_validator.validation_cache),
                "jwks_cache_size": len(self.token_validator.jwks_cache),
            }
        }

    def _store_authorization_state(self, state: str, session_id: str, code_verifier: str):
        """Store authorization state for later retrieval."""
        # This could be enhanced with a proper state store
        # For now, we'll use session metadata
        pass

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()