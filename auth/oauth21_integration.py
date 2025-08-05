"""
OAuth 2.1 Integration for Google Services

This module provides integration between FastMCP OAuth sessions and Google services,
allowing authenticated sessions to be passed through to Google API calls.
"""

import asyncio
import logging
from typing import Optional, Tuple, Any, Dict

from googleapiclient.discovery import build

from auth.google_auth import (
    GoogleAuthenticationError,
)

logger = logging.getLogger(__name__)


class OAuth21GoogleServiceBuilder:
    """Builds Google services using FastMCP OAuth authenticated sessions."""

    def __init__(self):
        """
        Initialize the service builder.
        """
        self._service_cache: Dict[str, Tuple[Any, str]] = {}

    def extract_session_from_context(self, context: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Extract session ID from various context sources.

        Args:
            context: Context dictionary that may contain session information

        Returns:
            Session ID if found, None otherwise
        """
        if not context:
            return None

        # Try to extract from OAuth 2.1 auth context
        if "auth_context" in context and hasattr(context["auth_context"], "session_id"):
            return context["auth_context"].session_id

        # Try direct session_id
        if "session_id" in context:
            return context["session_id"]

        # Try from request state
        if "request" in context:
            request = context["request"]
            if hasattr(request, "state") and hasattr(request.state, "auth"):
                auth_ctx = request.state.auth
                if hasattr(auth_ctx, "session_id"):
                    return auth_ctx.session_id

        return None

    async def get_authenticated_service_with_session(
        self,
        service_name: str,
        version: str,
        tool_name: str,
        user_google_email: str,
        required_scopes: list[str],
        session_id: Optional[str] = None,
        auth_context: Optional[Any] = None,
    ) -> Tuple[Any, str]:
        """
        Get authenticated Google service using OAuth 2.1 session if available.

        Args:
            service_name: Google service name (e.g., "gmail", "drive")
            version: API version (e.g., "v1", "v3")
            tool_name: Name of the tool for logging
            user_google_email: User's Google email
            required_scopes: Required OAuth scopes
            session_id: OAuth 2.1 session ID
            auth_context: OAuth 2.1 authentication context

        Returns:
            Tuple of (service instance, actual user email)

        Raises:
            GoogleAuthenticationError: If authentication fails
        """
        cache_key = f"{user_google_email}:{service_name}:{version}:{':'.join(sorted(required_scopes))}"

        # Check cache first
        if cache_key in self._service_cache:
            logger.debug(f"[{tool_name}] Using cached service for {user_google_email}")
            return self._service_cache[cache_key]

        try:
            # First check the global OAuth 2.1 session store
            from auth.oauth21_session_store import get_oauth21_session_store
            store = get_oauth21_session_store()
            credentials = store.get_credentials(user_google_email)

            if credentials and credentials.valid:
                logger.info(f"[{tool_name}] Found OAuth 2.1 credentials in global store for {user_google_email}")

                # Build the service
                service = await asyncio.to_thread(
                    build, service_name, version, credentials=credentials
                )

                # Cache the service
                self._service_cache[cache_key] = (service, user_google_email)

                return service, user_google_email

            # If OAuth 2.1 is not enabled, fall back to legacy authentication
            if not is_oauth21_enabled():
                logger.debug(f"[{tool_name}] OAuth 2.1 is not enabled. Falling back to legacy authentication for {user_google_email}")
                return await get_legacy_auth_service(
                    service_name=service_name,
                    version=version,
                    tool_name=tool_name,
                    user_google_email=user_google_email,
                    required_scopes=required_scopes,
                )

            # If we are here, it means OAuth 2.1 is enabled but credentials are not found
            logger.error(f"[{tool_name}] OAuth 2.1 is enabled, but no valid credentials found for {user_google_email}")
            raise GoogleAuthenticationError(
                f"OAuth 2.1 is enabled, but no valid credentials found for {user_google_email}"
            )

        except Exception as e:
            logger.error(f"[{tool_name}] Authentication failed for {user_google_email}: {e}")
            raise GoogleAuthenticationError(
                f"Failed to authenticate for {service_name}: {str(e)}"
            )

    def clear_cache(self):
        """Clear the service cache."""
        self._service_cache.clear()
        logger.debug("Cleared OAuth 2.1 service cache")


# Global instance
_global_service_builder: Optional[OAuth21GoogleServiceBuilder] = None


def get_oauth21_service_builder() -> OAuth21GoogleServiceBuilder:
    """Get the global OAuth 2.1 service builder instance."""
    global _global_service_builder
    if _global_service_builder is None:
        _global_service_builder = OAuth21GoogleServiceBuilder()
    return _global_service_builder


def set_auth_layer(auth_layer):
    """
    Legacy compatibility function - no longer needed with FastMCP auth.
    """
    logger.info("set_auth_layer called - OAuth is now handled by FastMCP")


_oauth21_enabled = False

def is_oauth21_enabled() -> bool:
    """
    Check if the OAuth 2.1 authentication layer is active.
    """
    global _oauth21_enabled
    return _oauth21_enabled


def enable_oauth21():
    """
    Enable the OAuth 2.1 authentication layer.
    """
    global _oauth21_enabled
    _oauth21_enabled = True
    logger.debug("OAuth 2.1 authentication enabled")


async def get_legacy_auth_service(
    service_name: str,
    version: str,
    tool_name: str,
    user_google_email: str,
    required_scopes: list[str],
) -> Tuple[Any, str]:
    """
    Get authenticated Google service using legacy authentication.
    """
    from auth.google_auth import get_authenticated_google_service as legacy_get_service

    return await legacy_get_service(
        service_name=service_name,
        version=version,
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=required_scopes,
    )


async def get_authenticated_google_service_oauth21(
    service_name: str,
    version: str,
    tool_name: str,
    user_google_email: str,
    required_scopes: list[str],
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, str]:
    """
    Enhanced version of get_authenticated_google_service that supports OAuth 2.1.

    This function checks for OAuth 2.1 session context and uses it if available,
    otherwise falls back to legacy authentication.

    Args:
        service_name: Google service name
        version: API version
        tool_name: Tool name for logging
        user_google_email: User's Google email
        required_scopes: Required OAuth scopes
        context: Optional context containing session information

    Returns:
        Tuple of (service instance, actual user email)
    """
    builder = get_oauth21_service_builder()

    # FastMCP handles context now - extract any session info
    session_id = None
    auth_context = None

    if context:
        session_id = builder.extract_session_from_context(context)
        auth_context = context.get("auth_context")

    return await builder.get_authenticated_service_with_session(
        service_name=service_name,
        version=version,
        tool_name=tool_name,
        user_google_email=user_google_email,
        required_scopes=required_scopes,
        session_id=session_id,
        auth_context=auth_context,
    )