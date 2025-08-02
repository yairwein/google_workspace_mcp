"""
Session Context Management for OAuth 2.1 Integration

This module provides thread-local storage for OAuth 2.1 session context,
allowing tool functions to access the current authenticated session.
"""

import contextvars
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Context variable to store the current session information
_current_session_context: contextvars.ContextVar[Optional['SessionContext']] = contextvars.ContextVar(
    'current_session_context',
    default=None
)


@dataclass
class SessionContext:
    """Container for session-related information."""
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    auth_context: Optional[Any] = None
    request: Optional[Any] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


def set_session_context(context: Optional[SessionContext]):
    """
    Set the current session context.

    Args:
        context: The session context to set
    """
    _current_session_context.set(context)
    if context:
        logger.debug(f"Set session context: session_id={context.session_id}, user_id={context.user_id}")
    else:
        logger.debug("Cleared session context")


def get_session_context() -> Optional[SessionContext]:
    """
    Get the current session context.

    Returns:
        The current session context or None
    """
    print('called get_session_context')
    return _current_session_context.get()


def clear_session_context():
    """Clear the current session context."""
    set_session_context(None)


class SessionContextManager:
    """
    Context manager for temporarily setting session context.

    Usage:
        with SessionContextManager(session_context):
            # Code that needs access to session context
            pass
    """

    def __init__(self, context: Optional[SessionContext]):
        self.context = context
        self.token = None

    def __enter__(self):
        """Set the session context."""
        self.token = _current_session_context.set(self.context)
        return self.context

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Reset the session context."""
        if self.token:
            _current_session_context.reset(self.token)


def extract_session_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """
    Extract session ID from request headers.

    Args:
        headers: Request headers

    Returns:
        Session ID if found
    """
    # Try different header names
    session_id = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
    if session_id:
        return session_id

    session_id = headers.get("x-session-id") or headers.get("X-Session-ID")
    if session_id:
        return session_id

    # Try Authorization header for Bearer token
    auth_header = headers.get("authorization") or headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        # For now, we can't extract session from bearer token without the full context
        # This would need to be handled by the OAuth 2.1 middleware
        pass

    return None