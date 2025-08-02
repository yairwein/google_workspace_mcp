"""
OAuth 2.1 Session Store for Google Services

This module provides a global store for OAuth 2.1 authenticated sessions
that can be accessed by Google service decorators.
"""

import logging
from typing import Dict, Optional, Any
from threading import RLock

from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)


class OAuth21SessionStore:
    """
    Global store for OAuth 2.1 authenticated sessions.
    
    This store maintains a mapping of user emails to their OAuth 2.1
    authenticated credentials, allowing Google services to access them.
    """
    
    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()
    
    def store_session(
        self,
        user_email: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_uri: str = "https://oauth2.googleapis.com/token",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scopes: Optional[list] = None,
        expiry: Optional[Any] = None,
        session_id: Optional[str] = None,
    ):
        """
        Store OAuth 2.1 session information.
        
        Args:
            user_email: User's email address
            access_token: OAuth 2.1 access token
            refresh_token: OAuth 2.1 refresh token
            token_uri: Token endpoint URI
            client_id: OAuth client ID
            client_secret: OAuth client secret
            scopes: List of granted scopes
            expiry: Token expiry time
            session_id: OAuth 2.1 session ID
        """
        with self._lock:
            session_info = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_uri": token_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": scopes or [],
                "expiry": expiry,
                "session_id": session_id,
            }
            
            self._sessions[user_email] = session_info
            logger.info(f"Stored OAuth 2.1 session for {user_email} (session_id: {session_id})")
    
    def get_credentials(self, user_email: str) -> Optional[Credentials]:
        """
        Get Google credentials for a user from OAuth 2.1 session.
        
        Args:
            user_email: User's email address
            
        Returns:
            Google Credentials object or None
        """
        with self._lock:
            session_info = self._sessions.get(user_email)
            if not session_info:
                logger.debug(f"No OAuth 2.1 session found for {user_email}")
                return None
            
            try:
                # Create Google credentials from session info
                credentials = Credentials(
                    token=session_info["access_token"],
                    refresh_token=session_info.get("refresh_token"),
                    token_uri=session_info["token_uri"],
                    client_id=session_info.get("client_id"),
                    client_secret=session_info.get("client_secret"),
                    scopes=session_info.get("scopes", []),
                    expiry=session_info.get("expiry"),
                )
                
                logger.debug(f"Retrieved OAuth 2.1 credentials for {user_email}")
                return credentials
                
            except Exception as e:
                logger.error(f"Failed to create credentials for {user_email}: {e}")
                return None
    
    def remove_session(self, user_email: str):
        """Remove session for a user."""
        with self._lock:
            if user_email in self._sessions:
                del self._sessions[user_email]
                logger.info(f"Removed OAuth 2.1 session for {user_email}")
    
    def has_session(self, user_email: str) -> bool:
        """Check if a user has an active session."""
        with self._lock:
            return user_email in self._sessions
    
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        with self._lock:
            return {
                "total_sessions": len(self._sessions),
                "users": list(self._sessions.keys()),
            }


# Global instance
_global_store = OAuth21SessionStore()


def get_oauth21_session_store() -> OAuth21SessionStore:
    """Get the global OAuth 2.1 session store."""
    return _global_store