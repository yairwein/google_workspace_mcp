"""
MCP OAuth 2.1 Bridge

This module bridges MCP transport sessions with OAuth 2.1 authenticated sessions,
allowing tool functions to access the OAuth 2.1 context.
"""

import logging
from typing import Dict, Optional, Any
from datetime import datetime

from auth.session_context import SessionContext, set_session_context
# OAuth 2.1 is now handled by FastMCP auth

logger = logging.getLogger(__name__)


class MCPOAuth21Bridge:
    """
    Bridges MCP transport sessions with OAuth 2.1 sessions.
    
    This class maintains a mapping between MCP transport session IDs
    and OAuth 2.1 authenticated sessions.
    """
    
    def __init__(self):
        # Session mapping now handled by OAuth21SessionStore
        pass
    
    def link_sessions(
        self, 
        mcp_session_id: str, 
        oauth21_session_id: str,
        user_id: Optional[str] = None,
        auth_context: Optional[Any] = None
    ):
        """
        Link an MCP transport session with an OAuth 2.1 session using OAuth21SessionStore.
        
        Args:
            mcp_session_id: MCP transport session ID
            oauth21_session_id: OAuth 2.1 session ID
            user_id: User identifier (user email)
            auth_context: OAuth 2.1 authentication context
        """
        from auth.oauth21_session_store import get_oauth21_session_store
        
        if user_id:  # user_id should be the user email
            store = get_oauth21_session_store()
            # Linking is handled by updating the mcp_session_id in the store
            # We need to check if the user already has a session and update it
            if store.has_session(user_id):
                # Get existing session info to preserve it
                existing_creds = store.get_credentials(user_id)
                if existing_creds:
                    store.store_session(
                        user_email=user_id,
                        access_token=existing_creds.token,
                        refresh_token=existing_creds.refresh_token,
                        token_uri=existing_creds.token_uri,
                        client_id=existing_creds.client_id,
                        client_secret=existing_creds.client_secret,
                        scopes=existing_creds.scopes,
                        expiry=existing_creds.expiry,
                        session_id=oauth21_session_id,
                        mcp_session_id=mcp_session_id
                    )
            
            logger.info(
                f"Linked MCP session {mcp_session_id} with OAuth 2.1 session {oauth21_session_id} "
                f"for user {user_id}"
            )
        else:
            logger.warning(f"Cannot link sessions without user_id")
    
    def get_oauth21_session(self, mcp_session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get OAuth 2.1 session info for an MCP transport session from OAuth21SessionStore.
        
        Args:
            mcp_session_id: MCP transport session ID
            
        Returns:
            OAuth 2.1 session information if linked
        """
        from auth.oauth21_session_store import get_oauth21_session_store
        
        store = get_oauth21_session_store()
        user_email = store.get_user_by_mcp_session(mcp_session_id)
        if user_email:
            credentials = store.get_credentials(user_email)
            if credentials:
                return {
                    "oauth21_session_id": f"oauth21_{user_email}",
                    "user_id": user_email,
                    "auth_context": {
                        "access_token": credentials.token,
                        "refresh_token": credentials.refresh_token,
                        "scopes": credentials.scopes
                    },
                    "linked_at": datetime.utcnow().isoformat(),
                }
        return None
    
    def get_mcp_session(self, oauth21_session_id: str) -> Optional[str]:
        """
        Get MCP transport session ID for an OAuth 2.1 session from OAuth21SessionStore.
        
        Args:
            oauth21_session_id: OAuth 2.1 session ID
            
        Returns:
            MCP transport session ID if linked
        """
        from auth.oauth21_session_store import get_oauth21_session_store
        
        store = get_oauth21_session_store()
        # Look through all sessions to find one with matching oauth21_session_id
        stats = store.get_stats()
        for user_email in stats["users"]:
            # Try to match based on session_id pattern
            if oauth21_session_id == f"oauth21_{user_email}":
                # Get all MCP session mappings and find the one for this user
                for mcp_session_id in stats["mcp_sessions"]:
                    if store.get_user_by_mcp_session(mcp_session_id) == user_email:
                        return mcp_session_id
        return None
    
    def unlink_mcp_session(self, mcp_session_id: str):
        """
        Remove the link for an MCP transport session using OAuth21SessionStore.
        
        Args:
            mcp_session_id: MCP transport session ID
        """
        from auth.oauth21_session_store import get_oauth21_session_store
        
        store = get_oauth21_session_store()
        user_email = store.get_user_by_mcp_session(mcp_session_id)
        if user_email:
            # Remove the entire session since MCP bridge is responsible for the link
            store.remove_session(user_email)
            logger.info(f"Unlinked MCP session {mcp_session_id} for user {user_email}")
        else:
            logger.warning(f"No linked session found for MCP session {mcp_session_id}")
    
    def set_session_context_for_mcp(self, mcp_session_id: str) -> bool:
        """
        Set the session context for the current request based on MCP session.
        
        Args:
            mcp_session_id: MCP transport session ID
            
        Returns:
            True if context was set, False otherwise
        """
        session_info = self.get_oauth21_session(mcp_session_id)
        if not session_info:
            logger.debug(f"No OAuth 2.1 session linked to MCP session {mcp_session_id}")
            return False
        
        # Create and set session context
        context = SessionContext(
            session_id=session_info["oauth21_session_id"],
            user_id=session_info["user_id"],
            auth_context=session_info["auth_context"],
            metadata={
                "mcp_session_id": mcp_session_id,
                "linked_at": session_info["linked_at"],
            }
        )
        
        set_session_context(context)
        logger.debug(
            f"Set session context for MCP session {mcp_session_id}: "
            f"OAuth 2.1 session {context.session_id}, user {context.user_id}"
        )
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get bridge statistics from OAuth21SessionStore."""
        from auth.oauth21_session_store import get_oauth21_session_store
        
        store = get_oauth21_session_store()
        store_stats = store.get_stats()
        return {
            "linked_sessions": store_stats["mcp_session_mappings"],
            "mcp_sessions": store_stats["mcp_sessions"],
            "oauth21_sessions": [f"oauth21_{user}" for user in store_stats["users"]],
        }


# Global bridge instance
_bridge = MCPOAuth21Bridge()


def get_bridge() -> MCPOAuth21Bridge:
    """Get the global MCP OAuth 2.1 bridge instance."""
    return _bridge