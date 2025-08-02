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
        # Map MCP transport session ID to OAuth 2.1 session info
        self._mcp_to_oauth21_map: Dict[str, Dict[str, Any]] = {}
        # Map OAuth 2.1 session ID to MCP transport session ID
        self._oauth21_to_mcp_map: Dict[str, str] = {}
    
    def link_sessions(
        self, 
        mcp_session_id: str, 
        oauth21_session_id: str,
        user_id: Optional[str] = None,
        auth_context: Optional[Any] = None
    ):
        """
        Link an MCP transport session with an OAuth 2.1 session.
        
        Args:
            mcp_session_id: MCP transport session ID
            oauth21_session_id: OAuth 2.1 session ID
            user_id: User identifier
            auth_context: OAuth 2.1 authentication context
        """
        session_info = {
            "oauth21_session_id": oauth21_session_id,
            "user_id": user_id,
            "auth_context": auth_context,
            "linked_at": datetime.utcnow().isoformat(),
        }
        
        self._mcp_to_oauth21_map[mcp_session_id] = session_info
        self._oauth21_to_mcp_map[oauth21_session_id] = mcp_session_id
        
        logger.info(
            f"Linked MCP session {mcp_session_id} with OAuth 2.1 session {oauth21_session_id} "
            f"for user {user_id}"
        )
    
    def get_oauth21_session(self, mcp_session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get OAuth 2.1 session info for an MCP transport session.
        
        Args:
            mcp_session_id: MCP transport session ID
            
        Returns:
            OAuth 2.1 session information if linked
        """
        return self._mcp_to_oauth21_map.get(mcp_session_id)
    
    def get_mcp_session(self, oauth21_session_id: str) -> Optional[str]:
        """
        Get MCP transport session ID for an OAuth 2.1 session.
        
        Args:
            oauth21_session_id: OAuth 2.1 session ID
            
        Returns:
            MCP transport session ID if linked
        """
        return self._oauth21_to_mcp_map.get(oauth21_session_id)
    
    def unlink_mcp_session(self, mcp_session_id: str):
        """
        Remove the link for an MCP transport session.
        
        Args:
            mcp_session_id: MCP transport session ID
        """
        session_info = self._mcp_to_oauth21_map.pop(mcp_session_id, None)
        if session_info:
            oauth21_session_id = session_info.get("oauth21_session_id")
            if oauth21_session_id:
                self._oauth21_to_mcp_map.pop(oauth21_session_id, None)
            logger.info(f"Unlinked MCP session {mcp_session_id}")
    
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
        """Get bridge statistics."""
        return {
            "linked_sessions": len(self._mcp_to_oauth21_map),
            "mcp_sessions": list(self._mcp_to_oauth21_map.keys()),
            "oauth21_sessions": list(self._oauth21_to_mcp_map.keys()),
        }


# Global bridge instance
_bridge = MCPOAuth21Bridge()


def get_bridge() -> MCPOAuth21Bridge:
    """Get the global MCP OAuth 2.1 bridge instance."""
    return _bridge