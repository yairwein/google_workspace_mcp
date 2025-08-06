"""
Shared configuration for Google Workspace MCP server.
This module holds configuration values that need to be shared across modules
to avoid circular imports.
"""

import os

# Server configuration
WORKSPACE_MCP_PORT = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", 8000)))
WORKSPACE_MCP_BASE_URI = os.getenv("WORKSPACE_MCP_BASE_URI", "http://localhost")

# Disable USER_GOOGLE_EMAIL in OAuth 2.1 multi-user mode
_oauth21_enabled = os.getenv("MCP_ENABLE_OAUTH21", "false").lower() == "true"
USER_GOOGLE_EMAIL = None if _oauth21_enabled else os.getenv("USER_GOOGLE_EMAIL", None)

# Transport mode (will be set by main.py)
_current_transport_mode = "stdio"  # Default to stdio


def set_transport_mode(mode: str):
    """Set the current transport mode for OAuth callback handling."""
    global _current_transport_mode
    _current_transport_mode = mode


def get_transport_mode() -> str:
    """Get the current transport mode."""
    return _current_transport_mode


def get_oauth_redirect_uri() -> str:
    """Get OAuth redirect URI based on current configuration."""
    # Use the standard OAuth callback path
    return f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}/oauth2callback"