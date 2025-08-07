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


# OAuth Configuration
# Determine base URL and redirect URI once at startup
_OAUTH_REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
if _OAUTH_REDIRECT_URI:
    # Extract base URL from the redirect URI (remove the /oauth2callback path)
    _OAUTH_BASE_URL = _OAUTH_REDIRECT_URI.removesuffix("/oauth2callback")
else:
    # Construct from base URI and port if not explicitly set
    _OAUTH_BASE_URL = f"{WORKSPACE_MCP_BASE_URI}:{WORKSPACE_MCP_PORT}"
    _OAUTH_REDIRECT_URI = f"{_OAUTH_BASE_URL}/oauth2callback"

def get_oauth_base_url() -> str:
    """Get OAuth base URL for constructing OAuth endpoints.
    
    Returns the base URL (without paths) for OAuth endpoints,
    respecting GOOGLE_OAUTH_REDIRECT_URI for reverse proxy scenarios.
    """
    return _OAUTH_BASE_URL

def get_oauth_redirect_uri() -> str:
    """Get OAuth redirect URI based on current configuration.
    
    Returns the redirect URI configured at startup, either from
    GOOGLE_OAUTH_REDIRECT_URI environment variable or constructed
    from WORKSPACE_MCP_BASE_URI and WORKSPACE_MCP_PORT.
    """
    return _OAUTH_REDIRECT_URI