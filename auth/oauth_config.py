"""
OAuth Configuration Management

This module centralizes OAuth-related configuration to eliminate hardcoded values
scattered throughout the codebase. It provides environment variable support and
sensible defaults for all OAuth-related settings.
"""

import os
from typing import List
from urllib.parse import urlparse


class OAuthConfig:
    """
    Centralized OAuth configuration management.
    
    This class eliminates the hardcoded configuration anti-pattern identified
    in the challenge review by providing a single source of truth for all
    OAuth-related configuration values.
    """
    
    def __init__(self):
        # Base server configuration
        self.base_uri = os.getenv("WORKSPACE_MCP_BASE_URI", "http://localhost")
        self.port = int(os.getenv("PORT", os.getenv("WORKSPACE_MCP_PORT", "8000")))
        self.base_url = f"{self.base_uri}:{self.port}"
        
        # OAuth client configuration
        self.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
        self.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
        
        # Redirect URI configuration
        self.redirect_uri = self._get_redirect_uri()
        
        # VS Code OAuth callback configuration
        self.vscode_callback_port = int(os.getenv("VSCODE_OAUTH_CALLBACK_PORT", "33418"))
        self.vscode_callback_hosts = self._get_vscode_callback_hosts()
        
        # Development/testing configuration
        self.development_ports = self._get_development_ports()
        
    def _get_redirect_uri(self) -> str:
        """
        Get the OAuth redirect URI, supporting reverse proxy configurations.
        
        Returns:
            The configured redirect URI
        """
        explicit_uri = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
        if explicit_uri:
            return explicit_uri
        return f"{self.base_url}/oauth2callback"
    
    def _get_vscode_callback_hosts(self) -> List[str]:
        """
        Get the list of VS Code callback hosts.
        
        Returns:
            List of VS Code callback hosts (localhost, 127.0.0.1)
        """
        custom_hosts = os.getenv("VSCODE_OAUTH_CALLBACK_HOSTS")
        if custom_hosts:
            return [host.strip() for host in custom_hosts.split(",")]
        return ["127.0.0.1", "localhost"]
    
    def _get_development_ports(self) -> List[int]:
        """
        Get the list of development server ports for testing.
        
        Returns:
            List of common development ports
        """
        custom_ports = os.getenv("OAUTH_DEVELOPMENT_PORTS")
        if custom_ports:
            return [int(port.strip()) for port in custom_ports.split(",")]
        return [3000, 5173, 8080]
    
    def get_redirect_uris(self) -> List[str]:
        """
        Get all valid OAuth redirect URIs.
        
        Returns:
            List of all supported redirect URIs
        """
        uris = []
        
        # Primary redirect URI
        uris.append(self.redirect_uri)
        
        # Development redirect URIs
        for port in self.development_ports:
            uris.append(f"http://localhost:{port}/auth/callback")
            uris.append(f"http://127.0.0.1:{port}/auth/callback")
        
        # VS Code callback URIs
        for host in self.vscode_callback_hosts:
            base_uri = f"http://{host}:{self.vscode_callback_port}"
            uris.extend([
                f"{base_uri}/callback",  # Standard callback path
                f"{base_uri}/",          # Root path with trailing slash
            ])
        
        # Custom redirect URIs from environment
        custom_uris = os.getenv("OAUTH_CUSTOM_REDIRECT_URIS")
        if custom_uris:
            uris.extend([uri.strip() for uri in custom_uris.split(",")])
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(uris))
    
    def get_allowed_origins(self) -> List[str]:
        """
        Get allowed CORS origins for OAuth endpoints.
        
        Returns:
            List of allowed origins for CORS
        """
        origins = []
        
        # Server's own origin
        origins.append(self.base_url)
        
        # VS Code and development origins
        origins.extend([
            "vscode-webview://",
            "https://vscode.dev",
            "https://github.dev",
        ])
        
        # Development origins
        for port in self.development_ports:
            origins.extend([
                f"http://localhost:{port}",
                f"http://127.0.0.1:{port}",
            ])
        
        # VS Code callback server origins
        for host in self.vscode_callback_hosts:
            origins.append(f"http://{host}:{self.vscode_callback_port}")
        
        # Custom origins from environment
        custom_origins = os.getenv("OAUTH_ALLOWED_ORIGINS")
        if custom_origins:
            origins.extend([origin.strip() for origin in custom_origins.split(",")])
        
        return list(dict.fromkeys(origins))
    
    def is_configured(self) -> bool:
        """
        Check if OAuth is properly configured.
        
        Returns:
            True if OAuth client credentials are available
        """
        return bool(self.client_id and self.client_secret)
    
    def get_oauth_base_url(self) -> str:
        """
        Get OAuth base URL for constructing OAuth endpoints.
        
        Returns:
            Base URL for OAuth endpoints
        """
        return self.base_url
    
    def validate_redirect_uri(self, uri: str) -> bool:
        """
        Validate if a redirect URI is allowed.
        
        Args:
            uri: The redirect URI to validate
            
        Returns:
            True if the URI is allowed, False otherwise
        """
        allowed_uris = self.get_redirect_uris()
        return uri in allowed_uris
    
    def get_environment_summary(self) -> dict:
        """
        Get a summary of the current OAuth configuration.
        
        Returns:
            Dictionary with configuration summary (excluding secrets)
        """
        return {
            "base_url": self.base_url,
            "redirect_uri": self.redirect_uri,
            "client_configured": bool(self.client_id),
            "vscode_callback_port": self.vscode_callback_port,
            "vscode_callback_hosts": self.vscode_callback_hosts,
            "development_ports": self.development_ports,
            "total_redirect_uris": len(self.get_redirect_uris()),
            "total_allowed_origins": len(self.get_allowed_origins()),
        }


# Global configuration instance
_oauth_config = None


def get_oauth_config() -> OAuthConfig:
    """
    Get the global OAuth configuration instance.
    
    Returns:
        The singleton OAuth configuration instance
    """
    global _oauth_config
    if _oauth_config is None:
        _oauth_config = OAuthConfig()
    return _oauth_config


def reload_oauth_config() -> OAuthConfig:
    """
    Reload the OAuth configuration from environment variables.
    
    This is useful for testing or when environment variables change.
    
    Returns:
        The reloaded OAuth configuration instance
    """
    global _oauth_config
    _oauth_config = OAuthConfig()
    return _oauth_config


# Convenience functions for backward compatibility
def get_oauth_base_url() -> str:
    """Get OAuth base URL."""
    return get_oauth_config().get_oauth_base_url()


def get_redirect_uris() -> List[str]:
    """Get all valid OAuth redirect URIs.""" 
    return get_oauth_config().get_redirect_uris()


def get_allowed_origins() -> List[str]:
    """Get allowed CORS origins."""
    return get_oauth_config().get_allowed_origins()


def is_oauth_configured() -> bool:
    """Check if OAuth is properly configured."""
    return get_oauth_config().is_configured()