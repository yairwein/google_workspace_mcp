"""
OAuth 2.1 Configuration Examples

Example configurations and usage patterns for OAuth 2.1 authentication.
"""

from typing import Dict, List
from .config import OAuth2Config, AuthConfig


def create_google_workspace_oauth2_config() -> OAuth2Config:
    """
    Create OAuth 2.1 configuration optimized for Google Workspace.
    
    Returns:
        OAuth 2.1 configuration for Google Workspace
    """
    return OAuth2Config(
        # Google OAuth 2.0 endpoints
        authorization_server_url="https://accounts.google.com",
        
        # Client credentials (set via environment variables)
        # OAUTH2_CLIENT_ID and OAUTH2_CLIENT_SECRET
        
        # Token configuration
        supported_token_types=["jwt"],  # Google uses JWTs
        token_validation_method="local",  # Validate JWTs locally
        expected_audience=None,  # Will be set to client_id automatically
        
        # Session management
        session_timeout=7200,  # 2 hours
        max_sessions_per_user=5,
        enable_session_persistence=True,
        
        # Security settings
        enable_pkce=True,
        enable_bearer_passthrough=True,
        required_scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
        
        # Google Workspace resource
        resource_url=None,  # Will be set from OAUTH2_RESOURCE_URL env var
        
        # Development settings
        enable_debug_logging=False,
        allow_insecure_transport=False,  # Set to True for localhost development
    )


def create_development_config() -> AuthConfig:
    """
    Create configuration for development environment.
    
    Returns:
        Development authentication configuration
    """
    oauth2_config = OAuth2Config(
        authorization_server_url="https://accounts.google.com",
        supported_token_types=["jwt", "opaque"],
        token_validation_method="introspection",  # More flexible for development
        session_timeout=3600,  # 1 hour
        max_sessions_per_user=10,
        enable_session_persistence=False,  # Don't persist in development
        enable_pkce=True,
        enable_bearer_passthrough=True,
        required_scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        exempt_paths=[
            "/health", 
            "/oauth2callback", 
            "/.well-known/",
            "/docs",  # Swagger docs
            "/redoc",  # ReDoc
        ],
        enable_debug_logging=True,
        allow_insecure_transport=True,  # Allow HTTP for localhost
    )
    
    return AuthConfig(
        oauth2=oauth2_config,
        enable_legacy_auth=True,  # Support legacy for easier migration
        single_user_mode=False,
    )


def create_production_config() -> AuthConfig:
    """
    Create configuration for production environment.
    
    Returns:
        Production authentication configuration
    """
    oauth2_config = OAuth2Config(
        authorization_server_url="https://accounts.google.com",
        supported_token_types=["jwt"],
        token_validation_method="local",
        session_timeout=3600,  # 1 hour
        max_sessions_per_user=3,  # Limit sessions in production
        session_cleanup_interval=300,  # 5 minutes
        enable_session_persistence=True,
        enable_pkce=True,
        enable_bearer_passthrough=True,
        required_scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
        discovery_cache_ttl=3600,  # 1 hour
        jwks_cache_ttl=3600,  # 1 hour
        exempt_paths=["/health", "/oauth2callback", "/.well-known/"],
        enable_debug_logging=False,
        allow_insecure_transport=False,
    )
    
    return AuthConfig(
        oauth2=oauth2_config,
        enable_legacy_auth=False,  # OAuth 2.1 only in production
        single_user_mode=False,
    )


def create_single_user_config() -> AuthConfig:
    """
    Create configuration for single-user deployments.
    
    Returns:
        Single-user authentication configuration
    """
    # In single-user mode, OAuth 2.1 is optional
    # Legacy auth will be used primarily
    return AuthConfig(
        oauth2=None,  # No OAuth 2.1 needed
        enable_legacy_auth=True,
        single_user_mode=True,
        default_user_email=None,  # Will be detected from credentials
    )


def create_hybrid_config() -> AuthConfig:
    """
    Create hybrid configuration supporting both OAuth 2.1 and legacy auth.
    
    Returns:
        Hybrid authentication configuration
    """
    oauth2_config = OAuth2Config(
        authorization_server_url="https://accounts.google.com",
        supported_token_types=["jwt", "opaque"],
        token_validation_method="introspection",
        session_timeout=3600,
        max_sessions_per_user=5,
        enable_bearer_passthrough=True,
        required_scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        enable_debug_logging=False,
    )
    
    return AuthConfig(
        oauth2=oauth2_config,
        enable_legacy_auth=True,  # Support both methods
        single_user_mode=False,
    )


# Example usage patterns
async def example_oauth2_server_setup():
    """Example of setting up an OAuth 2.1 enabled MCP server."""
    from ..oauth21.compat import AuthCompatibilityLayer
    from fastapi import FastAPI
    
    # Create configuration
    auth_config = create_google_workspace_oauth2_config()
    full_config = AuthConfig(oauth2=auth_config)
    
    # Create compatibility layer
    auth_layer = AuthCompatibilityLayer(full_config)
    
    # Create FastAPI app
    app = FastAPI(title="Google Workspace MCP Server")
    
    # Add OAuth 2.1 middleware
    if full_config.is_oauth2_enabled():
        middleware = auth_layer.create_enhanced_middleware()
        app.add_middleware(type(middleware), **middleware.__dict__)
    
    # Start authentication
    await auth_layer.start()
    
    return app, auth_layer


def example_environment_variables():
    """
    Example environment variables for OAuth 2.1 configuration.
    
    Set these in your environment or .env file:
    """
    return {
        # Required OAuth 2.1 settings
        "OAUTH2_CLIENT_ID": "your-google-client-id.googleusercontent.com",
        "OAUTH2_CLIENT_SECRET": "your-google-client-secret",
        
        # Optional OAuth 2.1 settings
        "OAUTH2_AUTHORIZATION_SERVER_URL": "https://accounts.google.com",
        "OAUTH2_EXPECTED_AUDIENCE": "your-client-id",
        "OAUTH2_SESSION_TIMEOUT": "3600",  # 1 hour
        "OAUTH2_MAX_SESSIONS_PER_USER": "5",
        "OAUTH2_ENABLE_BEARER_PASSTHROUGH": "true",
        "OAUTH2_REQUIRED_SCOPES": "https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/userinfo.profile",
        
        # Development settings
        "OAUTH2_ENABLE_DEBUG": "false",
        "OAUTH2_ALLOW_INSECURE_TRANSPORT": "false",  # Set to "true" for localhost
        
        # Legacy compatibility
        "MCP_SINGLE_USER_MODE": "false",
        "USER_GOOGLE_EMAIL": "user@example.com",  # Default user email
        "OAUTH2_ENABLE_LEGACY_AUTH": "true",
    }


def example_client_usage():
    """
    Example of how clients should use OAuth 2.1 authentication.
    """
    return {
        "bearer_token_usage": {
            "description": "Send Bearer token in Authorization header",
            "example": {
                "headers": {
                    "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "Mcp-Session-Id": "optional-session-id",
                    "Content-Type": "application/json",
                }
            }
        },
        
        "authorization_flow": {
            "description": "OAuth 2.1 authorization code flow with PKCE",
            "steps": [
                "1. GET /oauth2/authorize with PKCE parameters",
                "2. User authorizes in browser",
                "3. POST /oauth2/token to exchange code for tokens",
                "4. Use access_token as Bearer token in requests",
                "5. Use refresh_token to get new access tokens",
            ]
        },
        
        "session_management": {
            "description": "Session-based authentication",
            "steps": [
                "1. Perform OAuth flow to get session",
                "2. Include Mcp-Session-Id header in requests",
                "3. Optionally include Bearer token for validation",
                "4. Session maintains user context across requests",
            ]
        }
    }


# Configuration validation examples
def validate_oauth2_config(config: OAuth2Config) -> List[str]:
    """
    Validate OAuth 2.1 configuration and return any issues.
    
    Args:
        config: OAuth 2.1 configuration to validate
        
    Returns:
        List of validation issues (empty if valid)
    """
    issues = []
    
    if not config.client_id:
        issues.append("client_id is required")
    
    if not config.authorization_server_url:
        issues.append("authorization_server_url is required")
    
    if config.session_timeout <= 0:
        issues.append("session_timeout must be positive")
    
    if not config.supported_token_types:
        issues.append("at least one token type must be supported")
    
    if config.token_validation_method not in ["local", "introspection"]:
        issues.append("token_validation_method must be 'local' or 'introspection'")
    
    return issues


def get_config_recommendations() -> Dict[str, str]:
    """Get configuration recommendations for different deployment scenarios."""
    return {
        "development": "Use create_development_config() with debug logging enabled",
        "production": "Use create_production_config() with minimal session limits",
        "single_user": "Use create_single_user_config() for simple deployments",
        "migration": "Use create_hybrid_config() to support both OAuth 2.1 and legacy",
        "google_workspace": "Use create_google_workspace_oauth2_config() for Google-optimized settings",
    }