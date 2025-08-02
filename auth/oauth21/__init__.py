"""
OAuth 2.1 Authentication for MCP Server

A comprehensive OAuth 2.1 implementation with Bearer token support, session management,
and multi-user capabilities for Model Context Protocol servers.

Key Features:
- OAuth 2.1 compliant authorization flow with PKCE
- Bearer token authentication (JWT and opaque tokens)
- Multi-user session management with proper isolation
- Authorization server discovery (RFC9728 & RFC8414)
- Backward compatibility with existing authentication

Usage:
    # Basic setup
    from auth.oauth21 import create_auth_config, AuthCompatibilityLayer

    config = create_auth_config()
    auth_layer = AuthCompatibilityLayer(config)

    # Initialize
    await auth_layer.start()

    # Use with FastAPI
    middleware = auth_layer.create_enhanced_middleware()
    app.add_middleware(type(middleware), **middleware.__dict__)
"""

from .config import (
    OAuth2Config,
    AuthConfig,
    create_auth_config,
    create_default_oauth2_config,
    load_config_from_file,
    get_config_summary,
)

from .handler import OAuth2Handler

from .compat import (
    AuthCompatibilityLayer,
    create_compatible_auth_handler,
    get_enhanced_credentials,
)

from .middleware import (
    AuthenticationMiddleware,
    AuthContext,
    get_auth_context,
    require_auth,
    require_scopes,
)

from .sessions import Session, SessionStore

from .tokens import TokenValidator, TokenValidationError


__version__ = "1.0.0"

__all__ = [
    # Configuration
    "OAuth2Config",
    "AuthConfig",
    "create_auth_config",
    "create_default_oauth2_config",
    "load_config_from_file",
    "get_config_summary",

    # Main handlers
    "OAuth2Handler",
    "AuthCompatibilityLayer",
    "create_compatible_auth_handler",

    # Middleware and context
    "AuthenticationMiddleware",
    "AuthContext",
    "get_auth_context",
    "require_auth",
    "require_scopes",

    # Session management
    "Session",
    "SessionStore",

    # Token handling
    "TokenValidator",
    "TokenValidationError",

    # Enhanced credential function
    "get_enhanced_credentials"
]