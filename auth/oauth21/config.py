"""
OAuth 2.1 Configuration Schema

Configuration classes and validation for OAuth 2.1 authentication setup.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class OAuth2Config:
    """OAuth 2.1 configuration."""
    
    # Authorization Server Configuration
    authorization_server_url: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    
    # Token Configuration
    supported_token_types: List[str] = field(default_factory=lambda: ["jwt", "opaque"])
    token_validation_method: str = "introspection"  # or "local"
    expected_audience: Optional[str] = None
    
    # Session Management
    session_timeout: int = 3600  # 1 hour
    max_sessions_per_user: int = 10
    session_cleanup_interval: int = 300  # 5 minutes
    enable_session_persistence: bool = False
    session_persistence_file: Optional[str] = None
    
    # Security Settings
    enable_pkce: bool = True
    required_scopes: List[str] = field(default_factory=list)
    enable_bearer_passthrough: bool = True
    enable_dynamic_registration: bool = True
    
    # Discovery Settings
    resource_url: Optional[str] = None  # Will be set from OAUTH2_RESOURCE_URL env var
    proxy_base_url: Optional[str] = None  # Base URL for proxying discovery requests
    discovery_cache_ttl: int = 3600  # 1 hour
    jwks_cache_ttl: int = 3600  # 1 hour
    
    # HTTP Settings
    exempt_paths: List[str] = field(default_factory=lambda: [
        "/health", "/oauth2callback", "/.well-known/", "/auth/discovery/", "/oauth2/register", "/oauth2/token"
    ])
    
    # Development/Debug Settings
    enable_debug_logging: bool = False
    allow_insecure_transport: bool = False

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._load_from_environment()
        self._validate_config()

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        # Authorization server settings
        if not self.authorization_server_url:
            self.authorization_server_url = os.getenv("OAUTH2_AUTHORIZATION_SERVER_URL")
        
        if not self.client_id:
            self.client_id = os.getenv("OAUTH2_CLIENT_ID") or os.getenv("GOOGLE_OAUTH_CLIENT_ID")
        
        if not self.client_secret:
            self.client_secret = os.getenv("OAUTH2_CLIENT_SECRET") or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
        
        # Resource URL
        if not self.resource_url:
            self.resource_url = os.getenv("OAUTH2_RESOURCE_URL")
        
        # Proxy base URL
        if not self.proxy_base_url:
            self.proxy_base_url = os.getenv("OAUTH2_PROXY_BASE_URL")
            
        # Token settings
        if env_audience := os.getenv("OAUTH2_EXPECTED_AUDIENCE"):
            self.expected_audience = env_audience
        
        if env_validation := os.getenv("OAUTH2_TOKEN_VALIDATION_METHOD"):
            self.token_validation_method = env_validation
        
        # Session settings
        if env_timeout := os.getenv("OAUTH2_SESSION_TIMEOUT"):
            try:
                self.session_timeout = int(env_timeout)
            except ValueError:
                logger.warning(f"Invalid OAUTH2_SESSION_TIMEOUT value: {env_timeout}")
        
        if env_max_sessions := os.getenv("OAUTH2_MAX_SESSIONS_PER_USER"):
            try:
                self.max_sessions_per_user = int(env_max_sessions)
            except ValueError:
                logger.warning(f"Invalid OAUTH2_MAX_SESSIONS_PER_USER value: {env_max_sessions}")
        
        # Security settings
        if env_pkce := os.getenv("OAUTH2_ENABLE_PKCE"):
            self.enable_pkce = env_pkce.lower() in ("true", "1", "yes", "on")
        
        if env_passthrough := os.getenv("OAUTH2_ENABLE_BEARER_PASSTHROUGH"):
            self.enable_bearer_passthrough = env_passthrough.lower() in ("true", "1", "yes", "on")
        
        if env_scopes := os.getenv("OAUTH2_REQUIRED_SCOPES"):
            self.required_scopes = [scope.strip() for scope in env_scopes.split(",")]
        
        # Development settings
        if env_debug := os.getenv("OAUTH2_ENABLE_DEBUG"):
            self.enable_debug_logging = env_debug.lower() in ("true", "1", "yes", "on")
        
        if env_insecure := os.getenv("OAUTH2_ALLOW_INSECURE_TRANSPORT"):
            self.allow_insecure_transport = env_insecure.lower() in ("true", "1", "yes", "on")

    def _validate_config(self):
        """Validate configuration values."""
        errors = []
        
        # Validate token types
        valid_token_types = {"jwt", "opaque"}
        invalid_types = set(self.supported_token_types) - valid_token_types
        if invalid_types:
            errors.append(f"Invalid token types: {invalid_types}")
        
        # Validate token validation method
        if self.token_validation_method not in ("introspection", "local"):
            errors.append(f"Invalid token_validation_method: {self.token_validation_method}")
        
        # Validate session settings
        if self.session_timeout <= 0:
            errors.append("session_timeout must be positive")
        
        if self.max_sessions_per_user <= 0:
            errors.append("max_sessions_per_user must be positive")
        
        # Validate URLs
        if self.authorization_server_url:
            if not self.authorization_server_url.startswith(("http://", "https://")):
                errors.append("authorization_server_url must be a valid HTTP/HTTPS URL")
        
        if errors:
            raise ValueError(f"OAuth2 configuration errors: {'; '.join(errors)}")

    def is_enabled(self) -> bool:
        """Check if OAuth 2.1 authentication is enabled."""
        return bool(self.client_id)

    def get_session_persistence_path(self) -> Optional[Path]:
        """Get session persistence file path."""
        if not self.enable_session_persistence:
            return None
        
        if self.session_persistence_file:
            return Path(self.session_persistence_file)
        
        # Default to user home directory
        home_dir = Path.home()
        return home_dir / ".google_workspace_mcp" / "oauth21_sessions.json"

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "authorization_server_url": self.authorization_server_url,
            "client_id": self.client_id,
            "client_secret": "***" if self.client_secret else None,  # Redact secret
            "supported_token_types": self.supported_token_types,
            "token_validation_method": self.token_validation_method,
            "expected_audience": self.expected_audience,
            "session_timeout": self.session_timeout,
            "max_sessions_per_user": self.max_sessions_per_user,
            "enable_pkce": self.enable_pkce,
            "required_scopes": self.required_scopes,
            "enable_bearer_passthrough": self.enable_bearer_passthrough,
            "enable_dynamic_registration": self.enable_dynamic_registration,
            "resource_url": self.resource_url,
            "exempt_paths": self.exempt_paths,
            "enable_debug_logging": self.enable_debug_logging,
            "allow_insecure_transport": self.allow_insecure_transport,
        }


@dataclass  
class AuthConfig:
    """Complete authentication configuration including OAuth 2.1 and legacy settings."""
    
    # OAuth 2.1 Configuration
    oauth2: Optional[OAuth2Config] = None
    
    # Legacy Authentication Settings (for backward compatibility)
    enable_legacy_auth: bool = True
    legacy_credentials_dir: Optional[str] = None
    
    # Global Settings
    single_user_mode: bool = False
    default_user_email: Optional[str] = None

    def __post_init__(self):
        """Initialize configuration."""
        self._load_global_settings()
        
        # Initialize OAuth2 config if not provided but environment suggests it's needed
        if not self.oauth2 and self._should_enable_oauth2():
            self.oauth2 = OAuth2Config()

    def _load_global_settings(self):
        """Load global authentication settings."""
        # Single user mode
        if env_single_user := os.getenv("MCP_SINGLE_USER_MODE"):
            self.single_user_mode = env_single_user.lower() in ("true", "1", "yes", "on")
        
        # Default user email
        if not self.default_user_email:
            self.default_user_email = os.getenv("USER_GOOGLE_EMAIL")
        
        # Legacy settings
        if env_legacy := os.getenv("OAUTH2_ENABLE_LEGACY_AUTH"):
            self.enable_legacy_auth = env_legacy.lower() in ("true", "1", "yes", "on")
        
        if not self.legacy_credentials_dir:
            self.legacy_credentials_dir = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR")

    def _should_enable_oauth2(self) -> bool:
        """Check if OAuth 2.1 should be enabled based on environment."""
        oauth2_env_vars = [
            "OAUTH2_CLIENT_ID",
            "GOOGLE_OAUTH_CLIENT_ID", 
            "OAUTH2_AUTHORIZATION_SERVER_URL",
            "OAUTH2_ENABLE_BEARER_PASSTHROUGH",
        ]
        
        return any(os.getenv(var) for var in oauth2_env_vars)

    def is_oauth2_enabled(self) -> bool:
        """Check if OAuth 2.1 is enabled."""
        return self.oauth2 is not None and self.oauth2.is_enabled()

    def get_effective_auth_mode(self) -> str:
        """Get the effective authentication mode."""
        if self.single_user_mode:
            return "single_user"
        elif self.is_oauth2_enabled():
            if self.enable_legacy_auth:
                return "oauth2_with_legacy_fallback"
            else:
                return "oauth2_only"
        elif self.enable_legacy_auth:
            return "legacy_only"
        else:
            return "disabled"

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        result = {
            "oauth2": self.oauth2.to_dict() if self.oauth2 else None,
            "enable_legacy_auth": self.enable_legacy_auth,
            "legacy_credentials_dir": self.legacy_credentials_dir,
            "single_user_mode": self.single_user_mode,
            "default_user_email": self.default_user_email,
            "effective_auth_mode": self.get_effective_auth_mode(),
        }
        
        return result


def create_auth_config(
    oauth2_config: Optional[Dict[str, Any]] = None,
    **kwargs
) -> AuthConfig:
    """
    Create authentication configuration.

    Args:
        oauth2_config: OAuth 2.1 configuration dictionary
        **kwargs: Additional configuration options

    Returns:
        Authentication configuration
    """
    oauth2 = None
    if oauth2_config:
        oauth2 = OAuth2Config(**oauth2_config)
    
    return AuthConfig(oauth2=oauth2, **kwargs)


def create_default_oauth2_config() -> OAuth2Config:
    """
    Create default OAuth 2.1 configuration for Google Workspace.

    Returns:
        OAuth 2.1 configuration with Google Workspace defaults
    """
    return OAuth2Config(
        authorization_server_url="https://accounts.google.com",
        supported_token_types=["jwt"],
        token_validation_method="local",  # Use local JWT validation for Google
        expected_audience=None,  # Will be set based on client_id
        required_scopes=[
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
        ],
        enable_pkce=True,
        enable_bearer_passthrough=True,
        resource_url=None,  # Will be set from environment
    )


def load_config_from_file(config_path: Union[str, Path]) -> AuthConfig:
    """
    Load authentication configuration from file.

    Args:
        config_path: Path to configuration file (JSON or TOML)

    Returns:
        Authentication configuration

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config format is invalid
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        if config_path.suffix.lower() == ".json":
            import json
            with open(config_path) as f:
                config_data = json.load(f)
        elif config_path.suffix.lower() in (".toml", ".tml"):
            import tomlkit
            with open(config_path) as f:
                config_data = tomlkit.load(f)
        else:
            raise ValueError(f"Unsupported configuration file format: {config_path.suffix}")
        
        # Extract OAuth 2.1 config if present
        oauth2_config = None
        if "oauth2" in config_data:
            oauth2_config = config_data.pop("oauth2")
        
        return create_auth_config(oauth2_config=oauth2_config, **config_data)
        
    except Exception as e:
        raise ValueError(f"Failed to load configuration from {config_path}: {e}")


def get_config_summary(config: AuthConfig) -> str:
    """
    Get a human-readable summary of the authentication configuration.

    Args:
        config: Authentication configuration

    Returns:
        Configuration summary string
    """
    lines = [
        "Authentication Configuration Summary:",
        f"  Mode: {config.get_effective_auth_mode()}",
        f"  Single User Mode: {config.single_user_mode}",
    ]
    
    if config.oauth2:
        lines.extend([
            "  OAuth 2.1 Settings:",
            f"    Authorization Server: {config.oauth2.authorization_server_url or 'Not configured'}",
            f"    Client ID: {config.oauth2.client_id or 'Not configured'}",
            f"    Token Types: {', '.join(config.oauth2.supported_token_types)}",
            f"    Session Timeout: {config.oauth2.session_timeout}s",
            f"    Bearer Passthrough: {config.oauth2.enable_bearer_passthrough}",
            f"    PKCE Enabled: {config.oauth2.enable_pkce}",
        ])
    
    if config.enable_legacy_auth:
        lines.extend([
            "  Legacy Authentication:",
            f"    Enabled: {config.enable_legacy_auth}",
            f"    Credentials Dir: {config.legacy_credentials_dir or 'Default'}",
        ])
    
    return "\n".join(lines)