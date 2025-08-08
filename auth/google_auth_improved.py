"""
Google OAuth Authentication Module for MCP Server

This module provides OAuth2 authentication functionality for Google services,
including credential management, token refresh, and session handling.
"""

import os
import json
import logging
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any, Protocol, TypeVar, Union
from functools import lru_cache

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError

from config.google_config import OAUTH_STATE_TO_SESSION_ID_MAP, SCOPES
from mcp import types

# Configure logging
logger = logging.getLogger(__name__)

# Type definitions
ServiceT = TypeVar('ServiceT', bound=Resource)
CredentialsResult = Union[Tuple[ServiceT, str], types.CallToolResult]


class AuthMode(Enum):
    """Authentication modes supported by the system."""
    MULTI_USER = "multi_user"
    SINGLE_USER = "single_user"


@dataclass
class AuthConfig:
    """Configuration for authentication system."""
    credentials_dir: Path
    client_secrets_path: Path
    mode: AuthMode
    
    @classmethod
    def from_environment(cls) -> 'AuthConfig':
        """Create configuration from environment variables."""
        credentials_dir = Path(os.getenv("GOOGLE_CREDENTIALS_DIR", ".credentials"))
        
        client_secrets_env = os.getenv("GOOGLE_CLIENT_SECRETS")
        if client_secrets_env:
            client_secrets_path = Path(client_secrets_env)
        else:
            # Assumes this file is in auth/ and client_secret.json is in the root
            client_secrets_path = Path(__file__).parent.parent / 'client_secret.json'
        
        mode = AuthMode.SINGLE_USER if os.getenv('MCP_SINGLE_USER_MODE') == '1' else AuthMode.MULTI_USER
        
        return cls(
            credentials_dir=credentials_dir,
            client_secrets_path=client_secrets_path,
            mode=mode
        )


class CredentialsStorage(Protocol):
    """Protocol for credential storage implementations."""
    
    async def save(self, identifier: str, credentials: Credentials) -> None:
        """Save credentials with the given identifier."""
        ...
    
    async def load(self, identifier: str) -> Optional[Credentials]:
        """Load credentials by identifier."""
        ...
    
    async def find_any(self) -> Optional[Tuple[str, Credentials]]:
        """Find any available credentials (for single-user mode)."""
        ...


class FileCredentialsStorage:
    """File-based credential storage implementation."""
    
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_credential_path(self, identifier: str) -> Path:
        """Get the path for a credential file."""
        # Sanitize identifier to prevent path traversal
        safe_identifier = identifier.replace('/', '_').replace('\\', '_')
        return self.base_dir / f"{safe_identifier}.json"
    
    async def save(self, identifier: str, credentials: Credentials) -> None:
        """Save credentials to file."""
        creds_path = self._get_credential_path(identifier)
        creds_data = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        try:
            await asyncio.to_thread(
                lambda: creds_path.write_text(json.dumps(creds_data, indent=2))
            )
            logger.info(f"Credentials saved for {identifier}")
        except IOError as e:
            logger.error(f"Failed to save credentials for {identifier}: {e}")
            raise
    
    async def load(self, identifier: str) -> Optional[Credentials]:
        """Load credentials from file."""
        creds_path = self._get_credential_path(identifier)
        
        if not creds_path.exists():
            logger.debug(f"No credentials file found for {identifier}")
            return None
        
        try:
            creds_data = await asyncio.to_thread(
                lambda: json.loads(creds_path.read_text())
            )
            
            return Credentials(
                token=creds_data.get('token'),
                refresh_token=creds_data.get('refresh_token'),
                token_uri=creds_data.get('token_uri'),
                client_id=creds_data.get('client_id'),
                client_secret=creds_data.get('client_secret'),
                scopes=creds_data.get('scopes')
            )
        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to load credentials for {identifier}: {e}")
            return None
    
    async def find_any(self) -> Optional[Tuple[str, Credentials]]:
        """Find any valid credentials in the directory."""
        try:
            for creds_file in self.base_dir.glob("*.json"):
                try:
                    creds_data = json.loads(creds_file.read_text())
                    credentials = Credentials(
                        token=creds_data.get('token'),
                        refresh_token=creds_data.get('refresh_token'),
                        token_uri=creds_data.get('token_uri'),
                        client_id=creds_data.get('client_id'),
                        client_secret=creds_data.get('client_secret'),
                        scopes=creds_data.get('scopes')
                    )
                    identifier = creds_file.stem
                    logger.info(f"Found credentials: {identifier}")
                    return identifier, credentials
                except Exception as e:
                    logger.debug(f"Failed to load {creds_file}: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error scanning credentials directory: {e}")
        
        return None


class SessionCredentialsCache:
    """In-memory session-based credential cache."""
    
    def __init__(self):
        self._cache: Dict[str, Credentials] = {}
    
    async def save(self, session_id: str, credentials: Credentials) -> None:
        """Save credentials to session cache."""
        self._cache[session_id] = credentials
        logger.debug(f"Credentials cached for session: {session_id}")
    
    async def load(self, session_id: str) -> Optional[Credentials]:
        """Load credentials from session cache."""
        return self._cache.get(session_id)
    
    def clear(self, session_id: str) -> None:
        """Clear credentials for a specific session."""
        if session_id in self._cache:
            del self._cache[session_id]
            logger.debug(f"Cleared credentials for session: {session_id}")


class CredentialsManager:
    """Manages credential lifecycle including storage, refresh, and validation."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self.file_storage = FileCredentialsStorage(config.credentials_dir)
        self.session_cache = SessionCredentialsCache()
    
    async def get_credentials(
        self,
        user_email: Optional[str],
        required_scopes: List[str],
        session_id: Optional[str] = None
    ) -> Optional[Credentials]:
        """Get valid credentials for the user."""
        # Single-user mode: use any available credentials
        if self.config.mode == AuthMode.SINGLE_USER:
            result = await self.file_storage.find_any()
            if result:
                identifier, credentials = result
                if await self._validate_and_refresh(credentials, required_scopes, identifier):
                    return credentials
            return None
        
        # Multi-user mode: require user identification
        if not user_email and not session_id:
            logger.warning("No user_email or session_id provided in multi-user mode")
            return None
        
        # Try session cache first
        if session_id:
            credentials = await self.session_cache.load(session_id)
            if credentials and await self._validate_and_refresh(credentials, required_scopes, user_email):
                return credentials
        
        # Try file storage
        if user_email:
            credentials = await self.file_storage.load(user_email)
            if credentials:
                # Cache in session if available
                if session_id:
                    await self.session_cache.save(session_id, credentials)
                
                if await self._validate_and_refresh(credentials, required_scopes, user_email):
                    return credentials
        
        return None
    
    async def _validate_and_refresh(
        self,
        credentials: Credentials,
        required_scopes: List[str],
        identifier: Optional[str]
    ) -> bool:
        """Validate credentials and refresh if needed."""
        # Check scopes
        if not all(scope in credentials.scopes for scope in required_scopes):
            logger.warning(f"Credentials lack required scopes. Need: {required_scopes}, Have: {credentials.scopes}")
            return False
        
        # Check validity
        if credentials.valid:
            return True
        
        # Try to refresh
        if credentials.expired and credentials.refresh_token:
            try:
                await asyncio.to_thread(credentials.refresh, Request())
                logger.info("Credentials refreshed successfully")
                
                # Save refreshed credentials
                if identifier:
                    await self.file_storage.save(identifier, credentials)
                
                return True
            except Exception as e:
                logger.error(f"Failed to refresh credentials: {e}")
                return False
        
        return False
    
    async def save_credentials(
        self,
        user_email: str,
        credentials: Credentials,
        session_id: Optional[str] = None
    ) -> None:
        """Save credentials to storage."""
        await self.file_storage.save(user_email, credentials)
        
        if session_id:
            await self.session_cache.save(session_id, credentials)


class OAuthFlowManager:
    """Manages OAuth2 authorization flows."""
    
    def __init__(self, config: AuthConfig):
        self.config = config
        self._flows: Dict[str, Flow] = {}
    
    def _load_client_config(self) -> Dict[str, Any]:
        """Load client configuration from secrets file."""
        try:
            with open(self.config.client_secrets_path, 'r') as f:
                client_config = json.load(f)
                
            if "web" in client_config:
                return client_config["web"]
            elif "installed" in client_config:
                return client_config["installed"]
            else:
                raise ValueError("Invalid client secrets file format")
        except (IOError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load client secrets: {e}")
            raise
    
    async def start_flow(
        self,
        redirect_uri: str,
        scopes: List[str],
        session_id: Optional[str] = None,
        user_hint: Optional[str] = None
    ) -> Tuple[str, str]:
        """Start OAuth flow and return (auth_url, state)."""
        state = os.urandom(32).hex()  # More entropy for better security
        
        flow = Flow.from_client_secrets_file(
            str(self.config.client_secrets_path),
            scopes=scopes,
            redirect_uri=redirect_uri,
            state=state
        )
        
        # Store flow for later use
        self._flows[state] = flow
        
        # Map state to session if provided
        if session_id:
            OAUTH_STATE_TO_SESSION_ID_MAP[state] = session_id
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            login_hint=user_hint  # Pre-fill email if provided
        )
        
        logger.info(f"OAuth flow started. State: {state}")
        return auth_url, state
    
    async def complete_flow(
        self,
        authorization_response: str,
        state: str
    ) -> Tuple[str, Credentials]:
        """Complete OAuth flow and return (user_email, credentials)."""
        flow = self._flows.get(state)
        if not flow:
            raise ValueError(f"No flow found for state: {state}")
        
        try:
            # Exchange code for tokens
            await asyncio.to_thread(
                flow.fetch_token,
                authorization_response=authorization_response
            )
            
            credentials = flow.credentials
            
            # Get user info
            user_info = await get_user_info(credentials)
            if not user_info or 'email' not in user_info:
                raise ValueError("Failed to get user email")
            
            user_email = user_info['email']
            
            # Clean up
            del self._flows[state]
            if state in OAUTH_STATE_TO_SESSION_ID_MAP:
                del OAUTH_STATE_TO_SESSION_ID_MAP[state]
            
            return user_email, credentials
            
        except Exception as e:
            logger.error(f"Failed to complete OAuth flow: {e}")
            raise


async def get_user_info(credentials: Credentials) -> Optional[Dict[str, Any]]:
    """Fetch user profile information."""
    if not credentials or not credentials.valid:
        logger.error("Invalid credentials provided")
        return None
    
    try:
        service = await asyncio.to_thread(
            build, 'oauth2', 'v2', credentials=credentials
        )
        user_info = await asyncio.to_thread(
            service.userinfo().get().execute
        )
        logger.info(f"Fetched user info: {user_info.get('email')}")
        return user_info
    except HttpError as e:
        logger.error(f"HTTP error fetching user info: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching user info: {e}")
        return None


class GoogleServiceAuthenticator:
    """High-level authenticator for Google services."""
    
    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig.from_environment()
        self.credentials_manager = CredentialsManager(self.config)
        self.oauth_manager = OAuthFlowManager(self.config)
    
    async def get_authenticated_service(
        self,
        service_name: str,
        version: str,
        user_email: str,
        required_scopes: List[str],
        tool_name: str = "unknown",
        session_id: Optional[str] = None
    ) -> CredentialsResult:
        """Get authenticated Google service or return auth error."""
        logger.info(f"[{tool_name}] Authenticating {service_name} for {user_email}")
        
        # Validate email
        if not user_email or "@" not in user_email:
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(
                    type="text",
                    text=f"Invalid email address: {user_email}"
                )]
            )
        
        # Get credentials
        credentials = await self.credentials_manager.get_credentials(
            user_email=user_email,
            required_scopes=required_scopes,
            session_id=session_id
        )
        
        if not credentials:
            # Need to start auth flow
            from core.server import OAUTH_REDIRECT_URI  # Import here to avoid circular import
            
            return await self._create_auth_flow_result(
                user_email=user_email,
                service_name=service_name,
                redirect_uri=OAUTH_REDIRECT_URI,
                session_id=session_id
            )
        
        # Build service
        try:
            service = await asyncio.to_thread(
                build, service_name, version, credentials=credentials
            )
            logger.info(f"[{tool_name}] Successfully authenticated {service_name}")
            return service, user_email
        except Exception as e:
            logger.error(f"[{tool_name}] Failed to build service: {e}")
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(
                    type="text",
                    text=f"Failed to build {service_name} service: {str(e)}"
                )]
            )
    
    async def _create_auth_flow_result(
        self,
        user_email: str,
        service_name: str,
        redirect_uri: str,
        session_id: Optional[str]
    ) -> types.CallToolResult:
        """Create auth flow result for user."""
        try:
            auth_url, state = await self.oauth_manager.start_flow(
                redirect_uri=redirect_uri,
                scopes=SCOPES,
                session_id=session_id,
                user_hint=user_email
            )
            
            message = f"""**ACTION REQUIRED: Google Authentication Needed**

To proceed, please authorize this application for {service_name} access.

[Click here to authorize {service_name} access]({auth_url})

After authorization:
1. Complete the authorization in your browser
2. The page will display your authenticated email address
3. Retry your original command

The application will use the new credentials for {user_email}."""
            
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=message)]
            )
        except Exception as e:
            logger.error(f"Failed to start auth flow: {e}")
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(
                    type="text",
                    text=f"Failed to start authentication: {str(e)}"
                )]
            )


# Singleton instance for convenience
_default_authenticator: Optional[GoogleServiceAuthenticator] = None


def get_default_authenticator() -> GoogleServiceAuthenticator:
    """Get the default authenticator instance."""
    global _default_authenticator
    if _default_authenticator is None:
        _default_authenticator = GoogleServiceAuthenticator()
    return _default_authenticator


# Backward compatibility functions
async def get_authenticated_google_service(
    service_name: str,
    version: str,
    tool_name: str,
    user_google_email: str,
    required_scopes: List[str],
) -> CredentialsResult:
    """Backward compatible function for getting authenticated service."""
    authenticator = get_default_authenticator()
    return await authenticator.get_authenticated_service(
        service_name=service_name,
        version=version,
        user_email=user_google_email,
        required_scopes=required_scopes,
        tool_name=tool_name
    )


async def start_auth_flow(
    mcp_session_id: Optional[str],
    user_google_email: Optional[str],
    service_name: str,
    redirect_uri: str,
) -> types.CallToolResult:
    """Backward compatible function for starting auth flow."""
    authenticator = get_default_authenticator()
    return await authenticator._create_auth_flow_result(
        user_email=user_google_email or "unknown",
        service_name=service_name,
        redirect_uri=redirect_uri,
        session_id=mcp_session_id
    )