"""
Simplified OAuth 2.1 to Google Credentials Bridge

This module bridges FastMCP authentication to Google OAuth2 credentials
for use with Google API clients.
"""

import logging
from typing import Optional
from datetime import datetime, timezone, timedelta
from google.oauth2.credentials import Credentials
from auth.oauth21_session_store import get_oauth21_session_store

logger = logging.getLogger(__name__)

# Global auth provider instance (set during server initialization)
_auth_provider = None


def set_auth_provider(provider):
    """Set the global auth provider instance."""
    global _auth_provider
    _auth_provider = provider
    logger.info("OAuth 2.1 auth provider configured for Google credential bridging")


def get_auth_provider():
    """Get the global auth provider instance."""
    return _auth_provider


def get_credentials_from_token(access_token: str, user_email: Optional[str] = None) -> Optional[Credentials]:
    """
    Convert a bearer token to Google credentials.
    
    Args:
        access_token: The bearer token
        user_email: Optional user email for session lookup
        
    Returns:
        Google Credentials object or None
    """
    if not _auth_provider:
        logger.error("Auth provider not configured")
        return None
        
    try:
        # Check if we have session info for this token
        session_info = None
        if user_email:
            session_id = f"google_{user_email}"
            session_info = _auth_provider.get_session_info(session_id)
        
        # If we have a full token response (from token exchange), use it
        if session_info and "token_response" in session_info:
            token_data = session_info["token_response"]
            
            # Calculate expiry
            expiry = None
            if "expires_in" in token_data:
                # Google auth library expects timezone-naive datetime
                expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
            
            credentials = Credentials(
                token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                token_uri="https://oauth2.googleapis.com/token",
                client_id=_auth_provider.client_id,
                client_secret=_auth_provider.client_secret,
                scopes=token_data.get("scope", "").split() if token_data.get("scope") else None,
                expiry=expiry
            )
            
            logger.debug(f"Created Google credentials from token response for {user_email}")
            return credentials
            
        # Otherwise, create minimal credentials with just the access token
        else:
            # Assume token is valid for 1 hour (typical for Google tokens)
            # Google auth library expects timezone-naive datetime
            expiry = datetime.utcnow() + timedelta(hours=1)
            
            credentials = Credentials(
                token=access_token,
                refresh_token=None,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=_auth_provider.client_id,
                client_secret=_auth_provider.client_secret,
                scopes=None,  # Will be populated from token claims if available
                expiry=expiry
            )
            
            logger.debug("Created Google credentials from bearer token")
            return credentials
            
    except Exception as e:
        logger.error(f"Failed to create Google credentials from token: {e}")
        return None


def store_token_session(token_response: dict, user_email: str) -> str:
    """
    Store a token response in the session store.
    
    Args:
        token_response: OAuth token response from Google
        user_email: User's email address
        
    Returns:
        Session ID
    """
    if not _auth_provider:
        logger.error("Auth provider not configured")
        return ""
        
    try:
        session_id = f"google_{user_email}"
        _auth_provider._sessions[session_id] = {
            "token_response": token_response,
            "user_email": user_email,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        # Also store in the global OAuth21 session store for compatibility
        session_store = get_oauth21_session_store()
        session_store.store_session(
            user_email=user_email,
            access_token=token_response.get("access_token"),
            refresh_token=token_response.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=_auth_provider.client_id,
            client_secret=_auth_provider.client_secret,
            scopes=token_response.get("scope", "").split() if token_response.get("scope") else None,
            expiry=datetime.utcnow() + timedelta(seconds=token_response.get("expires_in", 3600)),
            session_id=session_id,
        )
        
        logger.info(f"Stored token session for {user_email}")
        return session_id
        
    except Exception as e:
        logger.error(f"Failed to store token session: {e}")
        return ""