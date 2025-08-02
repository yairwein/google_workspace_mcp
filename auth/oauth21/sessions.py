"""
Session Store

Manages user sessions with proper isolation for multi-user OAuth 2.1 environments.
Provides session persistence, cleanup, and security features.
"""

import asyncio
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List, Set
from threading import RLock

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Represents a user session with OAuth 2.1 context."""
    
    session_id: str
    user_id: str
    token_info: Dict[str, Any]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    scopes: List[str] = field(default_factory=list)
    authorization_server: Optional[str] = None
    client_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if session is expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) >= self.expires_at
        return False

    def update_access_time(self):
        """Update last accessed timestamp."""
        self.last_accessed = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "token_info": self.token_info,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "scopes": self.scopes,
            "authorization_server": self.authorization_server,
            "client_id": self.client_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Create session from dictionary."""
        session = cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            token_info=data["token_info"],
            scopes=data.get("scopes", []),
            authorization_server=data.get("authorization_server"),
            client_id=data.get("client_id"),
            metadata=data.get("metadata", {}),
        )
        
        # Parse timestamps
        session.created_at = datetime.fromisoformat(data["created_at"])
        session.last_accessed = datetime.fromisoformat(data["last_accessed"])
        if data.get("expires_at"):
            session.expires_at = datetime.fromisoformat(data["expires_at"])
        
        return session


class SessionStore:
    """Manages user sessions with proper isolation."""

    def __init__(
        self,
        default_session_timeout: int = 3600,  # 1 hour
        max_sessions_per_user: int = 10,
        cleanup_interval: int = 300,  # 5 minutes
        enable_persistence: bool = False,
        persistence_file: Optional[str] = None,
    ):
        """
        Initialize the session store.

        Args:
            default_session_timeout: Default session timeout in seconds
            max_sessions_per_user: Maximum sessions per user
            cleanup_interval: Session cleanup interval in seconds
            enable_persistence: Enable session persistence to disk
            persistence_file: File path for session persistence
        """
        self.default_session_timeout = default_session_timeout
        self.max_sessions_per_user = max_sessions_per_user
        self.cleanup_interval = cleanup_interval
        self.enable_persistence = enable_persistence
        self.persistence_file = persistence_file or ".oauth21_sessions.json"
        
        # Thread-safe session storage
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, Set[str]] = {}  # user_id -> set of session_ids
        self._lock = RLock()
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown = False
        
        # Load persisted sessions
        if self.enable_persistence:
            self._load_sessions()

    async def start_cleanup_task(self):
        """Start the background cleanup task."""
        if not self._cleanup_task or self._cleanup_task.done():
            self._shutdown = False
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Started session cleanup task")

    async def stop_cleanup_task(self):
        """Stop the background cleanup task."""
        self._shutdown = True
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped session cleanup task")

    def create_session(
        self,
        user_id: str,
        token_info: Dict[str, Any],
        session_timeout: Optional[int] = None,
        scopes: Optional[List[str]] = None,
        authorization_server: Optional[str] = None,
        client_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create new session and return session ID.

        Args:
            user_id: User identifier (email)
            token_info: OAuth token information
            session_timeout: Session timeout in seconds
            scopes: OAuth scopes
            authorization_server: Authorization server URL
            client_id: OAuth client ID
            metadata: Additional session metadata

        Returns:
            Session ID string

        Raises:
            ValueError: If maximum sessions exceeded
        """
        with self._lock:
            # Check session limits
            user_session_count = len(self._user_sessions.get(user_id, set()))
            if user_session_count >= self.max_sessions_per_user:
                # Clean up oldest session for this user
                self._cleanup_oldest_user_session(user_id)

            # Generate secure session ID
            session_id = self._generate_session_id()
            
            # Calculate expiration
            timeout = session_timeout or self.default_session_timeout
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=timeout)
            
            # Create session
            session = Session(
                session_id=session_id,
                user_id=user_id,
                token_info=token_info,
                expires_at=expires_at,
                scopes=scopes or [],
                authorization_server=authorization_server,
                client_id=client_id,
                metadata=metadata or {},
            )
            
            # Store session
            self._sessions[session_id] = session
            
            # Update user session mapping
            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = set()
            self._user_sessions[user_id].add(session_id)
            
            logger.info(f"Created session {session_id} for user {user_id}")
            
            # Persist if enabled
            if self.enable_persistence:
                self._save_sessions()
            
            return session_id

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Retrieve session by ID.

        Args:
            session_id: Session identifier

        Returns:
            Session object or None if not found/expired
        """
        with self._lock:
            session = self._sessions.get(session_id)
            
            if not session:
                return None
            
            # Check expiration
            if session.is_expired():
                logger.debug(f"Session {session_id} has expired")
                self._remove_session(session_id)
                return None
            
            # Update access time
            session.update_access_time()
            
            logger.debug(f"Retrieved session {session_id} for user {session.user_id}")
            return session

    def update_session(
        self,
        session_id: str,
        token_info: Optional[Dict[str, Any]] = None,
        extend_expiration: bool = True,
        metadata_updates: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Update session with new token information.

        Args:
            session_id: Session identifier
            token_info: Updated token information
            extend_expiration: Whether to extend session expiration
            metadata_updates: Metadata updates to apply

        Returns:
            True if session was updated, False if not found
        """
        with self._lock:
            session = self._sessions.get(session_id)
            
            if not session or session.is_expired():
                return False
            
            # Update token info
            if token_info:
                session.token_info.update(token_info)
            
            # Update metadata
            if metadata_updates:
                session.metadata.update(metadata_updates)
            
            # Extend expiration
            if extend_expiration:
                session.expires_at = datetime.now(timezone.utc) + timedelta(
                    seconds=self.default_session_timeout
                )
            
            session.update_access_time()
            
            logger.debug(f"Updated session {session_id}")
            
            # Persist if enabled
            if self.enable_persistence:
                self._save_sessions()
            
            return True

    def remove_session(self, session_id: str) -> bool:
        """
        Remove session by ID.

        Args:
            session_id: Session identifier

        Returns:
            True if session was removed, False if not found
        """
        with self._lock:
            return self._remove_session(session_id)

    def get_user_sessions(self, user_id: str) -> List[Session]:
        """
        Get all active sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            List of active sessions for the user
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, set())
            sessions = []
            
            for session_id in list(session_ids):  # Create copy to avoid modification during iteration
                session = self.get_session(session_id)  # This handles expiration
                if session:
                    sessions.append(session)
            
            return sessions

    def remove_user_sessions(self, user_id: str) -> int:
        """
        Remove all sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            Number of sessions removed
        """
        with self._lock:
            session_ids = self._user_sessions.get(user_id, set()).copy()
            removed_count = 0
            
            for session_id in session_ids:
                if self._remove_session(session_id):
                    removed_count += 1
            
            logger.info(f"Removed {removed_count} sessions for user {user_id}")
            return removed_count

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.

        Returns:
            Number of sessions removed
        """
        with self._lock:
            expired_session_ids = []
            
            for session_id, session in self._sessions.items():
                if session.is_expired():
                    expired_session_ids.append(session_id)
            
            removed_count = 0
            for session_id in expired_session_ids:
                if self._remove_session(session_id):
                    removed_count += 1
            
            if removed_count > 0:
                logger.info(f"Cleaned up {removed_count} expired sessions")
            
            return removed_count

    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session store statistics.

        Returns:
            Dictionary with session statistics
        """
        with self._lock:
            total_sessions = len(self._sessions)
            active_users = len(self._user_sessions)
            
            # Count sessions by user
            sessions_per_user = {}
            for user_id, session_ids in self._user_sessions.items():
                sessions_per_user[user_id] = len(session_ids)
            
            return {
                "total_sessions": total_sessions,
                "active_users": active_users,
                "sessions_per_user": sessions_per_user,
                "max_sessions_per_user": self.max_sessions_per_user,
                "default_timeout": self.default_session_timeout,
            }

    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _remove_session(self, session_id: str) -> bool:
        """Internal method to remove session (assumes lock is held)."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        
        # Remove from main storage
        del self._sessions[session_id]
        
        # Remove from user mapping
        user_sessions = self._user_sessions.get(session.user_id)
        if user_sessions:
            user_sessions.discard(session_id)
            if not user_sessions:
                del self._user_sessions[session.user_id]
        
        logger.debug(f"Removed session {session_id} for user {session.user_id}")
        
        # Persist if enabled
        if self.enable_persistence:
            self._save_sessions()
        
        return True

    def _cleanup_oldest_user_session(self, user_id: str):
        """Remove oldest session for a user."""
        session_ids = self._user_sessions.get(user_id, set())
        if not session_ids:
            return
        
        # Find oldest session
        oldest_session_id = None
        oldest_time = datetime.now(timezone.utc)
        
        for session_id in session_ids:
            session = self._sessions.get(session_id)
            if session and session.created_at < oldest_time:
                oldest_time = session.created_at
                oldest_session_id = session_id
        
        if oldest_session_id:
            self._remove_session(oldest_session_id)
            logger.info(f"Removed oldest session {oldest_session_id} for user {user_id}")

    async def _cleanup_loop(self):
        """Background cleanup task."""
        while not self._shutdown:
            try:
                self.cleanup_expired_sessions()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in session cleanup loop: {e}")
                await asyncio.sleep(self.cleanup_interval)

    def _save_sessions(self):
        """Save sessions to disk (if persistence enabled)."""
        if not self.enable_persistence:
            return
        
        try:
            import json
            
            data = {
                "sessions": {
                    session_id: session.to_dict()
                    for session_id, session in self._sessions.items()
                },
                "user_sessions": {
                    user_id: list(session_ids)
                    for user_id, session_ids in self._user_sessions.items()
                },
            }
            
            with open(self.persistence_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved {len(self._sessions)} sessions to {self.persistence_file}")
            
        except Exception as e:
            logger.error(f"Failed to save sessions: {e}")

    def _load_sessions(self):
        """Load sessions from disk (if persistence enabled)."""
        if not self.enable_persistence:
            return
        
        try:
            import json
            import os
            
            if not os.path.exists(self.persistence_file):
                return
            
            with open(self.persistence_file, "r") as f:
                data = json.load(f)
            
            # Load sessions
            for session_id, session_data in data.get("sessions", {}).items():
                try:
                    session = Session.from_dict(session_data)
                    if not session.is_expired():
                        self._sessions[session_id] = session
                except Exception as e:
                    logger.warning(f"Failed to load session {session_id}: {e}")
            
            # Rebuild user session mappings
            self._user_sessions.clear()
            for session_id, session in self._sessions.items():
                if session.user_id not in self._user_sessions:
                    self._user_sessions[session.user_id] = set()
                self._user_sessions[session.user_id].add(session_id)
            
            logger.info(f"Loaded {len(self._sessions)} sessions from {self.persistence_file}")
            
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start_cleanup_task()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop_cleanup_task()