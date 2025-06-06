"""
Google Workspace MCP Configuration

This module centralizes configuration variables for Google Workspace integration,
including OAuth scopes and the state map for authentication flows.
"""
import logging
from typing import Dict

logger = logging.getLogger(__name__)

# Temporary map to associate OAuth state with MCP session ID
# This should ideally be a more robust cache in a production system (e.g., Redis)
OAUTH_STATE_TO_SESSION_ID_MAP: Dict[str, str] = {}

# Individual OAuth Scope Constants
USERINFO_EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'
OPENID_SCOPE = 'openid'
CALENDAR_READONLY_SCOPE = 'https://www.googleapis.com/auth/calendar.readonly'
CALENDAR_EVENTS_SCOPE = 'https://www.googleapis.com/auth/calendar.events'

# Google Drive scopes
DRIVE_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.readonly'
DRIVE_FILE_SCOPE = 'https://www.googleapis.com/auth/drive.file'

# Google Docs scopes
DOCS_READONLY_SCOPE = 'https://www.googleapis.com/auth/documents.readonly'
DOCS_WRITE_SCOPE = 'https://www.googleapis.com/auth/documents'

# Gmail API scopes
GMAIL_READONLY_SCOPE   = 'https://www.googleapis.com/auth/gmail.readonly'
GMAIL_SEND_SCOPE       = 'https://www.googleapis.com/auth/gmail.send'
GMAIL_COMPOSE_SCOPE    = 'https://www.googleapis.com/auth/gmail.compose'
GMAIL_MODIFY_SCOPE     = 'https://www.googleapis.com/auth/gmail.modify'
GMAIL_LABELS_SCOPE     = 'https://www.googleapis.com/auth/gmail.labels'

# Google Chat API scopes
CHAT_READONLY_SCOPE = 'https://www.googleapis.com/auth/chat.messages.readonly'
CHAT_WRITE_SCOPE = 'https://www.googleapis.com/auth/chat.messages'
CHAT_SPACES_SCOPE = 'https://www.googleapis.com/auth/chat.spaces'

# Base OAuth scopes required for user identification
BASE_SCOPES = [
    USERINFO_EMAIL_SCOPE,
    OPENID_SCOPE
]

# Calendar-specific scopes
DOCS_SCOPES = [
    DOCS_READONLY_SCOPE,
    DOCS_WRITE_SCOPE
]

# Calendar-specific scopes
CALENDAR_SCOPES = [
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE
]

# Drive-specific scopes
DRIVE_SCOPES = [
    DRIVE_READONLY_SCOPE,
    DRIVE_FILE_SCOPE
]

# Gmail-specific scopes
GMAIL_SCOPES = [
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_MODIFY_SCOPE,
    GMAIL_LABELS_SCOPE
]

# Chat-specific scopes
CHAT_SCOPES = [
    CHAT_READONLY_SCOPE,
    CHAT_WRITE_SCOPE,
    CHAT_SPACES_SCOPE
]

# Combined scopes for all supported Google Workspace operations
SCOPES = list(set(BASE_SCOPES + CALENDAR_SCOPES + DRIVE_SCOPES + GMAIL_SCOPES + DOCS_SCOPES + CHAT_SCOPES))