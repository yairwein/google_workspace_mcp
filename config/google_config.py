"""
Google Workspace MCP Configuration

This module centralizes configuration variables for Google Workspace integration,
including OAuth scopes and the state map for authentication flows.
"""
import logging
from typing import Dict, Any # Removed str from typing import

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
# Add other Drive scopes here if needed in the future, e.g.:
# DRIVE_METADATA_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.metadata.readonly'
DRIVE_FILE_SCOPE = 'https://www.googleapis.com/auth/drive.file' # Per-file access

# Google Docs scopes
DOCS_READONLY_SCOPE = 'https://www.googleapis.com/auth/documents.readonly'
DOCS_WRITE_SCOPE = 'https://www.googleapis.com/auth/documents'

# Gmail API scopes
GMAIL_READONLY_SCOPE   = 'https://www.googleapis.com/auth/gmail.readonly'
GMAIL_SEND_SCOPE       = 'https://www.googleapis.com/auth/gmail.send'
# Optional, if you later need label management:
# GMAIL_LABELS_SCOPE     = 'https://www.googleapis.com/auth/gmail.labels'

# Base OAuth scopes required for user identification
BASE_SCOPES = [
    USERINFO_EMAIL_SCOPE,
    OPENID_SCOPE
]

# Calendar-specific scopes
CALENDAR_SCOPES = [
    CALENDAR_READONLY_SCOPE,
    CALENDAR_EVENTS_SCOPE
]

# Drive-specific scopes
DRIVE_SCOPES = [
    DRIVE_READONLY_SCOPE
]

# Gmail-specific scopes
GMAIL_SCOPES = [
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
]

# Combined scopes for all supported Google Workspace operations
SCOPES = list(set(BASE_SCOPES + CALENDAR_SCOPES + DRIVE_SCOPES + GMAIL_SCOPES + [DRIVE_FILE_SCOPE])) # Add DRIVE_FILE_SCOPE and GMAIL_SCOPES

# Note: OAUTH_REDIRECT_URI is defined in core/server.py as it depends on the server's port.
# It will be imported directly from core.server where needed.