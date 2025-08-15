"""
Google Drive Helper Functions

Shared utilities for Google Drive operations including permission checking.
"""
from typing import List, Dict, Any


def check_public_link_permission(permissions: List[Dict[str, Any]]) -> bool:
    """
    Check if file has 'anyone with the link' permission.
    
    Args:
        permissions: List of permission objects from Google Drive API
        
    Returns:
        bool: True if file has public link sharing enabled
    """
    return any(
        p.get('type') == 'anyone' and p.get('role') in ['reader', 'writer', 'commenter']
        for p in permissions
    )


def format_public_sharing_error(file_name: str, file_id: str) -> str:
    """
    Format error message for files without public sharing.
    
    Args:
        file_name: Name of the file
        file_id: Google Drive file ID
        
    Returns:
        str: Formatted error message
    """
    return (
        f"❌ Permission Error: '{file_name}' not shared publicly. "
        f"Set 'Anyone with the link' → 'Viewer' in Google Drive sharing. "
        f"File: https://drive.google.com/file/d/{file_id}/view"
    )


def get_drive_image_url(file_id: str) -> str:
    """
    Get the correct Drive URL format for publicly shared images.
    
    Args:
        file_id: Google Drive file ID
        
    Returns:
        str: URL for embedding Drive images
    """
    return f"https://drive.google.com/uc?export=view&id={file_id}"