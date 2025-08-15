"""
Google Drive File Permissions Tools

This module provides tools for checking and managing file permissions in Google Drive.
"""
import logging
import asyncio

from auth.service_decorator import require_google_service
from core.utils import handle_http_errors
from core.server import server

logger = logging.getLogger(__name__)

@server.tool()
@handle_http_errors("get_drive_file_permissions", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def get_drive_file_permissions(
    service,
    user_google_email: str,
    file_id: str,
) -> str:
    """
    Gets detailed metadata about a Google Drive file including sharing permissions.
    
    Args:
        user_google_email (str): The user's Google email address. Required.
        file_id (str): The ID of the file to check permissions for.
    
    Returns:
        str: Detailed file metadata including sharing status and URLs.
    """
    logger.info(f"[get_drive_file_permissions] Checking file {file_id} for {user_google_email}")
    
    try:
        # Get comprehensive file metadata including permissions
        file_metadata = await asyncio.to_thread(
            service.files().get(
                fileId=file_id,
                fields="id, name, mimeType, size, modifiedTime, owners, permissions, "
                       "webViewLink, webContentLink, shared, sharingUser, viewersCanCopyContent",
                supportsAllDrives=True
            ).execute
        )
        
        # Format the response
        output_parts = [
            f"File: {file_metadata.get('name', 'Unknown')}",
            f"ID: {file_id}",
            f"Type: {file_metadata.get('mimeType', 'Unknown')}",
            f"Size: {file_metadata.get('size', 'N/A')} bytes",
            f"Modified: {file_metadata.get('modifiedTime', 'N/A')}",
            "",
            "Sharing Status:",
            f"  Shared: {file_metadata.get('shared', False)}",
        ]
        
        # Add sharing user if available
        sharing_user = file_metadata.get('sharingUser')
        if sharing_user:
            output_parts.append(f"  Shared by: {sharing_user.get('displayName', 'Unknown')} ({sharing_user.get('emailAddress', 'Unknown')})")
        
        # Process permissions
        permissions = file_metadata.get('permissions', [])
        if permissions:
            output_parts.append(f"  Number of permissions: {len(permissions)}")
            output_parts.append("  Permissions:")
            for perm in permissions:
                perm_type = perm.get('type', 'unknown')
                role = perm.get('role', 'unknown')
                
                if perm_type == 'anyone':
                    output_parts.append(f"    - Anyone with the link ({role})")
                elif perm_type == 'user':
                    email = perm.get('emailAddress', 'unknown')
                    output_parts.append(f"    - User: {email} ({role})")
                elif perm_type == 'domain':
                    domain = perm.get('domain', 'unknown')
                    output_parts.append(f"    - Domain: {domain} ({role})")
                elif perm_type == 'group':
                    email = perm.get('emailAddress', 'unknown')
                    output_parts.append(f"    - Group: {email} ({role})")
                else:
                    output_parts.append(f"    - {perm_type} ({role})")
        else:
            output_parts.append("  No additional permissions (private file)")
        
        # Add URLs
        output_parts.extend([
            "",
            "URLs:",
            f"  View Link: {file_metadata.get('webViewLink', 'N/A')}",
        ])
        
        # webContentLink is only available for files that can be downloaded
        web_content_link = file_metadata.get('webContentLink')
        if web_content_link:
            output_parts.append(f"  Direct Download Link: {web_content_link}")
        
        # Check if file has "anyone with link" permission
        from gdrive.drive_helpers import check_public_link_permission
        has_public_link = check_public_link_permission(permissions)
        
        if has_public_link:
            output_parts.extend([
                "",
                "✅ This file is shared with 'Anyone with the link' - it can be inserted into Google Docs"
            ])
        else:
            output_parts.extend([
                "",
                "❌ This file is NOT shared with 'Anyone with the link' - it cannot be inserted into Google Docs",
                "   To fix: Right-click the file in Google Drive → Share → Anyone with the link → Viewer"
            ])
        
        return "\n".join(output_parts)
        
    except Exception as e:
        logger.error(f"Error getting file permissions: {e}")
        return f"Error getting file permissions: {e}"


@server.tool()
@handle_http_errors("check_drive_file_public_access", is_read_only=True, service_type="drive")
@require_google_service("drive", "drive_read")
async def check_drive_file_public_access(
    service,
    user_google_email: str,
    file_name: str,
) -> str:
    """
    Searches for a file by name and checks if it has public link sharing enabled.
    
    Args:
        user_google_email (str): The user's Google email address. Required.
        file_name (str): The name of the file to check.
    
    Returns:
        str: Information about the file's sharing status and whether it can be used in Google Docs.
    """
    logger.info(f"[check_drive_file_public_access] Searching for {file_name}")
    
    # Search for the file
    escaped_name = file_name.replace("'", "\\'")
    query = f"name = '{escaped_name}'"
    
    list_params = {
        "q": query,
        "pageSize": 10,
        "fields": "files(id, name, mimeType, webViewLink)",
        "supportsAllDrives": True,
        "includeItemsFromAllDrives": True,
    }
    
    results = await asyncio.to_thread(
        service.files().list(**list_params).execute
    )
    
    files = results.get('files', [])
    if not files:
        return f"No file found with name '{file_name}'"
    
    if len(files) > 1:
        output_parts = [f"Found {len(files)} files with name '{file_name}':"]
        for f in files:
            output_parts.append(f"  - {f['name']} (ID: {f['id']})")
        output_parts.append("\nChecking the first file...")
        output_parts.append("")
    else:
        output_parts = []
    
    # Check permissions for the first file
    file_id = files[0]['id']
    
    # Get detailed permissions
    file_metadata = await asyncio.to_thread(
        service.files().get(
            fileId=file_id,
            fields="id, name, mimeType, permissions, webViewLink, webContentLink, shared",
            supportsAllDrives=True
        ).execute
    )
    
    permissions = file_metadata.get('permissions', [])
    from gdrive.drive_helpers import check_public_link_permission
    has_public_link = check_public_link_permission(permissions)
    
    output_parts.extend([
        f"File: {file_metadata['name']}",
        f"ID: {file_id}",
        f"Type: {file_metadata['mimeType']}",
        f"Shared: {file_metadata.get('shared', False)}",
        ""
    ])
    
    if has_public_link:
        from gdrive.drive_helpers import get_drive_image_url
        output_parts.extend([
            "✅ PUBLIC ACCESS ENABLED - This file can be inserted into Google Docs",
            f"Use with insert_doc_image_url: {get_drive_image_url(file_id)}"
        ])
    else:
        output_parts.extend([
            "❌ NO PUBLIC ACCESS - Cannot insert into Google Docs",
            "Fix: Drive → Share → 'Anyone with the link' → 'Viewer'"
        ])
    
    return "\n".join(output_parts)