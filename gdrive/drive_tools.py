"""
Google Drive MCP Tools

This module provides MCP tools for interacting with Google Drive API.
"""
import logging
import asyncio
import os
from typing import List, Optional, Dict, Any

from mcp import types
from fastapi import Header
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload # For file content
import io # For file content

from auth.google_auth import get_credentials
from core.server import server, OAUTH_REDIRECT_URI, OAUTH_STATE_TO_SESSION_ID_MAP
from core.server import ( # Import Drive scopes defined in core.server
    DRIVE_READONLY_SCOPE,
    SCOPES # The combined list of all scopes for broad auth initiation
)

logger = logging.getLogger(__name__)

# Path to client secrets, similar to calendar_tools.py
_client_secrets_env = os.getenv("GOOGLE_CLIENT_SECRETS")
if _client_secrets_env:
    CONFIG_CLIENT_SECRETS_PATH = _client_secrets_env
else:
    # Adjusted path relative to gdrive/ assuming main.py is in parent dir of gdrive/
    CONFIG_CLIENT_SECRETS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'client_secret.json')


async def _initiate_drive_auth_and_get_message(
    mcp_session_id: Optional[str],
    required_scopes: List[str],
    user_google_email: Optional[str] = None
) -> types.CallToolResult:
    from google_auth_oauthlib.flow import Flow # Local import
    
    initial_email_provided = bool(user_google_email and user_google_email.strip() and user_google_email.lower() != 'default')
    user_display_name = f"Google Drive for '{user_google_email}'" if initial_email_provided else "Google Drive"

    logger.info(f"[_initiate_drive_auth_and_get_message] Initiating auth for {user_display_name} (session: {mcp_session_id}) with scopes: {required_scopes}")
    try:
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ and "localhost" in OAUTH_REDIRECT_URI:
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        
        oauth_state = os.urandom(16).hex()
        if mcp_session_id:
            OAUTH_STATE_TO_SESSION_ID_MAP[oauth_state] = mcp_session_id
        
        flow = Flow.from_client_secrets_file(
            CONFIG_CLIENT_SECRETS_PATH,
            scopes=required_scopes,
            redirect_uri=OAUTH_REDIRECT_URI,
            state=oauth_state
        )
        auth_url, _ = flow.authorization_url(access_type='offline', prompt='consent')
        
        message_lines = [
            f"**ACTION REQUIRED: Google Authentication Needed for {user_display_name}**\n",
            "To proceed, the user must authorize this application for Google Drive access.",
            "**LLM, please present this exact authorization URL to the user as a clickable hyperlink:**",
            f"Authorization URL: {auth_url}",
            f"Markdown for hyperlink: [Click here to authorize Google Drive access]({auth_url})\n",
            "**LLM, after presenting the link, instruct the user as follows:**",
            "1. Click the link and complete the authorization in their browser.",
        ]
        session_info_for_llm = f" (this will link to your current session {mcp_session_id})" if mcp_session_id else ""

        if not initial_email_provided:
            message_lines.extend([
                f"2. After successful authorization{session_info_for_llm}, the browser page will display the authenticated email address.",
                "   **LLM: Instruct the user to provide you with this email address.**",
                "3. Once you have the email, **retry their original command, ensuring you include this `user_google_email`.**"
            ])
        else:
            message_lines.append(f"2. After successful authorization{session_info_for_llm}, **retry their original command**.")
        
        message_lines.append(f"\nThe application will use the new credentials. If '{user_google_email}' was provided, it must match the authenticated account.")
        message = "\n".join(message_lines)
        
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=message)])
    except FileNotFoundError as e:
        error_text = f"OAuth client secrets file not found: {e}. Please ensure '{CONFIG_CLIENT_SECRETS_PATH}' is correctly configured."
        logger.error(error_text, exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_text)])
    except Exception as e:
        error_text = f"Could not initiate authentication for {user_display_name} due to an unexpected error: {str(e)}"
        logger.error(f"Failed to start the OAuth flow for {user_display_name}: {e}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_text)])

@server.tool()
async def search_drive_files(
    query: str,
    user_google_email: Optional[str] = None,
    page_size: int = 10,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Searches for files in Google Drive based on a query string.
    """
    logger.info(f"[search_drive_files] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', Query: '{query}'")
    tool_specific_scopes = [DRIVE_READONLY_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_specific_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[search_drive_files] No valid credentials for Drive. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
            return await _initiate_drive_auth_and_get_message(mcp_session_id, scopes=tool_specific_scopes, user_google_email=user_google_email)
        else:
            error_msg = "Drive Authentication required. LLM: Please ask for Google email."
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])
    
    try:
        service = build('drive', 'v3', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown (Drive)'
        results = await asyncio.to_thread(
            service.files().list(
                q=query,
                pageSize=page_size,
                fields="nextPageToken, files(id, name, mimeType, webViewLink, iconLink, modifiedTime, size)"
            ).execute
        )
        files = results.get('files', [])
        if not files:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No files found for '{query}'.")])

        formatted_files_text_parts = [f"Found {len(files)} files for {user_email_from_creds} matching '{query}':"]
        for item in files:
            size_str = f", Size: {item.get('size', 'N/A')}" if 'size' in item else ""
            formatted_files_text_parts.append(
                f"- Name: \"{item['name']}\" (ID: {item['id']}, Type: {item['mimeType']}{size_str}, Modified: {item.get('modifiedTime', 'N/A')}) Link: {item.get('webViewLink', '#')}"
            )
        text_output = "\n".join(formatted_files_text_parts)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text_output)])
    except HttpError as error:
        logger.error(f"API error searching Drive files: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error searching Drive files: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def get_drive_file_content(
    file_id: str,
    user_google_email: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Gets the content of a specific file from Google Drive.
    """
    logger.info(f"[get_drive_file_content] Invoked. File ID: '{file_id}'")
    tool_specific_scopes = [DRIVE_READONLY_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_specific_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[get_drive_file_content] No valid credentials for Drive. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
             return await _initiate_drive_auth_and_get_message(mcp_session_id, scopes=tool_specific_scopes, user_google_email=user_google_email)
        else:
            error_msg = "Drive Authentication required. LLM: Please ask for Google email."
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        service = build('drive', 'v3', credentials=credentials)
        file_metadata = await asyncio.to_thread(
            service.files().get(fileId=file_id, fields="id, name, mimeType, webViewLink").execute
        )
        mime_type = file_metadata.get('mimeType', '')
        file_name = file_metadata.get('name', 'Unknown File')
        content_text = f"File: \"{file_name}\" (ID: {file_id}, Type: {mime_type})\nLink: {file_metadata.get('webViewLink', '#')}\n\n--- CONTENT ---\n"
        
        export_mime_type = None
        if mime_type == 'application/vnd.google-apps.document': export_mime_type = 'text/plain'
        elif mime_type == 'application/vnd.google-apps.spreadsheet': export_mime_type = 'text/csv'
        elif mime_type == 'application/vnd.google-apps.presentation': export_mime_type = 'text/plain'
        
        request_obj = service.files().export_media(fileId=file_id, mimeType=export_mime_type) if export_mime_type \
            else service.files().get_media(fileId=file_id)

        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request_obj)
        done = False
        loop = asyncio.get_event_loop()
        while not done:
            status, done = await loop.run_in_executor(None, downloader.next_chunk)
        
        file_content_bytes = fh.getvalue()
        try:
            file_content_str = file_content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            file_content_str = f"[Content is binary or uses an unsupported text encoding. Length: {len(file_content_bytes)} bytes]"
        content_text += file_content_str
        logger.info(f"Successfully retrieved content for Drive file ID: {file_id}")
        return types.CallToolResult(content=[types.TextContent(type="text", text=content_text)])
    except HttpError as error:
        logger.error(f"API error getting Drive file content for {file_id}: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error getting Drive file content for {file_id}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def list_drive_items(
    folder_id: str = 'root', # Default to root folder
    user_google_email: Optional[str] = None,
    page_size: int = 100, # Default page size for listing
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Lists files and folders within a specified Google Drive folder.
    Defaults to listing items in the root folder if no folder_id is provided.
    """
    logger.info(f"[list_drive_items] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', Folder ID: '{folder_id}'")
    tool_specific_scopes = [DRIVE_READONLY_SCOPE]
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_specific_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[list_drive_items] No valid credentials for Drive. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
             return await _initiate_drive_auth_and_get_message(mcp_session_id, scopes=tool_specific_scopes, user_google_email=user_google_email)
        else:
            error_msg = "Drive Authentication required. LLM: Please ask for Google email."
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        service = build('drive', 'v3', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown (Drive)'
        logger.info(f"Successfully built Drive service for list_drive_items. User: {user_email_from_creds}")

        # Build the query to list items in the specified folder, excluding trashed items
        query = f"'{folder_id}' in parents and trashed = false"

        results = await asyncio.to_thread(
            service.files().list(
                q=query,
                pageSize=page_size,
                fields="nextPageToken, files(id, name, mimeType, webViewLink, iconLink, modifiedTime, size)"
            ).execute
        )

        items = results.get('files', [])
        if not items:
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"No items found in folder '{folder_id}' for {user_email_from_creds}.")])

        formatted_items_text_parts = [f"Items in folder '{folder_id}' for {user_email_from_creds}:"]
        for item in items:
            item_type = "Folder" if item.get('mimeType') == 'application/vnd.google-apps.folder' else "File"
            size_str = f", Size: {item.get('size', 'N/A')}" if 'size' in item else ""
            formatted_items_text_parts.append(
                f"- {item_type}: \"{item['name']}\" (ID: {item['id']}, Type: {item['mimeType']}{size_str}, Modified: {item.get('modifiedTime', 'N/A')}) Link: {item.get('webViewLink', '#')}"
            )

        text_output = "\n".join(formatted_items_text_parts)
        logger.info(f"Successfully listed {len(items)} items in folder: '{folder_id}'.")
        return types.CallToolResult(content=[types.TextContent(type="text", text=text_output)])

    except HttpError as error:
        logger.error(f"API error listing Drive items in folder {folder_id}: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error listing Drive items in folder {folder_id}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error: {e}")])

@server.tool()
async def create_drive_file(
    file_name: str,
    content: str,
    folder_id: str = 'root', # Default to root folder
    user_google_email: Optional[str] = None,
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id")
) -> types.CallToolResult:
    """
    Creates a new file with specified content in a Google Drive folder.
    Defaults to creating the file in the root folder if no folder_id is provided.
    Requires the drive.file scope.
    """
    logger.info(f"[create_drive_file] Invoked. Session: '{mcp_session_id}', Email: '{user_google_email}', File Name: '{file_name}', Folder ID: '{folder_id}'")
    
    # This tool requires the DRIVE_FILE_SCOPE for writing
    tool_specific_scopes = ['https://www.googleapis.com/auth/drive.file'] # Explicitly use the scope string

    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=user_google_email,
        required_scopes=tool_specific_scopes,
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=mcp_session_id
    )

    if not credentials or not credentials.valid:
        logger.warning(f"[create_drive_file] No valid credentials for Drive write access. Session: '{mcp_session_id}', Email: '{user_google_email}'.")
        if user_google_email and '@' in user_google_email:
             # Initiate auth asking for the specific scopes needed by this tool
             return await _initiate_drive_auth_and_get_message(mcp_session_id, required_scopes=tool_specific_scopes, user_google_email=user_google_email)
        else:
            error_msg = "Drive Authentication with write permissions required. LLM: Please ask for Google email."
            return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=error_msg)])

    try:
        service = build('drive', 'v3', credentials=credentials)
        user_email_from_creds = credentials.id_token.get('email') if credentials.id_token else 'Unknown (Drive)'
        logger.info(f"Successfully built Drive service for create_drive_file. User: {user_email_from_creds}")

        file_metadata = {
            'name': file_name,
            'parents': [folder_id] # Specify the parent folder
        }
        media = io.BytesIO(content.encode('utf-8')) # Encode content to bytes
        media_body = MediaIoBaseUpload(media, mimetype='text/plain', resumable=True) # Assume text/plain for now

        # Use asyncio.to_thread for the blocking API call
        created_file = await asyncio.to_thread(
            service.files().create(
                body=file_metadata,
                media_body=media_body,
                fields='id, name, webViewLink'
            ).execute
        )

        file_id = created_file.get('id')
        file_name = created_file.get('name')
        web_view_link = created_file.get('webViewLink')

        success_message = f"Successfully created file \"{file_name}\" (ID: {file_id}) in folder '{folder_id}' for {user_email_from_creds}. Link: {web_view_link}"
        logger.info(success_message)
        return types.CallToolResult(content=[types.TextContent(type="text", text=success_message)])

    except HttpError as error:
        logger.error(f"API error creating Drive file '{file_name}' in folder {folder_id}: {error}", exc_info=True)
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"API error creating file: {error}")])
    except Exception as e:
        logger.exception(f"Unexpected error creating Drive file '{file_name}' in folder {folder_id}: {e}")
        return types.CallToolResult(isError=True, content=[types.TextContent(type="text", text=f"Unexpected error creating file: {e}")])