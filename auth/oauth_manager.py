# auth/oauth_manager.py

import logging
import os
import threading
import time
from typing import Dict, Optional, Callable, Any, Tuple

from auth.callback_server import OAuthCallbackServer
from auth.google_auth import start_auth_flow, handle_auth_callback, get_credentials, get_user_info

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Track active OAuth flows
active_flows: Dict[str, Dict[str, Any]] = {}

def start_oauth_flow(
    user_id: str,
    scopes: list,
    client_secrets_path: str = 'client_secret.json',
    port: int = 8080
) -> str:
    """
    Start an OAuth flow with automatic callback handling.
    
    Args:
        user_id: The unique identifier (e.g., email address) for the user.
        scopes: List of OAuth scopes required.
        client_secrets_path: Path to the Google client secrets JSON file.
        port: Port to run the callback server on.
        
    Returns:
        A string with instructions for the user, including the authentication URL.
    """
    logger.info(f"Starting OAuth flow for user {user_id} with scopes {scopes}")
    
    # Cleanup any previous flow for this user
    if user_id in active_flows:
        stop_oauth_flow(user_id)
    
    # Create a callback function for this user
    def handle_code(code: str, state: str) -> None:
        try:
            logger.info(f"Received authorization code for user {user_id}")
            
            # Construct full callback URL
            redirect_uri = f"http://localhost:{port}/callback"
            full_callback_url = f"{redirect_uri}?code={code}&state={state}"
            
            # Exchange code for credentials
            authenticated_user, credentials = handle_auth_callback(
                client_secrets_path=client_secrets_path,
                scopes=scopes,
                authorization_response=full_callback_url,
                redirect_uri=redirect_uri
            )
            
            # Update flow status
            active_flows[user_id]["status"] = "authenticated"
            active_flows[user_id]["authenticated_user"] = authenticated_user
            active_flows[user_id]["credentials"] = credentials
            
            logger.info(f"Authentication successful for user {authenticated_user}")
            
        except Exception as e:
            logger.error(f"Error handling OAuth callback for user {user_id}: {e}")
            active_flows[user_id]["status"] = "error"
            active_flows[user_id]["error"] = str(e)
    
    # Start a callback server
    callback_server = OAuthCallbackServer(
        port=port,
        callback=handle_code,
        auto_open_browser=True  # Auto-open browser for better UX
    )
    
    try:
        # Start the server
        callback_server.start()
        
        # Generate the authorization URL
        redirect_uri = f"http://localhost:{port}/callback"
        auth_url, state = start_auth_flow(
            client_secrets_path=client_secrets_path,
            scopes=scopes,
            redirect_uri=redirect_uri,
            auto_handle_callback=False  # We're handling it ourselves
        )
        
        # Store flow information
        active_flows[user_id] = {
            "status": "pending",
            "start_time": time.time(),
            "scopes": scopes,
            "server": callback_server,
            "auth_url": auth_url,
            "state": state
        }
        
        # Return instructions for the user
        return (
            f"Authentication required. Please visit this URL to authorize access: "
            f"{auth_url}\n\n"
            f"A browser window should open automatically. After authorizing, you'll be "
            f"redirected to a success page.\n\n"
            f"If the browser doesn't open automatically, copy and paste the URL into your browser. "
            f"You can also check the status of your authentication by using:\n\n"
            f"check_auth_status\n"
            f"user_id: {user_id}"
        )
        
    except Exception as e:
        logger.error(f"Error starting OAuth flow for user {user_id}: {e}")
        # Clean up the server if it was started
        if "server" in active_flows.get(user_id, {}):
            active_flows[user_id]["server"].stop()
            del active_flows[user_id]
        raise

def check_auth_status(user_id: str) -> str:
    """
    Check the status of an active OAuth flow.
    
    Args:
        user_id: The unique identifier for the user.
        
    Returns:
        A string describing the current status.
    """
    if user_id not in active_flows:
        return f"No active authentication flow found for user {user_id}."
    
    flow = active_flows[user_id]
    status = flow.get("status", "unknown")
    
    if status == "authenticated":
        authenticated_user = flow.get("authenticated_user", "unknown")
        return (
            f"Authentication successful for user {authenticated_user}. "
            f"You can now use the Google Calendar tools."
        )
    elif status == "error":
        error = flow.get("error", "Unknown error")
        return f"Authentication failed: {error}"
    elif status == "pending":
        elapsed = int(time.time() - flow.get("start_time", time.time()))
        auth_url = flow.get("auth_url", "")
        return (
            f"Authentication pending for {elapsed} seconds. "
            f"Please complete the authorization at: {auth_url}"
        )
    else:
        return f"Unknown authentication status: {status}"

def stop_oauth_flow(user_id: str) -> str:
    """
    Stop an active OAuth flow and clean up resources.
    
    Args:
        user_id: The unique identifier for the user.
        
    Returns:
        A string describing the result.
    """
    if user_id not in active_flows:
        return f"No active authentication flow found for user {user_id}."
    
    try:
        # Stop the callback server
        if "server" in active_flows[user_id]:
            active_flows[user_id]["server"].stop()
        
        # Remove the flow
        final_status = active_flows[user_id].get("status", "unknown")
        del active_flows[user_id]
        
        return f"Authentication flow for user {user_id} stopped. Final status: {final_status}."
    except Exception as e:
        logger.error(f"Error stopping OAuth flow for user {user_id}: {e}")
        return f"Error stopping authentication flow: {e}"