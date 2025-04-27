# auth/google_auth.py

import os
import json
import logging
from typing import List, Optional, Tuple, Dict, Any, Callable

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from auth.callback_server import OAuthCallbackServer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_CREDENTIALS_DIR = ".credentials"
DEFAULT_REDIRECT_URI = "http://localhost:8080/callback"
DEFAULT_SERVER_PORT = 8080

# --- Helper Functions ---

def _get_user_credential_path(user_id: str, base_dir: str = DEFAULT_CREDENTIALS_DIR) -> str:
    """Constructs the path to a user's credential file."""
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
        logger.info(f"Created credentials directory: {base_dir}")
    return os.path.join(base_dir, f"{user_id}.json")

def _save_credentials(user_id: str, credentials: Credentials, base_dir: str = DEFAULT_CREDENTIALS_DIR):
    """Saves user credentials to a file."""
    creds_path = _get_user_credential_path(user_id, base_dir)
    creds_data = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    try:
        with open(creds_path, 'w') as f:
            json.dump(creds_data, f)
        logger.info(f"Credentials saved for user {user_id} to {creds_path}")
    except IOError as e:
        logger.error(f"Error saving credentials for user {user_id} to {creds_path}: {e}")
        raise

def _load_credentials(user_id: str, base_dir: str = DEFAULT_CREDENTIALS_DIR) -> Optional[Credentials]:
    """Loads user credentials from a file."""
    creds_path = _get_user_credential_path(user_id, base_dir)
    if not os.path.exists(creds_path):
        logger.info(f"No credentials file found for user {user_id} at {creds_path}")
        return None

    try:
        with open(creds_path, 'r') as f:
            creds_data = json.load(f)
        # Ensure all necessary keys are present, especially refresh_token which might be None
        credentials = Credentials(
            token=creds_data.get('token'),
            refresh_token=creds_data.get('refresh_token'),
            token_uri=creds_data.get('token_uri'),
            client_id=creds_data.get('client_id'),
            client_secret=creds_data.get('client_secret'),
            scopes=creds_data.get('scopes')
        )
        logger.info(f"Credentials loaded for user {user_id} from {creds_path}")
        return credentials
    except (IOError, json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error loading or parsing credentials for user {user_id} from {creds_path}: {e}")
        # Consider deleting the corrupted file or handling it differently
        return None

def load_client_secrets(client_secrets_path: str) -> Dict[str, Any]:
    """Loads the client secrets file."""
    try:
        with open(client_secrets_path, 'r') as f:
            client_config = json.load(f)
            # The file usually contains a top-level key like "web" or "installed"
            if "web" in client_config:
                return client_config["web"]
            elif "installed" in client_config:
                 return client_config["installed"]
            else:
                 logger.error(f"Client secrets file {client_secrets_path} has unexpected format.")
                 raise ValueError("Invalid client secrets file format")
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error loading client secrets file {client_secrets_path}: {e}")
        raise

# --- Core OAuth Logic ---

def start_auth_flow(
    client_secrets_path: str,
    scopes: List[str],
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    auto_handle_callback: bool = False,
    callback_function: Optional[Callable] = None,
    port: int = DEFAULT_SERVER_PORT
) -> Tuple[str, str]:
    """
    Initiates the OAuth 2.0 flow and returns the authorization URL and state.

    Args:
        client_secrets_path: Path to the Google client secrets JSON file.
        scopes: List of OAuth scopes required.
        redirect_uri: The URI Google will redirect to after authorization.
        auto_handle_callback: Whether to automatically handle the callback by
                             starting a local server on the specified port.
        callback_function: Function to call with the code and state when received.
        port: Port to run the callback server on, if auto_handle_callback is True.

    Returns:
        A tuple containing the authorization URL and the state parameter.
    """
    try:
        # Create and start the callback server if auto_handle_callback is enabled
        server = None
        if auto_handle_callback:
            logger.info("Starting OAuth callback server")
            server = OAuthCallbackServer(port=port, callback=callback_function, auto_open_browser=False)
            server.start()

        # Set up the OAuth flow
        flow = Flow.from_client_secrets_file(
            client_secrets_path,
            scopes=scopes,
            redirect_uri=redirect_uri
        )

        # Indicate that the user needs *offline* access to retrieve a refresh token.
        # 'prompt': 'consent' ensures the user sees the consent screen even if
        # they have previously granted permissions, which is useful for getting
        # a refresh token again if needed.
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent'
        )
        logger.info(f"Generated authorization URL. State: {state}")
        
        # Auto-open the browser if requested
        if auto_handle_callback and server:
            server.open_browser(authorization_url)
            
        return authorization_url, state

    except Exception as e:
        logger.error(f"Error starting OAuth flow: {e}")
        # If we created a server, shut it down
        if auto_handle_callback and server:
            server.stop()
        raise  # Re-raise the exception for the caller to handle

def handle_auth_callback(
    client_secrets_path: str,
    scopes: List[str],
    authorization_response: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    credentials_base_dir: str = DEFAULT_CREDENTIALS_DIR
) -> Tuple[str, Credentials]:
    """
    Handles the callback from Google, exchanges the code for credentials,
    fetches user info, determines user_id, saves credentials, and returns them.

    Args:
        client_secrets_path: Path to the Google client secrets JSON file.
        scopes: List of OAuth scopes requested (should match `start_auth_flow`).
        authorization_response: The full callback URL received from Google.
        redirect_uri: The redirect URI configured in the Google Cloud Console and used in start_auth_flow.
        credentials_base_dir: Base directory to store credential files.

    Returns:
        A tuple containing the user_id (email) and the obtained Credentials object.

    Raises:
        ValueError: If the state is missing or doesn't match.
        FlowExchangeError: If the code exchange fails.
        HttpError: If fetching user info fails.
    """
    try:
        flow = Flow.from_client_secrets_file(
            client_secrets_path,
            scopes=scopes,
            redirect_uri=redirect_uri
        )

        # Exchange the authorization code for credentials
        # Note: fetch_token will use the redirect_uri configured in the flow
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        logger.info("Successfully exchanged authorization code for tokens.")

        # Get user info to determine user_id (using email here)
        user_info = get_user_info(credentials)
        if not user_info or 'email' not in user_info:
             logger.error("Could not retrieve user email from Google.")
             raise ValueError("Failed to get user email for identification.")

        user_id = user_info['email']
        logger.info(f"Identified user ID: {user_id}")

        # Save the credentials for this user
        _save_credentials(user_id, credentials, credentials_base_dir)

        return user_id, credentials

    except Exception as e: # Catch specific exceptions like FlowExchangeError if needed
        logger.error(f"Error handling auth callback: {e}")
        raise # Re-raise for the caller

def get_credentials(
    user_id: str,
    required_scopes: List[str],
    client_secrets_path: Optional[str] = None, # Needed for refresh
    credentials_base_dir: str = DEFAULT_CREDENTIALS_DIR
) -> Optional[Credentials]:
    """
    Retrieves stored credentials for a user, refreshes if necessary.

    Args:
        user_id: The unique identifier for the user (e.g., email).
        required_scopes: List of scopes the credentials must have.
        client_secrets_path: Path to client secrets, required *only* if refresh might be needed.
        credentials_base_dir: Base directory where credential files are stored.

    Returns:
        Valid Credentials object if found and valid/refreshed, otherwise None.
    """
    credentials = _load_credentials(user_id, credentials_base_dir)

    if not credentials:
        logger.info(f"No stored credentials found for user {user_id}.")
        return None

    # Check if scopes are sufficient
    if not all(scope in credentials.scopes for scope in required_scopes):
        logger.warning(f"Stored credentials for user {user_id} lack required scopes. Need: {required_scopes}, Have: {credentials.scopes}")
        # Re-authentication is needed to grant missing scopes
        return None

    # Check if credentials are still valid or need refresh
    if credentials.valid:
        logger.info(f"Stored credentials for user {user_id} are valid.")
        return credentials
    elif credentials.expired and credentials.refresh_token:
        logger.info(f"Credentials for user {user_id} expired. Attempting refresh.")
        if not client_secrets_path:
             logger.error("Client secrets path is required to refresh credentials but was not provided.")
             # Cannot refresh without client secrets info
             return None
        try:
            # Load client secrets to provide info for refresh
            # Note: Credentials object holds client_id/secret if available from initial flow,
            # but loading from file is safer if they weren't stored or if using InstalledAppFlow secrets.
            client_config = load_client_secrets(client_secrets_path)
            credentials.refresh(Request()) # Pass client_id/secret if needed and not in creds
            logger.info(f"Credentials for user {user_id} refreshed successfully.")
            # Save the updated credentials (with potentially new access token)
            _save_credentials(user_id, credentials, credentials_base_dir)
            return credentials
        except Exception as e: # Catch specific refresh errors like google.auth.exceptions.RefreshError
            logger.error(f"Error refreshing credentials for user {user_id}: {e}")
            # Failed to refresh, re-authentication is needed
            return None
    else:
        logger.warning(f"Credentials for user {user_id} are invalid or missing refresh token.")
        # Invalid and cannot be refreshed, re-authentication needed
        return None


def get_user_info(credentials: Credentials) -> Optional[Dict[str, Any]]:
    """Fetches basic user profile information (requires userinfo.email scope)."""
    if not credentials or not credentials.valid:
        logger.error("Cannot get user info: Invalid or missing credentials.")
        return None
    try:
        # Using googleapiclient discovery to get user info
        # Requires 'google-api-python-client' library
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        logger.info(f"Successfully fetched user info: {user_info.get('email')}")
        return user_info
    except HttpError as e:
        logger.error(f"HttpError fetching user info: {e.status_code} {e.reason}")
        # Handle specific errors, e.g., 401 Unauthorized might mean token issue
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching user info: {e}")
        return None

# Example Usage (Illustrative - not meant to be run directly without context)
if __name__ == '__main__':
    # This block is for demonstration/testing purposes only.
    # Replace with actual paths and logic in your application.
    _CLIENT_SECRETS_FILE = 'path/to/your/client_secrets.json' # IMPORTANT: Replace this
    _SCOPES = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/calendar.readonly']
    _TEST_USER_ID = 'test.user@example.com' # Example user

    # --- Flow Initiation Example ---
    # In a real app, this URL would be presented to the user.
    # try:
    #     auth_url, state = start_auth_flow(_CLIENT_SECRETS_FILE, _SCOPES)
    #     print(f"Please go to this URL and authorize: {auth_url}")
    #     print(f"State parameter: {state}") # State needs to be stored/verified in callback
    #     # The application would then wait for the callback...
    # except Exception as e:
    #     print(f"Error starting flow: {e}")


    # --- Callback Handling Example ---
    # This would be triggered by the redirect from Google.
    # callback_url = input("Paste the full callback URL here: ")
    # try:
    #     user_id, creds = handle_auth_callback(_CLIENT_SECRETS_FILE, _SCOPES, callback_url)
    #     print(f"Authentication successful for user: {user_id}")
    #     print(f"Credentials obtained: {creds.token[:10]}...") # Print snippet
    # except Exception as e:
    #     print(f"Error handling callback: {e}")


    # --- Credential Retrieval Example ---
    # This would happen when the application needs to access a Google API.
    # print(f"\nAttempting to retrieve credentials for user: {_TEST_USER_ID}")
    # try:
    #     retrieved_creds = get_credentials(_TEST_USER_ID, _SCOPES, _CLIENT_SECRETS_FILE)
    #     if retrieved_creds and retrieved_creds.valid:
    #         print(f"Successfully retrieved valid credentials for {_TEST_USER_ID}.")
    #         # Example: Use credentials to get user info again
    #         user_data = get_user_info(retrieved_creds)
    #         print(f"User Info: {user_data}")
    #     elif retrieved_creds:
    #         print(f"Retrieved credentials for {_TEST_USER_ID}, but they are not valid (maybe expired and couldn't refresh?).")
    #     else:
    #         print(f"Could not retrieve valid credentials for {_TEST_USER_ID}. Re-authentication needed.")
    # except Exception as e:
    #      print(f"Error retrieving credentials: {e}")

    pass # Keep the example block commented out or remove for production