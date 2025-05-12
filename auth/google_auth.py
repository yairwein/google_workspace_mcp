# auth/google_auth.py

import os
import json
import logging
from typing import List, Optional, Tuple, Dict, Any, Callable

from oauthlib.oauth2.rfc6749.errors import InsecureTransportError

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_CREDENTIALS_DIR = ".credentials"
DEFAULT_REDIRECT_URI = "http://localhost:8000/oauth2callback"

# In-memory cache for session credentials
# Maps session_id to Credentials object
# This should be a more robust cache in a production system (e.g., Redis)
_SESSION_CREDENTIALS_CACHE: Dict[str, Credentials] = {}


# --- Helper Functions ---

def _get_user_credential_path(user_google_email: str, base_dir: str = DEFAULT_CREDENTIALS_DIR) -> str:
    """Constructs the path to a user's credential file."""
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
        logger.info(f"Created credentials directory: {base_dir}")
    return os.path.join(base_dir, f"{user_google_email}.json")

def save_credentials_to_file(user_google_email: str, credentials: Credentials, base_dir: str = DEFAULT_CREDENTIALS_DIR):
    """Saves user credentials to a file."""
    creds_path = _get_user_credential_path(user_google_email, base_dir)
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
        logger.info(f"Credentials saved for user {user_google_email} to {creds_path}")
    except IOError as e:
        logger.error(f"Error saving credentials for user {user_google_email} to {creds_path}: {e}")
        raise

def save_credentials_to_session(session_id: str, credentials: Credentials):
    """Saves user credentials to the in-memory session cache."""
    _SESSION_CREDENTIALS_CACHE[session_id] = credentials
    logger.info(f"Credentials saved to session cache for session_id: {session_id}")

def load_credentials_from_file(user_google_email: str, base_dir: str = DEFAULT_CREDENTIALS_DIR) -> Optional[Credentials]:
    """Loads user credentials from a file."""
    creds_path = _get_user_credential_path(user_google_email, base_dir)
    if not os.path.exists(creds_path):
        logger.info(f"No credentials file found for user {user_google_email} at {creds_path}")
        return None

    try:
        with open(creds_path, 'r') as f:
            creds_data = json.load(f)
        credentials = Credentials(
            token=creds_data.get('token'),
            refresh_token=creds_data.get('refresh_token'),
            token_uri=creds_data.get('token_uri'),
            client_id=creds_data.get('client_id'),
            client_secret=creds_data.get('client_secret'),
            scopes=creds_data.get('scopes')
        )
        logger.info(f"Credentials loaded for user {user_google_email} from {creds_path}")
        return credentials
    except (IOError, json.JSONDecodeError, KeyError) as e:
        logger.error(f"Error loading or parsing credentials for user {user_google_email} from {creds_path}: {e}")
        return None

def load_credentials_from_session(session_id: str) -> Optional[Credentials]:
    """Loads user credentials from the in-memory session cache."""
    credentials = _SESSION_CREDENTIALS_CACHE.get(session_id)
    if credentials:
        logger.info(f"Credentials loaded from session cache for session_id: {session_id}")
    else:
        logger.info(f"No credentials found in session cache for session_id: {session_id}")
    return credentials

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
    redirect_uri: str = DEFAULT_REDIRECT_URI
) -> Tuple[str, str]:
    """
    Initiates the OAuth 2.0 flow and returns the authorization URL and state.

    Args:
        client_secrets_path: Path to the Google client secrets JSON file.
        scopes: List of OAuth scopes required.
        redirect_uri: The URI Google will redirect to after authorization.

    Returns:
        A tuple containing the authorization URL and the state parameter.
    """
    try:
        # Allow HTTP for localhost in development
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ:
            logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

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
        
        return authorization_url, state

    except Exception as e:
        logger.error(f"Error starting OAuth flow: {e}")
        # We no longer shut down the server after completing the flow
        # The persistent server will handle multiple auth flows over time
        raise  # Re-raise the exception for the caller to handle

def handle_auth_callback(
    client_secrets_path: str,
    scopes: List[str],
    authorization_response: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    credentials_base_dir: str = DEFAULT_CREDENTIALS_DIR,
    session_id: Optional[str] = None
) -> Tuple[str, Credentials]:
    """
    Handles the callback from Google, exchanges the code for credentials,
    fetches user info, determines user_google_email, saves credentials (file & session),
    and returns them.

    Args:
        client_secrets_path: Path to the Google client secrets JSON file.
        scopes: List of OAuth scopes requested.
        authorization_response: The full callback URL from Google.
        redirect_uri: The redirect URI.
        credentials_base_dir: Base directory for credential files.
        session_id: Optional MCP session ID to associate with the credentials.

    Returns:
        A tuple containing the user_google_email and the obtained Credentials object.

    Raises:
        ValueError: If the state is missing or doesn't match.
        FlowExchangeError: If the code exchange fails.
        HttpError: If fetching user info fails.
    """
    try:
        # Allow HTTP for localhost in development
        if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ:
            logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
            os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

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

        user_google_email = user_info['email']
        logger.info(f"Identified user_google_email: {user_google_email}")

        # Save the credentials to file
        save_credentials_to_file(user_google_email, credentials, credentials_base_dir)

        # If session_id is provided, also save to session cache
        if session_id:
            save_credentials_to_session(session_id, credentials)

        return user_google_email, credentials

    except Exception as e: # Catch specific exceptions like FlowExchangeError if needed
        logger.error(f"Error handling auth callback: {e}")
        raise # Re-raise for the caller

def get_credentials(
    user_google_email: Optional[str], # Can be None if relying on session_id
    required_scopes: List[str],
    client_secrets_path: Optional[str] = None,
    credentials_base_dir: str = DEFAULT_CREDENTIALS_DIR,
    session_id: Optional[str] = None
) -> Optional[Credentials]:
    """
    Retrieves stored credentials, prioritizing session, then file. Refreshes if necessary.
    If credentials are loaded from file and a session_id is present, they are cached in the session.

    Args:
        user_google_email: Optional user's Google email.
        required_scopes: List of scopes the credentials must have.
        client_secrets_path: Path to client secrets, required for refresh if not in creds.
        credentials_base_dir: Base directory for credential files.
        session_id: Optional MCP session ID.

    Returns:
        Valid Credentials object or None.
    """
    credentials: Optional[Credentials] = None
    loaded_from_session = False

    logger.info(f"[get_credentials] Called for user_google_email: '{user_google_email}', session_id: '{session_id}', required_scopes: {required_scopes}")

    if session_id:
        credentials = load_credentials_from_session(session_id)
        if credentials:
            logger.info(f"[get_credentials] Loaded credentials from session for session_id '{session_id}'.")
            loaded_from_session = True

    if not credentials and user_google_email:
        logger.info(f"[get_credentials] No session credentials, trying file for user_google_email '{user_google_email}'.")
        credentials = load_credentials_from_file(user_google_email, credentials_base_dir)
        if credentials and session_id:
            logger.info(f"[get_credentials] Loaded from file for user '{user_google_email}', caching to session '{session_id}'.")
            save_credentials_to_session(session_id, credentials) # Cache for current session

    if not credentials:
        logger.info(f"[get_credentials] No credentials found for user '{user_google_email}' or session '{session_id}'.")
        return None
    
    logger.info(f"[get_credentials] Credentials found. Scopes: {credentials.scopes}, Valid: {credentials.valid}, Expired: {credentials.expired}")

    if not all(scope in credentials.scopes for scope in required_scopes):
        logger.warning(f"[get_credentials] Credentials lack required scopes. Need: {required_scopes}, Have: {credentials.scopes}. User: '{user_google_email}', Session: '{session_id}'")
        return None # Re-authentication needed for scopes
    
    logger.info(f"[get_credentials] Credentials have sufficient scopes. User: '{user_google_email}', Session: '{session_id}'")

    if credentials.valid:
        logger.info(f"[get_credentials] Credentials are valid. User: '{user_google_email}', Session: '{session_id}'")
        return credentials
    elif credentials.expired and credentials.refresh_token:
        logger.info(f"[get_credentials] Credentials expired. Attempting refresh. User: '{user_google_email}', Session: '{session_id}'")
        if not client_secrets_path:
             logger.error("[get_credentials] Client secrets path required for refresh but not provided.")
             return None
        try:
            logger.info(f"[get_credentials] Refreshing token using client_secrets_path: {client_secrets_path}")
            # client_config = load_client_secrets(client_secrets_path) # Not strictly needed if creds have client_id/secret
            credentials.refresh(Request())
            logger.info(f"[get_credentials] Credentials refreshed successfully. User: '{user_google_email}', Session: '{session_id}'")
            
            # Save refreshed credentials
            if user_google_email: # Always save to file if email is known
                save_credentials_to_file(user_google_email, credentials, credentials_base_dir)
            if session_id: # Update session cache if it was the source or is active
                save_credentials_to_session(session_id, credentials)
            return credentials
        except Exception as e:
            logger.error(f"[get_credentials] Error refreshing credentials: {e}. User: '{user_google_email}', Session: '{session_id}'", exc_info=True)
            return None # Failed to refresh
    else:
        logger.warning(f"[get_credentials] Credentials invalid/cannot refresh. Valid: {credentials.valid}, Refresh Token: {credentials.refresh_token is not None}. User: '{user_google_email}', Session: '{session_id}'")
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