# Google Workspace MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that integrates Google Workspace services like Calendar, Drive, and Gmail with AI assistants and other applications.

## Quick Start

1.  **Prerequisites:**
    *   Python 3.12+
    *   [uv](https://github.com/astral-sh/uv) package installer (or pip)
    *   [Node.js & npm](https://nodejs.org/) (Required only if using the MCP Inspector UI via `with_inspector.sh`)
    *   Google Cloud Project with OAuth 2.0 credentials enabled for required APIs (Calendar, Drive, Gmail).

2.  **Installation:**
    ```bash
    # Clone the repository (replace with the actual URL if different)
    git clone https://github.com/your-username/google_workspace_mcp.git
    cd google_workspace_mcp

    # Create a virtual environment and install dependencies
    uv venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    uv pip install -e .
    ```

3.  **Configuration:**
    *   Create OAuth 2.0 Credentials (Desktop application type) in the [Google Cloud Console](https://console.cloud.google.com/).
    *   Enable the Google Calendar API, Google Drive API, and Gmail API for your project.
    *   Download the OAuth client credentials as `client_secret.json` and place it in the project's root directory.
    *   Add the following redirect URI to your OAuth client configuration in the Google Cloud Console:
        ```
        http://localhost:8000/oauth2callback
        ```
    *   **Important:** Ensure `client_secret.json` is added to your `.gitignore` file and never committed to version control.

4.  **Environment Setup:**
    The server uses HTTP for localhost OAuth callbacks during development. Set this environment variable before running the server:
    ```bash
    # Allow HTTP for localhost OAuth callbacks (development only!)
    export OAUTHLIB_INSECURE_TRANSPORT=1
    ```
    Without this, you might encounter an "OAuth 2 MUST utilize HTTPS" error during the authentication flow.

5.  **Start the Server:**

    Choose one of the following methods to run the server:

    *   **Development Mode with Inspector UI:**
        ```bash
        ./with_inspector.sh
        ```
        This runs the server via `stdio` and launches the MCP Inspector web UI for debugging. Requires Node.js/npm.

    *   **Production Mode (stdio):**
        ```bash
        python main.py
        # or using uv
        uv run main.py
        ```
        This runs the server communicating over `stdin/stdout`, suitable for direct integration with MCP clients that manage the process lifecycle.

    *   **HTTP Mode:**
        ```bash
        python -c "from core.server import server; server.run(transport='http', port=8000)"
        # or using uv
        uv run python -c "from core.server import server; server.run(transport='http', port=8000)"
        ```
        Runs the server with an HTTP transport layer on port 8000.

    *   **Using `mcpo` (Recommended for API Access / Open WebUI):**
        Requires `mcpo` installed (`uv pip install mcpo` or `pip install mcpo`).
        ```bash
        # Ensure config.json points to your project directory
        mcpo --config config.json --port 8000
        ```
        See the `config.json` example in the "Integration with Open WebUI" section.

    **Important Ports:**
    *   OAuth Callback: `8000` (Handled internally by the server via the `/oauth2callback` route)
    *   HTTP Mode Server: `8000` (Default when using HTTP transport)
    *   `mcpo` API Proxy: `8000` (Default port for `mcpo`)

6.  **Connecting to the Server:**

    The server supports multiple connection methods:

    *   **Using `mcpo` (Recommended for OpenAPI Spec Access, e.g., Open WebUI):**
        *   Install `mcpo`: `uv pip install mcpo` or `pip install mcpo`.
        *   Create a `config.json` (see example below).
        *   Run `mcpo` pointing to your config: `mcpo --config config.json --port 8000 [--api-key YOUR_SECRET_KEY]`
        *   The MCP server API will be available at: `http://localhost:8000/gworkspace` (or the name defined in `config.json`).
        *   OpenAPI documentation (Swagger UI) available at: `http://localhost:8000/gworkspace/docs`.

    *   **Direct `stdio` (for MCP-compatible applications):**
        *   Start the server directly: `python main.py` or `uv run main.py`.
        *   The client application is responsible for launching and managing the server process and communicating via `stdin/stdout`.
        *   No network port is used for MCP communication in this mode.

    *   **HTTP Mode:**
        *   Start the server in HTTP mode (see step 5).
        *   Send MCP JSON requests directly to `http://localhost:8000`.
        *   Useful for testing with tools like `curl` or custom HTTP clients.

7.  **Integration with Open WebUI:**

    To use this server as a tool provider within Open WebUI:

    1.  **Create `mcpo` Configuration:**
        Create a file named `config.json` (or choose another name) with the following structure. **Replace `/path/to/google_workspace_mcp` with the actual absolute path to this project directory.**
        ```json
        {
          "mcpServers": {
            "gworkspace": {
              "command": "uv",
              "args": [
                "run",
                "main.py"
              ],
              "options": {
                "cwd": "/path/to/google_workspace_mcp",
                "env": {
                  "OAUTHLIB_INSECURE_TRANSPORT": "1"
                }
              }
            }
          }
        }
        ```
        *Note: Using `uv run main.py` ensures the correct virtual environment is used.*

    2.  **Start the `mcpo` Server:**
        ```bash
        # Make sure OAUTHLIB_INSECURE_TRANSPORT=1 is set in your shell environment
        # OR rely on the 'env' setting in config.json
        export OAUTHLIB_INSECURE_TRANSPORT=1
        mcpo --port 8000 --config config.json --api-key "your-optional-secret-key"
        ```
        This command starts the `mcpo` proxy, which in turn manages the `google_workspace_mcp` server process based on the configuration.

    3.  **Configure Open WebUI:**
        *   Navigate to your Open WebUI settings.
        *   Go to "Connections" -> "Tools".
        *   Click "Add Tool".
        *   Enter the Server URL: `http://localhost:8000/gworkspace` (matching the `mcpo` base URL and server name from `config.json`).
        *   If you used an `--api-key` with `mcpo`, enter it as the API Key.
        *   Save the configuration.
        *   The Google Workspace tools should now be available when interacting with models in Open WebUI.

8.  **First-time Authentication:**
    *   Start the server using one of the methods above.
    *   The first time you call a tool that requires Google API access (e.g., `list_calendars`, `search_drive_files`), the server will detect missing credentials and initiate the OAuth 2.0 flow.
    *   A URL will be printed to the console (or returned in the MCP response). Open this URL in your browser.
    *   Log in to your Google account and grant the requested permissions (Calendar, Drive, Gmail access).
    *   After authorization, Google will redirect your browser to `http://localhost:8000/oauth2callback`.
    *   The running MCP server (or `mcpo` if used) will handle this callback, exchange the authorization code for tokens, and securely store the credentials (e.g., in the `.credentials/your_email@example.com.json` file) for future use.
    *   Subsequent calls for the same user should work without requiring re-authentication until the refresh token expires or is revoked.

## Features

*   **OAuth 2.0 Authentication:** Securely connects to Google APIs using user-authorized credentials. Handles token refresh automatically.
*   **Google Calendar Integration:** List calendars and fetch events.
*   **Google Drive Integration:** Search files, list folder contents, read file content, and create new files.
*   **Gmail Integration:** Search for messages and retrieve message content (including body).
*   **Multiple Transport Options:** Supports `stdio` for direct process integration and `HTTP` for network-based access.
*   **`mcpo` Compatibility:** Easily expose the server as an OpenAPI endpoint using `mcpo` for integration with tools like Open WebUI.
*   **Extensible Design:** Simple structure for adding support for more Google Workspace APIs and tools.
*   **Integrated OAuth Callback:** Handles the OAuth redirect directly within the server on port 8000.

## Available Tools

*(Note: The first use of any tool for a specific Google service may trigger the OAuth authentication flow if valid credentials are not already stored.)*

### Calendar ([`gcalendar/calendar_tools.py`](gcalendar/calendar_tools.py))
*   `start_auth`: Initiates the OAuth flow for Google Calendar access if required.
    *   `user_google_email` (required): The user's Google email address.
*   `list_calendars`: Lists the user's available calendars.
*   `get_events`: Retrieves events from a specified calendar.
    *   `calendar_id` (required): The ID of the calendar (use `primary` for the main calendar).
    *   `time_min` (optional): Start time for events (RFC3339 timestamp, e.g., `2025-05-12T00:00:00Z`).
    *   `time_max` (optional): End time for events (RFC3339 timestamp).
    *   `max_results` (optional): Maximum number of events to return.

### Google Drive ([`gdrive/drive_tools.py`](gdrive/drive_tools.py))
*   [`search_drive_files`](gdrive/drive_tools.py:98): Searches for files and folders across the user's Drive.
    *   `query` (required): Search query string (e.g., `name contains 'report'` or `mimeType='application/vnd.google-apps.document'`). See [Drive Search Query Syntax](https://developers.google.com/drive/api/guides/search-files).
    *   `max_results` (optional): Maximum number of files to return.
*   [`get_drive_file_content`](gdrive/drive_tools.py:184): Retrieves the content of a specific file.
    *   `file_id` (required): The ID of the file.
    *   `mime_type` (optional): Specify the desired export format for Google Docs/Sheets/Slides (e.g., `text/plain`, `application/pdf`). If omitted, attempts a default export or direct download.
*   [`list_drive_items`](gdrive/drive_tools.py:265): Lists files and folders within a specific folder or the root.
    *   `folder_id` (optional): The ID of the folder to list. Defaults to the root ('root') if omitted.
    *   `max_results` (optional): Maximum number of items to return.
*   [`create_drive_file`](gdrive/drive_tools.py:348): Creates a new file in Google Drive.
    *   `name` (required): The desired name for the new file.
    *   `content` (required): The text content to write into the file.
    *   `folder_id` (optional): The ID of the parent folder. Defaults to the root if omitted.
    *   `mime_type` (optional): The MIME type of the file being created (defaults to `text/plain`).

### Gmail ([`gmail/gmail_tools.py`](gmail/gmail_tools.py))
*   [`search_gmail_messages`](gmail/gmail_tools.py:29): Searches for email messages matching a query.
    *   `query` (required): Search query string (e.g., `from:example@domain.com subject:Report is:unread`). See [Gmail Search Query Syntax](https://support.google.com/mail/answer/7190).
    *   `max_results` (optional): Maximum number of message threads to return.
*   [`get_gmail_message_content`](gmail/gmail_tools.py:106): Retrieves the details and body of a specific email message.
    *   `message_id` (required): The ID of the message to retrieve.

## Development

### Project Structure
```
google_workspace_mcp/
├── .venv/             # Virtual environment (created by uv)
├── auth/              # OAuth handling logic (google_auth.py, oauth_manager.py)
├── core/              # Core MCP server logic (server.py)
├── gcalendar/         # Google Calendar tools (calendar_tools.py)
├── gdrive/            # Google Drive tools (drive_tools.py)
├── gmail/             # Gmail tools (gmail_tools.py)
├── .gitignore         # Git ignore file
├── client_secret.json # Google OAuth Credentials (DO NOT COMMIT)
├── config.json        # Example mcpo configuration
├── main.py            # Main server entry point (imports tools)
├── mcp_server_debug.log # Log file for debugging
├── pyproject.toml     # Project metadata and dependencies (for uv/pip)
├── README.md          # This file
├── uv.lock            # uv lock file
└── with_inspector.sh  # Script to run with MCP Inspector
```

### Port Handling for OAuth
The server cleverly handles the OAuth 2.0 redirect URI (`/oauth2callback`) without needing a separate web server framework:
*   It utilizes the built-in HTTP server capabilities of the underlying MCP library when run in HTTP mode or via `mcpo`.
*   A custom MCP route is registered specifically for `/oauth2callback` on port `8000`.
*   When Google redirects the user back after authorization, the MCP server intercepts the request on this route.
*   The `auth` module extracts the authorization code and completes the token exchange.
*   This requires `OAUTHLIB_INSECURE_TRANSPORT=1` to be set when running locally, as the callback uses `http://localhost`.

### Debugging
*   **MCP Inspector:** Use `./with_inspector.sh` to launch the server with a web UI for inspecting MCP messages.
*   **Log File:** Check `mcp_server_debug.log` for detailed logs, including authentication steps and API calls. Enable debug logging if needed.
*   **OAuth Issues:**
    *   Verify `client_secret.json` is correct and present.
    *   Ensure the correct redirect URI (`http://localhost:8000/oauth2callback`) is configured in Google Cloud Console.
    *   Confirm the necessary APIs (Calendar, Drive, Gmail) are enabled in your Google Cloud project.
    *   Check that `OAUTHLIB_INSECURE_TRANSPORT=1` is set in the environment where the server process runs, especially if using `mcpo` or running in a container.
    *   Look for specific error messages during the browser-based OAuth flow.
*   **Tool Errors:** Check the server logs for tracebacks or error messages returned from the Google APIs.

### Adding New Tools
1.  Choose or create the appropriate module (e.g., `gdocs/gdocs_tools.py`).
2.  Import necessary libraries (Google API client library, etc.).
3.  Define an `async` function for your tool logic. Use type hints for parameters.
4.  Decorate the function with `@server.tool("your_tool_name")`.
5.  Inside the function, get authenticated credentials. This typically involves calling `auth.google_auth.get_credentials` within an `asyncio.to_thread` call, for example:
    ```python
    from auth.google_auth import get_credentials, CONFIG_CLIENT_SECRETS_PATH
    # ...
    credentials = await asyncio.to_thread(
        get_credentials,
        user_google_email=your_user_email_variable, # Optional, can be None if session_id is primary
        required_scopes=YOUR_SPECIFIC_SCOPES_LIST,  # e.g., [CALENDAR_READONLY_SCOPE]
        client_secrets_path=CONFIG_CLIENT_SECRETS_PATH,
        session_id=your_mcp_session_id_variable    # Usually injected via Header
    )
    if not credentials or not credentials.valid:
        # Handle missing/invalid credentials, possibly by calling start_auth_flow
        # from auth.google_auth (which is what service-specific start_auth tools do)
        pass
    ```
    `YOUR_SPECIFIC_SCOPES_LIST` should contain the minimum scopes needed for your tool.
6.  Build the Google API service client: `service = build('drive', 'v3', credentials=credentials)`.
7.  Implement the logic to call the Google API.
8.  Handle potential errors gracefully.
9.  Return the results as a JSON-serializable dictionary or list.
10. Import the tool function in [`main.py`](main.py) so it gets registered with the server.
11. Define necessary service-specific scope constants (e.g., `MY_SERVICE_READ_SCOPE`) in your tool's module. The global `SCOPES` list in [`config/google_config.py`](config/google_config.py) is used for the initial OAuth consent screen and should include all possible scopes your server might request. Individual tools should request the minimal `required_scopes` they need when calling `get_credentials`.
12. Update `pyproject.toml` if new dependencies are required.

## Security Notes

*   **`client_secret.json`:** This file contains sensitive credentials. **NEVER** commit it to version control. Ensure it's listed in your `.gitignore` file. Store it securely.
*   **User Tokens:** Authenticated user credentials (refresh tokens) are stored locally in files like `credentials-<user_id_hash>.json`. Protect these files as they grant access to the user's Google account data. Ensure they are also in `.gitignore`.
*   **OAuth Callback Security:** The use of `http://localhost` for the OAuth callback is standard for installed applications during development but requires `OAUTHLIB_INSECURE_TRANSPORT=1`. For production deployments outside of localhost, you **MUST** use HTTPS for the callback URI and configure it accordingly in Google Cloud Console.
*   **`mcpo` Security:** If using `mcpo` to expose the server over the network, consider:
    *   Using the `--api-key` option for basic authentication.
    *   Running `mcpo` behind a reverse proxy (like Nginx or Caddy) to handle HTTPS termination, proper logging, and potentially more robust authentication.
    *   Binding `mcpo` only to trusted network interfaces if exposing it beyond localhost.
*   **Scope Management:** The server requests specific OAuth scopes (permissions) for Calendar, Drive, and Gmail. Users grant access based on these scopes during the initial authentication. Do not request broader scopes than necessary for the implemented tools.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.