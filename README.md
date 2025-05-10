# Google Workspace MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server designed to integrate Google Workspace services (like Google Calendar) with AI assistants and other applications.

## Overview

This server acts as a bridge, allowing applications that speak MCP to securely interact with your Google Workspace data via Google's APIs. It handles authentication using OAuth 2.0 and provides tools for accessing services like Google Calendar.

## Features

*   **OAuth 2.0 Authentication:** Securely connects to Google APIs using user-authorized credentials.
*   **Google Calendar Integration:** Provides tools to list calendars and fetch events.
*   **MCP Standard Compliance:** Implements the Model Context Protocol for seamless integration.
*   **Stdio & HTTP Transport:** Supports both standard I/O (for direct integration) and HTTP (for development/testing).
*   **Extensible:** Designed to easily add support for more Google Workspace APIs.

## Prerequisites

Before you begin, ensure you have the following installed:

*   **Python:** Version 3.12 or higher.
*   **uv:** A fast Python package installer and resolver. ([Installation Guide](https://github.com/astral-sh/uv))
*   **Node.js & npm/npx:** Required for using the MCP Inspector tool. ([Download Node.js](https://nodejs.org/))
*   **Google Cloud Project:** You'll need a project set up in the Google Cloud Console with the necessary APIs enabled and OAuth 2.0 credentials configured.

## Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/google_workspace_mcp.git # Replace with the actual repo URL if different
    cd google_workspace_mcp
    ```

2.  **Install Dependencies:**
    Use `uv` to install the project and its dependencies in editable mode. This allows you to make changes to the code and have them reflected immediately without reinstalling.
    ```bash
    uv pip install -e .
    ```
    *Note: Ensure your shell is configured to use the Python version managed by `uv` if you use a version manager like `pyenv`.*

3.  **Configure Google Cloud & OAuth 2.0:**
    *   Go to the [Google Cloud Console](https://console.cloud.google.com/).
    *   Create a new project or select an existing one.
    *   **Enable APIs:** Navigate to "APIs & Services" > "Library" and enable the "Google Calendar API" (and any other Google Workspace APIs you intend to use).
    *   **Configure OAuth Consent Screen:** Go to "APIs & Services" > "OAuth consent screen". Configure it for your application type (likely "External" unless restricted to an organization). Add necessary scopes (e.g., `https://www.googleapis.com/auth/calendar.readonly`).
    *   **Create OAuth Client ID:** Go to "APIs & Services" > "Credentials". Click "Create Credentials" > "OAuth client ID".
        *   Select "Desktop app" as the Application type.
        *   Give it a name (e.g., "MCP Desktop Client").
    *   **Download Credentials:** After creation, download the client secrets JSON file. Rename it to `client_secret.json` and place it in the **root directory** of this project (`google_workspace_mcp/`).
        *   **Important:** This file contains sensitive application credentials. **Do not commit `client_secret.json` to version control.** Add it to your `.gitignore` file if it's not already there.

4.  **Understanding Token Storage:**
    *   `client_secret.json`: Contains your *application's* credentials (client ID and secret) used to identify your application to Google.
    *   `credentials.json` (or similar): When a *user* successfully authenticates via the OAuth flow, the server obtains access and refresh tokens specific to that user. These user tokens are typically stored locally (e.g., in a file named `credentials-<user_id_hash>.json` or similar within the project directory, managed by `auth/oauth_manager.py`).
        *   **Security:** These user credential files are also sensitive and **must not be committed to version control.** Ensure patterns like `credentials-*.json` are included in your `.gitignore`.

## Running the Server

You can run the MCP server in several ways:

### 1. With MCP Inspector (Recommended for Development & Debugging)

The `with_inspector.sh` script simplifies running the server with the MCP Inspector, a graphical tool for testing MCP servers.

Set `OAUTHLIB_INSECURE_TRANSPORT=1` if testing on localhost without https for OAuth to work.

```bash
./with_inspector.sh
```

This script handles dependency checks and starts the server process, instructing the MCP Inspector (run via `npx`) to connect to it using `uv` for execution within the correct environment.

The Inspector UI allows you to:
*   Discover available tools and resources.
*   Execute tools with specific arguments.
*   View results and logs.
*   Test the authentication flow interactively.

### 2. Manual Start with Stdio (Production/Direct Integration)

To run the server using standard input/output, which is how most MCP client applications will connect:

```bash
python main.py
```

The server will listen for MCP messages on stdin and send responses to stdout.

### 3. Manual Start with HTTP (Development/Testing)

To run the server with an HTTP transport layer, useful for testing with tools like `curl` or other HTTP clients:

```bash
python -c "from core.server import server; server.run(transport='http', port=8000)"
```

The server will be accessible at `http://localhost:8000`.

## Authentication Flow & Handling Localhost Redirects

This server uses OAuth 2.0's "Authorization Code Grant" flow for desktop applications.

1.  **Initiation:** When a tool requiring authentication is called (e.g., `list_calendars`) or the `start_auth` tool is explicitly used, the server generates a unique Google authorization URL.
2.  **User Authorization:**
    *   If using `start_auth` or running interactively where possible, the server attempts to automatically open this URL in the user's default web browser.
    *   If automatic opening fails or isn't supported, the URL is provided to the client/user to open manually.
3.  **Google Consent:** The user logs into their Google account (if necessary) and grants the requested permissions (scopes) defined in your Google Cloud Console consent screen.
4.  **Redirection with Code:** After authorization, Google redirects the user's browser back to a specific `redirect_uri`.
    *   **Handling `http://localhost`:** Google requires HTTPS for redirect URIs in production, but allows `http://localhost:<port>` for testing and desktop apps. This server handles this by:
        *   Starting a temporary local HTTP server (see `auth/callback_server.py`) on a predefined port (e.g., 8080).
        *   Constructing the authorization URL with `redirect_uri` set to `http://localhost:<port>/callback` (e.g., `http://localhost:8080/callback`).
        *   **Crucial:** You **must** add this exact `http://localhost:<port>/callback` URI to the "Authorized redirect URIs" list in your OAuth client ID settings within the Google Cloud Console.
    *   The temporary server listens for the callback, extracts the `authorization_code` and `state` parameters from the redirect request.
5.  **Token Exchange:** The server securely exchanges this `authorization_code` (along with the `client_secret.json` credentials) with Google for an `access_token` and a `refresh_token`.
6.  **Token Storage:** The obtained user tokens are stored locally (e.g., `credentials-<user_id_hash>.json`) for future use, managed by the `OAuthManager`. The refresh token allows the server to obtain new access tokens when the current one expires without requiring the user to re-authenticate constantly.
7.  **Completion:** The authentication process is complete, and the original tool request can now proceed using the stored credentials.

### Authentication Tools

*   `start_auth(user_id)`: Initiates the automatic browser-based flow.
*   `auth_status(user_id)`: Checks if valid credentials exist for the user.
*   `complete_auth(user_id, authorization_code)`: Used for manual code entry if the automatic callback fails (requires manually copying the code from the browser's address bar after authorization).

## Debugging

*   **MCP Inspector:** The primary tool for debugging. It shows request/response payloads, tool execution results, and errors. Use `./with_inspector.sh`.
*   **Python Logging:** Increase logging verbosity by adding the following near the start of `main.py` (or configure logging as needed):
    ```python
    import logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # You might want to specifically set levels for libraries like google-auth
    logging.getLogger('google_auth_oauthlib').setLevel(logging.INFO)
    logging.getLogger('googleapiclient').setLevel(logging.INFO)
    ```
*   **Check `client_secret.json`:** Ensure it's present in the project root and correctly configured in Google Cloud Console.
*   **Check Redirect URIs:** Double-check that `http://localhost:<port>/callback` (e.g., `http://localhost:8080/callback`) is listed in your Google Cloud OAuth Client's authorized redirect URIs.
*   **Check Enabled APIs:** Verify the Google Calendar API (and others) are enabled in your Google Cloud project.

## Available Tools

*(Based on the original README)*

### Authentication
*   `start_auth`: Starts automatic OAuth flow. Requires `user_id`.
*   `auth_status`: Checks current auth status. Requires `user_id`.
*   `complete_auth`: Completes flow with manual code. Requires `user_id`, `authorization_code`.
*   `oauth2callback` (Advanced): Low-level handler. Requires `code`, `state`. Optional `redirect_uri`.

### Calendar
*   `list_calendars`: Lists user's calendars. No parameters.
*   `get_events`: Gets events from a calendar. Requires `calendar_id`. Optional `time_min`, `time_max`, `max_results`.

## Development

*   **Project Structure:**
    *   `core/`: Core MCP server logic.
    *   `auth/`: Authentication handling (OAuth flow, token management, callback server).
    *   `gcalendar/`: Google Calendar specific tools.
    *   `main.py`: Main entry point for running the server.
    *   `pyproject.toml`: Project metadata and dependencies.
    *   `with_inspector.sh`: Helper script for running with MCP Inspector.
*   **Adding New Tools:**
    1.  Create the tool function within an appropriate module (e.g., a new `gmail/gmail_tools.py`).
    2.  Decorate it with `@server.tool("your_tool_name")` from `core.server`.
    3.  Define parameters using type hints.
    4.  Implement the logic, potentially using helper functions for API calls and authentication checks.
    5.  Ensure the function is imported so the decorator registers it (e.g., in the module's `__init__.py` or `main.py`).
    6.  Return results as a dictionary.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.