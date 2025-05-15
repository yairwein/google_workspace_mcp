<div align="center">

# Google Workspace MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![UV](https://img.shields.io/badge/Package%20Installer-UV-blueviolet)](https://github.com/astral-sh/uv)

**Connect MCP Clients, AI Assistants and more to Google Workspace services through the Model Context Protocol**

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Quick Start](#-quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Start the Server](#start-the-server)
  - [Connecting to the Server](#connecting-to-the-server)
  - [Integration with Open WebUI](#integration-with-open-webui)
  - [First-time Authentication](#first-time-authentication)
- [Available Tools](#-available-tools)
  - [Calendar](#calendar)
  - [Google Drive](#google-drive)
  - [Gmail](#gmail)
  - [Google Docs](#google-docs)
- [Development](#-development)
  - [Project Structure](#project-structure)
  - [Port Handling for OAuth](#port-handling-for-oauth)
  - [Debugging](#debugging)
  - [Adding New Tools](#adding-new-tools)
- [Security Notes](#-security-notes)
- [License](#-license)

---

## 🌐 Overview

The Google Workspace MCP Server integrates Google Workspace services (Calendar, Drive, Gmail, and Docs) with AI assistants and other applications using the Model Context Protocol (MCP). This allows AI systems to access and interact with user data from Google Workspace applications securely and efficiently.

---

## ✨ Features

- **🔐 OAuth 2.0 Authentication**: Securely connects to Google APIs using user-authorized credentials with automatic token refresh
- **📅 Google Calendar Integration**: List calendars and fetch events
- **📁 Google Drive Integration**: Search files, list folder contents, read file content, and create new files
- **📧 Gmail Integration**: Search for messages and retrieve message content (including body)
- **📄 Google Docs Integration**: Search for documents, read document content, list documents in folders, and create new documents
- **🔄 Multiple Transport Options**: Streamable HTTP + SSE fallback
- **🔌 `mcpo` Compatibility**: Easily expose the server as an OpenAPI endpoint for integration with tools like Open WebUI
- **🧩 Extensible Design**: Simple structure for adding support for more Google Workspace APIs and tools
- **🔄 Integrated OAuth Callback**: Handles the OAuth redirect directly within the server on port 8000

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.12+**
- **[uv](https://github.com/astral-sh/uv)** package installer (or pip)
- **Google Cloud Project** with OAuth 2.0 credentials enabled for required APIs (Calendar, Drive, Gmail, Docs)

### Installation

```bash
# Clone the repository (replace with the actual URL if different)
git clone https://github.com/your-username/google_workspace_mcp.git
cd google_workspace_mcp

# Create a virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
uv pip install -e .
```

### Configuration

1. Create **OAuth 2.0 Credentials** (Desktop application type) in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the **Google Calendar API**, **Google Drive API**, **Gmail API**, and **Google Docs API** for your project.
3. Download the OAuth client credentials as `client_secret.json` and place it in the project's root directory.
4. Add the following redirect URI to your OAuth client configuration in the Google Cloud Console. Note that `http://localhost:8000` is the default base URI and port, which can be customized via environment variables (`WORKSPACE_MCP_BASE_URI` and `WORKSPACE_MCP_PORT`). If you change these, you must update the redirect URI in the Google Cloud Console accordingly.
   ```
   http://localhost:8000/oauth2callback
   ```
5. **⚠️ Important**: Ensure `client_secret.json` is added to your `.gitignore` file and never committed to version control.

### Server Configuration

The server's base URL and port can be customized using environment variables:

- `WORKSPACE_MCP_BASE_URI`: Sets the base URI for the server (default: `http://localhost`). This affects the `server_url` used for Gemini native function calling and the `OAUTH_REDIRECT_URI`.
- `WORKSPACE_MCP_PORT`: Sets the port the server listens on (default: `8000`). This affects the `server_url`, `port`, and `OAUTH_REDIRECT_URI`.

Example usage:

```bash
export WORKSPACE_MCP_BASE_URI="https://my-custom-domain.com"
export WORKSPACE_MCP_PORT="9000"
uv run main.py
```

### Environment Setup

The server uses HTTP for localhost OAuth callbacks during development. Set this environment variable before running the server:

```bash
# Allow HTTP for localhost OAuth callbacks (development only!)
export OAUTHLIB_INSECURE_TRANSPORT=1
```

Without this, you might encounter an "OAuth 2 MUST utilize HTTPS" error during the authentication flow.

### Start the Server

Choose one of the following methods to run the server:

<details>
<summary><b>HTTP Server Mode</b></summary>

```bash
python main.py
# or using uv
uv run main.py
```

Runs the server with an HTTP transport layer on port 8000.
</details>

<details>
<summary><b>Using mcpo (Recommended for Open WebUI and other OpenAPI spec compatible clients)</b></summary>

Requires `mcpo` installed (`uv pip install mcpo` or `pip install mcpo`).

```bash
# Ensure config.json points to your project directory
mcpo --config config.json --port 8000
```

See the [Integration with Open WebUI](#integration-with-open-webui) section for a `config.json` example.
</details>

#### Important Ports

The default ports are `8000`, but can be changed via the `WORKSPACE_MCP_PORT` environment variable.

| Service | Default Port | Description |
|---------|------|-------------|
| OAuth Callback | `8000` | Handled internally by the server via the `/oauth2callback` route |
| HTTP Mode Server | `8000` | Default when using HTTP transport |

### Connecting to the Server

The server supports multiple connection methods:

<details>
<summary><b>Using mcpo (Recommended for OpenAPI Spec Access)</b></summary>

1. Install `mcpo`: `uv pip install mcpo` or `pip install mcpo`
2. Create a `config.json` (see [Integration with Open WebUI](#integration-with-open-webui))
3. Run `mcpo` pointing to your config: `mcpo --config config.json --port 8000 [--api-key YOUR_SECRET_KEY]`
4. The MCP server API will be available at: `http://localhost:8000/gworkspace` (or the name defined in `config.json`)
5. OpenAPI documentation (Swagger UI) available at: `http://localhost:8000/gworkspace/docs`
</details>

<summary><b>HTTP Mode</b></summary>

1. Start the server in HTTP mode (see [Start the Server](#start-the-server))
2. Send MCP JSON requests directly to `http://localhost:8000`
3. Useful for testing with tools like `curl` or custom HTTP clients, or derving to Claude via:
```json
{
  "mcpServers": {
    "Google workspace": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://yourendpoint.com:8000/mcp”
      ]
    }
  }
}
```
</details>

### Integration with Open WebUI

To use this server as a tool provider within Open WebUI:

1. **Create `mcpo` Configuration**:
   Create a file named `config.json` with the following structure. **Replace `/path/to/google_workspace_mcp` with the actual absolute path to this project directory.**

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

2. **Start the `mcpo` Server**:
   ```bash
   # Make sure OAUTHLIB_INSECURE_TRANSPORT=1 is set in your shell environment
   # OR rely on the 'env' setting in config.json
   export OAUTHLIB_INSECURE_TRANSPORT=1
   mcpo --port 8000 --config config.json --api-key "your-optional-secret-key"
   ```
   This command starts the `mcpo` proxy, which in turn manages the `google_workspace_mcp` server process based on the configuration.

3. **Configure Open WebUI**:
   - Navigate to your Open WebUI settings
   - Go to "Connections" -> "Tools"
   - Click "Add Tool"
   - Enter the Server URL: `http://localhost:8000/gworkspace` (matching the `mcpo` base URL and server name from `config.json`)
   - If you used an `--api-key` with `mcpo`, enter it as the API Key
   - Save the configuration
   - The Google Workspace tools should now be available when interacting with models in Open WebUI

### First-time Authentication

1. Start the server using one of the methods above
2. The first time you call a tool that requires Google API access (e.g., `list_calendars`, `search_drive_files`), the server will detect missing credentials and initiate the OAuth 2.0 flow
3. A URL will be printed to the console (or returned in the MCP response). Open this URL in your browser
4. Log in to your Google account and grant the requested permissions (Calendar, Drive, Gmail access)
5. After authorization, Google will redirect your browser to `http://localhost:8000/oauth2callback`
6. The running MCP server will handle this callback, exchange the authorization code for tokens, and securely store the credentials for future use
7. Subsequent calls for the same user should work without requiring re-authentication until the refresh token expires or is revoked

---

## 🧰 Available Tools

> **Note**: The first use of any tool for a specific Google service may trigger the OAuth authentication flow if valid credentials are not already stored.

### Calendar

Source: [`gcalendar/calendar_tools.py`](gcalendar/calendar_tools.py)

| Tool | Description | Parameters |
|------|-------------|------------|
| `start_auth` | Initiates the OAuth flow for Google Calendar access | • `user_google_email` (required): The user's Google email address |
| `list_calendars` | Lists the user's available calendars | (None) |
| `get_events` | Retrieves events from a specified calendar | • `calendar_id` (required): The ID of the calendar (use `primary` for the main calendar)<br>• `time_min` (optional): Start time for events (RFC3339 timestamp, e.g., `2025-05-12T00:00:00Z`)<br>• `time_max` (optional): End time for events (RFC3339 timestamp)<br>• `max_results` (optional): Maximum number of events to return |

### Google Drive

Source: [`gdrive/drive_tools.py`](gdrive/drive_tools.py)

| Tool | Description | Parameters |
|------|-------------|------------|
| [`search_drive_files`](gdrive/drive_tools.py:98) | Searches for files and folders across the user's Drive | • `query` (required): Search query string (e.g., `name contains 'report'`)<br>• `max_results` (optional): Maximum number of files to return |
| [`get_drive_file_content`](gdrive/drive_tools.py:184) | Retrieves the content of a specific file | • `file_id` (required): The ID of the file<br>• `mime_type` (optional): Specify the desired export format |
| [`list_drive_items`](gdrive/drive_tools.py:265) | Lists files and folders within a specific folder or the root | • `folder_id` (optional): The ID of the folder to list (defaults to root)<br>• `max_results` (optional): Maximum number of items to return |
| [`create_drive_file`](gdrive/drive_tools.py:348) | Creates a new file in Google Drive | • `name` (required): The desired name for the new file<br>• `content` (required): The text content to write into the file<br>• `folder_id` (optional): The ID of the parent folder<br>• `mime_type` (optional): The MIME type of the file (defaults to `text/plain`) |

> **Query Syntax**: For Google Drive search queries, see [Drive Search Query Syntax](https://developers.google.com/drive/api/guides/search-files)

### Gmail

Source: [`gmail/gmail_tools.py`](gmail/gmail_tools.py)

| Tool | Description | Parameters |
|------|-------------|------------|
| [`search_gmail_messages`](gmail/gmail_tools.py:29) | Searches for email messages matching a query | • `query` (required): Search query string (e.g., `from:example@domain.com subject:Report is:unread`)<br>• `max_results` (optional): Maximum number of message threads to return |
| [`get_gmail_message_content`](gmail/gmail_tools.py:106) | Retrieves the details and body of a specific email message | • `message_id` (required): The ID of the message to retrieve |

> **Query Syntax**: For Gmail search queries, see [Gmail Search Query Syntax](https://support.google.com/mail/answer/7190)

### Google Docs

Source: [`gdocs/docs_tools.py`](gdocs/docs_tools.py)

| Tool | Description | Parameters |
|------|-------------|------------|
| `search_docs` | Searches for Google Docs by name across user's Drive | • `query` (required): Search query string (e.g., `report`)<br>• `user_google_email` (optional): The user's Google email address<br>• `page_size` (optional): Maximum number of documents to return |
| `get_doc_content` | Retrieves the content of a specific Google Doc as plain text | • `document_id` (required): The ID of the document<br>• `user_google_email` (optional): The user's Google email address |
| `list_docs_in_folder` | Lists Google Docs within a specific folder | • `folder_id` (optional): The ID of the folder to list (defaults to root)<br>• `user_google_email` (optional): The user's Google email address<br>• `page_size` (optional): Maximum number of documents to return |
| `create_doc` | Creates a new Google Doc with a title and optional content | • `title` (required): The title for the new document<br>• `content` (optional): Initial text content for the document<br>• `user_google_email` (optional): The user's Google email address |

---

## 🛠️ Development

### Project Structure

```
google_workspace_mcp/
├── .venv/             # Virtual environment (created by uv)
├── auth/              # OAuth handling logic (google_auth.py, oauth_manager.py)
├── core/              # Core MCP server logic (server.py)
├── gcalendar/         # Google Calendar tools (calendar_tools.py)
├── gdocs/             # Google Docs tools (docs_tools.py)
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
```

### Port Handling for OAuth

The server cleverly handles the OAuth 2.0 redirect URI (`/oauth2callback`) without needing a separate web server framework:

- It utilizes the built-in HTTP server capabilities of the underlying MCP library when run in HTTP mode or via `mcpo`
- A custom MCP route is registered specifically for `/oauth2callback` on port `8000`
- When Google redirects the user back after authorization, the MCP server intercepts the request on this route
- The `auth` module extracts the authorization code and completes the token exchange
- This requires `OAUTHLIB_INSECURE_TRANSPORT=1` to be set when running locally, as the callback uses `http://localhost`

### Debugging

<details>
<summary><b>Log File</b></summary>

Check `mcp_server_debug.log` for detailed logs, including authentication steps and API calls. Enable debug logging if needed.
</details>

<details>
<summary><b>OAuth Issues</b></summary>

- Verify `client_secret.json` is correct and present
- Ensure the correct redirect URI (`http://localhost:8000/oauth2callback`) is configured in Google Cloud Console
- Confirm the necessary APIs (Calendar, Drive, Gmail) are enabled in your Google Cloud project
- Check that `OAUTHLIB_INSECURE_TRANSPORT=1` is set in the environment where the server process runs
- Look for specific error messages during the browser-based OAuth flow
</details>

<details>
<summary><b>Tool Errors</b></summary>

Check the server logs for tracebacks or error messages returned from the Google APIs.
</details>

### Adding New Tools

1. Choose or create the appropriate module (e.g., `gdocs/gdocs_tools.py`)
2. Import necessary libraries (Google API client library, etc.)
3. Define an `async` function for your tool logic. Use type hints for parameters
4. Decorate the function with `@server.tool("your_tool_name")`
5. Inside the function, get authenticated credentials:

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

6. Build the Google API service client: `service = build('drive', 'v3', credentials=credentials)`
7. Implement the logic to call the Google API
8. Handle potential errors gracefully
9. Return the results as a JSON-serializable dictionary or list
10. Import the tool function in [`main.py`](main.py) so it gets registered with the server
11. Define necessary service-specific scope constants in your tool's module
12. Update `pyproject.toml` if new dependencies are required

> **Scope Management**: The global `SCOPES` list in [`config/google_config.py`](config/google_config.py) is used for the initial OAuth consent screen. Individual tools should request the minimal `required_scopes` they need when calling `get_credentials`.

---

## 🔒 Security Notes

- **`client_secret.json`**: This file contains sensitive credentials. **NEVER** commit it to version control. Ensure it's listed in your `.gitignore` file. Store it securely.

- **User Tokens**: Authenticated user credentials (refresh tokens) are stored locally in files like `credentials-<user_id_hash>.json`. Protect these files as they grant access to the user's Google account data. Ensure they are also in `.gitignore`.

- **OAuth Callback Security**: The use of `http://localhost` for the OAuth callback is standard for installed applications during development but requires `OAUTHLIB_INSECURE_TRANSPORT=1`. For production deployments outside of localhost, you **MUST** use HTTPS for the callback URI and configure it accordingly in Google Cloud Console.

- **`mcpo` Security**: If using `mcpo` to expose the server over the network, consider:
  - Using the `--api-key` option for basic authentication
  - Running `mcpo` behind a reverse proxy (like Nginx or Caddy) to handle HTTPS termination, proper logging, and more robust authentication
  - Binding `mcpo` only to trusted network interfaces if exposing it beyond localhost

- **Scope Management**: The server requests specific OAuth scopes (permissions) for Calendar, Drive, and Gmail. Users grant access based on these scopes during the initial authentication. Do not request broader scopes than necessary for the implemented tools.

---

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
