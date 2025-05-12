# Google Workspace MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server that integrates Google Workspace services with AI assistants and other applications.

## Quick Start

1. **Prerequisites:**
   - Python 3.12+
   - [uv](https://github.com/astral-sh/uv) package installer
   - [Node.js & npm](https://nodejs.org/) (for MCP Inspector)
   - Google Cloud Project with OAuth 2.0 credentials

2. **Installation:**
   ```bash
   git clone https://github.com/your-username/google_workspace_mcp.git
   cd google_workspace_mcp
   uv pip install -e .
   ```

3. **Configuration:**
   - Create OAuth 2.0 credentials in [Google Cloud Console](https://console.cloud.google.com/)
   - Download credentials as `client_secret.json` to project root
   - Add the following redirect URI to your OAuth client in Google Cloud Console:
     ```
     http://localhost:8000/oauth2callback
     ```

4. **Environment Setup:**
   The server uses HTTP for localhost OAuth callbacks in development. Set this environment variable:
   ```bash
   # Allow HTTP for localhost OAuth callbacks (development only)
   export OAUTHLIB_INSECURE_TRANSPORT=1
   ```
   Without this, you'll get an "OAuth 2 MUST utilize HTTPS" error.

5. **Start the Server:**

   Choose one of these methods to run the server:

   ```bash
   # Development mode with Inspector UI
   ./with_inspector.sh

   # OR Production mode (stdin/stdout)
   python main.py

   # OR HTTP mode
   python -c "from core.server import server; server.run(transport='http', port=8000)"

   # OR Using mcpo (recommended for API access)
   mcpo --config config.json
   ```

   **Important Ports:**
   - OAuth Callback: `8000` (handled by MCP custom route)
   - HTTP Mode: `8000` (when running in HTTP mode)
   - mcpo API: `8000` (default when using mcpo)

6. **Connecting to the Server:**

   The server supports multiple connection methods:

   - **Using mcpo (Recommended for OpenAPI Spec Access ie Open WebUI usage)**:
     - Install mcpo: `pip install mcpo` or `uvx mcpo`
     - Run with provided config: `mcpo --config config.json`
     - Access API at: `http://localhost:8000/gworkspace`
     - OpenAPI docs at: `http://localhost:8000/gworkspace/docs`

   - **Direct stdio (for MCP-compatible applications)**:
     - Start server with `python main.py`
     - Application manages server process and communicates via stdin/stdout
     - No network port needed - uses process I/O streams

   - **HTTP Mode**:
     - Start server in HTTP mode
     - Send requests to `http://localhost:8000`
     - Useful for direct HTTP client access

7. **Integration with Open WebUI:**

   To use this server with Open WebUI:

   1. **Create mcpo Configuration:**
      ```json
      {
        "mcpServers": {
          "gworkspace": {
            "command": "uv",
            "args": [
              "--directory",
              "/path/to/google_workspace_mcp",
              "run",
              "main.py"
            ]
          }
        }
      }
      ```
      Save this as `config.json` in your project directory.

   2. **Start the mcpo Server:**
      ```bash
      mcpo --port 8000 --api-key "your-secret-key" --config config.json
      ```
      This exposes your MCP server as an OpenAPI-compatible endpoint.

   3. **Configure Open WebUI:**
      - Go to Open WebUI settings
      - Add a new API endpoint
      - Use URL: `http://localhost:8000/gworkspace`
      - Add your API key if configured
      - The Google Workspace tools will now be available in Open WebUI

8. **First-time Setup:**
   - Start the server using one of the methods above
   - First API call will trigger OAuth flow
   - Browser will open to Google login
   - OAuth callback is handled by the MCP server on port 8000
   - After authorization, server stores credentials for future use

## Features

- OAuth 2.0 authentication with Google APIs
- Google Calendar integration (list calendars, fetch events)
- Both stdio and HTTP transport support
- Extensible design for adding more Google Workspace APIs
- Dynamic port selection for OAuth callback

## Available Tools

### Calendar
- `list_calendars`: Lists user's calendars
- `get_events`: Gets calendar events (requires `calendar_id`, optional `time_min`, `time_max`, `max_results`)

### Authentication
- `start_auth`: Starts OAuth flow (requires `user_id`)
- `auth_status`: Checks auth status (requires `user_id`)
- `complete_auth`: Manual code entry (requires `user_id`, `authorization_code`)

## Development

### Project Structure
```
google_workspace_mcp/
├── core/           # Core MCP server logic
├── auth/           # OAuth handling
├── gcalendar/      # Calendar tools
├── main.py         # Entry point
├── config.json     # mcpo configuration
├── pyproject.toml  # Dependencies
└── with_inspector.sh
```

### Port Handling
The server handles OAuth callbacks through a custom MCP route:
- Uses port 8000 for all OAuth callbacks
- Callback endpoint at /oauth2callback
- Integrated with MCP server's HTTP transport
- Handles credential exchange and storage
- Requires OAUTHLIB_INSECURE_TRANSPORT=1 for HTTP callbacks

### Debugging
- Use MCP Inspector UI (`./with_inspector.sh`)
- Check `mcp_server_debug.log` for detailed logs
- Monitor port assignment in logs when OAuth flow starts
- Verify OAuth setup in Google Cloud Console
- Ensure APIs are enabled in Google Cloud project
- Check OAUTHLIB_INSECURE_TRANSPORT is set if you get HTTPS errors

### Adding New Tools
1. Create tool function in appropriate module
2. Decorate with `@server.tool("tool_name")`
3. Define parameters using type hints
4. Implement logic
5. Import in `main.py`
6. Return results as dictionary

## Security Notes

- Store `client_secret.json` securely (never commit to VCS)
- User tokens stored as `credentials-<user_id_hash>.json`
- Add both files to `.gitignore`
- OAuth callback uses HTTP on localhost only (requires OAUTHLIB_INSECURE_TRANSPORT=1)
- Production deployments should use HTTPS
- When using mcpo, secure your API key and use HTTPS in production

## License

MIT License - see [LICENSE](LICENSE) file