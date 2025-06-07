# Google Workspace MCP Server <img src="https://github.com/user-attachments/assets/b89524e4-6e6e-49e6-ba77-00d6df0c6e5c" width="80" align="right" />

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![UV](https://img.shields.io/badge/Package%20Installer-UV-blueviolet)](https://github.com/astral-sh/uv)

**The world's most feature-complete Google Workspace MCP server**

*Connect AI assistants to Google Calendar, Drive, Gmail, Docs, Sheets, and Chat through the Model Context Protocol*

**See it in action:**
<div align="center">
  <video width="832" src="https://github.com/user-attachments/assets/a342ebb4-1319-4060-a974-39d202329710"></video>
</div>

---

## 🌐 Overview

A production-ready MCP server that integrates all major Google Workspace services with AI assistants. Built with FastMCP for optimal performance, featuring advanced authentication handling, service caching, and streamlined development patterns.


## ✨ Features

- **🔐 Advanced OAuth 2.0**: Secure authentication with automatic token refresh, session management, and service-specific scope handling
- **📅 Google Calendar**: Full calendar management with event CRUD operations
- **📁 Google Drive**: File operations with native Microsoft Office format support (.docx, .xlsx)
- **📧 Gmail**: Complete email management with search, send, and draft capabilities
- **📄 Google Docs**: Document operations including content extraction and creation
- **📊 Google Sheets**: Comprehensive spreadsheet management with flexible cell operations
- **💬 Google Chat**: Space management and messaging capabilities
- **🔄 Multiple Transports**: HTTP with SSE fallback, OpenAPI compatibility via `mcpo`
- **⚡ High Performance**: Service caching, thread-safe sessions, FastMCP integration
- **🧩 Developer Friendly**: Minimal boilerplate, automatic service injection, centralized configuration

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **[uv](https://github.com/astral-sh/uv)** (recommended) or pip
- **Google Cloud Project** with OAuth 2.0 credentials

### Installation

```bash
git clone https://github.com/taylorwilsdon/google_workspace_mcp.git
cd google_workspace_mcp
uv run main.py
```

### Configuration

1. **Google Cloud Setup**:
   - Create OAuth 2.0 credentials (web application) in [Google Cloud Console](https://console.cloud.google.com/)
   - Enable APIs: Calendar, Drive, Gmail, Docs, Sheets, Chat
   - Download credentials as `client_secret.json` in project root
   - Add redirect URI: `http://localhost:8000/oauth2callback`

2. **Environment**:
   ```bash
   export OAUTHLIB_INSECURE_TRANSPORT=1  # Development only
   ```

### Start the Server

```bash
# HTTP mode (recommended)
uv run main.py

# Single-user mode (simplified authentication)
uv run main.py --single-user

# Selective tool registration (only register specific tools)
uv run main.py --tools gmail drive calendar
uv run main.py --tools sheets docs
uv run main.py --single-user --tools gmail  # Can combine with other flags

# Docker
docker build -t google-workspace-mcp .
docker run -p 8000:8000 -v $(pwd):/app google-workspace-mcp
```

**Available Tools for `--tools` flag**: `gmail`, `drive`, `calendar`, `docs`, `sheets`, `chat`

### Connect to Claude Desktop

**Option 1: Auto-install (Recommended)**
```bash
python install_claude.py
```

**Option 2: Manual Configuration**
1. Open Claude Desktop Settings → Developer → Edit Config
2. This creates/opens the config file at:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
3. Add the server configuration:

```json
{
  "mcpServers": {
    "google_workspace": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:8000/mcp"]
    }
  }
}
```

### First-Time Authentication

When calling a tool:
1. Server returns authorization URL
2. Open URL in browser and authorize
3. Server handles OAuth callback automatically
4. Retry the original request

---

## 🧰 Available Tools

> **Note**: All tools support automatic authentication via `@require_google_service()` decorators with 30-minute service caching.

### 📅 Google Calendar ([`calendar_tools.py`](gcalendar/calendar_tools.py))

| Tool | Description |
|------|-------------|
| `list_calendars` | List accessible calendars |
| `get_events` | Retrieve events with time range filtering |
| `create_event` | Create events (all-day or timed) |
| `modify_event` | Update existing events |
| `delete_event` | Remove events |

### 📁 Google Drive ([`drive_tools.py`](gdrive/drive_tools.py))

| Tool | Description |
|------|-------------|
| `search_drive_files` | Search files with query syntax |
| `get_drive_file_content` | Read file content (supports Office formats) |
| `list_drive_items` | List folder contents |
| `create_drive_file` | Create new files |

### 📧 Gmail ([`gmail_tools.py`](gmail/gmail_tools.py))

| Tool | Description |
|------|-------------|
| `search_gmail_messages` | Search with Gmail operators |
| `get_gmail_message_content` | Retrieve message content |
| `send_gmail_message` | Send emails |
| `draft_gmail_message` | Create drafts |

### 📝 Google Docs ([`docs_tools.py`](gdocs/docs_tools.py))

| Tool | Description |
|------|-------------|
| `search_docs` | Find documents by name |
| `get_doc_content` | Extract document text |
| `list_docs_in_folder` | List docs in folder |
| `create_doc` | Create new documents |

### 📊 Google Sheets ([`sheets_tools.py`](gsheets/sheets_tools.py))

| Tool | Description |
|------|-------------|
| `list_spreadsheets` | List accessible spreadsheets |
| `get_spreadsheet_info` | Get spreadsheet metadata |
| `read_sheet_values` | Read cell ranges |
| `modify_sheet_values` | Write/update/clear cells |
| `create_spreadsheet` | Create new spreadsheets |
| `create_sheet` | Add sheets to existing files |

### 💬 Google Chat ([`chat_tools.py`](gchat/chat_tools.py))

| Tool | Description |
|------|-------------|
| `list_spaces` | List chat spaces/rooms |
| `get_messages` | Retrieve space messages |
| `send_message` | Send messages to spaces |
| `search_messages` | Search across chat history |

---

## 🛠️ Development

### Project Structure

```
google_workspace_mcp/
├── auth/              # Authentication system with decorators
├── core/              # MCP server and utilities
├── g{service}/        # Service-specific tools
├── main.py            # Server entry point
├── client_secret.json # OAuth credentials (not committed)
└── pyproject.toml     # Dependencies
```

### Adding New Tools

```python
from auth.service_decorator import require_google_service

@require_google_service("drive", "drive_read")  # Service + scope group
async def your_new_tool(service, param1: str, param2: int = 10):
    """Tool description"""
    # service is automatically injected and cached
    result = service.files().list().execute()
    return result  # Return native Python objects
```

### Architecture Highlights

- **Service Caching**: 30-minute TTL reduces authentication overhead
- **Scope Management**: Centralized in `SCOPE_GROUPS` for easy maintenance
- **Error Handling**: Native exceptions instead of manual error construction
- **Multi-Service Support**: `@require_multiple_services()` for complex tools

---

## 🔒 Security

- **Credentials**: Never commit `client_secret.json` or `.credentials/` directory
- **OAuth Callback**: Uses `http://localhost` for development (requires `OAUTHLIB_INSECURE_TRANSPORT=1`)
- **Production**: Use HTTPS for callback URIs and configure accordingly
- **Network Exposure**: Consider authentication when using `mcpo` over networks
- **Scope Minimization**: Tools request only necessary permissions

---

## 📄 License

MIT License - see `LICENSE` file for details.

---

<div align="center">
<img width="810" alt="Gmail Integration" src="https://github.com/user-attachments/assets/656cea40-1f66-40c1-b94c-5a2c900c969d" />
<img width="810" alt="Calendar Management" src="https://github.com/user-attachments/assets/d3c2a834-fcca-4dc5-8990-6d6dc1d96048" />
<img width="810" alt="Drive Operations" src="https://github.com/user-attachments/assets/7f91aa4e-6763-4dc8-8368-05049aa5c2c7" />
</div>