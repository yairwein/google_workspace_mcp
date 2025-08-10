# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Development
- `uv run main.py` - Start server in stdio mode (default for MCP clients)
- `uv run main.py --transport streamable-http` - Start server in HTTP mode for debugging
- `uv run main.py --single-user` - Run in single-user mode (bypass session mapping)
- `uv run main.py --tools gmail drive calendar` - Start with specific tools only

### Installation & Setup
- `python install_claude.py` - Auto-install MCP server configuration in Claude Desktop
- `uvx workspace-mcp` - Run directly via uvx without local installation

### Docker
- `docker build -t workspace-mcp .`
- `docker run -p 8000:8000 -v $(pwd):/app workspace-mcp --transport streamable-http`

## Architecture Overview

This is a comprehensive Google Workspace MCP server built with FastMCP. The architecture follows a modular design pattern:

### Core Components
- **`main.py`** - Entry point with argument parsing and tool module loading
- **`core/server.py`** - FastMCP server configuration with OAuth callback handling  
- **`core/utils.py`** - Shared utilities and credential directory management

### Authentication System (`auth/`)
- **Service Decorator Pattern**: Uses `@require_google_service()` decorators for automatic authentication
- **OAuth 2.0 Flow**: Transport-aware callback handling (stdio mode starts minimal HTTP server on port 8000)
- **Service Caching**: 30-minute TTL to reduce authentication overhead
- **Session Management**: Maps OAuth state to MCP session IDs for multi-user support
- **Scope Management**: Centralized scope definitions in `auth/scopes.py` with predefined scope groups

### Service Modules
Each Google service has its own module in `g{service}/` format:
- `gcalendar/` - Google Calendar API integration
- `gdrive/` - Google Drive API with Office format support  
- `gmail/` - Gmail API for email management
- `gdocs/` - Google Docs API operations with full editing support
- `gsheets/` - Google Sheets API with cell operations
- `gforms/` - Google Forms creation and response management
- `gchat/` - Google Chat/Spaces messaging
- `gslides/` - Google Slides presentation management

### Key Patterns
- **Service Injection**: The `@require_google_service(service_name, scope_group)` decorator automatically injects authenticated Google API service objects
- **Multi-Service Support**: Use `@require_multiple_services()` for tools needing multiple Google services
- **Error Handling**: Native Python exceptions are automatically converted to MCP errors
- **Transport Modes**: Supports both stdio (for MCP clients) and streamable-http (for debugging/web interfaces)

### Configuration
- Environment variables: `WORKSPACE_MCP_PORT` (default: 8000), `WORKSPACE_MCP_BASE_URI` (default: http://localhost)
- OAuth credentials: `client_secret.json` in project root or set `GOOGLE_CLIENT_SECRETS` env var
- Single-user mode: Set `MCP_SINGLE_USER_MODE=1` or use `--single-user` flag

### Tool Development
When adding new tools:
1. Use appropriate service decorator: `@require_google_service("service_name", "scope_group")`
2. Service object is automatically injected as first parameter
3. Return native Python objects (automatic JSON serialization)
4. Follow existing naming patterns in scope groups from `auth/scopes.py`
5. Add service configuration to `SERVICE_CONFIGS` in `auth/service_decorator.py`

## Google Docs Editing Capabilities

The Google Docs integration now supports comprehensive document editing through these tools:

### Core Text Operations
- `update_doc_text` - Insert or replace text at specific positions
- `find_and_replace_doc` - Find and replace text throughout the document
- `format_doc_text` - Apply text formatting (bold, italic, underline, font size/family)

### Structural Elements
- `insert_doc_elements` - Add tables, lists, or page breaks
- `insert_doc_image` - Insert images from Google Drive or URLs
- `update_doc_headers_footers` - Modify document headers and footers

### Advanced Operations
- `batch_update_doc` - Execute multiple document operations atomically

### Helper Functions
The `gdocs/docs_helpers.py` module provides utility functions for:
- Building text style objects
- Creating API request structures
- Validating batch operations
- Extracting document text
- Calculating text indices

These tools use the Google Docs API's batchUpdate method for efficient, atomic document modifications. All editing operations require the `docs_write` scope which is already configured in the authentication system.