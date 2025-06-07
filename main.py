import argparse
import logging
import os
import sys

# Local imports
from core.server import server, set_transport_mode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    root_logger = logging.getLogger()
    log_file_dir = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(log_file_dir, 'mcp_server_debug.log')

    file_handler = logging.FileHandler(log_file_path, mode='a')
    file_handler.setLevel(logging.DEBUG)

    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(threadName)s '
        '[%(module)s.%(funcName)s:%(lineno)d] - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)

    logger.debug(f"Detailed file logging configured to: {log_file_path}")
except Exception as e:
    sys.stderr.write(f"CRITICAL: Failed to set up file logging to '{log_file_path}': {e}\n")

def main():
    """
    Main entry point for the Google Workspace MCP server.
    Uses FastMCP's native streamable-http transport.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Google Workspace MCP Server')
    parser.add_argument('--single-user', action='store_true',
                        help='Run in single-user mode - bypass session mapping and use any credentials from ./credentials directory')
    parser.add_argument('--tools', nargs='*',
                        choices=['gmail', 'drive', 'calendar', 'docs', 'sheets', 'chat'],
                        help='Specify which tools to register. If not provided, all tools are registered.')
    parser.add_argument('--transport', choices=['stdio', 'streamable-http'], default='stdio',
                        help='Transport mode: stdio (default) or streamable-http')
    args = parser.parse_args()

    print("🔧 Google Workspace MCP Server")
    print("=" * 35)
    print("📋 Server Information:")
    print(f"   📦 Version: 0.1.1")
    print(f"   🌐 Transport: {args.transport}")
    if args.transport == 'streamable-http':
        print(f"   🔗 URL: http://localhost:{os.getenv('WORKSPACE_MCP_PORT', 8000)}")
        print(f"   🔐 OAuth Callback: http://localhost:{os.getenv('WORKSPACE_MCP_PORT', 8000)}/oauth2callback")
    print(f"   👤 Mode: {'Single-user' if args.single_user else 'Multi-user'}")
    print(f"   🐍 Python: {sys.version.split()[0]}")
    print()

    # Import tool modules to register them with the MCP server via decorators
    tool_imports = {
        'gmail': lambda: __import__('gmail.gmail_tools'),
        'drive': lambda: __import__('gdrive.drive_tools'),
        'calendar': lambda: __import__('gcalendar.calendar_tools'),
        'docs': lambda: __import__('gdocs.docs_tools'),
        'sheets': lambda: __import__('gsheets.sheets_tools'),
        'chat': lambda: __import__('gchat.chat_tools')
    }

    tool_icons = {
        'gmail': '📧',
        'drive': '📁',
        'calendar': '📅',
        'docs': '📄',
        'sheets': '📊',
        'chat': '💬'
    }

    # Import specified tools or all tools if none specified
    tools_to_import = args.tools if args.tools is not None else tool_imports.keys()
    print(f"🛠️  Loading {len(tools_to_import)} tool module{'s' if len(tools_to_import) != 1 else ''}:")
    for tool in tools_to_import:
        tool_imports[tool]()
        print(f"   {tool_icons[tool]} {tool.title()} - Google {tool.title()} API integration")
    print()
    
    print(f"📊 Configuration Summary:")
    print(f"   🔧 Tools Enabled: {len(tools_to_import)}/{len(tool_imports)}")
    print(f"   🔑 Auth Method: OAuth 2.0 with PKCE")
    print(f"   📝 Log Level: {logging.getLogger().getEffectiveLevel()}")
    print()

    # Set global single-user mode flag
    if args.single_user:
        os.environ['MCP_SINGLE_USER_MODE'] = '1'
        print("🔐 Single-user mode enabled")
        print()

    try:
        # Set transport mode for OAuth callback handling
        set_transport_mode(args.transport)
        
        if args.transport == 'streamable-http':
            print("🚀 Starting server on http://localhost:8000")
        else:
            print("🚀 Starting server in stdio mode")
            # Start minimal OAuth callback server for stdio mode
            from auth.oauth_callback_server import ensure_oauth_callback_available
            port = int(os.getenv('WORKSPACE_MCP_PORT', 8000))
            if ensure_oauth_callback_available('stdio', port):
                print(f"   OAuth callback server started on http://localhost:{port}/oauth2callback")
            else:
                print("   ⚠️  Warning: Failed to start OAuth callback server")
        
        print("   Ready for MCP connections!")
        print()
        
        if args.transport == 'streamable-http':
            # The server is already configured with port and server_url in core/server.py
            server.run(transport="streamable-http")
        else:
            server.run()
    except KeyboardInterrupt:
        print("\n👋 Server shutdown requested")
        # Clean up OAuth callback server if running
        from auth.oauth_callback_server import cleanup_oauth_callback_server
        cleanup_oauth_callback_server()
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        logger.error(f"Unexpected error running server: {e}", exc_info=True)
        # Clean up OAuth callback server if running
        from auth.oauth_callback_server import cleanup_oauth_callback_server
        cleanup_oauth_callback_server()
        sys.exit(1)

if __name__ == "__main__":
    main()
