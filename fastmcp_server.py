# ruff: noqa
"""
FastMCP CLI entrypoint for Google Workspace MCP Server.
This file imports all tool modules to register them with the server instance.
Includes full initialization bootstrap that main.py provides.
"""
import logging
import os
import sys
from dotenv import load_dotenv

from auth.oauth_config import reload_oauth_config
from core.log_formatter import EnhancedLogFormatter
from core.utils import check_credentials_directory_permissions
from core.server import server, set_transport_mode, configure_server_for_http
from core.tool_registry import set_enabled_tools as set_enabled_tool_names, wrap_server_tool_method, filter_server_tools
from auth.scopes import set_enabled_tools

# Load environment variables
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(dotenv_path=dotenv_path)

# Suppress googleapiclient discovery cache warning
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

# Reload OAuth configuration after env vars loaded
reload_oauth_config()

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Skip file logging in stateless mode
stateless_mode = os.getenv("WORKSPACE_MCP_STATELESS_MODE", "false").lower() == "true"
if not stateless_mode:
    # Configure file logging
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
else:
    logger.debug("File logging disabled in stateless mode")

def configure_safe_logging():
    """Configure safe Unicode handling for logging."""
    class SafeEnhancedFormatter(EnhancedLogFormatter):
        """Enhanced ASCII formatter with additional Windows safety."""
        def format(self, record):
            try:
                return super().format(record)
            except UnicodeEncodeError:
                # Fallback to ASCII-safe formatting
                service_prefix = self._get_ascii_prefix(record.name, record.levelname)
                safe_msg = str(record.getMessage()).encode('ascii', errors='replace').decode('ascii')
                return f"{service_prefix} {safe_msg}"

    # Replace all console handlers' formatters with safe enhanced ones
    for handler in logging.root.handlers:
        # Only apply to console/stream handlers, keep file handlers as-is
        if isinstance(handler, logging.StreamHandler) and handler.stream.name in ['<stderr>', '<stdout>']:
            safe_formatter = SafeEnhancedFormatter(use_colors=True)
            handler.setFormatter(safe_formatter)

# Configure safe logging
configure_safe_logging()

# Check credentials directory permissions (skip in stateless mode)
if not stateless_mode:
    try:
        logger.info("🔍 Checking credentials directory permissions...")
        check_credentials_directory_permissions()
        logger.info("✅ Credentials directory permissions verified")
    except (PermissionError, OSError) as e:
        logger.error(f"❌ Credentials directory permission check failed: {e}")
        logger.error("   Please ensure the service has write permissions to create/access the credentials directory")
        sys.exit(1)
else:
    logger.info("🔍 Skipping credentials directory check (stateless mode)")

# Set transport mode for HTTP (FastMCP CLI defaults to streamable-http)
set_transport_mode('streamable-http')
configure_server_for_http()

# Import all tool modules to register their @server.tool() decorators
import gmail.gmail_tools
import gdrive.drive_tools
import gcalendar.calendar_tools
import gdocs.docs_tools
import gsheets.sheets_tools
import gchat.chat_tools
import gforms.forms_tools
import gslides.slides_tools
import gtasks.tasks_tools
import gsearch.search_tools

# Configure tool registration
wrap_server_tool_method(server)

# Enable all tools and services by default
all_services = ['gmail', 'drive', 'calendar', 'docs', 'sheets', 'chat', 'forms', 'slides', 'tasks', 'search']
set_enabled_tools(all_services)  # Set enabled services for scopes
set_enabled_tool_names(None)  # Don't filter individual tools - enable all

# Filter tools based on configuration
filter_server_tools(server)

# Export server instance for FastMCP CLI (looks for 'mcp', 'server', or 'app')
mcp = server
app = server