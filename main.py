import argparse
import logging
import os
import sys

# Local imports
from core.server import server

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

    logger.info(f"Detailed file logging configured to: {log_file_path}")
except Exception as e:
    sys.stderr.write(f"CRITICAL: Failed to set up file logging to '{log_file_path}': {e}\n")

# Import tool modules to register them with the MCP server via decorators
import gcalendar.calendar_tools
import gdrive.drive_tools
import gmail.gmail_tools
import gdocs.docs_tools
import gchat.chat_tools
import gsheets.sheets_tools


def main():
    """
    Main entry point for the Google Workspace MCP server.
    Uses FastMCP's native streamable-http transport.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Google Workspace MCP Server')
    parser.add_argument('--single-user', action='store_true',
                        help='Run in single-user mode - bypass session mapping and use any credentials from ./credentials directory')
    args = parser.parse_args()

    # Set global single-user mode flag
    if args.single_user:
        os.environ['MCP_SINGLE_USER_MODE'] = '1'
        logger.info("Starting in single-user mode - bypassing session-to-OAuth mapping")

    try:
        logger.info("Google Workspace MCP server starting...")
        # The server is already configured with port and server_url in core/server.py
        server.run(transport="streamable-http")
    except KeyboardInterrupt:
        logger.info("Server shutdown requested via keyboard interrupt")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error running server: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
