"""
Google Workspace MCP Server - Main Entry Point

This module initializes and runs the Google Workspace MCP server with properly registered tools.
"""
import sys
import logging
import asyncio
from core.server import server
import os # For path joining if needed, though not strictly for this change

# Configure logging for main module
# This basicConfig sets up console logging.
logging.basicConfig(
    level=logging.INFO, # Console logs at INFO level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
# Get the logger for the main module
logger = logging.getLogger(__name__)

# === ADD FILE LOGGING SETUP ===
try:
    # Get the root logger to add a file handler
    root_logger = logging.getLogger()
    
    # Define log file path (in the same directory as main.py)
    # SCRIPT_DIR is usually where main.py is, from with_inspector.sh context
    # Make log_file_path absolute to ensure it's always in the project directory
    log_file_dir = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(log_file_dir, 'mcp_server_debug.log')
    
    # Create a file handler
    # mode='a' for append, so logs from multiple runs are kept
    file_handler = logging.FileHandler(log_file_path, mode='a')
    
    # Set the logging level for the file handler (e.g., DEBUG for more verbosity in file)
    file_handler.setLevel(logging.DEBUG)
    
    # Create a detailed formatter for the file logs
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(threadName)s [%(module)s.%(funcName)s:%(lineno)d] - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    
    # Add the file handler to the root logger
    root_logger.addHandler(file_handler)
    
    # Log that file logging is active (this will go to both console and file)
    logger.info(f"Detailed file logging configured to: {log_file_path}")
    
except Exception as e:
    # Fallback if file logging setup fails, print to stderr so it's visible
    sys.stderr.write(f"CRITICAL: Failed to set up file logging to '{log_file_path}': {e}\n")
# === END FILE LOGGING SETUP ===

# Explicitly import calendar tools to register them
# This import should happen AFTER logging is fully configured if it also does logging.
import gcalendar.calendar_tools

def main():
    """Main entry point for the MCP server"""
    try:
        logger.info("Google Workspace MCP server starting")
        # Run with no parameters to use the stdio transport
        # that MCP Inspector expects
        server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested via keyboard interrupt")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error running server: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
