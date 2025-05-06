"""
Google Workspace MCP Server - Main Entry Point

This module initializes and runs the Google Workspace MCP server with properly registered tools.
"""
import sys
import logging
import asyncio
from core.server import server

# Configure logging for main module
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Explicitly import calendar tools to register them
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
