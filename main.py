from core.server import server

if __name__ == "__main__":
    # Run the MCP server using stdio transport
    server.run(transport='stdio')
