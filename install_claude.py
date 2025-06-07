#!/usr/bin/env python3
"""
Auto-installer for Google Workspace MCP in Claude Desktop
"""

import json
import os
import platform
import sys
from pathlib import Path


def get_claude_config_path():
    """Get the Claude Desktop config file path for the current platform."""
    system = platform.system()
    if system == "Darwin":  # macOS
        return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError("APPDATA environment variable not found")
        return Path(appdata) / "Claude/claude_desktop_config.json"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def main():
    try:
        config_path = get_claude_config_path()
        
        # Create directory if it doesn't exist
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing config or create new one
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {}
        
        # Ensure mcpServers section exists
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        
        # Add Google Workspace MCP server
        config["mcpServers"]["google_workspace"] = {
            "command": "npx",
            "args": ["mcp-remote", "http://localhost:8000/mcp"]
        }
        
        # Write updated config
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Successfully added Google Workspace MCP to Claude Desktop config!")
        print(f"📁 Config file: {config_path}")
        print("\n🚀 Next steps:")
        print("1. Start the MCP server: uv run main.py")
        print("2. Restart Claude Desktop")
        print("3. The Google Workspace tools will be available in your chats!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        print("\n📋 Manual installation:")
        print("1. Open Claude Desktop Settings → Developer → Edit Config")
        print("2. Add the server configuration shown in the README")
        sys.exit(1)


if __name__ == "__main__":
    main()