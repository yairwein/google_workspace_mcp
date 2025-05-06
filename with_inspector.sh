#!/bin/bash

# with_inspector.sh - Start Google Workspace MCP server with MCP Inspector
#
# This script automatically:
# 1. Determines the current directory of the script
# 2. Ensures all dependencies are installed
# 3. Starts the server with the MCP Inspector

set -e  # Exit immediately if a command exits with non-zero status

# Get the absolute path of the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"  # Change to script directory

echo "===== Google Workspace MCP with Inspector ====="
echo "Working directory: $SCRIPT_DIR"

# Check for Python 3.12+
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo "$PYTHON_VERSION < 3.12" | bc -l) -eq 1 ]]; then
    echo "Error: Python 3.12 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "✓ Python version: $PYTHON_VERSION"

# Check for uv and install if needed
if ! command -v uv &> /dev/null; then
    echo "Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$PATH"
fi
echo "✓ uv package manager found"

# Check for client_secret.json
if [ ! -f "$SCRIPT_DIR/client_secret.json" ]; then
    echo "Warning: client_secret.json not found in $SCRIPT_DIR."
    echo "You will need to set up Google Cloud credentials for the server to function properly."
    echo "See README.md for instructions on setting up Google Cloud credentials."
    echo ""
fi

# Ensure the package is installed in development mode
echo "Ensuring all dependencies are installed..."
uv pip install -e . --quiet
echo "✓ Dependencies installed"

# Check for npx (Node.js)
if ! command -v npx &> /dev/null; then
    echo "Error: npx is required but not found. Please install Node.js and npm."
    exit 1
fi
echo "✓ Node.js environment found"

# Create core/__init__.py if it doesn't exist
if [ ! -f "$SCRIPT_DIR/core/__init__.py" ]; then
    echo "Creating core/__init__.py"
    echo "# Make the core directory a Python package" > "$SCRIPT_DIR/core/__init__.py"
fi

# Create auth/__init__.py if it doesn't exist
if [ ! -f "$SCRIPT_DIR/auth/__init__.py" ]; then
    echo "Creating auth/__init__.py"
    echo "# Make the auth directory a Python package" > "$SCRIPT_DIR/auth/__init__.py"
fi

# Create gcalendar/__init__.py if it doesn't exist
if [ ! -f "$SCRIPT_DIR/gcalendar/__init__.py" ]; then
    # Check if the directory exists first; if not, it may be using calendar instead
    if [ -d "$SCRIPT_DIR/gcalendar" ]; then
        echo "Creating gcalendar/__init__.py"
        echo "# Make the gcalendar directory a Python package" > "$SCRIPT_DIR/gcalendar/__init__.py"
    elif [ -d "$SCRIPT_DIR/calendar" ] && [ ! -f "$SCRIPT_DIR/calendar/__init__.py" ]; then
        echo "Creating calendar/__init__.py"
        echo "# Make the calendar directory a Python package" > "$SCRIPT_DIR/calendar/__init__.py"
        echo "Warning: Using 'calendar' directory which may conflict with Python's built-in module."
        echo "Consider renaming to 'gcalendar' for better compatibility."
    fi
fi

echo ""
echo "Starting Google Workspace MCP server with MCP Inspector..."
echo "Press Ctrl+C to stop the server."
echo ""

# Start the server with the MCP Inspector
echo "[DEBUG] About to start npx inspector command..."
npx -y @modelcontextprotocol/inspector uv --directory "$SCRIPT_DIR" run main.py
echo "[DEBUG] npx inspector command exited." # This might not be reached if Ctrl+C

# This part will execute if npx is interrupted with Ctrl+C
echo ""
echo "Server stopped."