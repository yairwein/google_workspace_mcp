# auth/callback_server.py

import http.server
import logging
import socketserver
import threading
import urllib.parse
import webbrowser
from typing import Callable, Optional, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Handler for OAuth callback requests."""
    
    # Class variable to store the callback function
    callback_function: Optional[Callable] = None
    
    def do_GET(self):
        """Handle GET requests to the callback endpoint."""
        try:
            # Parse the URL and extract query parameters
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Check if we're handling the OAuth callback
            if parsed_url.path == '/callback':
                # Extract authorization code and state
                code = query_params.get('code', [''])[0]
                state = query_params.get('state', [''])[0]
                
                logger.info(f"Received OAuth callback with code: {code[:10]}... and state: {state}")
                
                # Show success page to the user
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Google OAuth - Success</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            max-width: 600px;
                            margin: 40px auto;
                            padding: 20px;
                            text-align: center;
                        }
                        .success {
                            color: #4CAF50;
                            font-size: 24px;
                            margin-bottom: 20px;
                        }
                        .info {
                            color: #555;
                            margin-bottom: 30px;
                        }
                        .close-button {
                            background-color: #4CAF50;
                            color: white;
                            padding: 10px 20px;
                            border: none;
                            border-radius: 4px;
                            cursor: pointer;
                            font-size: 16px;
                        }
                    </style>
                </head>
                <body>
                    <div class="success">✅ Authentication Successful!</div>
                    <div class="info">
                        You have successfully authenticated with Google. 
                        You can now close this window and return to your application.
                    </div>
                    <button class="close-button" onclick="window.close()">Close Window</button>
                    <script>
                        // Auto-close after 10 seconds
                        setTimeout(function() {
                            window.close();
                        }, 10000);
                    </script>
                </body>
                </html>
                """
                
                self.wfile.write(html_content.encode())
                
                # Call the callback function if provided
                if OAuthCallbackHandler.callback_function and code:
                    threading.Thread(
                        target=OAuthCallbackHandler.callback_function,
                        args=(code, state),
                        daemon=True
                    ).start()
                
                # Signal the server to shutdown after handling the request
                threading.Thread(
                    target=self.server.shutdown,
                    daemon=True
                ).start()
                
            else:
                # Handle other paths with a 404 response
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                
        except Exception as e:
            logger.error(f"Error handling callback request: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Internal Server Error: {str(e)}".encode())
    
    def log_message(self, format, *args):
        """Override to use our logger instead of printing to stderr."""
        logger.info(f"{self.address_string()} - {format%args}")

class OAuthCallbackServer:
    """Server to handle OAuth callbacks."""
    
    def __init__(self, 
                 port: int = 8080, 
                 callback: Optional[Callable] = None,
                 auto_open_browser: bool = True):
        """
        Initialize the callback server.
        
        Args:
            port: Port to listen on (default: 8080)
            callback: Function to call with the code and state
            auto_open_browser: Whether to automatically open the browser
        """
        self.port = port
        self.server = None
        self.server_thread = None
        self.auto_open_browser = auto_open_browser
        
        # Set the callback function
        OAuthCallbackHandler.callback_function = callback
    
    def start(self) -> None:
        """Start the callback server in a separate thread."""
        if self.server:
            logger.warning("Server is already running")
            return
        
        try:
            # Create and start the server
            self.server = socketserver.TCPServer(('localhost', self.port), OAuthCallbackHandler)
            logger.info(f"Starting OAuth callback server on port {self.port}")
            
            # Run the server in a separate thread
            self.server_thread = threading.Thread(
                target=self.server.serve_forever,
                daemon=True
            )
            self.server_thread.start()
            
            logger.info(f"OAuth callback server is running on http://localhost:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start callback server: {e}")
            raise
    
    def stop(self) -> None:
        """Stop the callback server."""
        if self.server:
            logger.info("Stopping OAuth callback server")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.server_thread = None
        else:
            logger.warning("Server is not running")
    
    def open_browser(self, url: str) -> bool:
        """Open the default web browser to the given URL."""
        if not self.auto_open_browser:
            return False
            
        try:
            logger.info(f"Opening browser to: {url}")
            webbrowser.open(url)
            return True
        except Exception as e:
            logger.error(f"Failed to open browser: {e}")
            return False