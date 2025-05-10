# auth/callback_server.py

import http.server
import logging
import os
import socketserver
import threading
import urllib.parse
import webbrowser
from typing import Callable, Optional, Dict, Any, Literal

from oauthlib.oauth2.rfc6749.errors import InsecureTransportError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_response_html(
    title: str,
    status: Literal["success", "error"],
    message: str,
    show_close_button: bool = True,
    auto_close_seconds: int = 0
) -> str:
    """Generate HTML response for OAuth callback.
    
    Args:
        title: Page title
        status: 'success' or 'error'
        message: Message to display to the user
        show_close_button: Whether to show a close button
        auto_close_seconds: Auto-close after this many seconds (0 to disable)
    
    Returns:
        HTML content as a string
    """
    icon = "✅" if status == "success" else "⚠️"
    color = "#4CAF50" if status == "success" else "#d32f2f"
    
    close_button = """
    <button class="button" onclick="window.close()">Close Window</button>
    """ if show_close_button else ""
    
    auto_close_script = f"""
    <script>
        setTimeout(function() {{ window.close(); }}, {auto_close_seconds * 1000});
    </script>
    """ if auto_close_seconds > 0 else ""
    
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            max-width: 500px;
            margin: 40px auto;
            padding: 20px;
            text-align: center;
            color: #333;
        }}
        .status {{
            color: {color};
            font-size: 24px;
            margin-bottom: 20px;
        }}
        .message {{
            margin-bottom: 30px;
            line-height: 1.5;
        }}
        .button {{
            background-color: {color};
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }}
    </style>
</head>
<body>
    <div class="status">{icon} {title}</div>
    <div class="message">{message}</div>
    {close_button}
    {auto_close_script}
</body>
</html>"""

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """Handler for OAuth callback requests."""
    
    # Class variables to store callback functions by state
    callback_registry: Dict[str, Callable] = {}
    
    @classmethod
    def register_callback(cls, state: str, callback: Callable) -> None:
        """Register a callback function for a specific state parameter."""
        logger.info(f"Registering callback for state: {state}")
        cls.callback_registry[state] = callback
    
    @classmethod
    def unregister_callback(cls, state: str) -> None:
        """Unregister a callback function for a specific state parameter."""
        if state in cls.callback_registry:
            logger.info(f"Unregistering callback for state: {state}")
            del cls.callback_registry[state]
    
    def do_GET(self):
        """Handle GET requests to the callback endpoint."""
        request_thread_id = threading.get_ident()
        logger.info(f"[Handler {request_thread_id}] GET request received for path: {self.path}")
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
                
                html_content = get_response_html(
                    title="Authentication Successful",
                    status="success",
                    message="You have successfully authenticated with Google. You can now close this window and return to your application.",
                    show_close_button=True,
                    auto_close_seconds=10
                )
                
                self.wfile.write(html_content.encode())
                
                try:
                    # Ensure OAUTHLIB_INSECURE_TRANSPORT is set
                    if 'OAUTHLIB_INSECURE_TRANSPORT' not in os.environ:
                        logger.warning("OAUTHLIB_INSECURE_TRANSPORT not set. Setting it for localhost development.")
                        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

                    # Call the appropriate callback function based on state
                    if state in OAuthCallbackHandler.callback_registry and code:
                        logger.info(f"[Handler {request_thread_id}] Found callback for state: {state}")
                        callback_function = OAuthCallbackHandler.callback_registry[state]
                        logger.info(f"[Handler {request_thread_id}] Preparing to call callback function in new thread.")
                        callback_thread = threading.Thread(
                            target=callback_function,
                            args=(code, state),
                            daemon=True
                        )
                        callback_thread.start()
                        logger.info(f"[Handler {request_thread_id}] Callback function thread started (ID: {callback_thread.ident}).")
                        
                        # Unregister the callback after it's been called
                        OAuthCallbackHandler.unregister_callback(state)
                    else:
                        logger.warning(f"[Handler {request_thread_id}] No callback registered for state: {state} or no code received.")
                except InsecureTransportError as e:
                    logger.error(f"[Handler {request_thread_id}] InsecureTransportError: {e}. Ensure OAUTHLIB_INSECURE_TRANSPORT is set for localhost development.")
                    self.send_response(400)
                    self.send_header('Content-Type', 'text/html')
                    self.end_headers()
                    error_html = get_response_html(
                        title="OAuth Error: Insecure Transport",
                        status="error",
                        message="The OAuth flow requires HTTPS or explicit allowance of HTTP for localhost development. Please ensure OAUTHLIB_INSECURE_TRANSPORT is set in your environment.",
                        show_close_button=False
                    )
                    self.wfile.write(error_html.encode())
                    return

                    # Note: We no longer shut down the server after handling a callback
                    # This allows it to handle multiple auth flows over time

            else:
                # Handle other paths with a 404 response
                self.send_response(404)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                error_html = get_response_html(
                    title="Not Found",
                    status="error",
                    message="The requested resource was not found.",
                    show_close_button=False
                )
                self.wfile.write(error_html.encode())
                
        except Exception as e:
            logger.error(f"[Handler {request_thread_id}] Error handling callback request: {e}", exc_info=True)
            try:
                self.send_response(500)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                error_html = get_response_html(
                    title="Internal Server Error",
                    status="error",
                    message=f"An error occurred while processing your request: {str(e)}",
                    show_close_button=False
                )
                self.wfile.write(error_html.encode())
            except Exception as send_error:
                logger.error(f"[Handler {request_thread_id}] Error sending 500 response: {send_error}")
    
    def log_message(self, format, *args):
        """Override to use our logger instead of printing to stderr."""
        logger.info(f"{self.address_string()} - {format%args}")

class OAuthCallbackServer:
    """Server to handle OAuth callbacks."""
    
    def __init__(self,
                 port: int = 8080,
                 auto_open_browser: bool = True):
        """
        Initialize the callback server.
        
        Args:
            port: Port to listen on (default: 8080)
            auto_open_browser: Whether to automatically open the browser
        """
        self.port = port
        self.server = None
        self.server_thread = None
        self.auto_open_browser = auto_open_browser
    
    def start(self) -> Dict[str, Any]:
        """
        Start the callback server in a separate thread.
        
        Returns:
            Dict containing server status and port information:
            {
                'success': bool,
                'port': int,
                'message': str
            }
        """
        if self.server:
            logger.warning("Server is already running")
            return {'success': False, 'port': self.port, 'message': 'Server is already running'}
        
        original_port = self.port
        max_port = 8090  # Try ports 8080-8090
        
        def serve():
            thread_id = threading.get_ident()
            logger.info(f"[Server Thread {thread_id}] Starting serve_forever loop.")
            try:
                self.server.serve_forever()
            except Exception as serve_e:
                logger.error(f"[Server Thread {thread_id}] Exception in serve_forever: {serve_e}", exc_info=True)
            finally:
                logger.info(f"[Server Thread {thread_id}] serve_forever loop finished.")
                # Ensure server_close is called even if shutdown wasn't clean
                try:
                    if self.server:
                        self.server.server_close()
                except Exception as close_e:
                    logger.error(f"[Server Thread {thread_id}] Error during server_close: {close_e}")

        try:
            while self.port <= max_port:
                try:
                    # Create and start the server
                    self.server = socketserver.TCPServer(('localhost', self.port), OAuthCallbackHandler)
                    logger.info(f"Starting OAuth callback server on port {self.port}")
                    
                    if self.port != original_port:
                        logger.info(f"Successfully reassigned from port {original_port} to {self.port}")
                    
                    # Start the server thread
                    self.server_thread = threading.Thread(target=serve, daemon=True)
                    self.server_thread.start()
                    
                    logger.info(f"OAuth callback server thread started (ID: {self.server_thread.ident}) on http://localhost:{self.port}")
                    
                    return {
                        'success': True,
                        'port': self.port,
                        'message': f"Server started successfully on port {self.port}"
                    }
                    
                except OSError as e:
                    if e.errno == 48:  # Address already in use
                        logger.warning(f"Port {self.port} is already in use, trying next port")
                        self.port += 1
                        if self.port > max_port:
                            error_msg = f"Failed to find available port in range {original_port}-{max_port}"
                            logger.error(error_msg)
                            return {'success': False, 'port': None, 'message': error_msg}
                        continue
                    else:
                        logger.error(f"Failed to start server: {e}")
                        return {'success': False, 'port': None, 'message': str(e)}
                    
        except Exception as e:
            error_msg = f"Failed to start callback server: {e}"
            logger.error(error_msg)
            return {'success': False, 'port': None, 'message': error_msg}
    
    def stop(self) -> None:
        """Stop the callback server."""
        if self.server:
            logger.info("Stopping OAuth callback server")
            # shutdown() signals serve_forever to stop
            self.server.shutdown()
            logger.info("Server shutdown() called.")
            # Wait briefly for the server thread to finish
            if self.server_thread:
                self.server_thread.join(timeout=2.0) # Wait up to 2 seconds
                if self.server_thread.is_alive():
                    logger.warning("Server thread did not exit cleanly after shutdown.")
            # server_close() is now called in the 'finally' block of the serve() function
            self.server = None
            self.server_thread = None
            logger.info("Server resources released.")
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