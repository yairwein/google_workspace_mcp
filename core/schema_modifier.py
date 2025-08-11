"""
Schema modification utilities for context-aware parameter injection
"""

import logging
import functools
import re
import os
from typing import Dict, Any, Callable
from inspect import signature

logger = logging.getLogger(__name__)


def remove_user_email_from_docstring(docstring: str) -> str:
    """
    Remove user_google_email parameter documentation from docstring.
    
    Args:
        docstring: The original function docstring
        
    Returns:
        Modified docstring with user_google_email parameter removed
    """
    if not docstring:
        return docstring
    
    # Pattern to match user_google_email parameter documentation
    # Handles various formats like:
    # - user_google_email (str): The user's Google email address. Required.
    # - user_google_email: Description
    # - user_google_email (str) - Description
    patterns = [
        r'\s*user_google_email\s*\([^)]*\)\s*:\s*[^\n]*\.?\s*(?:Required\.?)?\s*\n?',
        r'\s*user_google_email\s*:\s*[^\n]*\n?',
        r'\s*user_google_email\s*\([^)]*\)\s*-\s*[^\n]*\n?',
    ]
    
    modified_docstring = docstring
    for pattern in patterns:
        modified_docstring = re.sub(pattern, '', modified_docstring, flags=re.MULTILINE)
    
    # Clean up any double newlines that might have been created
    modified_docstring = re.sub(r'\n\s*\n\s*\n', '\n\n', modified_docstring)
    
    return modified_docstring


def inject_user_email(func: Callable) -> Callable:
    """
    Decorator that removes user_google_email parameter from tool schema and docstring
    in multi-user mode (when MCP_SINGLE_USER_MODE != "1").
    
    Args:
        func: The tool function to modify
        
    Returns:
        Modified function with conditional parameter handling
    """
    
    # Check if we're in single-user mode
    is_single_user = os.getenv("MCP_SINGLE_USER_MODE") == "1"
    
    if is_single_user:
        # In single-user mode, return function unchanged
        return func
    
    # In multi-user mode, modify the function
    original_sig = signature(func)
    original_doc = func.__doc__
    
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        # In multi-user mode, get user_google_email from context
        try:
            from fastmcp.server.dependencies import get_fastmcp_context
            context = get_fastmcp_context()
            authenticated_user = context.get_state("authenticated_user_email")
            
            if authenticated_user:
                # Inject user_google_email from authenticated context
                kwargs['user_google_email'] = authenticated_user
                logger.debug(f"Injected user_google_email from context: {authenticated_user}")
            else:
                # No authenticated user in context
                raise ValueError(
                    "Authentication required: No authenticated user found in context. "
                    "Please authenticate first using the appropriate authentication flow."
                )
        except Exception as e:
            logger.error(f"Failed to get authenticated user from context: {e}")
            raise ValueError(
                "Authentication context error: Unable to determine authenticated user. "
                "Please ensure you are properly authenticated."
            )
        
        return await func(*args, **kwargs)
    
    # Create new parameters excluding user_google_email
    new_params = []
    for name, param in original_sig.parameters.items():
        if name != 'user_google_email':
            new_params.append(param)
    
    # Create new signature for schema generation
    new_sig = original_sig.replace(parameters=new_params)
    wrapper.__signature__ = new_sig
    
    # Update annotations to exclude user_google_email
    if hasattr(func, '__annotations__'):
        new_annotations = {k: v for k, v in func.__annotations__.items() if k != 'user_google_email'}
        wrapper.__annotations__ = new_annotations
    
    # Modify docstring to remove user_google_email parameter documentation
    if original_doc:
        wrapper.__doc__ = remove_user_email_from_docstring(original_doc)
    
    return wrapper
