"""
Google Docs Helper Functions

This module provides utility functions for common Google Docs operations
to simplify the implementation of document editing tools.
"""
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

def build_text_style(
    bold: bool = None,
    italic: bool = None,
    underline: bool = None,
    font_size: int = None,
    font_family: str = None
) -> tuple[Dict[str, Any], List[str]]:
    """
    Build text style object for Google Docs API requests.
    
    Args:
        bold: Whether text should be bold
        italic: Whether text should be italic
        underline: Whether text should be underlined
        font_size: Font size in points
        font_family: Font family name
    
    Returns:
        Tuple of (text_style_dict, list_of_field_names)
    """
    text_style = {}
    fields = []
    
    if bold is not None:
        text_style['bold'] = bold
        fields.append('bold')
    
    if italic is not None:
        text_style['italic'] = italic
        fields.append('italic')
    
    if underline is not None:
        text_style['underline'] = underline
        fields.append('underline')
    
    if font_size is not None:
        text_style['fontSize'] = {'magnitude': font_size, 'unit': 'PT'}
        fields.append('fontSize')
    
    if font_family is not None:
        text_style['fontFamily'] = font_family
        fields.append('fontFamily')
    
    return text_style, fields

def create_insert_text_request(index: int, text: str) -> Dict[str, Any]:
    """
    Create an insertText request for Google Docs API.
    
    Args:
        index: Position to insert text
        text: Text to insert
    
    Returns:
        Dictionary representing the insertText request
    """
    return {
        'insertText': {
            'location': {'index': index},
            'text': text
        }
    }

def create_delete_range_request(start_index: int, end_index: int) -> Dict[str, Any]:
    """
    Create a deleteContentRange request for Google Docs API.
    
    Args:
        start_index: Start position of content to delete
        end_index: End position of content to delete
    
    Returns:
        Dictionary representing the deleteContentRange request
    """
    return {
        'deleteContentRange': {
            'range': {
                'startIndex': start_index,
                'endIndex': end_index
            }
        }
    }

def create_format_text_request(
    start_index: int, 
    end_index: int,
    bold: bool = None,
    italic: bool = None,
    underline: bool = None,
    font_size: int = None,
    font_family: str = None
) -> Optional[Dict[str, Any]]:
    """
    Create an updateTextStyle request for Google Docs API.
    
    Args:
        start_index: Start position of text to format
        end_index: End position of text to format
        bold: Whether text should be bold
        italic: Whether text should be italic
        underline: Whether text should be underlined
        font_size: Font size in points
        font_family: Font family name
    
    Returns:
        Dictionary representing the updateTextStyle request, or None if no styles provided
    """
    text_style, fields = build_text_style(bold, italic, underline, font_size, font_family)
    
    if not text_style:
        return None
    
    return {
        'updateTextStyle': {
            'range': {
                'startIndex': start_index,
                'endIndex': end_index
            },
            'textStyle': text_style,
            'fields': ','.join(fields)
        }
    }

def create_find_replace_request(
    find_text: str, 
    replace_text: str, 
    match_case: bool = False
) -> Dict[str, Any]:
    """
    Create a replaceAllText request for Google Docs API.
    
    Args:
        find_text: Text to find
        replace_text: Text to replace with
        match_case: Whether to match case exactly
    
    Returns:
        Dictionary representing the replaceAllText request
    """
    return {
        'replaceAllText': {
            'containsText': {
                'text': find_text,
                'matchCase': match_case
            },
            'replaceText': replace_text
        }
    }

def create_insert_table_request(index: int, rows: int, columns: int) -> Dict[str, Any]:
    """
    Create an insertTable request for Google Docs API.
    
    Args:
        index: Position to insert table
        rows: Number of rows
        columns: Number of columns
    
    Returns:
        Dictionary representing the insertTable request
    """
    return {
        'insertTable': {
            'location': {'index': index},
            'rows': rows,
            'columns': columns
        }
    }

def create_insert_page_break_request(index: int) -> Dict[str, Any]:
    """
    Create an insertPageBreak request for Google Docs API.
    
    Args:
        index: Position to insert page break
    
    Returns:
        Dictionary representing the insertPageBreak request
    """
    return {
        'insertPageBreak': {
            'location': {'index': index}
        }
    }

def create_insert_image_request(
    index: int, 
    image_uri: str,
    width: int = None,
    height: int = None
) -> Dict[str, Any]:
    """
    Create an insertInlineImage request for Google Docs API.
    
    Args:
        index: Position to insert image
        image_uri: URI of the image (Drive URL or public URL)
        width: Image width in points
        height: Image height in points
    
    Returns:
        Dictionary representing the insertInlineImage request
    """
    request = {
        'insertInlineImage': {
            'location': {'index': index},
            'uri': image_uri
        }
    }
    
    # Add size properties if specified
    object_size = {}
    if width is not None:
        object_size['width'] = {'magnitude': width, 'unit': 'PT'}
    if height is not None:
        object_size['height'] = {'magnitude': height, 'unit': 'PT'}
    
    if object_size:
        request['insertInlineImage']['objectSize'] = object_size
    
    return request

def create_bullet_list_request(
    start_index: int, 
    end_index: int,
    list_type: str = "UNORDERED"
) -> Dict[str, Any]:
    """
    Create a createParagraphBullets request for Google Docs API.
    
    Args:
        start_index: Start of text range to convert to list
        end_index: End of text range to convert to list
        list_type: Type of list ("UNORDERED" or "ORDERED")
    
    Returns:
        Dictionary representing the createParagraphBullets request
    """
    bullet_preset = (
        'BULLET_DISC_CIRCLE_SQUARE' 
        if list_type == "UNORDERED" 
        else 'NUMBERED_DECIMAL_ALPHA_ROMAN'
    )
    
    return {
        'createParagraphBullets': {
            'range': {
                'startIndex': start_index,
                'endIndex': end_index
            },
            'bulletPreset': bullet_preset
        }
    }

def validate_operation(operation: Dict[str, Any]) -> tuple[bool, str]:
    """
    Validate a batch operation dictionary.
    
    Args:
        operation: Operation dictionary to validate
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    op_type = operation.get('type')
    if not op_type:
        return False, "Missing 'type' field"
    
    # Validate required fields for each operation type
    required_fields = {
        'insert_text': ['index', 'text'],
        'delete_text': ['start_index', 'end_index'],
        'replace_text': ['start_index', 'end_index', 'text'],
        'format_text': ['start_index', 'end_index'],
        'insert_table': ['index', 'rows', 'columns'],
        'insert_page_break': ['index'],
        'find_replace': ['find_text', 'replace_text']
    }
    
    if op_type not in required_fields:
        return False, f"Unsupported operation type: {op_type}"
    
    for field in required_fields[op_type]:
        if field not in operation:
            return False, f"Missing required field: {field}"
    
    return True, ""

def extract_document_text_simple(doc_data: Dict[str, Any]) -> str:
    """
    Extract plain text from a Google Docs document structure.
    Simplified version that handles basic text extraction.
    
    Args:
        doc_data: Document data from Google Docs API
    
    Returns:
        Plain text content of the document
    """
    def extract_from_elements(elements):
        text_parts = []
        for element in elements:
            if 'paragraph' in element:
                paragraph = element['paragraph']
                para_elements = paragraph.get('elements', [])
                for pe in para_elements:
                    text_run = pe.get('textRun', {})
                    if 'content' in text_run:
                        text_parts.append(text_run['content'])
            elif 'table' in element:
                table = element['table']
                for row in table.get('tableRows', []):
                    for cell in row.get('tableCells', []):
                        cell_content = cell.get('content', [])
                        text_parts.append(extract_from_elements(cell_content))
        return ''.join(text_parts)
    
    # Extract from main document body
    body_elements = doc_data.get('body', {}).get('content', [])
    return extract_from_elements(body_elements)

def calculate_text_indices(text: str, target_text: str, occurrence: int = 1) -> tuple[int, int]:
    """
    Calculate start and end indices for a text occurrence in a document.
    
    Args:
        text: Full document text
        target_text: Text to find indices for
        occurrence: Which occurrence to find (1-based)
    
    Returns:
        Tuple of (start_index, end_index) or (-1, -1) if not found
    """
    if occurrence < 1:
        return -1, -1
    
    start_pos = 0
    for i in range(occurrence):
        pos = text.find(target_text, start_pos)
        if pos == -1:
            return -1, -1
        start_pos = pos + 1
        if i == occurrence - 1:  # Found the target occurrence
            return pos, pos + len(target_text)
    
    return -1, -1