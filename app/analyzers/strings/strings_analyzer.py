import json
from typing import Dict, Any, List


def extract_ascii_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract ASCII strings from binary data"""
    strings = []
    current_string = []
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            current_string = []
    
    # Don't forget the last string
    if len(current_string) >= min_length:
        strings.append(''.join(current_string))
    
    return strings


def extract_unicode_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract Unicode (UTF-16 LE) strings from binary data"""
    strings = []
    current_string = []
    i = 0
    
    while i < len(data) - 1:
        # Try to read a UTF-16 LE character (little-endian)
        char = data[i]
        next_byte = data[i + 1]
        
        # Check if it's a printable ASCII character in UTF-16 LE format (char, 0x00)
        if 32 <= char <= 126 and next_byte == 0:
            current_string.append(chr(char))
            i += 2
        else:
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            current_string = []
            i += 1
    
    # Don't forget the last string
    if len(current_string) >= min_length:
        strings.append(''.join(current_string))
    
    return strings


def calculate_string_statistics(strings: List[str]) -> Dict[str, Any]:
    """Calculate statistics about the extracted strings"""
    if not strings:
        return {
            'longest_string_length': 0,
            'average_string_length': 0.0
        }
    
    lengths = [len(s) for s in strings]
    
    return {
        'longest_string_length': max(lengths),
        'average_string_length': sum(lengths) / len(lengths)
    }


def extract_strings_metadata(file_path: str, min_length: int = 4, max_strings: int = 10000) -> Dict[str, Any]:
    """
    Extract strings metadata from a file
    
    Args:
        file_path: Path to the file to analyze
        min_length: Minimum string length to extract (default: 4)
        max_strings: Maximum number of strings to store for each type (default: 10000)
    
    Returns:
        Dictionary containing extracted strings and metadata
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Extract ASCII strings
        ascii_strings = extract_ascii_strings(data, min_length)
        
        # Extract Unicode strings
        unicode_strings = extract_unicode_strings(data, min_length)
        
        # Combine all strings for statistics
        all_strings = ascii_strings + unicode_strings
        
        # Calculate statistics
        stats = calculate_string_statistics(all_strings)
        
        # Limit the number of strings stored (to prevent database bloat)
        ascii_strings_limited = ascii_strings[:max_strings]
        unicode_strings_limited = unicode_strings[:max_strings]
        
        # Prepare metadata
        metadata = {
            'ascii_strings': json.dumps(ascii_strings_limited),
            'unicode_strings': json.dumps(unicode_strings_limited),
            'ascii_count': len(ascii_strings),
            'unicode_count': len(unicode_strings),
            'total_count': len(all_strings),
            'min_length': min_length,
            'longest_string_length': stats['longest_string_length'],
            'average_string_length': f"{stats['average_string_length']:.2f}",
        }
        
        return metadata
        
    except Exception as e:
        raise Exception(f"Failed to extract strings metadata: {e}")
