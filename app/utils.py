import hashlib
import magic
import math
import os
from pathlib import Path
from typing import BinaryIO, Dict, Any, Optional
import json
from datetime import datetime
import filetype


def calculate_hashes(file_content: bytes) -> Dict[str, str]:
    """Calculate multiple hashes for file content"""
    return {
        'md5': hashlib.md5(file_content).hexdigest(),
        'sha1': hashlib.sha1(file_content).hexdigest(),
        'sha256': hashlib.sha256(file_content).hexdigest(),
        'sha512': hashlib.sha512(file_content).hexdigest(),
    }


def get_file_type_from_magic(file_content: bytes) -> tuple[str, str]:
    """Get MIME type and description from file content"""
    try:
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(file_content)
        
        description_magic = magic.Magic()
        description = description_magic.from_buffer(file_content)
        
        return mime_type, description
    except Exception as e:
        return "application/octet-stream", f"Unknown: {str(e)}"


def determine_file_type(mime_type: str, description: str, file_content: bytes = None) -> str:
    """
    Determine file type category using filetype package for dynamic detection
    
    Args:
        mime_type: MIME type from python-magic
        description: File description from python-magic
        file_content: Optional raw file bytes for filetype package detection
    
    Returns:
        File type category string: 'pe', 'elf', 'macho', 'script', 'archive', 'document', 'other'
    """
    description_lower = description.lower()
    mime_lower = mime_type.lower()
    
    # Try filetype package first if file_content is provided (more accurate)
    if file_content:
        kind = filetype.guess(file_content)
        if kind is not None:
            # Map filetype categories to our file types
            if kind.mime.startswith('application/x-executable') or kind.mime == 'application/x-dosexec':
                # Check if it's PE or ELF based on description
                if 'pe32' in description_lower or 'pe64' in description_lower or 'pe' in description_lower:
                    return 'pe'
                elif 'elf' in description_lower:
                    return 'elf'
                elif 'mach-o' in description_lower:
                    return 'macho'
            
            # Archive types
            if kind.mime in [
                'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
                'application/x-tar', 'application/gzip', 'application/x-bzip2', 'application/x-xz'
            ]:
                return 'archive'
            
            # Documents
            if kind.mime.startswith('application/pdf') or kind.mime.startswith('application/msword') or \
               kind.mime.startswith('application/vnd.openxmlformats-officedocument'):
                return 'document'
            
            # Scripts/text
            if kind.mime.startswith('text/'):
                return 'script'
    
    # Fallback to python-magic based detection
    # PE executables
    if 'pe32' in description_lower or 'pe64' in description_lower or mime_lower == 'application/x-dosexec':
        return 'pe'
    
    # ELF executables
    elif 'elf' in description_lower or mime_lower == 'application/x-executable':
        return 'elf'
    
    # Mach-O executables
    elif 'mach-o' in description_lower:
        return 'macho'
    
    # Scripts
    elif 'script' in description_lower or mime_lower.startswith('text/'):
        return 'script'
    
    # Archives - comprehensive check
    elif (
        'archive' in description_lower or 
        'compressed' in description_lower or 
        'zip' in mime_lower or 
        'zip' in description_lower or
        'rar' in mime_lower or 
        'rar' in description_lower or
        '7-zip' in description_lower or
        'x-7z' in mime_lower or
        'tar' in mime_lower or
        'gzip' in mime_lower or
        'bzip' in mime_lower
    ):
        return 'archive'
    
    # Documents
    elif 'pdf' in mime_lower or 'document' in mime_lower:
        return 'document'
    
    # Default
    else:
        return 'other'


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    entropy = 0.0
    byte_counts = [0] * 256
    
    for byte in data:
        byte_counts[byte] += 1
    
    data_len = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / data_len
        entropy -= probability * math.log2(probability)
    
    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> int:
    """Extract and count printable strings from binary data"""
    strings = []
    current_string = []
    
    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                strings.append(''.join(current_string))
            current_string = []
    
    if len(current_string) >= min_length:
        strings.append(''.join(current_string))
    
    return len(strings)


def get_storage_path(sha512: str) -> str:
    """Generate storage path based on SHA512 hash"""
    # Use first 2 chars for first level, next 2 for second level
    # This prevents too many files in a single directory
    return f"{sha512[:2]}/{sha512[2:4]}/{sha512}"
