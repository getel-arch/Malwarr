import hashlib
import magic
import math
import os
from pathlib import Path
from typing import BinaryIO, Dict, Any, Optional
import json
from datetime import datetime


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


def determine_file_type(mime_type: str, description: str) -> str:
    """Determine file type category"""
    description_lower = description.lower()
    mime_lower = mime_type.lower()
    
    if 'pe32' in description_lower or 'pe64' in description_lower or mime_lower == 'application/x-dosexec':
        return 'pe'
    elif 'elf' in description_lower or mime_lower == 'application/x-executable':
        return 'elf'
    elif 'mach-o' in description_lower:
        return 'macho'
    elif 'script' in description_lower or mime_lower.startswith('text/'):
        return 'script'
    elif 'archive' in description_lower or 'compressed' in description_lower or 'zip' in mime_lower:
        return 'archive'
    elif 'pdf' in mime_lower or 'document' in mime_lower:
        return 'document'
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
