import pefile
import json
from typing import Dict, Any, Optional
from datetime import datetime


def extract_pe_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from PE files (exe, dll)"""
    try:
        pe = pefile.PE(file_path)
        
        metadata = {}
        
        # Import hash
        try:
            metadata['imphash'] = pe.get_imphash()
        except:
            metadata['imphash'] = None
        
        # Compilation timestamp
        try:
            timestamp = pe.FILE_HEADER.TimeDateStamp
            metadata['compilation_timestamp'] = datetime.fromtimestamp(timestamp).isoformat()
        except:
            metadata['compilation_timestamp'] = None
        
        # Entry point
        try:
            metadata['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        except:
            metadata['entry_point'] = None
        
        # Sections
        sections = []
        for section in pe.sections:
            sections.append({
                'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': section.get_entropy()
            })
        metadata['sections'] = json.dumps(sections)
        
        # Imports
        imports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    functions = []
                    for imp in entry.imports[:50]:  # Limit to first 50
                        if imp.name:
                            functions.append(imp.name.decode('utf-8', errors='ignore'))
                    imports.append({
                        'dll': dll_name,
                        'functions': functions
                    })
            metadata['imports'] = json.dumps(imports[:20])  # Limit to 20 DLLs
        except:
            metadata['imports'] = None
        
        # Exports
        exports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:100]:  # Limit to 100
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
            metadata['exports'] = json.dumps(exports)
        except:
            metadata['exports'] = None
        
        pe.close()
        return metadata
        
    except Exception as e:
        return {
            'imphash': None,
            'compilation_timestamp': None,
            'entry_point': None,
            'sections': None,
            'imports': None,
            'exports': None
        }
