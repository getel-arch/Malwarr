from elftools.elf.elffile import ELFFile
import json
from typing import Dict, Any


def extract_elf_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from ELF files"""
    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)
            
            metadata = {}
            
            # Machine architecture
            metadata['machine'] = elf.get_machine_arch()
            
            # Entry point
            metadata['entry_point'] = hex(elf.header['e_entry'])
            
            # Sections
            sections = []
            for section in elf.iter_sections():
                sections.append({
                    'name': section.name,
                    'type': section['sh_type'],
                    'address': hex(section['sh_addr']),
                    'size': section['sh_size']
                })
            metadata['sections'] = json.dumps(sections)
            
            return metadata
            
    except Exception as e:
        return {
            'machine': None,
            'entry_point': None,
            'sections': None
        }
