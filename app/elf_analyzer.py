from elftools.elf.elffile import ELFFile
import json
import math
from collections import Counter
from typing import Dict, Any


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    
    # Count byte frequencies
    counter = Counter(data)
    length = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


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
                # Get section data for entropy calculation
                section_data = section.data()
                entropy = calculate_entropy(section_data) if section_data else 0.0
                
                # Get section flags
                flags = []
                sh_flags = section['sh_flags']
                if sh_flags & 0x1:  # SHF_WRITE
                    flags.append('W')
                if sh_flags & 0x2:  # SHF_ALLOC
                    flags.append('A')
                if sh_flags & 0x4:  # SHF_EXECINSTR
                    flags.append('X')
                flags_str = ''.join(flags) if flags else '-'
                
                sections.append({
                    'name': section.name,
                    'type': section['sh_type'],
                    'address': hex(section['sh_addr']),
                    'offset': hex(section['sh_offset']),
                    'size': section['sh_size'],
                    'flags': flags_str,
                    'entropy': round(entropy, 2)
                })
            metadata['sections'] = json.dumps(sections)
            
            return metadata
            
    except Exception as e:
        return {
            'machine': None,
            'entry_point': None,
            'sections': None
        }
