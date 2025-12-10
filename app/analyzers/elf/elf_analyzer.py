from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.segments import InterpSegment
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
            
            # Header information
            header = elf.header
            metadata['machine'] = elf.get_machine_arch()
            metadata['entry_point'] = hex(header['e_entry'])
            metadata['file_class'] = header['e_ident']['EI_CLASS']  # 32-bit or 64-bit
            metadata['data_encoding'] = header['e_ident']['EI_DATA']  # Endianness
            metadata['os_abi'] = header['e_ident']['EI_OSABI']
            metadata['abi_version'] = header['e_ident']['EI_ABIVERSION']
            metadata['type'] = header['e_type']
            metadata['version'] = header['e_version']
            metadata['flags'] = hex(header['e_flags'])
            metadata['header_size'] = header['e_ehsize']
            metadata['program_header_offset'] = hex(header['e_phoff'])
            metadata['section_header_offset'] = hex(header['e_shoff'])
            metadata['program_header_entry_size'] = header['e_phentsize']
            metadata['program_header_count'] = header['e_phnum']
            metadata['section_header_entry_size'] = header['e_shentsize']
            metadata['section_header_count'] = header['e_shnum']
            
            # Sections - handle corrupted/missing string tables
            sections = []
            try:
                for i in range(elf.num_sections()):
                    try:
                        section = elf.get_section(i)
                        
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
                        
                        # Try to get section name, use index if name unavailable
                        try:
                            section_name = section.name
                        except:
                            section_name = f"section_{i}"
                        
                        sections.append({
                            'name': section_name,
                            'type': section['sh_type'],
                            'address': hex(section['sh_addr']),
                            'offset': hex(section['sh_offset']),
                            'size': section['sh_size'],
                            'flags': flags_str,
                            'entropy': round(entropy, 2)
                        })
                    except Exception as e:
                        # If we can't parse this section, skip it but continue with others
                        continue
                        
            except Exception as e:
                # If we can't iterate sections at all, at least return basic metadata
                pass
                
            metadata['sections'] = json.dumps(sections) if sections else None
            metadata['section_count'] = len(sections)
            
            # Program headers (segments)
            segments = []
            try:
                for segment in elf.iter_segments():
                    seg_info = {
                        'type': segment['p_type'],
                        'offset': hex(segment['p_offset']),
                        'virtual_address': hex(segment['p_vaddr']),
                        'physical_address': hex(segment['p_paddr']),
                        'file_size': segment['p_filesz'],
                        'memory_size': segment['p_memsz'],
                        'flags': segment['p_flags'],
                        'alignment': segment['p_align']
                    }
                    
                    # Check for interpreter segment
                    if isinstance(segment, InterpSegment):
                        interpreter = segment.get_interp_name()
                        seg_info['interpreter'] = interpreter
                        metadata['interpreter'] = interpreter
                    
                    segments.append(seg_info)
            except Exception as e:
                pass
            
            metadata['segments'] = json.dumps(segments) if segments else None
            metadata['segment_count'] = len(segments)
            
            # Dynamic section (shared libraries, etc.)
            dynamic_tags = []
            shared_libraries = []
            soname = None
            try:
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            tag_info = {
                                'tag': tag.entry.d_tag,
                                'value': str(tag.entry.d_val)
                            }
                            
                            # Capture shared library dependencies
                            if tag.entry.d_tag == 'DT_NEEDED':
                                shared_libraries.append(tag.needed)
                            
                            # Capture SONAME (shared object name) for internal name
                            if tag.entry.d_tag == 'DT_SONAME':
                                soname = tag.soname
                            
                            dynamic_tags.append(tag_info)
            except Exception as e:
                pass
            
            metadata['dynamic_tags'] = json.dumps(dynamic_tags) if dynamic_tags else None
            metadata['shared_libraries'] = json.dumps(shared_libraries) if shared_libraries else None
            metadata['shared_library_count'] = len(shared_libraries)
            
            # Store SONAME as internal name for filename resolution
            metadata['internal_name'] = soname
            
            # Symbol tables
            symbols = []
            symbol_count = 0
            try:
                for section in elf.iter_sections():
                    if section.header['sh_type'] in ['SHT_SYMTAB', 'SHT_DYNSYM']:
                        try:
                            for symbol in section.iter_symbols():
                                if symbol.name:  # Only include named symbols
                                    symbols.append({
                                        'name': symbol.name,
                                        'value': hex(symbol['st_value']),
                                        'size': symbol['st_size'],
                                        'type': symbol['st_info']['type'],
                                        'binding': symbol['st_info']['bind'],
                                        'section_index': symbol['st_shndx']
                                    })
                                    symbol_count += 1
                                    # Limit to first 500 symbols to avoid huge JSON
                                    if symbol_count >= 500:
                                        break
                        except Exception as e:
                            continue
                    if symbol_count >= 500:
                        break
            except Exception as e:
                pass
            
            metadata['symbols'] = json.dumps(symbols) if symbols else None
            metadata['symbol_count'] = symbol_count
            
            # Relocations
            relocations = []
            relocation_count = 0
            try:
                for section in elf.iter_sections():
                    if isinstance(section, RelocationSection):
                        for reloc in section.iter_relocations():
                            relocations.append({
                                'offset': hex(reloc['r_offset']),
                                'info': hex(reloc['r_info']),
                                'type': reloc['r_info_type']
                            })
                            relocation_count += 1
                            # Limit to first 200 relocations
                            if relocation_count >= 200:
                                break
                    if relocation_count >= 200:
                        break
            except Exception as e:
                pass
            
            metadata['relocations'] = json.dumps(relocations) if relocations else None
            metadata['relocation_count'] = relocation_count
            
            return metadata
            
    except Exception as e:
        return {
            'machine': None,
            'entry_point': None,
            'sections': None
        }
