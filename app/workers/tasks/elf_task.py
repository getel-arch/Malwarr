import logging
import json
import math
from collections import Counter
from typing import Dict, Any, List, Optional
from datetime import datetime
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.segments import InterpSegment
from app.models import MalwareSample, ELFAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class ELFAnalysisTask(AnalysisTask):
    """ELF file analysis task"""
    
    @property
    def task_name(self) -> str:
        return "ELF"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        return [FileType.ELF]
    
    @staticmethod
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

    def extract_elf_metadata(self, file_path: str) -> Dict[str, Any]:
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
                            entropy = self.calculate_entropy(section_data) if section_data else 0.0
                            
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
                metadata['symbol_count'] = symbol_countount
                
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
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """Extract ELF metadata from the file"""
        elf_metadata = self.extract_elf_metadata(file_path)
        
        if elf_metadata:
            return {
                "success": True,
                "elf_metadata": elf_metadata
            }
        else:
            return {
                "success": False,
                "error": "ELF metadata extraction failed"
            }
    
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """Save ELF analysis results to database"""
        elf_metadata = analysis_result.get("elf_metadata", {})
        
        # Check if ELF analysis already exists
        elf_analysis = self.db.query(ELFAnalysis).filter(
            ELFAnalysis.sha512 == sample.sha512
        ).first()
        
        if not elf_analysis:
            # Create new ELF analysis record
            elf_analysis = ELFAnalysis(
                sha512=sample.sha512,
                analysis_date=datetime.utcnow()
            )
            self.db.add(elf_analysis)
        
        # Update ELF analysis with extracted metadata
        elf_analysis.machine = elf_metadata.get('machine')
        elf_analysis.entry_point = elf_metadata.get('entry_point')
        elf_analysis.file_class = elf_metadata.get('file_class')
        elf_analysis.data_encoding = elf_metadata.get('data_encoding')
        elf_analysis.os_abi = elf_metadata.get('os_abi')
        elf_analysis.abi_version = elf_metadata.get('abi_version')
        elf_analysis.elf_type = elf_metadata.get('type')
        elf_analysis.version = elf_metadata.get('version')
        elf_analysis.flags = elf_metadata.get('flags')
        elf_analysis.header_size = elf_metadata.get('header_size')
        elf_analysis.program_header_offset = elf_metadata.get('program_header_offset')
        elf_analysis.section_header_offset = elf_metadata.get('section_header_offset')
        elf_analysis.program_header_entry_size = elf_metadata.get('program_header_entry_size')
        elf_analysis.program_header_count = elf_metadata.get('program_header_count')
        elf_analysis.section_header_entry_size = elf_metadata.get('section_header_entry_size')
        elf_analysis.section_header_count = elf_metadata.get('section_header_count')
        elf_analysis.sections = elf_metadata.get('sections')
        elf_analysis.section_count = elf_metadata.get('section_count')
        elf_analysis.segments = elf_metadata.get('segments')
        elf_analysis.segment_count = elf_metadata.get('segment_count')
        elf_analysis.interpreter = elf_metadata.get('interpreter')
        elf_analysis.dynamic_tags = elf_metadata.get('dynamic_tags')
        elf_analysis.shared_libraries = elf_metadata.get('shared_libraries')
        elf_analysis.shared_library_count = elf_metadata.get('shared_library_count')
        elf_analysis.symbols = elf_metadata.get('symbols')
        elf_analysis.symbol_count = elf_metadata.get('symbol_count')
        elf_analysis.relocations = elf_metadata.get('relocations')
        elf_analysis.relocation_count = elf_metadata.get('relocation_count')
        elf_analysis.analysis_date = datetime.utcnow()
        
        # Update sample filename with internal name (SONAME) if available
        internal_name = elf_metadata.get('internal_name')
        if internal_name:
            # Use SONAME as the display filename
            sample.filename = internal_name
            logger.info(f"Updated filename to internal name (SONAME): '{internal_name}'")
        
        self.db.commit()


@celery_app.task(base=ELFAnalysisTask, bind=True, name='app.workers.tasks.elf_task')
def analyze_sample_with_elf(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with ELF metadata extraction in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    return self.run_analysis(sha512)