import logging
import pefile
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.models import MalwareSample, PEAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class PEAnalysisTask(AnalysisTask):
    """PE file analysis task"""
    
    @property
    def task_name(self) -> str:
        return "PE"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        return [FileType.PE]
    
    def extract_pe_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract comprehensive metadata from PE files (exe, dll)"""
        try:
            pe = pefile.PE(file_path)
            
            metadata = {}
            
            # ========== FILE HEADER ==========
            try:
                metadata['machine'] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
                metadata['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
                metadata['characteristics'] = hex(pe.FILE_HEADER.Characteristics)
                metadata['timestamp'] = pe.FILE_HEADER.TimeDateStamp
                metadata['compilation_timestamp'] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
            except:
                metadata['machine'] = None
                metadata['number_of_sections'] = None
                metadata['characteristics'] = None
                metadata['timestamp'] = None
                metadata['compilation_timestamp'] = None
            
            # ========== OPTIONAL HEADER ==========
            try:
                metadata['magic'] = hex(pe.OPTIONAL_HEADER.Magic)
                metadata['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
                metadata['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
                metadata['subsystem'] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, hex(pe.OPTIONAL_HEADER.Subsystem))
                metadata['dll_characteristics'] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
                metadata['checksum'] = hex(pe.OPTIONAL_HEADER.CheckSum)
                metadata['size_of_image'] = pe.OPTIONAL_HEADER.SizeOfImage
                metadata['size_of_headers'] = pe.OPTIONAL_HEADER.SizeOfHeaders
                metadata['base_of_code'] = hex(pe.OPTIONAL_HEADER.BaseOfCode)
                
                # Version information
                metadata['linker_version'] = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
                metadata['os_version'] = f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"
                metadata['image_version'] = f"{pe.OPTIONAL_HEADER.MajorImageVersion}.{pe.OPTIONAL_HEADER.MinorImageVersion}"
                metadata['subsystem_version'] = f"{pe.OPTIONAL_HEADER.MajorSubsystemVersion}.{pe.OPTIONAL_HEADER.MinorSubsystemVersion}"
            except:
                pass
            
            # ========== IMPORT HASH ==========
            try:
                metadata['imphash'] = pe.get_imphash()
            except:
                metadata['imphash'] = None
            
            # ========== SECTIONS ==========
            sections = []
            for section in pe.sections:
                sections.append({
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy(),
                    'characteristics': hex(section.Characteristics)
                })
            metadata['sections'] = json.dumps(sections)
            
            # ========== IMPORTS ==========
            imports = []
            total_imported_functions = 0
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='ignore')
                        functions = []
                        for imp in entry.imports[:100]:  # Limit to first 100 per DLL
                            total_imported_functions += 1
                            if imp.name:
                                functions.append(imp.name.decode('utf-8', errors='ignore'))
                            else:
                                functions.append(f"Ordinal_{imp.ordinal}")
                        imports.append({
                            'dll': dll_name,
                            'functions': functions
                        })
                metadata['imports'] = json.dumps(imports[:50])  # Limit to 50 DLLs
                metadata['import_dll_count'] = len(imports)
                metadata['imported_functions_count'] = total_imported_functions
            except:
                metadata['imports'] = None
                metadata['import_dll_count'] = 0
                metadata['imported_functions_count'] = 0
            
            # ========== EXPORTS ==========
            exports = []
            export_info = {}
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    export_info['dll_name'] = pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8', errors='ignore') if pe.DIRECTORY_ENTRY_EXPORT.name else None
                    export_info['number_of_functions'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
                    
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:200]:  # Limit to 200
                        if exp.name:
                            exports.append({
                                'name': exp.name.decode('utf-8', errors='ignore'),
                                'ordinal': exp.ordinal,
                                'address': hex(exp.address) if exp.address else None
                            })
                        else:
                            exports.append({
                                'name': f"Ordinal_{exp.ordinal}",
                                'ordinal': exp.ordinal,
                                'address': hex(exp.address) if exp.address else None
                            })
                    
                    export_info['exports'] = exports
                    metadata['exports'] = json.dumps(export_info)
                    metadata['export_count'] = export_info['number_of_functions']
                else:
                    metadata['exports'] = None
                    metadata['export_count'] = 0
            except:
                metadata['exports'] = None
                metadata['export_count'] = 0
            
            # ========== RESOURCES ==========
            resources = []
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    def parse_resource_entry(entry, level=0, type_name=''):
                        if hasattr(entry, 'data'):
                            resources.append({
                                'type': type_name,
                                'name': entry.name if hasattr(entry, 'name') else str(entry.id),
                                'language': entry.data.lang if hasattr(entry.data, 'lang') else None,
                                'sublanguage': entry.data.sublang if hasattr(entry.data, 'sublang') else None,
                                'size': entry.data.struct.Size,
                                'offset': hex(entry.data.struct.OffsetToData)
                            })
                        elif hasattr(entry, 'directory'):
                            for res_entry in entry.directory.entries:
                                next_type = type_name
                                if level == 0:
                                    next_type = pefile.RESOURCE_TYPE.get(res_entry.id, f'Type_{res_entry.id}')
                                parse_resource_entry(res_entry, level + 1, next_type)
                    
                    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        parse_resource_entry(entry)
                    
                    metadata['resources'] = json.dumps(resources[:100])  # Limit to 100 resources
                    metadata['resource_count'] = len(resources)
            except:
                metadata['resources'] = None
                metadata['resource_count'] = 0
            
            # ========== VERSION INFO ==========
            version_info = {}
            internal_name = None
            try:
                if hasattr(pe, 'VS_VERSIONINFO') and hasattr(pe, 'FileInfo'):
                    for fileinfo in pe.FileInfo:
                        if hasattr(fileinfo, 'StringTable'):
                            for st in fileinfo.StringTable:
                                for entry in st.entries.items():
                                    key = entry[0].decode('utf-8', errors='ignore')
                                    value = entry[1].decode('utf-8', errors='ignore')
                                    version_info[key] = value
                                    
                                    # Extract internal name (prefer InternalName, fallback to OriginalFilename)
                                    if key == 'InternalName' and value:
                                        internal_name = value
                                    elif key == 'OriginalFilename' and value and not internal_name:
                                        internal_name = value
                        elif hasattr(fileinfo, 'Var'):
                            for var in fileinfo.Var:
                                if hasattr(var, 'entry'):
                                    version_info['Translation'] = var.entry
                    
                    if version_info:
                        metadata['version_info'] = json.dumps(version_info)
                    else:
                        metadata['version_info'] = None
            except:
                metadata['version_info'] = None
            
            # Store internal name for filename resolution
            metadata['internal_name'] = internal_name
            
            # ========== DEBUG INFO ==========
            debug_info = []
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                    for entry in pe.DIRECTORY_ENTRY_DEBUG:
                        debug_entry = {
                            'type': pefile.DEBUG_TYPE.get(entry.struct.Type, f'Type_{entry.struct.Type}'),
                            'timestamp': entry.struct.TimeDateStamp,
                            'size': entry.struct.SizeOfData
                        }
                        
                        # Try to extract PDB path for CodeView debug info
                        if entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                            try:
                                if hasattr(entry, 'entry'):
                                    pdb_data = entry.entry
                                    if hasattr(pdb_data, 'PdbFileName'):
                                        debug_entry['pdb_path'] = pdb_data.PdbFileName.decode('utf-8', errors='ignore')
                            except:
                                pass
                        
                        debug_info.append(debug_entry)
                    
                    metadata['debug_info'] = json.dumps(debug_info)
            except:
                metadata['debug_info'] = None
            
            # ========== TLS ==========
            try:
                if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                    tls_info = {
                        'callbacks': []
                    }
                    if hasattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks'):
                        tls_info['callback_address'] = hex(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
                    
                    metadata['tls_info'] = json.dumps(tls_info)
            except:
                metadata['tls_info'] = None
            
            # ========== RICH HEADER ==========
            try:
                if hasattr(pe, 'RICH_HEADER'):
                    rich_header = {
                        'checksum': hex(pe.RICH_HEADER.checksum) if hasattr(pe.RICH_HEADER, 'checksum') else None,
                        'values': []
                    }
                    if hasattr(pe.RICH_HEADER, 'values'):
                        for entry in pe.RICH_HEADER.values[:20]:  # Limit to 20 entries
                            rich_header['values'].append({
                                'product_id': entry.get('product_id'),
                                'build_id': entry.get('build_id'),
                                'count': entry.get('count')
                            })
                    
                    metadata['rich_header'] = json.dumps(rich_header)
            except:
                metadata['rich_header'] = None
            
            # ========== DIGITAL SIGNATURE ==========
            try:
                signature_info = {}
                is_signed = False
                
                # Check for security directory in the data directory
                if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
                    security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
                    if security_dir.VirtualAddress != 0 and security_dir.Size != 0:
                        is_signed = True
                        signature_info['present'] = True
                        signature_info['address'] = hex(security_dir.VirtualAddress)
                        signature_info['size'] = security_dir.Size
                
                # Also check if DIRECTORY_ENTRY_SECURITY attribute exists
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') and pe.DIRECTORY_ENTRY_SECURITY:
                    is_signed = True
                    signature_info['present'] = True
                    if 'size' not in signature_info:
                        signature_info['size'] = len(pe.DIRECTORY_ENTRY_SECURITY)
                
                metadata['is_signed'] = is_signed
                metadata['signature_info'] = json.dumps(signature_info) if signature_info else None
            except Exception as e:
                metadata['is_signed'] = False
                metadata['signature_info'] = None
            
            pe.close()
            return metadata
            
        except Exception as e:
            return {
                'imphash': None,
                'compilation_timestamp': None,
                'entry_point': None,
                'sections': None,
                'imports': None,
                'exports': None,
                'machine': None,
                'subsystem': None,
                'version_info': None,
                'resources': None,
                'debug_info': None,
                'is_signed': False
            }
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """Extract PE metadata from the file"""
        pe_metadata = self.extract_pe_metadata(file_path)
        
        if pe_metadata:
            return {
                "success": True,
                "pe_metadata": pe_metadata
            }
        else:
            return {
                "success": False,
                "error": "PE metadata extraction failed"
            }
    
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """Save PE analysis results to database"""
        pe_metadata = analysis_result.get("pe_metadata", {})
        
        # Check if PE analysis already exists
        pe_analysis = self.db.query(PEAnalysis).filter(
            PEAnalysis.sha512 == sample.sha512
        ).first()
        
        if not pe_analysis:
            # Create new PE analysis record
            pe_analysis = PEAnalysis(
                sha512=sample.sha512,
                analysis_date=datetime.utcnow()
            )
            self.db.add(pe_analysis)
        
        # Update PE analysis with extracted metadata
        pe_analysis.imphash = pe_metadata.get('imphash')
        pe_analysis.compilation_timestamp = datetime.fromisoformat(pe_metadata['compilation_timestamp']) if pe_metadata.get('compilation_timestamp') else None
        pe_analysis.entry_point = pe_metadata.get('entry_point')
        pe_analysis.sections = pe_metadata.get('sections')
        pe_analysis.imports = pe_metadata.get('imports')
        pe_analysis.exports = pe_metadata.get('exports')
        pe_analysis.machine = pe_metadata.get('machine')
        pe_analysis.number_of_sections = pe_metadata.get('number_of_sections')
        pe_analysis.characteristics = pe_metadata.get('characteristics')
        pe_analysis.magic = pe_metadata.get('magic')
        pe_analysis.image_base = pe_metadata.get('image_base')
        pe_analysis.subsystem = pe_metadata.get('subsystem')
        pe_analysis.dll_characteristics = pe_metadata.get('dll_characteristics')
        pe_analysis.checksum = pe_metadata.get('checksum')
        pe_analysis.size_of_image = pe_metadata.get('size_of_image')
        pe_analysis.size_of_headers = pe_metadata.get('size_of_headers')
        pe_analysis.base_of_code = pe_metadata.get('base_of_code')
        pe_analysis.linker_version = pe_metadata.get('linker_version')
        pe_analysis.os_version = pe_metadata.get('os_version')
        pe_analysis.image_version = pe_metadata.get('image_version')
        pe_analysis.subsystem_version = pe_metadata.get('subsystem_version')
        pe_analysis.import_dll_count = pe_metadata.get('import_dll_count')
        pe_analysis.imported_functions_count = pe_metadata.get('imported_functions_count')
        pe_analysis.export_count = pe_metadata.get('export_count')
        pe_analysis.resources = pe_metadata.get('resources')
        pe_analysis.resource_count = pe_metadata.get('resource_count')
        pe_analysis.version_info = pe_metadata.get('version_info')
        pe_analysis.debug_info = pe_metadata.get('debug_info')
        pe_analysis.tls_info = pe_metadata.get('tls_info')
        pe_analysis.rich_header = pe_metadata.get('rich_header')
        pe_analysis.is_signed = pe_metadata.get('is_signed', False)
        pe_analysis.signature_info = pe_metadata.get('signature_info')
        pe_analysis.analysis_date = datetime.utcnow()
        
        # Update sample filename with internal name if available
        internal_name = pe_metadata.get('internal_name')
        if internal_name:
            # Use internal name as the display filename
            sample.filename = internal_name
            logger.info(f"Updated filename to internal name: '{internal_name}'")
        
        self.db.commit()


@celery_app.task(base=PEAnalysisTask, bind=True, name='app.workers.tasks.pe_task')
def analyze_sample_with_pe(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with PE metadata extraction in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    return self.run_analysis(sha512)