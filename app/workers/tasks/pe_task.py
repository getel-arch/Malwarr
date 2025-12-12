import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.models import MalwareSample, PEAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.analyzers.pe.pe_analyzer import extract_pe_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class PEAnalysisTask(AnalysisTask):
    """PE file analysis task"""
    
    @property
    def task_name(self) -> str:
        return "PE"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        return [FileType.PE]
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """Extract PE metadata from the file"""
        pe_metadata = extract_pe_metadata(file_path)
        
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
            # Store the original uploaded filename in internal_name field
            sample.internal_name = internal_name
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