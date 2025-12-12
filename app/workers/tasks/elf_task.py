import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.models import MalwareSample, ELFAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.analyzers.elf.elf_analyzer import extract_elf_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class ELFAnalysisTask(AnalysisTask):
    """ELF file analysis task"""
    
    @property
    def task_name(self) -> str:
        return "ELF"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        return [FileType.ELF]
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """Extract ELF metadata from the file"""
        elf_metadata = extract_elf_metadata(file_path)
        
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
            # Store the SONAME in internal_name field
            sample.internal_name = internal_name
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