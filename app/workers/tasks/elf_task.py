import logging
from typing import Dict, Any
from pathlib import Path
from datetime import datetime
from app.models import MalwareSample, ELFAnalysis, FileType, AnalysisStatus
from app.workers.tasks.database_task import DatabaseTask
from app.analyzers.elf.elf_analyzer import extract_elf_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.elf_task')
def analyze_sample_with_elf(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with ELF metadata extraction in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Starting ELF analysis for sample: {sha512}")

    try:
        # Get sample from database
        sample = self.db.query(MalwareSample).filter(
            MalwareSample.sha512 == sha512
        ).first()

        if not sample:
            logger.error(f"Sample not found: {sha512}")
            return {
                "success": False,
                "error": "Sample not found"
            }

        # Update status to analyzing
        sample.analysis_status = AnalysisStatus.ANALYZING
        self.db.commit()

        # Only analyze ELF files
        if sample.file_type != FileType.ELF:
            logger.info(f"Skipping ELF analysis for file type: {sample.file_type}")
            sample.analysis_status = AnalysisStatus.SKIPPED
            self.db.commit()
            return {
                "success": False,
                "error": f"ELF analysis not supported for file type: {sample.file_type}"
            }

        # Determine full file path in storage
        if Path(sample.storage_path).is_absolute():
            full_path = sample.storage_path
        else:
            full_path = str(self.storage.storage_path / sample.storage_path)

        # Check file exists
        if not Path(full_path).exists():
            logger.error(f"Sample file not found in storage: {full_path}")
            sample.analysis_status = AnalysisStatus.FAILED
            self.db.commit()
            return {
                "success": False,
                "error": "Sample file not found in storage"
            }

        # Extract ELF metadata
        logger.info(f"Extracting ELF metadata for {sample.filename}")
        elf_metadata = extract_elf_metadata(full_path)

        if elf_metadata:
            # Check if ELF analysis already exists
            elf_analysis = self.db.query(ELFAnalysis).filter(
                ELFAnalysis.sha512 == sha512
            ).first()
            
            if not elf_analysis:
                # Create new ELF analysis record
                elf_analysis = ELFAnalysis(
                    sha512=sha512,
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
            
            sample.analysis_status = AnalysisStatus.COMPLETED
            self.db.commit()

            logger.info(f"ELF analysis completed for sample: {sha512}")
            return {
                "success": True,
                "sha512": sha512,
                "elf_metadata": elf_metadata
            }
        else:
            logger.warning(f"ELF analysis failed for sample: {sha512}")
            sample.analysis_status = AnalysisStatus.FAILED
            self.db.commit()

            return {
                "success": False,
                "error": "ELF analysis failed"
            }

    except Exception as e:
        logger.error(f"Error in ELF analysis task: {e}", exc_info=True)

        # Update sample status to failed
        try:
            sample = self.db.query(MalwareSample).filter(
                MalwareSample.sha512 == sha512
            ).first()
            if sample:
                sample.analysis_status = AnalysisStatus.FAILED
                self.db.commit()
        except Exception as db_error:
            logger.error(f"Error updating sample status: {db_error}")

        return {
            "success": False,
            "error": str(e)
        }