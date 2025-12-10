import logging
from typing import Dict, Any
from pathlib import Path
from datetime import datetime
from app.models import MalwareSample, PEAnalysis, FileType, AnalysisStatus
from app.workers.tasks.database_task import DatabaseTask
from app.analyzers.pe.pe_analyzer import extract_pe_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.pe_task')
def analyze_sample_with_pe(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with PE metadata extraction in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Starting PE analysis for sample: {sha512}")

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

        # Only analyze PE files
        if sample.file_type != FileType.PE:
            logger.info(f"Skipping PE analysis for file type: {sample.file_type}")
            sample.analysis_status = AnalysisStatus.SKIPPED
            self.db.commit()
            return {
                "success": False,
                "error": f"PE analysis not supported for file type: {sample.file_type}"
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

        # Extract PE metadata
        logger.info(f"Extracting PE metadata for {sample.filename}")
        pe_metadata = extract_pe_metadata(full_path)

        if pe_metadata:
            # Check if PE analysis already exists
            pe_analysis = self.db.query(PEAnalysis).filter(
                PEAnalysis.sha512 == sha512
            ).first()
            
            if not pe_analysis:
                # Create new PE analysis record
                pe_analysis = PEAnalysis(
                    sha512=sha512,
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
            
            sample.analysis_status = AnalysisStatus.COMPLETED
            self.db.commit()

            logger.info(f"PE analysis completed for sample: {sha512}")
            return {
                "success": True,
                "sha512": sha512,
                "pe_metadata": pe_metadata
            }
        else:
            logger.warning(f"PE analysis failed for sample: {sha512}")
            sample.analysis_status = AnalysisStatus.FAILED
            self.db.commit()

            return {
                "success": False,
                "error": "PE analysis failed"
            }

    except Exception as e:
        logger.error(f"Error in PE analysis task: {e}", exc_info=True)

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