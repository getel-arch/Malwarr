import logging
from typing import Dict, Any
from pathlib import Path
from app.models import MalwareSample, FileType, AnalysisStatus
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
            # Update sample with ELF metadata
            sample.elf_metadata = elf_metadata
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