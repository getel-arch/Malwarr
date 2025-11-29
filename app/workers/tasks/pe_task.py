import logging
from typing import Dict, Any
from pathlib import Path
from app.models import MalwareSample, FileType, AnalysisStatus
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
            # Update sample with PE metadata
            sample.pe_metadata = pe_metadata
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