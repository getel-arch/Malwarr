import json
import logging
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from app.models import MalwareSample, FileType, AnalysisStatus
from app.workers.tasks.database_task import DatabaseTask
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.capa_task')
def analyze_sample_with_capa(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with CAPA in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Starting CAPA analysis for sample: {sha512}")

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

        # Only analyze PE and ELF files
        if sample.file_type not in [FileType.PE, FileType.ELF]:
            logger.info(f"Skipping CAPA analysis for file type: {sample.file_type}")
            sample.analysis_status = AnalysisStatus.SKIPPED
            self.db.commit()
            return {
                "success": False,
                "error": f"CAPA analysis not supported for file type: {sample.file_type}"
            }

        # Get file from storage
        file_content = self.storage.get_file(sample.storage_path)
        if not file_content:
            logger.error(f"Sample file not found in storage: {sample.storage_path}")
            sample.analysis_status = AnalysisStatus.FAILED
            self.db.commit()
            return {
                "success": False,
                "error": "Sample file not found in storage"
            }

        # Write to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(sample.filename).suffix) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name

        try:
            logger.info(f"Running CAPA analysis on {sample.filename}")
            capa_result = self.capa_analyzer.analyze_file(tmp_path)

            if capa_result.get("success"):
                # Update sample with CAPA results
                sample.capa_capabilities = json.dumps(capa_result.get("capabilities", {}))
                sample.capa_attack = json.dumps(capa_result.get("attack", []))
                sample.capa_mbc = json.dumps(capa_result.get("mbc", []))
                sample.capa_result_document = json.dumps(capa_result.get("result_document", {}))
                sample.capa_analysis_date = datetime.utcnow()
                sample.capa_total_capabilities = sum(
                    capa_result.get("namespace_counts", {}).values()
                )
                sample.analysis_status = AnalysisStatus.COMPLETED

                self.db.commit()

                logger.info(f"CAPA analysis completed: {sample.capa_total_capabilities} capabilities detected")
                return {
                    "success": True,
                    "sha512": sha512,
                    "capabilities_count": sample.capa_total_capabilities
                }
            else:
                error_msg = capa_result.get('error', 'Unknown error')
                logger.warning(f"CAPA analysis failed: {error_msg}")

                sample.analysis_status = AnalysisStatus.FAILED
                self.db.commit()

                return {
                    "success": False,
                    "error": error_msg
                }
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    except Exception as e:
        logger.error(f"Error in CAPA analysis task: {e}", exc_info=True)

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