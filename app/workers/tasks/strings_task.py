import logging
from typing import Dict, Any
from pathlib import Path
from datetime import datetime
from app.models import MalwareSample, StringsAnalysis, AnalysisStatus
from app.workers.tasks.database_task import DatabaseTask
from app.analyzers.strings.strings_analyzer import extract_strings_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.strings_task')
def analyze_sample_with_strings(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with strings extraction in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Starting strings analysis for sample: {sha512}")

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

        # Extract strings metadata
        logger.info(f"Extracting strings for {sample.filename}")
        strings_metadata = extract_strings_metadata(full_path)

        if strings_metadata:
            # Check if strings analysis already exists
            strings_analysis = self.db.query(StringsAnalysis).filter(
                StringsAnalysis.sha512 == sha512
            ).first()
            
            if not strings_analysis:
                # Create new strings analysis record
                strings_analysis = StringsAnalysis(
                    sha512=sha512,
                    analysis_date=datetime.utcnow()
                )
                self.db.add(strings_analysis)
            
            # Update strings analysis with extracted metadata
            strings_analysis.ascii_strings = strings_metadata.get('ascii_strings')
            strings_analysis.unicode_strings = strings_metadata.get('unicode_strings')
            strings_analysis.ascii_count = strings_metadata.get('ascii_count')
            strings_analysis.unicode_count = strings_metadata.get('unicode_count')
            strings_analysis.total_count = strings_metadata.get('total_count')
            strings_analysis.min_length = strings_metadata.get('min_length')
            strings_analysis.longest_string_length = strings_metadata.get('longest_string_length')
            strings_analysis.average_string_length = strings_metadata.get('average_string_length')
            strings_analysis.analysis_date = datetime.utcnow()
            
            sample.analysis_status = AnalysisStatus.COMPLETED
            self.db.commit()

            logger.info(f"Strings analysis completed for sample: {sha512} - "
                       f"ASCII: {strings_metadata.get('ascii_count')}, "
                       f"Unicode: {strings_metadata.get('unicode_count')}")
            
            return {
                "success": True,
                "sha512": sha512,
                "strings_metadata": {
                    "ascii_count": strings_metadata.get('ascii_count'),
                    "unicode_count": strings_metadata.get('unicode_count'),
                    "total_count": strings_metadata.get('total_count')
                }
            }
        else:
            logger.warning(f"Strings analysis failed for sample: {sha512}")
            sample.analysis_status = AnalysisStatus.FAILED
            self.db.commit()

            return {
                "success": False,
                "error": "Strings analysis failed"
            }

    except Exception as e:
        logger.error(f"Error in strings analysis task: {e}", exc_info=True)

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
