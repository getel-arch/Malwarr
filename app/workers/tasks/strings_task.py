import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.models import MalwareSample, StringsAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.analyzers.strings.strings_analyzer import extract_strings_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class StringsAnalysisTask(AnalysisTask):
    """Strings extraction analysis task"""
    
    @property
    def task_name(self) -> str:
        return "Strings"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        # Strings can be extracted from any file type
        return None
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """Extract strings from the file"""
        strings_metadata = extract_strings_metadata(file_path)
        
        if strings_metadata:
            logger.info(f"Strings extracted - ASCII: {strings_metadata.get('ascii_count')}, "
                       f"Unicode: {strings_metadata.get('unicode_count')}")
            return {
                "success": True,
                "strings_metadata": strings_metadata
            }
        else:
            return {
                "success": False,
                "error": "Strings extraction failed"
            }
    
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """Save strings analysis results to database"""
        strings_metadata = analysis_result.get("strings_metadata", {})
        
        # Check if strings analysis already exists
        strings_analysis = self.db.query(StringsAnalysis).filter(
            StringsAnalysis.sha512 == sample.sha512
        ).first()
        
        if not strings_analysis:
            # Create new strings analysis record
            strings_analysis = StringsAnalysis(
                sha512=sample.sha512,
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
        
        self.db.commit()


@celery_app.task(base=StringsAnalysisTask, bind=True, name='app.workers.tasks.strings_task')
def analyze_sample_with_strings(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with strings extraction in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    return self.run_analysis(sha512)
