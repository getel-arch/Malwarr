import json
import logging
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from app.models import MalwareSample, CAPAAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class CAPAAnalysisTask(AnalysisTask):
    """CAPA capabilities analysis task"""
    
    @property
    def task_name(self) -> str:
        return "CAPA"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        return [FileType.PE, FileType.ELF]
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """
        Perform CAPA analysis using temporary file.
        Note: CAPA uses temp file instead of direct path access.
        """
        # Get file content from storage
        file_content = self.storage.get_file(sample.storage_path)
        if not file_content:
            logger.error(f"Sample file not found in storage: {sample.storage_path}")
            return {
                "success": False,
                "error": "Sample file not found in storage"
            }
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(sample.filename).suffix) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        try:
            capa_result = self.capa_analyzer.analyze_file(tmp_path)
            
            if capa_result.get("success"):
                return {
                    "success": True,
                    "capa_result": capa_result
                }
            else:
                error_msg = capa_result.get('error', 'Unknown error')
                return {
                    "success": False,
                    "error": error_msg
                }
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """Save CAPA analysis results to database"""
        capa_result = analysis_result.get("capa_result", {})
        
        # Check if CAPA analysis already exists
        capa_analysis = self.db.query(CAPAAnalysis).filter(
            CAPAAnalysis.sha512 == sample.sha512
        ).first()
        
        if not capa_analysis:
            # Create new CAPA analysis record
            capa_analysis = CAPAAnalysis(
                sha512=sample.sha512,
                analysis_date=datetime.utcnow()
            )
            self.db.add(capa_analysis)
        
        # Update CAPA analysis with results
        capa_analysis.capabilities = json.dumps(capa_result.get("capabilities", {}))
        capa_analysis.attack = json.dumps(capa_result.get("attack", []))
        capa_analysis.mbc = json.dumps(capa_result.get("mbc", []))
        capa_analysis.result_document = json.dumps(capa_result.get("result_document", {}))
        capa_analysis.total_capabilities = sum(
            capa_result.get("namespace_counts", {}).values()
        )
        capa_analysis.analysis_date = datetime.utcnow()
        
        logger.info(f"CAPA analysis saved: {capa_analysis.total_capabilities} capabilities detected")
        
        self.db.commit()


@celery_app.task(base=CAPAAnalysisTask, bind=True, name='app.workers.tasks.capa_task')
def analyze_sample_with_capa(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with CAPA in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    return self.run_analysis(sha512)