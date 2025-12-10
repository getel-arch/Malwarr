"""
Celery task for VirusTotal analysis
"""
import logging
from typing import Dict, Any
from app.workers.tasks.database_task import DatabaseTask
from app.analyzers.virustotal.vt_analyzer import analyze_sample_virustotal
from app.workers.celery_app import celery_app
from app.config import settings

logger = logging.getLogger(__name__)


@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.vt_task')
def analyze_sample_with_virustotal(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with VirusTotal hash lookup
    
    Args:
        sha512: SHA512 hash of the sample to analyze
        
    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Starting VirusTotal analysis for sample: {sha512}")
    
    try:
        # Check if VT API key is configured
        if not settings.virustotal_api_key or settings.virustotal_api_key == "":
            logger.warning("VirusTotal API key not configured, skipping VT analysis")
            return {
                "success": False,
                "error": "VirusTotal API key not configured"
            }
        
        # Analyze with VirusTotal
        logger.info(f"Running VirusTotal analysis for sample: {sha512}")
        vt_result = analyze_sample_virustotal(
            db=self.db,
            sample_id=sha512,
            api_key=settings.virustotal_api_key
        )
        
        if vt_result:
            logger.info(
                f"VirusTotal analysis completed for sample: {sha512} "
                f"({vt_result.get('positives', 0)}/{vt_result.get('total', 0)} detections)"
            )
            
            return {
                "success": True,
                "sha512": sha512,
                "vt_result": {
                    "positives": vt_result.get('positives'),
                    "total": vt_result.get('total'),
                    "detection_ratio": vt_result.get('detection_ratio'),
                    "permalink": vt_result.get('permalink'),
                    "not_found": vt_result.get('not_found', False)
                }
            }
        else:
            logger.warning(f"VirusTotal analysis returned no results for sample: {sha512}")
            return {
                "success": False,
                "error": "VirusTotal analysis failed"
            }
            
    except Exception as e:
        logger.error(f"Error in VirusTotal analysis task: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }
