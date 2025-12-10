"""
Celery task for polling VirusTotal analysis results
"""
import logging
from typing import Dict, Any, List
from app.workers.tasks.database_task import DatabaseTask
from app.analyzers.virustotal.vt_analyzer import check_virustotal_analysis_status
from app.workers.celery_app import celery_app
from app.config import settings
from app.models import VirusTotalAnalysis

logger = logging.getLogger(__name__)


@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.vt_polling_task')
def poll_pending_virustotal_analyses(self) -> Dict[str, Any]:
    """
    Poll VirusTotal for pending analysis results
    
    This task runs periodically to check uploaded files that are still being analyzed
    by VirusTotal and updates the database when results are available.
    
    Returns:
        Dictionary with polling summary
    """
    logger.info("Starting VirusTotal polling task")
    
    try:
        # Check if VT API key is configured
        if not settings.virustotal_api_key or settings.virustotal_api_key == "":
            logger.warning("VirusTotal API key not configured, skipping VT polling")
            return {
                "success": False,
                "error": "VirusTotal API key not configured"
            }
        
        # Find all VT analysis records that indicate upload in progress
        pending_analyses = self.db.query(VirusTotalAnalysis).filter(
            VirusTotalAnalysis.verbose_msg.like('%upload%'),
            VirusTotalAnalysis.scan_id.isnot(None)
        ).all()
        
        if not pending_analyses:
            logger.info("No pending VT analyses found")
            return {
                "success": True,
                "pending_count": 0,
                "checked": 0,
                "completed": 0,
                "still_pending": 0,
                "errors": 0
            }
        
        logger.info(f"Found {len(pending_analyses)} pending VT analyses to check")
        
        checked = 0
        completed = 0
        still_pending = 0
        errors = 0
        
        for vt_analysis in pending_analyses:
            try:
                # Check the status of this analysis
                result = check_virustotal_analysis_status(
                    db=self.db,
                    sample_id=vt_analysis.sha512,
                    analysis_id=vt_analysis.scan_id,
                    api_key=settings.virustotal_api_key
                )
                
                checked += 1
                
                if result:
                    if result.get('complete'):
                        if result.get('status') == 'completed':
                            completed += 1
                            logger.info(f"Analysis completed for {vt_analysis.sha512}: {result.get('detection_ratio')}")
                        else:
                            errors += 1
                            logger.warning(f"Analysis ended with status: {result.get('status')} for {vt_analysis.sha512}")
                    else:
                        still_pending += 1
                        logger.debug(f"Analysis still {result.get('status')} for {vt_analysis.sha512}")
                else:
                    errors += 1
                    logger.error(f"Failed to check analysis status for {vt_analysis.sha512}")
                    
            except Exception as e:
                errors += 1
                logger.error(f"Error checking VT analysis for {vt_analysis.sha512}: {e}", exc_info=True)
        
        summary = {
            "success": True,
            "pending_count": len(pending_analyses),
            "checked": checked,
            "completed": completed,
            "still_pending": still_pending,
            "errors": errors
        }
        
        logger.info(f"VT polling completed: {completed} completed, {still_pending} still pending, {errors} errors")
        
        return summary
        
    except Exception as e:
        logger.error(f"Error in VT polling task: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }
