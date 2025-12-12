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


class VirusTotalPollingTask(DatabaseTask):
    """VirusTotal polling task for checking pending analyses"""
    
    def validate_api_key(self) -> bool:
        """Check if VirusTotal API key is configured"""
        return bool(settings.virustotal_api_key and settings.virustotal_api_key != "")
    
    def get_pending_analyses(self) -> List[VirusTotalAnalysis]:
        """Retrieve all pending VT analysis records from database"""
        return self.db.query(VirusTotalAnalysis).filter(
            VirusTotalAnalysis.verbose_msg.like('%upload%'),
            VirusTotalAnalysis.scan_id.isnot(None)
        ).all()
    
    def check_single_analysis(self, vt_analysis: VirusTotalAnalysis) -> Dict[str, Any]:
        """
        Check status of a single VT analysis
        
        Args:
            vt_analysis: VirusTotalAnalysis record to check
            
        Returns:
            Dictionary with status: 'completed', 'pending', or 'error'
        """
        try:
            result = check_virustotal_analysis_status(
                db=self.db,
                sample_id=vt_analysis.sha512,
                analysis_id=vt_analysis.scan_id,
                api_key=settings.virustotal_api_key
            )
            
            if not result:
                logger.error(f"Failed to check analysis status for {vt_analysis.sha512}")
                return {"status": "error"}
            
            if result.get('complete'):
                if result.get('status') == 'completed':
                    logger.info(f"Analysis completed for {vt_analysis.sha512}: {result.get('detection_ratio')}")
                    return {"status": "completed"}
                else:
                    logger.warning(f"Analysis ended with status: {result.get('status')} for {vt_analysis.sha512}")
                    return {"status": "error"}
            else:
                logger.debug(f"Analysis still {result.get('status')} for {vt_analysis.sha512}")
                return {"status": "pending"}
                
        except Exception as e:
            logger.error(f"Error checking VT analysis for {vt_analysis.sha512}: {e}", exc_info=True)
            return {"status": "error"}
    
    def run_polling(self) -> Dict[str, Any]:
        """
        Poll VirusTotal for pending analysis results
        
        Returns:
            Dictionary with polling summary
        """
        logger.info("Starting VirusTotal polling task")
        
        try:
            # Check if VT API key is configured
            if not self.validate_api_key():
                logger.warning("VirusTotal API key not configured, skipping VT polling")
                return {
                    "success": False,
                    "error": "VirusTotal API key not configured"
                }
            
            # Find all pending analyses
            pending_analyses = self.get_pending_analyses()
            
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
            
            # Process each pending analysis
            checked = 0
            completed = 0
            still_pending = 0
            errors = 0
            
            for vt_analysis in pending_analyses:
                result = self.check_single_analysis(vt_analysis)
                checked += 1
                
                status = result.get("status")
                if status == "completed":
                    completed += 1
                elif status == "pending":
                    still_pending += 1
                else:  # error
                    errors += 1
            
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


@celery_app.task(base=VirusTotalPollingTask, bind=True, name='app.workers.tasks.vt_polling_task')
def poll_pending_virustotal_analyses(self) -> Dict[str, Any]:
    """
    Poll VirusTotal for pending analysis results
    
    This task runs periodically to check uploaded files that are still being analyzed
    by VirusTotal and updates the database when results are available.
    
    Returns:
        Dictionary with polling summary
    """
    return self.run_polling()
