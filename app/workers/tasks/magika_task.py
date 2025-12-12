"""Magika analysis Celery task"""
import logging
from typing import Dict, Any
from pathlib import Path
from datetime import datetime
from app.models import MalwareSample, MagikaAnalysis, AnalysisStatus
from app.workers.tasks.database_task import DatabaseTask
from app.analyzers.magika.magika_analyzer import extract_magika_metadata
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.magika_task')
def analyze_sample_with_magika(self, sha512: str) -> Dict[str, Any]:
    """
    Perform Magika analysis on a malware sample
    
    Args:
        sha512: SHA512 hash of the sample to analyze
        
    Returns:
        Dictionary with analysis results
    """
    logger.info(f"Starting Magika analysis for sample: {sha512}")
    
    try:
        # Get the sample
        sample = self.db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
        if not sample:
            logger.error(f"Sample not found: {sha512}")
            return {
                "success": False,
                "error": "Sample not found"
            }
        
        logger.info(f"Starting Magika analysis for {sample.filename} ({sha512})")
        
        # Determine full file path in storage
        if Path(sample.storage_path).is_absolute():
            full_path = sample.storage_path
        else:
            full_path = str(self.storage.storage_path / sample.storage_path)
        
        if not Path(full_path).exists():
            logger.error(f"Sample file not found in storage: {full_path}")
            return {
                "success": False,
                "error": "Sample file not found in storage"
            }
        
        # Run Magika analysis
        magika_metadata = extract_magika_metadata(str(full_path))
        
        # Get or create Magika analysis record
        magika_analysis = self.db.query(MagikaAnalysis).filter(
            MagikaAnalysis.sha512 == sha512
        ).first()
        
        if not magika_analysis:
            magika_analysis = MagikaAnalysis(sha512=sha512)
            self.db.add(magika_analysis)
        
        # Update Magika analysis with results (including timestamp)
        magika_analysis.analysis_date = datetime.utcnow()
        magika_analysis.label = magika_metadata.get('label')
        magika_analysis.score = f"{magika_metadata.get('score'):.4f}" if magika_metadata.get('score') is not None else None
        magika_analysis.mime_type = magika_metadata.get('mime_type')
        magika_analysis.group = magika_metadata.get('group')
        magika_analysis.description = magika_metadata.get('description')
        magika_analysis.is_text = magika_metadata.get('is_text')
        
        self.db.commit()
        
        logger.info(f"Magika analysis completed for {sample.filename}: {magika_analysis.label} (score: {magika_analysis.score})")
        
        return {
            "success": True,
            "sha512": sha512,
            "label": magika_analysis.label,
            "score": magika_analysis.score
        }
        
    except Exception as e:
        logger.error(f"Error analyzing sample with Magika: {e}", exc_info=True)
        if self.db:
            self.db.rollback()
        return {
            "success": False,
            "error": str(e)
        }
