"""
Background tasks for malware analysis
"""
import json
import logging
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from celery import Task
from sqlalchemy.orm import Session

from app.workers.celery_app import celery_app
from app.database import SessionLocal
from app.models import MalwareSample, FileType, AnalysisStatus
from app.analyzers.capa.capa_analyzer import CapaAnalyzer
from app.storage import FileStorage
from app.config import settings

logger = logging.getLogger(__name__)


class DatabaseTask(Task):
    """Base task that provides database session"""
    _db = None
    _storage = None
    _capa_analyzer = None

    @property
    def db(self) -> Session:
        if self._db is None:
            self._db = SessionLocal()
        return self._db

    @property
    def storage(self) -> FileStorage:
        if self._storage is None:
            self._storage = FileStorage()
        return self._storage

    @property
    def capa_analyzer(self) -> CapaAnalyzer:
        if self._capa_analyzer is None:
            self._capa_analyzer = CapaAnalyzer()
        return self._capa_analyzer

    def after_return(self, *args, **kwargs):
        """Clean up database session after task completes"""
        if self._db is not None:
            self._db.close()
            self._db = None


@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.analyze_sample_with_capa')
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


@celery_app.task(base=DatabaseTask, bind=True, name='app.workers.tasks.batch_analyze_samples')
def batch_analyze_samples(self, sha512_list: list) -> Dict[str, Any]:
    """
    Analyze multiple samples with CAPA in the background
    
    Args:
        sha512_list: List of SHA512 hashes to analyze
        
    Returns:
        Dictionary with batch analysis results
    """
    logger.info(f"Starting batch CAPA analysis for {len(sha512_list)} samples")
    
    results = {
        "total": len(sha512_list),
        "queued": 0,
        "failed": 0
    }
    
    for sha512 in sha512_list:
        try:
            # Queue individual analysis task
            analyze_sample_with_capa.delay(sha512)
            results["queued"] += 1
        except Exception as e:
            logger.error(f"Error queuing analysis for {sha512}: {e}")
            results["failed"] += 1
    
    logger.info(f"Batch analysis queued: {results['queued']} tasks")
    return results
