"""Magika analysis Celery task"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
from app.models import MalwareSample, MagikaAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class MagikaAnalysisTask(AnalysisTask):
    """Magika file type detection analysis task"""
    
    # Class-level Magika instance - initialized once for performance
    _magika_instance = None
    
    @property
    def task_name(self) -> str:
        return "Magika"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        # Magika can analyze any file type
        return None
    
    @classmethod
    def _get_magika(cls):
        """Get or initialize the global Magika instance"""
        if cls._magika_instance is None:
            try:
                from magika import Magika
                cls._magika_instance = Magika()
                logger.info("Magika analyzer initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Magika: {e}", exc_info=True)
                raise
        return cls._magika_instance
    
    def extract_magika_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Extract file type information using Magika deep learning model
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing Magika analysis results:
            - label: Detected file type label
            - score: Confidence score (0-1)
            - description: Human-readable description
            - mime_type: Detected MIME type
            - magic: Magic bytes pattern
            - group: File type group/category
            - is_text: Whether file is text-based
            - extensions: List of common extensions for this type
        """
        try:
            magika = self._get_magika()
            
            # Analyze the file
            result = magika.identify_path(Path(file_path))
            
            metadata = {
                'label': result.output.ct_label,
                'score': float(result.output.score),
                'mime_type': result.output.mime_type,
                'group': result.output.group,
                'description': result.output.description if hasattr(result.output, 'description') else None,
                'magic': result.output.magic if hasattr(result.output, 'magic') else None,
                'is_text': result.output.is_text if hasattr(result.output, 'is_text') else None,
            }
            
            # Add extensions if available
            if hasattr(result.output, 'extensions'):
                metadata['extensions'] = result.output.extensions
            
            logger.info(f"Magika analysis completed: {metadata['label']} (score: {metadata['score']:.3f})")
            return metadata
            
        except Exception as e:
            logger.error(f"Magika analysis failed for {file_path}: {e}", exc_info=True)
            return {
                'label': None,
                'score': None,
                'mime_type': None,
                'group': None,
                'description': f"Analysis failed: {str(e)}",
                'magic': None,
                'is_text': None,
                'extensions': None
            }
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """Perform Magika file type detection"""
        magika_metadata = self.extract_magika_metadata(str(file_path))
        
        if magika_metadata:
            return {
                "success": True,
                "magika_metadata": magika_metadata
            }
        else:
            return {
                "success": False,
                "error": "Magika analysis failed"
            }
    
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """Save Magika analysis results to database"""
        magika_metadata = analysis_result.get("magika_metadata", {})
        
        # Get or create Magika analysis record
        magika_analysis = self.db.query(MagikaAnalysis).filter(
            MagikaAnalysis.sha512 == sample.sha512
        ).first()
        
        if not magika_analysis:
            magika_analysis = MagikaAnalysis(sha512=sample.sha512)
            self.db.add(magika_analysis)
        
        # Update Magika analysis with results (including timestamp)
        magika_analysis.analysis_date = datetime.utcnow()
        magika_analysis.label = magika_metadata.get('label')
        magika_analysis.score = f"{magika_metadata.get('score'):.4f}" if magika_metadata.get('score') is not None else None
        magika_analysis.mime_type = magika_metadata.get('mime_type')
        magika_analysis.group = magika_metadata.get('group')
        magika_analysis.description = magika_metadata.get('description')
        magika_analysis.is_text = magika_metadata.get('is_text')
        
        logger.info(f"Magika result: {magika_analysis.label} (score: {magika_analysis.score})")
        
        self.db.commit()
    
    def run_analysis(self, sha512: str) -> Dict[str, Any]:
        """
        Override run_analysis to skip AnalysisStatus updates (Magika doesn't use them).
        This provides a simpler workflow for Magika.
        """
        logger.info(f"Starting {self.task_name} analysis for sample: {sha512}")
        
        try:
            # Get sample from database
            sample = self.get_sample_from_db(sha512)
            if not sample:
                return {
                    "success": False,
                    "error": "Sample not found"
                }
            
            # Get file path and validate it exists
            file_path = self.get_file_path(sample)
            if not self.validate_file_exists(file_path):
                return {
                    "success": False,
                    "error": "Sample file not found in storage"
                }
            
            # Perform the analysis
            logger.info(f"Running {self.task_name} analysis on {sample.filename}")
            analysis_result = self.perform_analysis(sample, file_path)
            
            # Check if analysis was successful
            if not analysis_result or not analysis_result.get("success", False):
                error_msg = analysis_result.get("error", "Analysis failed") if analysis_result else "Analysis failed"
                logger.warning(f"{self.task_name} analysis failed: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg
                }
            
            # Save results to database
            self.save_analysis_results(sample, analysis_result)
            
            logger.info(f"{self.task_name} analysis completed for sample: {sha512}")
            return {
                "success": True,
                "sha512": sha512,
                **analysis_result
            }
            
        except Exception as e:
            logger.error(f"Error in {self.task_name} analysis task: {e}", exc_info=True)
            if self.db:
                self.db.rollback()
            return {
                "success": False,
                "error": str(e)
            }


@celery_app.task(base=MagikaAnalysisTask, bind=True, name='app.workers.tasks.magika_task')
def analyze_sample_with_magika(self, sha512: str) -> Dict[str, Any]:
    """
    Perform Magika analysis on a malware sample
    
    Args:
        sha512: SHA512 hash of the sample to analyze
        
    Returns:
        Dictionary with analysis results
    """
    return self.run_analysis(sha512)
