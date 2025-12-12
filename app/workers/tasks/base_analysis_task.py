"""
Base class for analysis tasks with common functionality
"""
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
from app.models import MalwareSample, AnalysisStatus, FileType
from app.workers.tasks.database_task import DatabaseTask

logger = logging.getLogger(__name__)


class AnalysisTask(DatabaseTask, ABC):
    """
    Base class for file analysis tasks.
    
    Provides common functionality for:
    - Sample retrieval
    - Status management
    - File type validation
    - File path resolution
    - Error handling
    - Analysis record management
    """
    
    @property
    @abstractmethod
    def task_name(self) -> str:
        """Return the human-readable name of this analysis task"""
        pass
    
    @abstractmethod
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        """
        Return list of supported file types, or None if all types are supported.
        
        Returns:
            List of FileType enums, or None for universal support
        """
        pass
    
    @abstractmethod
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """
        Perform the actual analysis.
        
        Args:
            sample: The MalwareSample object from database
            file_path: Full path to the sample file in storage
            
        Returns:
            Dictionary with analysis results
        """
        pass
    
    @abstractmethod
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """
        Save analysis results to database.
        
        Args:
            sample: The MalwareSample object
            analysis_result: Results from perform_analysis
        """
        pass
    
    def get_sample_from_db(self, sha512: str) -> Optional[MalwareSample]:
        """
        Retrieve sample from database by SHA512.
        
        Args:
            sha512: SHA512 hash of the sample
            
        Returns:
            MalwareSample object or None if not found
        """
        sample = self.db.query(MalwareSample).filter(
            MalwareSample.sha512 == sha512
        ).first()
        
        if not sample:
            logger.error(f"Sample not found: {sha512}")
        
        return sample
    
    def is_file_type_supported(self, sample: MalwareSample) -> bool:
        """
        Check if the sample's file type is supported by this analyzer.
        
        Args:
            sample: The MalwareSample object
            
        Returns:
            True if supported, False otherwise
        """
        supported_types = self.get_supported_file_types()
        
        # None means all types are supported
        if supported_types is None:
            return True
        
        return sample.file_type in supported_types
    
    def get_file_path(self, sample: MalwareSample) -> str:
        """
        Get the full file path for a sample.
        
        Args:
            sample: The MalwareSample object
            
        Returns:
            Full path to the sample file
        """
        if Path(sample.storage_path).is_absolute():
            return sample.storage_path
        else:
            return str(self.storage.storage_path / sample.storage_path)
    
    def validate_file_exists(self, file_path: str) -> bool:
        """
        Check if file exists at the given path.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file exists, False otherwise
        """
        exists = Path(file_path).exists()
        if not exists:
            logger.error(f"Sample file not found in storage: {file_path}")
        return exists
    
    def update_sample_status(self, sample: MalwareSample, status: AnalysisStatus) -> None:
        """
        Update the analysis status of a sample.
        
        Args:
            sample: The MalwareSample object
            status: New AnalysisStatus value
        """
        sample.analysis_status = status
        self.db.commit()
        logger.debug(f"Updated sample {sample.sha512} status to {status.value}")
    
    def handle_analysis_error(self, sha512: str, error: Exception) -> Dict[str, Any]:
        """
        Handle analysis errors by updating sample status and logging.
        
        Args:
            sha512: SHA512 of the sample
            error: The exception that occurred
            
        Returns:
            Error result dictionary
        """
        logger.error(f"Error in {self.task_name} analysis task: {error}", exc_info=True)
        
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
            "error": str(error)
        }
    
    def run_analysis(self, sha512: str) -> Dict[str, Any]:
        """
        Main analysis workflow that all tasks follow.
        
        Args:
            sha512: SHA512 hash of the sample to analyze
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting {self.task_name} analysis for sample: {sha512}")
        
        try:
            # Step 1: Get sample from database
            sample = self.get_sample_from_db(sha512)
            if not sample:
                return {
                    "success": False,
                    "error": "Sample not found"
                }
            
            # Step 2: Update status to analyzing
            self.update_sample_status(sample, AnalysisStatus.ANALYZING)
            
            # Step 3: Check if file type is supported
            if not self.is_file_type_supported(sample):
                logger.info(f"Skipping {self.task_name} analysis for file type: {sample.file_type}")
                self.update_sample_status(sample, AnalysisStatus.SKIPPED)
                return {
                    "success": False,
                    "error": f"{self.task_name} analysis not supported for file type: {sample.file_type}"
                }
            
            # Step 4: Get file path and validate it exists
            file_path = self.get_file_path(sample)
            if not self.validate_file_exists(file_path):
                self.update_sample_status(sample, AnalysisStatus.FAILED)
                return {
                    "success": False,
                    "error": "Sample file not found in storage"
                }
            
            # Step 5: Perform the analysis (delegated to subclass)
            logger.info(f"Running {self.task_name} analysis on {sample.filename}")
            analysis_result = self.perform_analysis(sample, file_path)
            
            # Step 6: Check if analysis was successful
            if not analysis_result or not analysis_result.get("success", False):
                error_msg = analysis_result.get("error", "Analysis failed") if analysis_result else "Analysis failed"
                logger.warning(f"{self.task_name} analysis failed: {error_msg}")
                self.update_sample_status(sample, AnalysisStatus.FAILED)
                return {
                    "success": False,
                    "error": error_msg
                }
            
            # Step 7: Save results to database (delegated to subclass)
            self.save_analysis_results(sample, analysis_result)
            
            # Step 8: Update status to completed
            self.update_sample_status(sample, AnalysisStatus.COMPLETED)
            
            logger.info(f"{self.task_name} analysis completed for sample: {sha512}")
            return {
                "success": True,
                "sha512": sha512,
                **analysis_result
            }
            
        except Exception as e:
            return self.handle_analysis_error(sha512, e)
