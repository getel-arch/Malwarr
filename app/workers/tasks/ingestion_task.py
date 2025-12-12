"""
Celery task for file ingestion
"""
import base64
import logging
from typing import Dict, Any, Optional, List
from app.workers.celery_app import celery_app
from app.workers.tasks.database_task import DatabaseTask
from app.ingestion import IngestionService

logger = logging.getLogger(__name__)


class IngestionTask(DatabaseTask):
    """File ingestion task"""
    
    def __init__(self):
        super().__init__()
        self._ingestion_service = None
    
    @property
    def ingestion_service(self) -> IngestionService:
        """Lazy initialization of ingestion service"""
        if self._ingestion_service is None:
            self._ingestion_service = IngestionService(self.storage)
        return self._ingestion_service
    
    def run_ingestion(
        self,
        file_content_base64: str,
        filename: str,
        tags: Optional[List[str]] = None,
        family: Optional[str] = None,
        classification: Optional[str] = None,
        notes: Optional[str] = None,
        archive_password: Optional[str] = None,
        parent_archive_sha512: Optional[str] = None,
        source_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ingest a file into the system
        
        Args:
            file_content_base64: Base64-encoded file content
            filename: Original filename
            tags: Optional list of tags
            family: Optional malware family
            classification: Optional classification
            notes: Optional notes
            archive_password: Optional password for encrypted archives
            parent_archive_sha512: SHA512 of parent archive if this file was extracted
            source_url: Optional URL where the sample was downloaded from
            
        Returns:
            Dict with sample info and extracted samples
        """
        try:
            # Decode file content
            file_content = base64.b64decode(file_content_base64)
            
            # Ingest the file
            logger.info(f"Starting ingestion of {filename}")
            sample, extracted_samples = self.ingestion_service.ingest_file(
                file_content=file_content,
                filename=filename,
                db=self.db,
                tags=tags or [],
                family=family,
                classification=classification,
                notes=notes,
                archive_password=archive_password,
                parent_archive_sha512=parent_archive_sha512,
                source_url=source_url
            )
            
            logger.info(f"Successfully ingested {filename} - SHA512: {sample.sha512}")
            
            # Return sample info
            return {
                "sha512": sample.sha512,
                "filename": sample.filename,
                "file_type": sample.file_type.value if sample.file_type else None,
                "file_size": sample.file_size,
                "is_archive": sample.is_archive == "true",
                "extracted_count": len(extracted_samples),
                "extracted_samples": [
                    {
                        "sha512": s.sha512,
                        "filename": s.filename,
                        "file_type": s.file_type.value if s.file_type else None
                    }
                    for s in extracted_samples
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to ingest {filename}: {e}", exc_info=True)
            raise


@celery_app.task(base=IngestionTask, bind=True, name="ingest_file")
def ingest_file_task(
    self,
    file_content_base64: str,
    filename: str,
    tags: list = None,
    family: str = None,
    classification: str = None,
    notes: str = None,
    archive_password: str = None,
    parent_archive_sha512: str = None,
    source_url: str = None
):
    """
    Background task to ingest a file
    
    Args:
        file_content_base64: Base64-encoded file content
        filename: Original filename
        tags: Optional list of tags
        family: Optional malware family
        classification: Optional classification
        notes: Optional notes
        archive_password: Optional password for encrypted archives
        parent_archive_sha512: SHA512 of parent archive if this file was extracted
        source_url: Optional URL where the sample was downloaded from
        
    Returns:
        Dict with sample info and extracted samples
    """
    return self.run_ingestion(
        file_content_base64=file_content_base64,
        filename=filename,
        tags=tags,
        family=family,
        classification=classification,
        notes=notes,
        archive_password=archive_password,
        parent_archive_sha512=parent_archive_sha512,
        source_url=source_url
    )
