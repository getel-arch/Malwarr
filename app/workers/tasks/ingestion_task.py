"""
Celery task for file ingestion
"""
import base64
import json
import tempfile
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from app.workers.celery_app import celery_app
from app.workers.tasks.database_task import DatabaseTask
from app.models import MalwareSample, MagikaAnalysis, FileType, AnalysisStatus
from app.utils import (
    calculate_hashes,
    get_file_type_from_magic,
    determine_file_type,
    get_storage_path
)
from app.workers.tasks.magika_task import MagikaAnalysisTask

logger = logging.getLogger(__name__)


class IngestionTask(DatabaseTask):
    """File ingestion task"""
    
    def ingest_file(
        self,
        file_content: bytes,
        filename: str,
        tags: Optional[List[str]] = None,
        family: Optional[str] = None,
        classification: Optional[str] = None,
        notes: Optional[str] = None,
        archive_password: Optional[str] = None,
        parent_archive_sha512: Optional[str] = None,
        source_url: Optional[str] = None
    ) -> Tuple[MalwareSample, List[MalwareSample]]:
        """
        Ingest a malware file and extract metadata
        
        Args:
            file_content: Raw file bytes
            filename: Original filename
            tags: Optional list of tags
            family: Optional malware family
            classification: Optional classification
            notes: Optional notes
            archive_password: Optional password for encrypted archives
            parent_archive_sha512: SHA512 of parent archive if this file was extracted
            source_url: Optional URL where the sample was downloaded from
            
        Returns:
            Tuple of (main_sample, extracted_samples)
        """
        # Calculate hashes
        hashes = calculate_hashes(file_content)
        sha512 = hashes['sha512']
        
        # Check if file already exists
        existing = self.db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
        if existing:
            # Update metadata if provided
            if tags:
                existing.tags = json.dumps(tags)
            if family:
                existing.family = family
            if classification:
                existing.classification = classification
            if notes:
                existing.notes = notes
            self.db.commit()
            self.db.refresh(existing)
            # If archive, queue extraction task
            if existing.is_archive == "true" and archive_password:
                from app.workers.tasks import extract_archive_task
                try:
                    task = extract_archive_task.delay(
                        archive_sha512=sha512,
                        archive_password=archive_password,
                        tags=tags,
                        family=family,
                        classification=classification
                    )
                    logger.info(f"Archive extraction task queued for existing archive: {task.id}")
                except Exception as e:
                    logger.error(f"Failed to queue archive extraction: {e}")
            return existing, []
        
        # Get MIME type and description
        mime_type, magic_description = get_file_type_from_magic(file_content)
        
        # Determine file type
        file_type = determine_file_type(mime_type, magic_description, file_content)
        
        # Run Magika analysis first to determine if file is an archive
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        magika_metadata = None
        is_archive_file = False
        
        try:
            try:
                # Create a MagikaAnalysisTask instance to use its method
                magika_task = MagikaAnalysisTask()
                magika_metadata = magika_task.extract_magika_metadata(tmp_path)
                
                # Use Magika's file group to determine if this is an archive
                magika_group = magika_metadata.get('group', '').lower()
                is_archive_file = (magika_group == 'archive') or (file_type == 'archive')
                
                logger.info(f"Magika detected group: {magika_group}, is_archive: {is_archive_file}")
            except Exception as e:
                logger.warning(f"Magika analysis failed: {e}")
                # Fallback: if Magika fails, use file_type
                is_archive_file = (file_type == 'archive')
            
            # Create sample object with archive determination from Magika
            sample = MalwareSample(
                sha512=sha512,
                sha256=hashes['sha256'],
                sha1=hashes['sha1'],
                md5=hashes['md5'],
                filename=filename,
                file_size=len(file_content),
                file_type=FileType(file_type),
                tags=json.dumps(tags or []),
                family=family,
                classification=classification,
                notes=notes,
                storage_path=get_storage_path(sha512),
                is_archive="true" if is_archive_file else "false",
                parent_archive_sha512=parent_archive_sha512,
                extracted_file_count=0,
                source_url=source_url
            )
            
            # Save Magika analysis results if available
            if magika_metadata:
                magika_analysis = self.db.query(MagikaAnalysis).filter(
                    MagikaAnalysis.sha512 == sample.sha512
                ).first()
                
                if not magika_analysis:
                    magika_analysis = MagikaAnalysis(
                        sha512=sample.sha512,
                        analysis_date=datetime.utcnow()
                    )
                    self.db.add(magika_analysis)
                
                magika_analysis.label = magika_metadata.get('label')
                magika_analysis.score = f"{magika_metadata.get('score'):.4f}" if magika_metadata.get('score') is not None else None
                magika_analysis.mime_type = magika_metadata.get('mime_type')
                magika_analysis.group = magika_metadata.get('group')
                magika_analysis.description = magika_metadata.get('description')
                magika_analysis.is_text = magika_metadata.get('is_text')
                magika_analysis.analysis_date = datetime.utcnow()
                
                logger.info(f"Magika analysis completed: {magika_analysis.label}")
            
            if file_type not in ['pe', 'elf']:
                sample.analysis_status = AnalysisStatus.SKIPPED
                
        finally:
            Path(tmp_path).unlink()
        
        # Save file to storage
        self.storage.save_file(file_content, sample.storage_path)
        
        # Save to database
        self.db.add(sample)
        self.db.commit()
        self.db.refresh(sample)
        
        # Queue analysis tasks
        if file_type == 'pe':
            from app.workers.tasks import analyze_sample_with_pe
            try:
                task = analyze_sample_with_pe.delay(sample.sha512)
                sample.analysis_task_id = task.id
                self.db.commit()
                logger.info(f"PE analysis task queued: {task.id}")
            except Exception as e:
                logger.error(f"Failed to queue PE analysis: {e}")
                sample.analysis_status = AnalysisStatus.FAILED
                self.db.commit()

        elif file_type == 'elf':
            from app.workers.tasks import analyze_sample_with_elf
            try:
                task = analyze_sample_with_elf.delay(sample.sha512)
                sample.analysis_task_id = task.id
                self.db.commit()
                logger.info(f"ELF analysis task queued: {task.id}")
            except Exception as e:
                logger.error(f"Failed to queue ELF analysis: {e}")
                sample.analysis_status = AnalysisStatus.FAILED
                self.db.commit()

        # Queue CAPA analysis for PE and ELF files
        if file_type in ['pe', 'elf']:
            from app.workers.tasks import analyze_sample_with_capa
            try:
                task = analyze_sample_with_capa.delay(sample.sha512)
                sample.analysis_task_id = task.id
                self.db.commit()
                logger.info(f"CAPA analysis task queued: {task.id}")
            except Exception as e:
                logger.error(f"Failed to queue CAPA analysis: {e}")

        # Queue VirusTotal analysis
        from app.workers.tasks import analyze_sample_with_virustotal
        try:
            task = analyze_sample_with_virustotal.delay(sample.sha512)
            logger.info(f"VirusTotal analysis task queued: {task.id}")
        except Exception as e:
            logger.error(f"Failed to queue VirusTotal analysis: {e}")

        # Queue Strings analysis
        from app.workers.tasks import analyze_sample_with_strings
        try:
            task = analyze_sample_with_strings.delay(sample.sha512)
            logger.info(f"Strings analysis task queued: {task.id}")
        except Exception as e:
            logger.error(f"Failed to queue Strings analysis: {e}")
        
        # Queue archive extraction if applicable
        if is_archive_file:
            from app.workers.tasks import extract_archive_task
            try:
                task = extract_archive_task.delay(
                    archive_sha512=sha512,
                    archive_password=archive_password,
                    tags=tags,
                    family=family,
                    classification=classification
                )
                logger.info(f"Archive extraction task queued: {task.id}")
            except Exception as e:
                logger.error(f"Failed to queue archive extraction: {e}")
        
        return sample, []
    
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
        Ingest a file into the system (Celery task wrapper)
        
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
            Dict with sample info
        """
        try:
            # Decode file content
            file_content = base64.b64decode(file_content_base64)
            
            # Ingest the file
            logger.info(f"Starting ingestion of {filename}")
            sample, _ = self.ingest_file(
                file_content=file_content,
                filename=filename,
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
                "extracted_count": 0
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
