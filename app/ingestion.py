import tempfile
import json
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from datetime import datetime
from app.models import MalwareSample, FileType, AnalysisStatus
from app.utils import (
    calculate_hashes,
    get_file_type_from_magic,
    determine_file_type,
    calculate_entropy,
    extract_strings,
    get_storage_path
)
from app.pe_analyzer import extract_pe_metadata
from app.elf_analyzer import extract_elf_metadata
from app.storage import FileStorage
from app.archive_utils import is_archive, extract_archive
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)


class IngestionService:
    """Service for ingesting malware samples"""
    
    def __init__(self, storage: FileStorage, enable_capa: bool = True):
        self.storage = storage
        self.enable_capa = enable_capa
        logger.info(f"IngestionService initialized. CAPA analysis will be {'queued asynchronously' if enable_capa else 'disabled'}.")
    
    def ingest_file(self, file_content: bytes, filename: str, db: Session, 
                    tags: list = None, family: str = None, 
                    classification: str = None, notes: str = None,
                    archive_password: Optional[str] = None,
                    parent_archive_sha512: Optional[str] = None,
                    source_url: Optional[str] = None) -> Tuple[MalwareSample, List[MalwareSample]]:
        """
        Ingest a malware file and extract metadata
        
        Args:
            file_content: Raw file bytes
            filename: Original filename
            db: Database session
            tags: Optional list of tags
            family: Optional malware family
            classification: Optional classification
            notes: Optional notes
            archive_password: Optional password for encrypted archives
            parent_archive_sha512: SHA512 of parent archive if this file was extracted
            source_url: Optional URL where the sample was downloaded from
            
        Returns:
            Tuple of (main_sample, extracted_samples)
            main_sample: MalwareSample object for the uploaded file
            extracted_samples: List of MalwareSample objects for files extracted from archive (empty if not an archive)
        """
        # Calculate hashes
        hashes = calculate_hashes(file_content)
        sha512 = hashes['sha512']
        
        # Check if file already exists
        existing = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
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
            db.commit()
            db.refresh(existing)
            # If archive, still process extracted files
            if existing.is_archive == "true":
                extracted_samples = self._process_archive(
                    file_content, filename, sha512, db, 
                    archive_password, tags, family, classification
                )
                return existing, extracted_samples
            return existing, []
        
        # Get MIME type and description
        mime_type, magic_description = get_file_type_from_magic(file_content)
        
        # Determine file type - use determine_file_type which prioritizes executables over archives
        # Pass file_content for dynamic detection with filetype package
        file_type = determine_file_type(mime_type, magic_description, file_content)
        
        # Check if this is an archive using is_archive() function for extraction logic
        # But only consider it a true archive if determine_file_type didn't detect it as executable
        is_archive_file = (file_type == 'archive') or (
            is_archive(mime_type, magic_description, filename) and file_type not in ['pe', 'elf', 'macho']
        )
        
        # Calculate entropy
        entropy = calculate_entropy(file_content)
        
        # Extract strings
        strings_count = extract_strings(file_content)
        
        # Create sample object
        sample = MalwareSample(
            sha512=sha512,
            sha256=hashes['sha256'],
            sha1=hashes['sha1'],
            md5=hashes['md5'],
            filename=filename,
            file_size=len(file_content),
            file_type=FileType(file_type),
            mime_type=mime_type,
            magic_description=magic_description,
            entropy=f"{entropy:.2f}",
            strings_count=strings_count,
            tags=json.dumps(tags or []),
            family=family,
            classification=classification,
            notes=notes,
            storage_path=get_storage_path(sha512),
            is_archive="true" if is_archive_file else "false",
            parent_archive_sha512=parent_archive_sha512,
            extracted_file_count=0,  # Will be updated if extraction occurs
            source_url=source_url
        )
        
        # Extract type-specific metadata
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        try:
            if file_type == 'pe':
                pe_metadata = extract_pe_metadata(tmp_path)
                sample.pe_imphash = pe_metadata.get('imphash')
                if pe_metadata.get('compilation_timestamp'):
                    from datetime import datetime
                    sample.pe_compilation_timestamp = datetime.fromisoformat(
                        pe_metadata['compilation_timestamp']
                    )
                sample.pe_entry_point = pe_metadata.get('entry_point')
                sample.pe_sections = pe_metadata.get('sections')
                sample.pe_imports = pe_metadata.get('imports')
                sample.pe_exports = pe_metadata.get('exports')
            
            elif file_type == 'elf':
                elf_metadata = extract_elf_metadata(tmp_path)
                sample.elf_machine = elf_metadata.get('machine')
                sample.elf_entry_point = elf_metadata.get('entry_point')
                sample.elf_sections = elf_metadata.get('sections')
            
            # Queue CAPA analysis for PE and ELF files (async)
            if self.enable_capa and file_type in ['pe', 'elf']:
                logger.info(f"Queuing CAPA analysis for {filename}")
                sample.analysis_status = AnalysisStatus.PENDING
            else:
                # Mark as skipped for non-PE/ELF files
                sample.analysis_status = AnalysisStatus.SKIPPED
                
        finally:
            Path(tmp_path).unlink()
        
        # Save file to storage
        self.storage.save_file(file_content, sample.storage_path)
        
        # Save to database
        db.add(sample)
        db.commit()
        db.refresh(sample)
        
        # Process archive if applicable
        extracted_samples = []
        if is_archive_file:
            extracted_samples = self._process_archive(
                file_content, filename, sha512, db, 
                archive_password, tags, family, classification
            )
        
        # Queue async CAPA analysis if needed
        if sample.analysis_status == AnalysisStatus.PENDING:
            try:
                from app.tasks import analyze_sample_with_capa
                task = analyze_sample_with_capa.delay(sample.sha512)
                sample.analysis_task_id = task.id
                db.commit()
                logger.info(f"CAPA analysis task queued: {task.id}")
            except Exception as e:
                logger.error(f"Failed to queue CAPA analysis: {e}")
                sample.analysis_status = AnalysisStatus.FAILED
                db.commit()
        
        return sample, extracted_samples
    
    def _process_archive(
        self,
        archive_content: bytes,
        archive_filename: str,
        archive_sha512: str,
        db: Session,
        password: Optional[str] = None,
        tags: list = None,
        family: str = None,
        classification: str = None
    ) -> List[MalwareSample]:
        """
        Extract and process files from an archive
        
        Args:
            archive_content: Raw archive bytes
            archive_filename: Original archive filename
            archive_sha512: SHA512 hash of the archive
            db: Database session
            password: Optional password for encrypted archives
            tags: Optional tags to apply to extracted files
            family: Optional family to apply to extracted files
            classification: Optional classification to apply to extracted files
            
        Returns:
            List of MalwareSample objects for extracted files
        """
        logger.info(f"Processing archive: {archive_filename}")
        
        # Extract files from archive
        success, extracted_files, error_msg = extract_archive(
            archive_content,
            archive_filename,
            password
        )
        
        if not success:
            logger.error(f"Failed to extract archive {archive_filename}: {error_msg}")
            # We still want to store the archive itself, just log the extraction failure
            return []
        
        extracted_samples = []
        for extracted_file in extracted_files:
            try:
                # Recursively ingest the extracted file
                # Note: This will handle nested archives automatically
                # Parent archive relationship is shown in the relations tab
                extracted_sample, nested_samples = self.ingest_file(
                    file_content=extracted_file['content'],
                    filename=extracted_file['filename'],
                    db=db,
                    tags=tags,
                    family=family,
                    classification=classification,
                    notes=None,  # No notes needed - parent shown in relations tab
                    archive_password=password,  # Try same password for nested archives
                    parent_archive_sha512=archive_sha512
                )
                
                extracted_samples.append(extracted_sample)
                extracted_samples.extend(nested_samples)  # Add any nested extracted files
                
            except Exception as e:
                logger.error(f"Failed to ingest extracted file {extracted_file['filename']}: {e}")
                continue
        
        # Update the archive sample with extraction count
        archive_sample = db.query(MalwareSample).filter(
            MalwareSample.sha512 == archive_sha512
        ).first()
        
        if archive_sample:
            archive_sample.extracted_file_count = len(extracted_samples)
            db.commit()
        
        logger.info(f"Extracted and processed {len(extracted_samples)} files from {archive_filename}")
        return extracted_samples
    
    def run_capa_analysis(self, sample: MalwareSample, db: Session) -> tuple[bool, str]:
        """
        Queue CAPA analysis on an existing sample
        
        Args:
            sample: MalwareSample object
            db: Database session
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.enable_capa:
            logger.warning("CAPA analyzer is not available")
            return False, "CAPA analyzer is not available"
        
        # Only analyze PE and ELF files
        if sample.file_type not in [FileType.PE, FileType.ELF]:
            logger.info(f"Skipping CAPA analysis for file type: {sample.file_type}")
            return False, f"CAPA analysis not supported for file type: {sample.file_type}"
        
        try:
            # Queue async CAPA analysis
            from app.tasks import analyze_sample_with_capa
            
            sample.analysis_status = AnalysisStatus.PENDING
            db.commit()
            
            task = analyze_sample_with_capa.delay(sample.sha512)
            sample.analysis_task_id = task.id
            db.commit()
            
            logger.info(f"CAPA analysis task queued: {task.id}")
            return True, f"Analysis queued with task ID: {task.id}"
                
        except Exception as e:
            logger.error(f"Error queuing CAPA analysis: {e}")
            sample.analysis_status = AnalysisStatus.FAILED
            db.commit()
            return False, str(e)
