import tempfile
import json
from typing import Dict, Any, Optional
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
                    classification: str = None, notes: str = None) -> MalwareSample:
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
            
        Returns:
            MalwareSample object
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
            return existing
        
        # Get MIME type and description
        mime_type, magic_description = get_file_type_from_magic(file_content)
        file_type = determine_file_type(mime_type, magic_description)
        
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
            storage_path=get_storage_path(sha512)
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
        
        return sample
    
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
