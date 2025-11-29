from sqlalchemy import Column, String, Integer, DateTime, BigInteger, Text, Enum
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import datetime
from app.database import Base
import enum
import json


class FileType(str, enum.Enum):
    """Supported file types"""
    PE = "pe"  # Windows PE (exe, dll)
    ELF = "elf"  # Linux/Unix ELF
    MACHO = "macho"  # macOS Mach-O
    SCRIPT = "script"  # Scripts (bat, ps1, sh, etc.)
    ARCHIVE = "archive"  # Archives (zip, rar, etc.)
    DOCUMENT = "document"  # Documents (pdf, doc, etc.)
    OTHER = "other"


class AnalysisStatus(str, enum.Enum):
    """Analysis status for background tasks"""
    PENDING = "pending"  # Queued for analysis
    ANALYZING = "analyzing"  # Currently being analyzed
    COMPLETED = "completed"  # Analysis completed successfully
    FAILED = "failed"  # Analysis failed
    SKIPPED = "skipped"  # Analysis skipped (unsupported file type)


class MalwareSample(Base):
    """Malware sample model"""
    
    __tablename__ = "malware_samples"
    
    # Primary identifier - SHA512 of file content
    sha512 = Column(String(128), primary_key=True, index=True)
    
    # Other hashes
    sha256 = Column(String(64), index=True, nullable=False)
    sha1 = Column(String(40), index=True, nullable=False)
    md5 = Column(String(32), index=True, nullable=False)
    
    # File metadata
    filename = Column(String(255), nullable=False)
    file_size = Column(BigInteger, nullable=False)
    file_type = Column(Enum(FileType), nullable=False)
    mime_type = Column(String(100))
    
    # PE specific metadata
    pe_imphash = Column(String(32), index=True)
    pe_compilation_timestamp = Column(DateTime)
    pe_entry_point = Column(String(20))
    pe_sections = Column(Text)  # JSON array of sections
    pe_imports = Column(Text)  # JSON array of imports
    pe_exports = Column(Text)  # JSON array of exports
    
    # ELF specific metadata
    elf_machine = Column(String(50))
    elf_entry_point = Column(String(20))
    elf_sections = Column(Text)  # JSON array of sections
    
    # CAPA analysis results
    capa_capabilities = Column(Text)  # JSON object of capabilities by namespace
    capa_attack = Column(Text)  # JSON array of ATT&CK techniques
    capa_mbc = Column(Text)  # JSON array of MBC objectives
    capa_result_document = Column(Text)  # Full CAPA result document JSON for CAPA Explorer
    capa_analysis_date = Column(DateTime)
    capa_total_capabilities = Column(Integer)
    
    # Analysis status tracking for async tasks
    analysis_status = Column(Enum(AnalysisStatus), default=AnalysisStatus.PENDING)
    analysis_task_id = Column(String(255))  # Celery task ID for tracking
    
    # General metadata
    magic_description = Column(Text)
    strings_count = Column(Integer)
    entropy = Column(String(10))
    
    # Tags and classification
    tags = Column(Text)  # JSON array of tags
    family = Column(String(100))
    classification = Column(String(50))
    
    # External references
    virustotal_link = Column(String(255))
    malwarebazaar_link = Column(String(255))
    
    # Notes and description
    notes = Column(Text)
    
    # Timestamps
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    upload_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Archive relationships
    is_archive = Column(String(10), default="false")  # "true" or "false"
    parent_archive_sha512 = Column(String(128), index=True)  # SHA512 of parent archive if extracted from one
    extracted_file_count = Column(Integer, default=0)  # Number of files extracted from this archive
    
    # Source information
    source_url = Column(String(2048))  # URL where the sample was downloaded from (if applicable)
    
    # Storage location (relative path from storage root)
    storage_path = Column(String(255), nullable=False)
