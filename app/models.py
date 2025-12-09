from sqlalchemy import Column, String, Integer, DateTime, BigInteger, Text, Enum, Boolean
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
    
    # PE Header information
    pe_machine = Column(String(100))
    pe_number_of_sections = Column(Integer)
    pe_characteristics = Column(String(20))
    pe_magic = Column(String(10))
    pe_image_base = Column(String(20))
    pe_subsystem = Column(String(100))
    pe_dll_characteristics = Column(String(20))
    pe_checksum = Column(String(20))
    pe_size_of_image = Column(Integer)
    pe_size_of_headers = Column(Integer)
    pe_base_of_code = Column(String(20))
    
    # PE Version information
    pe_linker_version = Column(String(20))
    pe_os_version = Column(String(20))
    pe_image_version = Column(String(20))
    pe_subsystem_version = Column(String(20))
    
    # PE Import/Export counts
    pe_import_dll_count = Column(Integer)
    pe_imported_functions_count = Column(Integer)
    pe_export_count = Column(Integer)
    
    # PE Resources
    pe_resources = Column(Text)
    pe_resource_count = Column(Integer)
    
    # PE Version info (embedded in binary)
    pe_version_info = Column(Text)
    
    # PE Debug info
    pe_debug_info = Column(Text)
    
    # PE TLS
    pe_tls_info = Column(Text)
    
    # PE Rich header
    pe_rich_header = Column(Text)
    
    # PE Digital signature
    pe_is_signed = Column(Boolean, default=False)
    pe_signature_info = Column(Text)
    
    # ELF specific metadata
    elf_machine = Column(String(50))
    elf_entry_point = Column(String(20))
    elf_file_class = Column(String(20))  # 32-bit or 64-bit
    elf_data_encoding = Column(String(20))  # Endianness
    elf_os_abi = Column(String(50))
    elf_abi_version = Column(Integer)
    elf_type = Column(String(50))
    elf_version = Column(String(20))
    elf_flags = Column(String(20))
    elf_header_size = Column(Integer)
    elf_program_header_offset = Column(String(20))
    elf_section_header_offset = Column(String(20))
    elf_program_header_entry_size = Column(Integer)
    elf_program_header_count = Column(Integer)
    elf_section_header_entry_size = Column(Integer)
    elf_section_header_count = Column(Integer)
    elf_sections = Column(Text)  # JSON array of sections
    elf_section_count = Column(Integer)
    elf_segments = Column(Text)  # JSON array of program headers/segments
    elf_segment_count = Column(Integer)
    elf_interpreter = Column(String(255))  # Dynamic linker/interpreter path
    elf_dynamic_tags = Column(Text)  # JSON array of dynamic tags
    elf_shared_libraries = Column(Text)  # JSON array of shared library dependencies
    elf_shared_library_count = Column(Integer)
    elf_symbols = Column(Text)  # JSON array of symbols
    elf_symbol_count = Column(Integer)
    elf_relocations = Column(Text)  # JSON array of relocations
    elf_relocation_count = Column(Integer)
    
    # Magika deep learning-based file type detection
    magika_label = Column(String(100))  # Detected file type label
    magika_score = Column(String(10))  # Confidence score (0-1)
    magika_mime_type = Column(String(100))  # Detected MIME type
    magika_group = Column(String(100))  # File type group/category
    magika_description = Column(Text)  # Human-readable description
    magika_is_text = Column(Boolean)  # Whether file is text-based
    
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
