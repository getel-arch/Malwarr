from sqlalchemy import Column, String, Integer, DateTime, BigInteger, Text, Enum, Boolean, ForeignKey
from sqlalchemy.orm import relationship
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
    """Malware sample model - core file information only"""
    
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
    parent_archive_sha512 = Column(String(128), index=True)
    extracted_file_count = Column(Integer, default=0)
    
    # Source information
    source_url = Column(String(2048))
    
    # Storage location (relative path from storage root)
    storage_path = Column(String(255), nullable=False)
    
    # Analysis status tracking for async tasks
    analysis_status = Column(Enum(AnalysisStatus), default=AnalysisStatus.PENDING)
    analysis_task_id = Column(String(255))  # Celery task ID for tracking
    
    # Relationships to analyzer results
    pe_analysis = relationship("PEAnalysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    elf_analysis = relationship("ELFAnalysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    capa_analysis = relationship("CAPAAnalysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    magika_analysis = relationship("MagikaAnalysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    virustotal_analysis = relationship("VirusTotalAnalysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    strings_analysis = relationship("StringsAnalysis", back_populates="sample", uselist=False, cascade="all, delete-orphan")


class PEAnalysis(Base):
    """PE (Portable Executable) file analysis results"""
    
    __tablename__ = "pe_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sha512 = Column(String(128), ForeignKey("malware_samples.sha512", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # PE specific metadata
    imphash = Column(String(32), index=True)
    compilation_timestamp = Column(DateTime)
    entry_point = Column(String(20))
    sections = Column(Text)  # JSON array of sections
    imports = Column(Text)  # JSON array of imports
    exports = Column(Text)  # JSON array of exports
    
    # PE Header information
    machine = Column(String(100))
    number_of_sections = Column(Integer)
    characteristics = Column(String(20))
    magic = Column(String(10))
    image_base = Column(String(20))
    subsystem = Column(String(100))
    dll_characteristics = Column(String(20))
    checksum = Column(String(20))
    size_of_image = Column(Integer)
    size_of_headers = Column(Integer)
    base_of_code = Column(String(20))
    
    # PE Version information
    linker_version = Column(String(20))
    os_version = Column(String(20))
    image_version = Column(String(20))
    subsystem_version = Column(String(20))
    
    # PE Import/Export counts
    import_dll_count = Column(Integer)
    imported_functions_count = Column(Integer)
    export_count = Column(Integer)
    
    # PE Resources
    resources = Column(Text)
    resource_count = Column(Integer)
    
    # PE Version info (embedded in binary)
    version_info = Column(Text)
    
    # PE Debug info
    debug_info = Column(Text)
    
    # PE TLS
    tls_info = Column(Text)
    
    # PE Rich header
    rich_header = Column(Text)
    
    # PE Digital signature
    is_signed = Column(Boolean, default=False)
    signature_info = Column(Text)
    
    # Timestamps
    analysis_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    sample = relationship("MalwareSample", back_populates="pe_analysis")


class ELFAnalysis(Base):
    """ELF (Executable and Linkable Format) file analysis results"""
    
    __tablename__ = "elf_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sha512 = Column(String(128), ForeignKey("malware_samples.sha512", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # ELF specific metadata
    machine = Column(String(50))
    entry_point = Column(String(20))
    file_class = Column(String(20))  # 32-bit or 64-bit
    data_encoding = Column(String(20))  # Endianness
    os_abi = Column(String(50))
    abi_version = Column(Integer)
    elf_type = Column(String(50))
    version = Column(String(20))
    flags = Column(String(20))
    header_size = Column(Integer)
    program_header_offset = Column(String(20))
    section_header_offset = Column(String(20))
    program_header_entry_size = Column(Integer)
    program_header_count = Column(Integer)
    section_header_entry_size = Column(Integer)
    section_header_count = Column(Integer)
    sections = Column(Text)  # JSON array of sections
    section_count = Column(Integer)
    segments = Column(Text)  # JSON array of program headers/segments
    segment_count = Column(Integer)
    interpreter = Column(String(255))  # Dynamic linker/interpreter path
    dynamic_tags = Column(Text)  # JSON array of dynamic tags
    shared_libraries = Column(Text)  # JSON array of shared library dependencies
    shared_library_count = Column(Integer)
    symbols = Column(Text)  # JSON array of symbols
    symbol_count = Column(Integer)
    relocations = Column(Text)  # JSON array of relocations
    relocation_count = Column(Integer)
    
    # Timestamps
    analysis_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    sample = relationship("MalwareSample", back_populates="elf_analysis")


class MagikaAnalysis(Base):
    """Magika deep learning-based file type detection results"""
    
    __tablename__ = "magika_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sha512 = Column(String(128), ForeignKey("malware_samples.sha512", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # Magika detection results
    label = Column(String(100))  # Detected file type label
    score = Column(String(10))  # Confidence score (0-1)
    mime_type = Column(String(100))  # Detected MIME type
    group = Column(String(100))  # File type group/category
    description = Column(Text)  # Human-readable description
    is_text = Column(Boolean)  # Whether file is text-based
    
    # Timestamps
    analysis_date = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationship
    sample = relationship("MalwareSample", back_populates="magika_analysis")


class CAPAAnalysis(Base):
    """CAPA capability analysis results"""
    
    __tablename__ = "capa_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sha512 = Column(String(128), ForeignKey("malware_samples.sha512", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # CAPA analysis results
    capabilities = Column(Text)  # JSON object of capabilities by namespace
    attack = Column(Text)  # JSON array of ATT&CK techniques
    mbc = Column(Text)  # JSON array of MBC objectives
    result_document = Column(Text)  # Full CAPA result document JSON for CAPA Explorer
    total_capabilities = Column(Integer)
    
    # Timestamps
    analysis_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    sample = relationship("MalwareSample", back_populates="capa_analysis")


class VirusTotalAnalysis(Base):
    """VirusTotal scan results"""
    
    __tablename__ = "virustotal_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sha512 = Column(String(128), ForeignKey("malware_samples.sha512", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # VirusTotal metadata
    positives = Column(Integer)  # Number of positive detections
    total = Column(Integer)  # Total number of scanners
    scan_date = Column(DateTime)  # Date of last VT scan
    permalink = Column(String(512))  # Link to VT report
    scans = Column(Text)  # JSON object of individual scanner results
    detection_ratio = Column(String(20))  # e.g., "45/72"
    scan_id = Column(String(255))  # VT scan ID
    verbose_msg = Column(Text)  # VT verbose message
    
    # Timestamps
    analysis_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    sample = relationship("MalwareSample", back_populates="virustotal_analysis")


class StringsAnalysis(Base):
    """Strings extraction analysis results"""
    
    __tablename__ = "strings_analysis"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sha512 = Column(String(128), ForeignKey("malware_samples.sha512", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # Strings metadata
    ascii_strings = Column(Text)  # JSON array of ASCII strings
    unicode_strings = Column(Text)  # JSON array of Unicode strings
    ascii_count = Column(Integer)  # Count of ASCII strings
    unicode_count = Column(Integer)  # Count of Unicode strings
    total_count = Column(Integer)  # Total strings count
    min_length = Column(Integer, default=4)  # Minimum string length used
    
    # String statistics
    longest_string_length = Column(Integer)  # Length of longest string found
    average_string_length = Column(String(10))  # Average string length
    
    # Notable patterns (JSON arrays)
    urls = Column(Text)  # Extracted URLs
    ip_addresses = Column(Text)  # Extracted IP addresses
    file_paths = Column(Text)  # Extracted file paths
    registry_keys = Column(Text)  # Extracted Windows registry keys
    email_addresses = Column(Text)  # Extracted email addresses
    
    # Pattern counts
    url_count = Column(Integer, default=0)
    ip_count = Column(Integer, default=0)
    file_path_count = Column(Integer, default=0)
    registry_key_count = Column(Integer, default=0)
    email_count = Column(Integer, default=0)
    
    # Timestamps
    analysis_date = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationship
    sample = relationship("MalwareSample", back_populates="strings_analysis")
