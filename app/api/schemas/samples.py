"""Malware sample schemas"""
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List
from app.models import FileType
import json


class PEAnalysisResponse(BaseModel):
    """Schema for PE analysis results"""
    imphash: Optional[str]
    compilation_timestamp: Optional[datetime]
    entry_point: Optional[str]
    sections: Optional[str]
    imports: Optional[str]
    exports: Optional[str]
    machine: Optional[str]
    number_of_sections: Optional[int]
    characteristics: Optional[str]
    magic: Optional[str]
    image_base: Optional[str]
    subsystem: Optional[str]
    dll_characteristics: Optional[str]
    checksum: Optional[str]
    size_of_image: Optional[int]
    size_of_headers: Optional[int]
    base_of_code: Optional[str]
    linker_version: Optional[str]
    os_version: Optional[str]
    image_version: Optional[str]
    subsystem_version: Optional[str]
    import_dll_count: Optional[int]
    imported_functions_count: Optional[int]
    export_count: Optional[int]
    resources: Optional[str]
    resource_count: Optional[int]
    version_info: Optional[str]
    debug_info: Optional[str]
    tls_info: Optional[str]
    rich_header: Optional[str]
    is_signed: Optional[bool]
    signature_info: Optional[str]
    analysis_date: datetime
    
    class Config:
        from_attributes = True


class ELFAnalysisResponse(BaseModel):
    """Schema for ELF analysis results"""
    machine: Optional[str]
    entry_point: Optional[str]
    file_class: Optional[str]
    data_encoding: Optional[str]
    os_abi: Optional[str]
    abi_version: Optional[int]
    elf_type: Optional[str]
    version: Optional[str]
    flags: Optional[str]
    header_size: Optional[int]
    program_header_offset: Optional[str]
    section_header_offset: Optional[str]
    program_header_entry_size: Optional[int]
    program_header_count: Optional[int]
    section_header_entry_size: Optional[int]
    section_header_count: Optional[int]
    sections: Optional[str]
    section_count: Optional[int]
    segments: Optional[str]
    segment_count: Optional[int]
    interpreter: Optional[str]
    dynamic_tags: Optional[str]
    shared_libraries: Optional[str]
    shared_library_count: Optional[int]
    symbols: Optional[str]
    symbol_count: Optional[int]
    relocations: Optional[str]
    relocation_count: Optional[int]
    analysis_date: datetime
    
    class Config:
        from_attributes = True


class MagikaAnalysisResponse(BaseModel):
    """Schema for Magika analysis results"""
    label: Optional[str]
    score: Optional[str]
    mime_type: Optional[str]
    group: Optional[str]
    description: Optional[str]
    is_text: Optional[bool]
    analysis_date: datetime
    
    class Config:
        from_attributes = True


class CAPAAnalysisResponse(BaseModel):
    """Schema for CAPA analysis results"""
    capabilities: Optional[str]
    attack: Optional[str]
    mbc: Optional[str]
    result_document: Optional[str]
    total_capabilities: Optional[int]
    analysis_date: datetime
    
    class Config:
        from_attributes = True


class VirusTotalAnalysisResponse(BaseModel):
    """Schema for VirusTotal analysis results"""
    positives: Optional[int]
    total: Optional[int]
    scan_date: Optional[datetime]
    permalink: Optional[str]
    scans: Optional[str]
    detection_ratio: Optional[str]
    scan_id: Optional[str]
    verbose_msg: Optional[str]
    analysis_date: datetime
    
    class Config:
        from_attributes = True


class StringsAnalysisResponse(BaseModel):
    """Schema for Strings analysis results"""
    ascii_strings: Optional[str]
    unicode_strings: Optional[str]
    ascii_count: Optional[int]
    unicode_count: Optional[int]
    total_count: Optional[int]
    min_length: Optional[int]
    longest_string_length: Optional[int]
    average_string_length: Optional[str]
    urls: Optional[str]
    ip_addresses: Optional[str]
    file_paths: Optional[str]
    registry_keys: Optional[str]
    email_addresses: Optional[str]
    url_count: Optional[int]
    ip_count: Optional[int]
    file_path_count: Optional[int]
    registry_key_count: Optional[int]
    email_count: Optional[int]
    analysis_date: datetime
    
    class Config:
        from_attributes = True


class MalwareSampleBase(BaseModel):
    """Base schema for malware sample"""
    filename: str
    tags: Optional[List[str]] = []
    family: Optional[str] = None
    classification: Optional[str] = None
    notes: Optional[str] = None
    archive_password: Optional[str] = None  # Password for encrypted archives


class MalwareSampleCreate(MalwareSampleBase):
    """Schema for creating a malware sample"""
    pass


class MalwareSampleURL(BaseModel):
    """Schema for uploading a malware sample from URL"""
    url: str = Field(..., description="URL to download the malware sample from")
    filename: Optional[str] = Field(None, description="Optional filename override")
    tags: Optional[List[str]] = []
    family: Optional[str] = None
    classification: Optional[str] = None
    notes: Optional[str] = None
    archive_password: Optional[str] = None  # Password for encrypted archives


class MalwareSampleUpdate(BaseModel):
    """Schema for updating a malware sample"""
    tags: Optional[List[str]] = None
    family: Optional[str] = None
    classification: Optional[str] = None
    notes: Optional[str] = None
    virustotal_link: Optional[str] = None
    malwarebazaar_link: Optional[str] = None


class MalwareSampleResponse(MalwareSampleBase):
    """Schema for malware sample response"""
    sha512: str
    sha256: str
    sha1: str
    md5: str
    file_size: int
    file_type: FileType
    mime_type: Optional[str]
    
    # Archive metadata
    is_archive: Optional[str]
    parent_archive_sha512: Optional[str]
    extracted_file_count: Optional[int]
    
    # Source information
    source_url: Optional[str]
    
    # Analysis results from separate tables
    pe_analysis: Optional[PEAnalysisResponse] = None
    elf_analysis: Optional[ELFAnalysisResponse] = None
    magika_analysis: Optional[MagikaAnalysisResponse] = None
    capa_analysis: Optional[CAPAAnalysisResponse] = None
    virustotal_analysis: Optional[VirusTotalAnalysisResponse] = None
    strings_analysis: Optional[StringsAnalysisResponse] = None
    
    # Analysis status
    analysis_status: Optional[str]
    analysis_task_id: Optional[str]
    
    # General metadata
    magic_description: Optional[str]
    strings_count: Optional[int]
    entropy: Optional[str]
    
    # External references
    virustotal_link: Optional[str]
    malwarebazaar_link: Optional[str]
    
    # Timestamps
    first_seen: datetime
    last_updated: datetime
    upload_date: datetime
    
    storage_path: str
    
    @field_validator('tags', mode='before')
    @classmethod
    def parse_tags(cls, v):
        """Convert JSON string to list if needed"""
        if isinstance(v, str):
            try:
                return json.loads(v) if v else []
            except json.JSONDecodeError:
                return []
        return v if v is not None else []
    
    class Config:
        from_attributes = True


class UploadResponse(BaseModel):
    """Response for file upload with archive extraction info"""
    sample: MalwareSampleResponse
    extracted_samples: List[MalwareSampleResponse] = []
    is_archive: bool = False
    extraction_count: int = 0
