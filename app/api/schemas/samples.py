"""Malware sample schemas"""
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List
from app.models import FileType
import json


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
    
    # PE metadata
    pe_imphash: Optional[str]
    pe_compilation_timestamp: Optional[datetime]
    pe_entry_point: Optional[str]
    pe_sections: Optional[str]
    pe_imports: Optional[str]
    pe_exports: Optional[str]
    
    # PE Header information
    pe_machine: Optional[str]
    pe_number_of_sections: Optional[int]
    pe_characteristics: Optional[str]
    pe_magic: Optional[str]
    pe_image_base: Optional[str]
    pe_subsystem: Optional[str]
    pe_dll_characteristics: Optional[str]
    pe_checksum: Optional[str]
    pe_size_of_image: Optional[int]
    pe_size_of_headers: Optional[int]
    pe_base_of_code: Optional[str]
    
    # PE Version information
    pe_linker_version: Optional[str]
    pe_os_version: Optional[str]
    pe_image_version: Optional[str]
    pe_subsystem_version: Optional[str]
    
    # PE Import/Export counts
    pe_import_dll_count: Optional[int]
    pe_imported_functions_count: Optional[int]
    pe_export_count: Optional[int]
    
    # PE Resources
    pe_resources: Optional[str]
    pe_resource_count: Optional[int]
    
    # PE Version info
    pe_version_info: Optional[str]
    
    # PE Debug info
    pe_debug_info: Optional[str]
    
    # PE TLS
    pe_tls_info: Optional[str]
    
    # PE Rich header
    pe_rich_header: Optional[str]
    
    # PE Digital signature
    pe_is_signed: Optional[bool]
    pe_signature_info: Optional[str]
    
    # ELF metadata
    elf_machine: Optional[str]
    elf_entry_point: Optional[str]
    elf_file_class: Optional[str]
    elf_data_encoding: Optional[str]
    elf_os_abi: Optional[str]
    elf_abi_version: Optional[int]
    elf_type: Optional[str]
    elf_version: Optional[str]
    elf_flags: Optional[str]
    elf_header_size: Optional[int]
    elf_program_header_offset: Optional[str]
    elf_section_header_offset: Optional[str]
    elf_program_header_entry_size: Optional[int]
    elf_program_header_count: Optional[int]
    elf_section_header_entry_size: Optional[int]
    elf_section_header_count: Optional[int]
    elf_sections: Optional[str]
    elf_section_count: Optional[int]
    elf_segments: Optional[str]
    elf_segment_count: Optional[int]
    elf_interpreter: Optional[str]
    elf_dynamic_tags: Optional[str]
    elf_shared_libraries: Optional[str]
    elf_shared_library_count: Optional[int]
    elf_symbols: Optional[str]
    elf_symbol_count: Optional[int]
    elf_relocations: Optional[str]
    elf_relocation_count: Optional[int]
    
    # CAPA analysis results
    capa_capabilities: Optional[str]
    capa_attack: Optional[str]
    capa_mbc: Optional[str]
    capa_analysis_date: Optional[datetime]
    capa_total_capabilities: Optional[int]
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
