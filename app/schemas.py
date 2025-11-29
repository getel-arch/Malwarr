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
    
    # ELF metadata
    elf_machine: Optional[str]
    elf_entry_point: Optional[str]
    elf_sections: Optional[str]
    
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


class SystemInfo(BaseModel):
    """System information response"""
    app_name: str
    version: str
    total_samples: int
    storage_used: int  # bytes
    database_status: str


class UploadResponse(BaseModel):
    """Response for file upload with archive extraction info"""
    sample: MalwareSampleResponse
    extracted_samples: List[MalwareSampleResponse] = []
    is_archive: bool = False
    extraction_count: int = 0
