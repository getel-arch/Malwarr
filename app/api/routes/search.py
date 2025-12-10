"""Search routes - Advanced query interface for samples and analyzer results"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_, and_, func, cast, String
from typing import List, Optional, Dict, Any
import json
import logging
import re

from app.api.dependencies import get_db, verify_api_key
from app.models import (
    MalwareSample, 
    PEAnalysis, 
    ELFAnalysis, 
    CAPAAnalysis,
    MagikaAnalysis,
    VirusTotalAnalysis,
    StringsAnalysis,
    FileType,
    AnalysisStatus
)

router = APIRouter(prefix="/api/v1/search", tags=["search"])
logger = logging.getLogger(__name__)


class QueryParser:
    """Parse advanced search queries into SQLAlchemy filters"""
    
    # Mapping of field names to model attributes
    FIELD_MAPPINGS = {
        # MalwareSample fields
        'sha256': ('sample', 'sha256'),
        'sha512': ('sample', 'sha512'),
        'sha1': ('sample', 'sha1'),
        'md5': ('sample', 'md5'),
        'filename': ('sample', 'filename'),
        'file_size': ('sample', 'file_size'),
        'file_type': ('sample', 'file_type'),
        'mime_type': ('sample', 'mime_type'),
        'family': ('sample', 'family'),
        'classification': ('sample', 'classification'),
        'tags': ('sample', 'tags'),
        'entropy': ('sample', 'entropy'),
        'analysis_status': ('sample', 'analysis_status'),
        'source_url': ('sample', 'source_url'),
        
        # PE fields
        'pe.imphash': ('pe', 'imphash'),
        'pe.machine': ('pe', 'machine'),
        'pe.subsystem': ('pe', 'subsystem'),
        'pe.is_signed': ('pe', 'is_signed'),
        'pe.import_dll_count': ('pe', 'import_dll_count'),
        'pe.section_count': ('pe', 'number_of_sections'),
        
        # ELF fields
        'elf.machine': ('elf', 'machine'),
        'elf.file_class': ('elf', 'file_class'),
        'elf.os_abi': ('elf', 'os_abi'),
        'elf.elf_type': ('elf', 'elf_type'),
        'elf.shared_library_count': ('elf', 'shared_library_count'),
        
        # CAPA fields
        'capa.total_capabilities': ('capa', 'total_capabilities'),
        
        # Magika fields
        'magika.label': ('magika', 'label'),
        'magika.score': ('magika', 'score'),
        'magika.group': ('magika', 'group'),
        'magika.is_text': ('magika', 'is_text'),
        
        # VirusTotal fields
        'vt.positives': ('vt', 'positives'),
        'vt.total': ('vt', 'total'),
        'vt.detection_ratio': ('vt', 'detection_ratio'),
        
        # Strings fields
        'strings.total_count': ('strings', 'total_count'),
        'strings.url_count': ('strings', 'url_count'),
        'strings.ip_count': ('strings', 'ip_count'),
    }
    
    def __init__(self, query: str):
        self.query = query.strip()
        self.filters = []
        self.joins = set()
    
    def parse(self) -> tuple[List, set]:
        """Parse the query and return filters and required joins"""
        if not self.query:
            return [], set()
        
        # Split by AND/OR operators (case insensitive)
        tokens = re.split(r'\s+(AND|OR)\s+', self.query, flags=re.IGNORECASE)
        
        i = 0
        current_op = 'AND'
        temp_filters = []
        
        while i < len(tokens):
            token = tokens[i].strip()
            
            if token.upper() in ['AND', 'OR']:
                current_op = token.upper()
                i += 1
                continue
            
            # Parse individual condition
            filter_expr = self._parse_condition(token)
            if filter_expr is not None:
                temp_filters.append((filter_expr, current_op))
            
            i += 1
        
        # Build final filter combining with AND/OR
        if temp_filters:
            # Start with first filter
            combined_filter = temp_filters[0][0]
            
            # Combine subsequent filters
            for i in range(1, len(temp_filters)):
                filter_expr, op = temp_filters[i]
                if op == 'OR':
                    combined_filter = or_(combined_filter, filter_expr)
                else:  # AND
                    combined_filter = and_(combined_filter, filter_expr)
            
            self.filters.append(combined_filter)
        
        return self.filters, self.joins
    
    def _parse_condition(self, condition: str):
        """Parse a single condition like 'field=value' or 'field>value'"""
        # Match patterns: field operator value
        patterns = [
            (r'([a-zA-Z0-9_.]+)\s*=\s*"([^"]+)"', '='),  # field="value"
            (r'([a-zA-Z0-9_.]+)\s*=\s*([^\s]+)', '='),    # field=value
            (r'([a-zA-Z0-9_.]+)\s*!=\s*"([^"]+)"', '!='),  # field!="value"
            (r'([a-zA-Z0-9_.]+)\s*!=\s*([^\s]+)', '!='),   # field!=value
            (r'([a-zA-Z0-9_.]+)\s*>\s*([^\s]+)', '>'),     # field>value
            (r'([a-zA-Z0-9_.]+)\s*<\s*([^\s]+)', '<'),     # field<value
            (r'([a-zA-Z0-9_.]+)\s*>=\s*([^\s]+)', '>='),   # field>=value
            (r'([a-zA-Z0-9_.]+)\s*<=\s*([^\s]+)', '<='),   # field<=value
            (r'([a-zA-Z0-9_.]+)\s+LIKE\s+"([^"]+)"', 'LIKE'),  # field LIKE "pattern"
            (r'([a-zA-Z0-9_.]+)\s+CONTAINS\s+"([^"]+)"', 'CONTAINS'),  # field CONTAINS "text"
        ]
        
        for pattern, operator in patterns:
            match = re.match(pattern, condition, re.IGNORECASE)
            if match:
                field_name = match.group(1).lower()
                value = match.group(2)
                return self._build_filter(field_name, operator, value)
        
        logger.warning(f"Could not parse condition: {condition}")
        return None
    
    def _build_filter(self, field_name: str, operator: str, value: str):
        """Build SQLAlchemy filter for a field/operator/value combination"""
        if field_name not in self.FIELD_MAPPINGS:
            logger.warning(f"Unknown field: {field_name}")
            return None
        
        table_name, attr_name = self.FIELD_MAPPINGS[field_name]
        
        # Track which joins we need
        if table_name != 'sample':
            self.joins.add(table_name)
        
        # Get the model and attribute
        model = self._get_model(table_name)
        if model is None:
            return None
        
        attr = getattr(model, attr_name, None)
        if attr is None:
            logger.warning(f"Attribute {attr_name} not found on {table_name}")
            return None
        
        # Build the filter based on operator
        operator = operator.upper()
        
        if operator == '=':
            return attr == value
        elif operator == '!=':
            return attr != value
        elif operator == '>':
            return attr > self._convert_value(value)
        elif operator == '<':
            return attr < self._convert_value(value)
        elif operator == '>=':
            return attr >= self._convert_value(value)
        elif operator == '<=':
            return attr <= self._convert_value(value)
        elif operator == 'LIKE':
            return attr.like(f"%{value}%")
        elif operator == 'CONTAINS':
            # For JSON fields or text fields
            return attr.contains(value)
        
        return None
    
    def _get_model(self, table_name: str):
        """Get the SQLAlchemy model for a table name"""
        models = {
            'sample': MalwareSample,
            'pe': PEAnalysis,
            'elf': ELFAnalysis,
            'capa': CAPAAnalysis,
            'magika': MagikaAnalysis,
            'vt': VirusTotalAnalysis,
            'strings': StringsAnalysis,
        }
        return models.get(table_name)
    
    def _convert_value(self, value: str):
        """Convert string value to appropriate type"""
        # Try to convert to int
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try to convert to float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Try to convert to bool
        if value.lower() in ['true', 'false']:
            return value.lower() == 'true'
        
        # Return as string
        return value


@router.get("/query")
async def search_samples(
    q: str = Query(..., description="Advanced search query string"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Number of results to skip"),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Search samples using advanced query syntax
    
    **Query Syntax:**
    - Simple equality: `field=value` (e.g., `file_type=pe`)
    - String matching: `field LIKE "pattern"` (e.g., `filename LIKE "malware"`)
    - Comparisons: `field>value`, `field<value`, `field>=value`, `field<=value`
    - Contains: `field CONTAINS "text"` (for JSON/text fields)
    - Boolean logic: `condition1 AND condition2`, `condition1 OR condition2`
    
    **Available Fields:**
    
    *Sample Fields:*
    - `sha256`, `sha512`, `sha1`, `md5` - File hashes
    - `filename` - Original filename
    - `file_size` - File size in bytes
    - `file_type` - File type (pe, elf, archive, etc.)
    - `mime_type` - MIME type
    - `family` - Malware family
    - `classification` - Classification
    - `tags` - Tags (use CONTAINS)
    - `entropy` - File entropy
    - `analysis_status` - Analysis status
    - `source_url` - Source URL
    
    *PE Fields:*
    - `pe.imphash` - Import hash
    - `pe.machine` - Machine type
    - `pe.subsystem` - PE subsystem
    - `pe.is_signed` - Digital signature status
    - `pe.import_dll_count` - Number of imported DLLs
    - `pe.section_count` - Number of sections
    
    *ELF Fields:*
    - `elf.machine` - Machine architecture
    - `elf.file_class` - 32-bit or 64-bit
    - `elf.os_abi` - OS/ABI
    - `elf.elf_type` - ELF type
    - `elf.shared_library_count` - Shared library count
    
    *CAPA Fields:*
    - `capa.total_capabilities` - Total capabilities detected
    
    *Magika Fields:*
    - `magika.label` - Detected file type
    - `magika.score` - Detection confidence
    - `magika.group` - File type group
    - `magika.is_text` - Is text file
    
    *VirusTotal Fields:*
    - `vt.positives` - Positive detections
    - `vt.total` - Total scanners
    - `vt.detection_ratio` - Detection ratio
    
    *Strings Fields:*
    - `strings.total_count` - Total strings count
    - `strings.url_count` - URL count
    - `strings.ip_count` - IP address count
    
    **Example Queries:**
    - `file_type=pe AND pe.is_signed=false`
    - `vt.positives>10 AND file_size<1000000`
    - `filename LIKE "trojan" OR family="emotet"`
    - `magika.label=pe AND capa.total_capabilities>50`
    - `strings.url_count>0 AND strings.ip_count>5`
    """
    try:
        logger.info(f"Search query: {q}")
        
        # Parse the query
        parser = QueryParser(q)
        filters, joins = parser.parse()
        
        # Start building query
        query = db.query(MalwareSample)
        
        # Add necessary joins
        if 'pe' in joins:
            query = query.outerjoin(PEAnalysis)
        if 'elf' in joins:
            query = query.outerjoin(ELFAnalysis)
        if 'capa' in joins:
            query = query.outerjoin(CAPAAnalysis)
        if 'magika' in joins:
            query = query.outerjoin(MagikaAnalysis)
        if 'vt' in joins:
            query = query.outerjoin(VirusTotalAnalysis)
        if 'strings' in joins:
            query = query.outerjoin(StringsAnalysis)
        
        # Apply filters
        for filter_expr in filters:
            query = query.filter(filter_expr)
        
        # Get total count before pagination
        total_count = query.count()
        
        # Apply pagination
        samples = query.offset(offset).limit(limit).all()
        
        # Convert to response format
        results = []
        for sample in samples:
            sample_dict = {
                'sha512': sample.sha512,
                'sha256': sample.sha256,
                'sha1': sample.sha1,
                'md5': sample.md5,
                'filename': sample.filename,
                'file_size': sample.file_size,
                'file_type': sample.file_type.value if sample.file_type else None,
                'mime_type': sample.mime_type,
                'family': sample.family,
                'classification': sample.classification,
                'tags': json.loads(sample.tags) if sample.tags else [],
                'entropy': sample.entropy,
                'first_seen': sample.first_seen.isoformat() if sample.first_seen else None,
                'analysis_status': sample.analysis_status.value if sample.analysis_status else None,
                'has_pe_analysis': sample.pe_analysis is not None,
                'has_elf_analysis': sample.elf_analysis is not None,
                'has_capa_analysis': sample.capa_analysis is not None,
                'has_magika_analysis': sample.magika_analysis is not None,
                'has_vt_analysis': sample.virustotal_analysis is not None,
                'has_strings_analysis': sample.strings_analysis is not None,
            }
            
            # Add analyzer-specific fields if joined
            if 'pe' in joins and sample.pe_analysis:
                sample_dict['pe'] = {
                    'imphash': sample.pe_analysis.imphash,
                    'machine': sample.pe_analysis.machine,
                    'subsystem': sample.pe_analysis.subsystem,
                    'is_signed': sample.pe_analysis.is_signed,
                }
            
            if 'vt' in joins and sample.virustotal_analysis:
                sample_dict['vt'] = {
                    'positives': sample.virustotal_analysis.positives,
                    'total': sample.virustotal_analysis.total,
                    'detection_ratio': sample.virustotal_analysis.detection_ratio,
                }
            
            results.append(sample_dict)
        
        return {
            'query': q,
            'total': total_count,
            'limit': limit,
            'offset': offset,
            'results': results
        }
    
    except Exception as e:
        logger.error(f"Search error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"Query error: {str(e)}")


@router.get("/fields")
async def get_available_fields(
    api_key: str = Depends(verify_api_key)
):
    """Get list of all searchable fields with descriptions"""
    
    fields = {
        'sample': {
            'sha256': {'type': 'string', 'description': 'SHA256 hash'},
            'sha512': {'type': 'string', 'description': 'SHA512 hash'},
            'sha1': {'type': 'string', 'description': 'SHA1 hash'},
            'md5': {'type': 'string', 'description': 'MD5 hash'},
            'filename': {'type': 'string', 'description': 'Original filename'},
            'file_size': {'type': 'integer', 'description': 'File size in bytes'},
            'file_type': {'type': 'enum', 'description': 'File type', 'values': ['pe', 'elf', 'archive', 'document', 'script', 'other']},
            'mime_type': {'type': 'string', 'description': 'MIME type'},
            'family': {'type': 'string', 'description': 'Malware family'},
            'classification': {'type': 'string', 'description': 'Classification'},
            'tags': {'type': 'array', 'description': 'Tags (use CONTAINS)'},
            'entropy': {'type': 'string', 'description': 'File entropy'},
            'analysis_status': {'type': 'enum', 'description': 'Analysis status', 'values': ['pending', 'analyzing', 'completed', 'failed', 'skipped']},
            'source_url': {'type': 'string', 'description': 'Source URL'},
        },
        'pe': {
            'pe.imphash': {'type': 'string', 'description': 'Import hash'},
            'pe.machine': {'type': 'string', 'description': 'Machine type'},
            'pe.subsystem': {'type': 'string', 'description': 'PE subsystem'},
            'pe.is_signed': {'type': 'boolean', 'description': 'Digital signature status'},
            'pe.import_dll_count': {'type': 'integer', 'description': 'Number of imported DLLs'},
            'pe.section_count': {'type': 'integer', 'description': 'Number of sections'},
        },
        'elf': {
            'elf.machine': {'type': 'string', 'description': 'Machine architecture'},
            'elf.file_class': {'type': 'string', 'description': '32-bit or 64-bit'},
            'elf.os_abi': {'type': 'string', 'description': 'OS/ABI'},
            'elf.elf_type': {'type': 'string', 'description': 'ELF type'},
            'elf.shared_library_count': {'type': 'integer', 'description': 'Shared library count'},
        },
        'capa': {
            'capa.total_capabilities': {'type': 'integer', 'description': 'Total capabilities detected'},
        },
        'magika': {
            'magika.label': {'type': 'string', 'description': 'Detected file type'},
            'magika.score': {'type': 'string', 'description': 'Detection confidence'},
            'magika.group': {'type': 'string', 'description': 'File type group'},
            'magika.is_text': {'type': 'boolean', 'description': 'Is text file'},
        },
        'virustotal': {
            'vt.positives': {'type': 'integer', 'description': 'Positive detections'},
            'vt.total': {'type': 'integer', 'description': 'Total scanners'},
            'vt.detection_ratio': {'type': 'string', 'description': 'Detection ratio'},
        },
        'strings': {
            'strings.total_count': {'type': 'integer', 'description': 'Total strings count'},
            'strings.url_count': {'type': 'integer', 'description': 'URL count'},
            'strings.ip_count': {'type': 'integer', 'description': 'IP address count'},
        }
    }
    
    return {
        'fields': fields,
        'operators': ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'CONTAINS'],
        'logical_operators': ['AND', 'OR'],
        'examples': [
            'file_type=pe AND pe.is_signed=false',
            'vt.positives>10 AND file_size<1000000',
            'filename LIKE "trojan" OR family="emotet"',
            'magika.label=pe AND capa.total_capabilities>50',
            'strings.url_count>0 AND strings.ip_count>5',
        ]
    }
