"""Sample management routes - CRUD operations for malware samples"""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query, Form
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_
from typing import List, Optional
import json
import logging
from io import BytesIO

from app.api.dependencies import get_db, verify_api_key
from app.api.schemas import (
    MalwareSampleResponse,
    MalwareSampleURL,
    MalwareSampleUpdate,
    UploadResponse
)
from app.models import MalwareSample, FileType
from app.ingestion import IngestionService
from app.storage import FileStorage

router = APIRouter(prefix="/api/v1/samples", tags=["samples"])
logger = logging.getLogger(__name__)

# Storage instance
file_storage = FileStorage()


@router.post("", response_model=dict)
async def upload_sample(
    file: UploadFile = File(...),
    tags: Optional[str] = Form(None),
    family: Optional[str] = Form(None),
    classification: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    archive_password: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload a malware sample (queued for background processing)
    
    - **file**: The malware file to upload
    - **tags**: Comma-separated tags (optional)
    - **family**: Malware family name (optional)
    - **classification**: Classification type (optional)
    - **notes**: Additional notes (optional)
    - **archive_password**: Password for encrypted archives (optional)
    
    Returns immediately with task ID. Processing happens in background.
    """
    import base64
    from app.workers.tasks import ingest_file_task
    
    # Read file content
    content = await file.read()
    
    # Parse tags
    tag_list = [t.strip() for t in tags.split(',')] if tags else []
    
    # Debug logging
    logger.info(f"Queuing upload: filename={file.filename}, size={len(content)} bytes")
    
    # Encode content as base64 for Celery JSON serialization
    content_base64 = base64.b64encode(content).decode('utf-8')
    
    # Queue the ingestion task
    task = ingest_file_task.delay(
        file_content_base64=content_base64,
        filename=file.filename,
        tags=tag_list,
        family=family,
        classification=classification,
        notes=notes,
        archive_password=archive_password
    )
    
    logger.info(f"Upload queued: {file.filename} - Task ID: {task.id}")
    
    return {
        "task_id": task.id,
        "filename": file.filename,
        "status": "queued",
        "message": "File queued for processing. Use task ID to check status."
    }


@router.post("/bulk", response_model=dict)
async def upload_bulk_samples(
    files: List[UploadFile] = File(...),
    tags: Optional[str] = Form(None),
    family: Optional[str] = Form(None),
    classification: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    archive_password: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload multiple malware samples at once (queued for background processing)
    
    - **files**: Multiple files to upload
    - **tags**: Comma-separated tags applied to all files (optional)
    - **family**: Malware family name applied to all files (optional)
    - **classification**: Classification type applied to all files (optional)
    - **notes**: Additional notes applied to all files (optional)
    - **archive_password**: Password for encrypted archives (optional)
    
    Returns immediately with task IDs. All files are queued for background processing.
    """
    import base64
    from app.workers.tasks import ingest_file_task
    
    # Parse tags once for all files
    tag_list = [t.strip() for t in tags.split(',')] if tags else []
    
    logger.info(f"Bulk upload: {len(files)} files queued")
    
    queued_files = []
    
    for file in files:
        # Read file content
        content = await file.read()
        
        # Encode content as base64 for Celery JSON serialization
        content_base64 = base64.b64encode(content).decode('utf-8')
        
        # Queue the ingestion task
        task = ingest_file_task.delay(
            file_content_base64=content_base64,
            filename=file.filename,
            tags=tag_list,
            family=family,
            classification=classification,
            notes=notes,
            archive_password=archive_password
        )
        
        queued_files.append({
            "task_id": task.id,
            "filename": file.filename,
            "size": len(content)
        })
        
        logger.info(f"Queued: {file.filename} - Task ID: {task.id}")
    
    return {
        "total_files": len(files),
        "status": "queued",
        "message": f"{len(files)} files queued for processing",
        "files": queued_files
    }


@router.post("/from-url", response_model=dict)
async def upload_sample_from_url(
    sample_data: MalwareSampleURL,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload a malware sample from a URL (queued for background processing)
    
    - **url**: The URL to download the sample from
    - **filename**: Optional filename (will be extracted from URL if not provided)
    - **tags**: Optional list of tags
    - **family**: Malware family name (optional)
    - **classification**: Classification type (optional)
    - **notes**: Additional notes (optional)
    - **archive_password**: Password for encrypted archives (optional)
    
    Returns immediately with task ID. Processing happens in background.
    """
    import httpx
    import base64
    from urllib.parse import urlparse, unquote
    from app.workers.tasks import ingest_file_task
    
    try:
        # Download file from URL with timeout
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            response = await client.get(sample_data.url)
            response.raise_for_status()
            content = response.content
        
        # Determine filename
        if sample_data.filename:
            filename = sample_data.filename
        else:
            # Try to get filename from Content-Disposition header
            content_disposition = response.headers.get('content-disposition')
            if content_disposition and 'filename=' in content_disposition:
                filename = content_disposition.split('filename=')[1].strip('"')
            else:
                # Extract from URL
                parsed_url = urlparse(sample_data.url)
                filename = unquote(parsed_url.path.split('/')[-1])
                if not filename or filename == '':
                    filename = 'downloaded_sample'
        
        logger.info(f"Queuing URL download: {filename} from {sample_data.url}")
        
        # Encode content as base64 for Celery JSON serialization
        content_base64 = base64.b64encode(content).decode('utf-8')
        
        # Queue the ingestion task
        task = ingest_file_task.delay(
            file_content_base64=content_base64,
            filename=filename,
            tags=sample_data.tags or [],
            family=sample_data.family,
            classification=sample_data.classification,
            notes=sample_data.notes,
            archive_password=sample_data.archive_password,
            source_url=sample_data.url
        )
        
        logger.info(f"URL download queued: {filename} - Task ID: {task.id}")
        
        return {
            "task_id": task.id,
            "filename": filename,
            "status": "queued",
            "message": "File queued for processing. Use task ID to check status."
        }
        
    except httpx.HTTPError as e:
        raise HTTPException(status_code=400, detail=f"Failed to download from URL: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing sample: {str(e)}")


@router.get("", response_model=List[MalwareSampleResponse])
async def list_samples(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    file_type: Optional[FileType] = None,
    family: Optional[str] = None,
    tag: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List malware samples with optional filtering
    
    - **skip**: Number of records to skip (pagination)
    - **limit**: Maximum number of records to return
    - **file_type**: Filter by file type (pe, elf, etc.)
    - **family**: Filter by malware family
    - **tag**: Filter by tag
    """
    query = db.query(MalwareSample).options(
        joinedload(MalwareSample.pe_analysis),
        joinedload(MalwareSample.elf_analysis),
        joinedload(MalwareSample.magika_analysis),
        joinedload(MalwareSample.capa_analysis),
        joinedload(MalwareSample.virustotal_analysis)
    )
    
    if file_type:
        query = query.filter(MalwareSample.file_type == file_type)
    
    if family:
        query = query.filter(MalwareSample.family == family)
    
    if tag:
        query = query.filter(MalwareSample.tags.contains(f'"{tag}"'))
    
    samples = query.order_by(MalwareSample.upload_date.desc()).offset(skip).limit(limit).all()
    return samples


@router.get("/search")
async def search_samples(
    q: str = Query(..., min_length=1),
    db: Session = Depends(get_db)
):
    """
    Search for samples by hash, filename, or family
    
    - **q**: Search query (hash, filename, or family name)
    """
    query_lower = q.lower()
    
    samples = db.query(MalwareSample).options(
        joinedload(MalwareSample.pe_analysis),
        joinedload(MalwareSample.elf_analysis),
        joinedload(MalwareSample.magika_analysis),
        joinedload(MalwareSample.capa_analysis),
        joinedload(MalwareSample.virustotal_analysis)
    ).filter(
        or_(
            MalwareSample.sha512 == query_lower,
            MalwareSample.sha256 == query_lower,
            MalwareSample.sha1 == query_lower,
            MalwareSample.md5 == query_lower,
            func.lower(MalwareSample.filename).contains(query_lower),
            func.lower(MalwareSample.family).contains(query_lower)
        )
    ).limit(50).all()
    
    return samples


@router.get("/{sha512}", response_model=MalwareSampleResponse)
async def get_sample_metadata(sha512: str, db: Session = Depends(get_db)):
    """Get metadata for a specific sample by SHA512 hash"""
    sample = db.query(MalwareSample).options(
        joinedload(MalwareSample.pe_analysis),
        joinedload(MalwareSample.elf_analysis),
        joinedload(MalwareSample.magika_analysis),
        joinedload(MalwareSample.capa_analysis),
        joinedload(MalwareSample.virustotal_analysis)
    ).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    return sample


@router.get("/{sha512}/download")
async def download_sample(
    sha512: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """Download a malware sample by SHA512 hash (requires API key)"""
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    file_content = file_storage.get_file(sample.storage_path)
    
    if not file_content:
        raise HTTPException(status_code=404, detail="Sample file not found in storage")
    
    return StreamingResponse(
        BytesIO(file_content),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{sample.filename}"',
            "X-SHA512": sample.sha512,
            "X-SHA256": sample.sha256,
            "X-MD5": sample.md5
        }
    )


@router.patch("/{sha512}", response_model=MalwareSampleResponse)
async def update_sample_metadata(
    sha512: str,
    update_data: MalwareSampleUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """Update metadata for a specific sample"""
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    # Update fields
    if update_data.tags is not None:
        sample.tags = json.dumps(update_data.tags)
    if update_data.family is not None:
        sample.family = update_data.family
    if update_data.classification is not None:
        sample.classification = update_data.classification
    if update_data.notes is not None:
        sample.notes = update_data.notes
    if update_data.virustotal_link is not None:
        sample.virustotal_link = update_data.virustotal_link
    if update_data.malwarebazaar_link is not None:
        sample.malwarebazaar_link = update_data.malwarebazaar_link
    
    db.commit()
    db.refresh(sample)
    
    return sample


@router.delete("/{sha512}")
async def delete_sample(
    sha512: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """Delete a malware sample"""
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    # Delete file from storage
    file_storage.delete_file(sample.storage_path)
    
    # Delete from database
    db.delete(sample)
    db.commit()
    
    return {"status": "deleted", "sha512": sha512}
