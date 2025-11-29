from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Query, Header, Request, Form
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, text
from typing import List, Optional
import json
import logging
from io import BytesIO
from pathlib import Path

from app.database import get_db, engine, Base
from app.models import MalwareSample, FileType, AnalysisStatus
from app.schemas import (
    MalwareSampleResponse,
    MalwareSampleCreate,
    MalwareSampleUpdate,
    MalwareSampleURL,
    SystemInfo,
    UploadResponse
)
from app.ingestion import IngestionService
from app.storage import FileStorage
from app.config import settings, app_name, app_version
from app.analyzers.capa.capa_rules_manager import CapaRulesManager
from app.analyzers.capa.capa_explorer_manager import CapaExplorerManager
from app.version import __version__, get_full_version

logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=app_name,
    version=app_version,
    description="Malware repository management system - Arr compatible"
)

# Add CORS middleware to allow iframe communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your actual domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize storage
file_storage = FileStorage()

# Mount static files for frontend (CSS, JS, etc.)
static_path = Path(__file__).parent / "static"
static_assets_path = static_path / "static"  # React build puts assets in /static subdirectory
if static_assets_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_assets_path)), name="static")

# Mount CAPA Explorer if it exists
capa_explorer_path = Path(settings.capa_explorer_path)
if capa_explorer_path.exists() and (capa_explorer_path / "index.html").exists():
    app.mount("/capa-explorer", StaticFiles(directory=str(capa_explorer_path), html=True), name="capa-explorer")


def verify_api_key(x_api_key: str = Header(None)):
    """Verify API key for protected endpoints"""
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


@app.get("/api/v1/version")
async def get_version():
    """Get application version information"""
    return {
        "version": __version__,
        "app_name": app_name,
        "full_version": get_full_version()
    }


@app.get("/api/v1/system", response_model=SystemInfo)
async def get_system_info(db: Session = Depends(get_db)):
    """Get system information and statistics"""
    total_samples = db.query(func.count(MalwareSample.sha512)).scalar()
    storage_used = file_storage.get_storage_size()
    
    return SystemInfo(
        app_name=app_name,
        version=app_version,
        total_samples=total_samples,
        storage_used=storage_used,
        database_status="connected"
    )


@app.post("/api/v1/samples", response_model=UploadResponse)
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
    Upload a malware sample
    
    - **file**: The malware file to upload
    - **tags**: Comma-separated tags (optional)
    - **family**: Malware family name (optional)
    - **classification**: Classification type (optional)
    - **notes**: Additional notes (optional)
    - **archive_password**: Password for encrypted archives (optional)
    """
    # Read file content
    content = await file.read()
    
    # Parse tags
    tag_list = [t.strip() for t in tags.split(',')] if tags else []
    
    # Debug logging for archive password
    logger.info(f"Upload: filename={file.filename}, archive_password={archive_password!r}")
    
    # Ingest file
    ingestion_service = IngestionService(file_storage)
    sample, extracted_samples = ingestion_service.ingest_file(
        file_content=content,
        filename=file.filename,
        db=db,
        tags=tag_list,
        family=family,
        classification=classification,
        notes=notes,
        archive_password=archive_password
    )
    
    return UploadResponse(
        sample=sample,
        extracted_samples=extracted_samples,
        is_archive=(sample.is_archive == "true"),
        extraction_count=len(extracted_samples)
    )


@app.post("/api/v1/samples/from-url", response_model=UploadResponse)
async def upload_sample_from_url(
    sample_data: MalwareSampleURL,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload a malware sample from a URL
    
    - **url**: The URL to download the sample from
    - **filename**: Optional filename (will be extracted from URL if not provided)
    - **tags**: Optional list of tags
    - **family**: Malware family name (optional)
    - **classification**: Classification type (optional)
    - **notes**: Additional notes (optional)
    - **archive_password**: Password for encrypted archives (optional)
    """
    import httpx
    from urllib.parse import urlparse, unquote
    
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
        
        # Ingest file
        ingestion_service = IngestionService(file_storage)
        sample, extracted_samples = ingestion_service.ingest_file(
            file_content=content,
            filename=filename,
            db=db,
            tags=sample_data.tags or [],
            family=sample_data.family,
            classification=sample_data.classification,
            notes=sample_data.notes,
            archive_password=sample_data.archive_password,
            source_url=sample_data.url
        )
        
        return UploadResponse(
            sample=sample,
            extracted_samples=extracted_samples,
            is_archive=(sample.is_archive == "true"),
            extraction_count=len(extracted_samples)
        )
        
    except httpx.HTTPError as e:
        raise HTTPException(status_code=400, detail=f"Failed to download from URL: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing sample: {str(e)}")


@app.get("/api/v1/samples", response_model=List[MalwareSampleResponse])
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
    query = db.query(MalwareSample)
    
    if file_type:
        query = query.filter(MalwareSample.file_type == file_type)
    
    if family:
        query = query.filter(MalwareSample.family == family)
    
    if tag:
        query = query.filter(MalwareSample.tags.contains(f'"{tag}"'))
    
    samples = query.order_by(MalwareSample.upload_date.desc()).offset(skip).limit(limit).all()
    return samples


@app.get("/api/v1/samples/search")
async def search_samples(
    q: str = Query(..., min_length=1),
    db: Session = Depends(get_db)
):
    """
    Search for samples by hash, filename, or family
    
    - **q**: Search query (hash, filename, or family name)
    """
    query_lower = q.lower()
    
    samples = db.query(MalwareSample).filter(
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


@app.get("/api/v1/samples/{sha512}", response_model=MalwareSampleResponse)
async def get_sample_metadata(sha512: str, db: Session = Depends(get_db)):
    """Get metadata for a specific sample by SHA512 hash"""
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    return sample


@app.get("/api/v1/samples/{sha512}/download")
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


@app.patch("/api/v1/samples/{sha512}", response_model=MalwareSampleResponse)
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


@app.delete("/api/v1/samples/{sha512}")
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


@app.post("/api/v1/samples/{sha512}/analyze/capa")
async def run_capa_analysis(
    sha512: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Queue CAPA analysis on a specific sample (runs asynchronously)
    
    - **sha512**: SHA512 hash of the sample
    
    Returns task information for tracking the analysis progress
    """
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    # Queue CAPA analysis
    ingestion_service = IngestionService(file_storage)
    success, message = ingestion_service.run_capa_analysis(sample, db)
    
    if not success:
        # Check if it's an unsupported format error
        if message and "unsupported" in message.lower():
            raise HTTPException(status_code=422, detail=message)
        else:
            raise HTTPException(status_code=500, detail=message or "CAPA analysis failed")
    
    return {
        "status": "queued",
        "sha512": sha512,
        "task_id": sample.analysis_task_id,
        "message": message
    }


@app.post("/api/v1/samples/{sha512}/rescan")
async def rescan_sample(
    sha512: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Trigger all relevant analyzers for a specific sample (PE/ELF/CAPA)

    - Queues PE/ELF metadata extraction and CAPA analysis when applicable
    """
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    queued = {}

    try:
        # Mark sample as pending
        sample.analysis_status = AnalysisStatus.PENDING
        db.commit()

        # Queue PE analysis when appropriate
        if sample.file_type == FileType.PE:
            from app.workers.tasks import analyze_sample_with_pe
            task = analyze_sample_with_pe.delay(sample.sha512)
            queued['pe'] = task.id
            sample.analysis_task_id = task.id
            db.commit()

        # Queue ELF analysis when appropriate
        if sample.file_type == FileType.ELF:
            from app.workers.tasks import analyze_sample_with_elf
            task = analyze_sample_with_elf.delay(sample.sha512)
            queued['elf'] = task.id
            sample.analysis_task_id = task.id
            db.commit()

        # Queue CAPA analysis for PE/ELF
        if sample.file_type in [FileType.PE, FileType.ELF]:
            from app.workers.tasks import analyze_sample_with_capa
            task = analyze_sample_with_capa.delay(sample.sha512)
            queued['capa'] = task.id
            sample.analysis_task_id = task.id
            db.commit()

        if not queued:
            # Nothing to run for this file type
            sample.analysis_status = AnalysisStatus.SKIPPED
            db.commit()
            return {
                "status": "skipped",
                "message": f"No analyzers applicable for file type: {sample.file_type}"
            }

        return {
            "status": "queued",
            "sha512": sha512,
            "queued": queued
        }

    except Exception as e:
        # Attempt to mark failed
        try:
            sample.analysis_status = AnalysisStatus.FAILED
            db.commit()
        except:
            pass
        logger.error(f"Error queueing rescan tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/samples/{sha512}/analyze/status")
async def get_analysis_status(
    sha512: str,
    db: Session = Depends(get_db)
):
    """
    Get the status of CAPA analysis for a specific sample
    
    - **sha512**: SHA512 hash of the sample
    """
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    result = {
        "sha512": sha512,
        "analysis_status": sample.analysis_status.value if sample.analysis_status else "unknown",
        "task_id": sample.analysis_task_id,
        "total_capabilities": sample.capa_total_capabilities,
        "analysis_date": sample.capa_analysis_date
    }
    
    # If we have a task ID, try to get detailed status from Celery
    if sample.analysis_task_id:
        try:
            from app.workers.celery_app import celery_app
            from celery.result import AsyncResult
            
            task = AsyncResult(sample.analysis_task_id, app=celery_app)
            result["task_state"] = task.state
            
            if task.state == 'FAILURE':
                result["task_error"] = str(task.info)
            elif task.state == 'SUCCESS':
                result["task_result"] = task.info
        except Exception as e:
            logger.warning(f"Could not get task status: {e}")
    
    return result


@app.post("/api/v1/samples/batch/analyze/capa")
async def batch_analyze_samples(
    sha512_list: List[str],
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Queue CAPA analysis for multiple samples (runs asynchronously)
    
    - **sha512_list**: List of SHA512 hashes to analyze
    """
    try:
        from app.workers.tasks import batch_analyze_samples as batch_task
        
        # Validate that samples exist
        existing_samples = db.query(MalwareSample.sha512).filter(
            MalwareSample.sha512.in_(sha512_list)
        ).all()
        existing_hashes = [s[0] for s in existing_samples]
        
        missing_hashes = set(sha512_list) - set(existing_hashes)
        if missing_hashes:
            return {
                "status": "partial",
                "message": f"{len(missing_hashes)} samples not found",
                "missing": list(missing_hashes),
                "queued": len(existing_hashes)
            }
        
        # Queue batch analysis
        task = batch_task.delay(existing_hashes)
        
        return {
            "status": "queued",
            "task_id": task.id,
            "total_samples": len(existing_hashes)
        }
    except Exception as e:
        logger.error(f"Error queuing batch analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/samples/{sha512}/capa")
async def get_capa_results(
    sha512: str,
    db: Session = Depends(get_db)
):
    """
    Get CAPA analysis results for a specific sample
    
    - **sha512**: SHA512 hash of the sample
    """
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if not sample.capa_analysis_date:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Parse JSON fields
    capabilities = json.loads(sample.capa_capabilities) if sample.capa_capabilities else {}
    attack = json.loads(sample.capa_attack) if sample.capa_attack else []
    mbc = json.loads(sample.capa_mbc) if sample.capa_mbc else []
    
    return {
        "sha512": sha512,
        "filename": sample.filename,
        "analysis_date": sample.capa_analysis_date,
        "total_capabilities": sample.capa_total_capabilities,
        "capabilities": capabilities,
        "attack_techniques": attack,
        "mbc_objectives": mbc
    }


@app.get("/api/v1/samples/{sha512}/capa/document")
async def get_capa_result_document(
    sha512: str,
    db: Session = Depends(get_db)
):
    """
    Get full CAPA result document for use with CAPA Explorer
    
    - **sha512**: SHA512 hash of the sample
    """
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if not sample.capa_result_document:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Return the full result document
    return json.loads(sample.capa_result_document)


@app.get("/api/v1/samples/{sha512}/capa/explorer")
async def serve_capa_explorer_with_data(
    sha512: str,
    db: Session = Depends(get_db)
):
    """
    Serve CAPA Explorer HTML with JSON data pre-loaded
    
    - **sha512**: SHA512 hash of the sample
    """
    
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if not sample.capa_result_document:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Check if local CAPA Explorer exists
    capa_explorer_path = Path(settings.capa_explorer_path)
    index_path = capa_explorer_path / "index.html"
    
    if not index_path.exists():
        raise HTTPException(
            status_code=404, 
            detail="Local CAPA Explorer not installed. Please download it from Settings."
        )
    
    # Read the index.html file
    html_content = index_path.read_text(encoding='utf-8')
    
    # Get the CAPA JSON data
    capa_json_data = sample.capa_result_document
    
    # Inject the JSON data into the HTML
    # CAPA Explorer looks for data in localStorage or can be passed via script
    # Multiple methods to ensure data loading works with different versions of CAPA Explorer
    injection_script = f"""
    <script>
        // Auto-load CAPA data using multiple methods for maximum compatibility
        window.CAPA_DATA = {capa_json_data};
        
        // Method 1: Store in localStorage (standard CAPA Explorer method)
        try {{
            localStorage.setItem('capa-explorer-data', JSON.stringify(window.CAPA_DATA));
            localStorage.setItem('capaData', JSON.stringify(window.CAPA_DATA));
            console.log('[Malwarr] CAPA data stored in localStorage');
        }} catch (e) {{
            console.warn('[Malwarr] Could not save to localStorage:', e);
        }}
        
        // Method 2: Direct injection via global variable
        window.rdoc = window.CAPA_DATA;
        
        // Method 3: Wait for CAPA Explorer to initialize and inject data
        (function() {{
            let attempts = 0;
            const maxAttempts = 50; // Try for up to 5 seconds
            
            function injectData() {{
                attempts++;
                
                // Try various CAPA Explorer loading mechanisms
                if (window.App && window.App.loadDocument) {{
                    window.App.loadDocument(window.CAPA_DATA);
                    console.log('[Malwarr] Data loaded via App.loadDocument');
                    return true;
                }}
                
                if (window.loadCapaData && typeof window.loadCapaData === 'function') {{
                    window.loadCapaData(window.CAPA_DATA);
                    console.log('[Malwarr] Data loaded via loadCapaData');
                    return true;
                }}
                
                // Check if Vue app is available (CAPA Explorer uses Vue.js)
                if (window.app && window.app.loadDocument) {{
                    window.app.loadDocument(window.CAPA_DATA);
                    console.log('[Malwarr] Data loaded via Vue app');
                    return true;
                }}
                
                // If not ready and haven't exceeded attempts, try again
                if (attempts < maxAttempts) {{
                    setTimeout(injectData, 100);
                    return false;
                }}
                
                // Fallback: dispatch event for custom integrations
                console.log('[Malwarr] Using event-based fallback for data loading');
                window.dispatchEvent(new CustomEvent('capaDataReady', {{ detail: window.CAPA_DATA }}));
                return false;
            }}
            
            // Start injection attempts after DOM is loaded
            if (document.readyState === 'loading') {{
                document.addEventListener('DOMContentLoaded', function() {{
                    setTimeout(injectData, 100);
                }});
            }} else {{
                setTimeout(injectData, 100);
            }}
        }})();
        
        console.log('[Malwarr] CAPA Explorer auto-load initialized');
    </script>
    """
    
    # Inject before closing head tag or body tag
    if "</head>" in html_content:
        html_content = html_content.replace("</head>", f"{injection_script}</head>")
    elif "</body>" in html_content:
        html_content = html_content.replace("</body>", f"{injection_script}</body>")
    else:
        # Append at the end if no closing tags found
        html_content += injection_script
    
    return HTMLResponse(content=html_content)


@app.get("/api/v1/samples/{sha512}/capa/explorer-wrapped")
async def serve_capa_explorer_wrapped(
    sha512: str,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Serve CAPA Explorer with automatic JSON loading via rdoc parameter
    This provides the most reliable auto-loading experience using CAPA Explorer's native URL parameter
    
    - **sha512**: SHA512 hash of the sample
    """
    
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if not sample.capa_result_document:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Check if local CAPA Explorer exists
    capa_explorer_path = Path(settings.capa_explorer_path)
    
    # Determine the explorer URL to use
    if capa_explorer_path.exists() and (capa_explorer_path / "index.html").exists():
        # Use local explorer
        explorer_url = "/capa-explorer/index.html"
    else:
        # Use remote explorer
        explorer_url = "https://mandiant.github.io/capa/explorer/"
    
    # Load the wrapper template
    template_path = Path(__file__).parent / "templates" / "capa_explorer_wrapper.html"
    
    if not template_path.exists():
        # Fallback to direct method if template doesn't exist
        raise HTTPException(
            status_code=500,
            detail="Explorer wrapper template not found"
        )
    
    # Read template
    html_content = template_path.read_text(encoding='utf-8')
    
    # Construct the full URL to the CAPA JSON document
    # Use the request to build the absolute URL
    base_url = str(request.base_url).rstrip('/')
    capa_json_url = f"{base_url}/api/v1/samples/{sha512}/capa/document"
    
    # URL encode the JSON URL for use in the rdoc parameter
    from urllib.parse import quote
    capa_json_url_encoded = quote(capa_json_url, safe='')
    
    # Replace template variables
    html_content = html_content.replace('{{explorer_url}}', explorer_url)
    html_content = html_content.replace('{{capa_json_url}}', capa_json_url_encoded)
    html_content = html_content.replace('{{sample_sha512}}', sha512)
    
    return HTMLResponse(content=html_content)


@app.get("/api/v1/samples/{sha512}/capa/download")
async def download_capa_json(
    sha512: str,
    db: Session = Depends(get_db)
):
    """
    Download CAPA analysis result as JSON file
    
    - **sha512**: SHA512 hash of the sample
    """
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if not sample.capa_result_document:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Create a filename based on the sample
    filename = f"capa-{sample.md5[:8]}.json"
    
    # Return the JSON as a downloadable file
    return JSONResponse(
        content=json.loads(sample.capa_result_document),
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@app.get("/api/v1/stats/types")
async def get_file_type_stats(db: Session = Depends(get_db)):
    """Get statistics on file types"""
    stats = db.query(
        MalwareSample.file_type,
        func.count(MalwareSample.sha512).label('count')
    ).group_by(MalwareSample.file_type).all()
    
    return {
        "file_types": [
            {"type": stat[0].value, "count": stat[1]}
            for stat in stats
        ]
    }


@app.get("/api/v1/stats/families")
async def get_family_stats(db: Session = Depends(get_db)):
    """Get statistics on malware families"""
    stats = db.query(
        MalwareSample.family,
        func.count(MalwareSample.sha512).label('count')
    ).filter(
        MalwareSample.family.isnot(None)
    ).group_by(MalwareSample.family).order_by(
        func.count(MalwareSample.sha512).desc()
    ).limit(20).all()
    
    return {
        "top_families": [
            {"family": stat[0], "count": stat[1]}
            for stat in stats
        ]
    }


# CAPA Rules Management Endpoints

@app.get("/api/v1/capa/rules/status")
async def get_capa_rules_status():
    """Get CAPA rules installation status"""
    rules_manager = CapaRulesManager()
    return rules_manager.get_rules_info()


@app.post("/api/v1/capa/rules/download")
async def download_capa_rules(
    version: str = "latest",
    api_key: str = Depends(verify_api_key)
):
    """
    Download CAPA rules from GitHub
    
    Args:
        version: Version tag to download (e.g., 'v7.0.1' or 'latest')
    """
    rules_manager = CapaRulesManager()
    result = rules_manager.download_rules(version)
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to download rules"))
    
    return result


@app.post("/api/v1/capa/rules/upload")
async def upload_capa_rules(
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload CAPA rules from a ZIP file
    
    Args:
        file: ZIP file containing CAPA rules
    """
    import tempfile
    
    # Verify it's a ZIP file
    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
        content = await file.read()
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    try:
        rules_manager = CapaRulesManager()
        result = rules_manager.upload_rules(temp_file_path)
        
        if not result.get("success"):
            raise HTTPException(status_code=500, detail=result.get("error", "Failed to upload rules"))
        
        return result
    finally:
        # Clean up temporary file
        Path(temp_file_path).unlink(missing_ok=True)


@app.delete("/api/v1/capa/rules")
async def delete_capa_rules(api_key: str = Depends(verify_api_key)):
    """Delete all CAPA rules"""
    rules_manager = CapaRulesManager()
    result = rules_manager.delete_rules()
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to delete rules"))
    
    return result


# CAPA Explorer Management Endpoints

@app.get("/api/v1/capa/explorer/status")
async def get_capa_explorer_status():
    """Get CAPA Explorer installation status"""
    explorer_manager = CapaExplorerManager()
    return explorer_manager.get_explorer_info()


@app.post("/api/v1/capa/explorer/download")
async def download_capa_explorer(
    version: str = "latest",
    api_key: str = Depends(verify_api_key)
):
    """
    Download CAPA Explorer from GitHub
    
    Args:
        version: Version tag to download (e.g., 'v7.0.1' or 'latest')
    """
    explorer_manager = CapaExplorerManager()
    result = explorer_manager.download_explorer(version)
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to download explorer"))
    
    return result


@app.delete("/api/v1/capa/explorer")
async def delete_capa_explorer(api_key: str = Depends(verify_api_key)):
    """Delete CAPA Explorer"""
    explorer_manager = CapaExplorerManager()
    result = explorer_manager.delete_explorer()
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to delete explorer"))
    
    return result


@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint"""
    try:
        # Test database connection
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy" if db_status == "healthy" else "unhealthy",
        "database": db_status,
        "storage": "healthy" if file_storage.storage_path.exists() else "unhealthy"
    }


# Serve React app - this must be last to catch all non-API routes
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serve the React single-page application"""
    static_file = static_path / full_path
    
    # If file exists, serve it
    if static_file.is_file():
        return FileResponse(static_file)
    
    # Otherwise serve index.html (for React Router)
    index_file = static_path / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    
    # If no frontend built, return 404
    raise HTTPException(status_code=404, detail="Frontend not built. Run: cd frontend && npm run build")
