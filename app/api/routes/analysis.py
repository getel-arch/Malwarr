"""Analysis routes - CAPA and other analysis operations"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
import json
import logging
from pathlib import Path

from app.api.dependencies import get_db, verify_api_key
from app.models import (
    MalwareSample, 
    PEAnalysis, 
    ELFAnalysis, 
    MagikaAnalysis, 
    CAPAAnalysis, 
    VirusTotalAnalysis,
    StringsAnalysis,
    FileType, 
    AnalysisStatus
)
from app.api.schemas.samples import (
    PEAnalysisResponse,
    ELFAnalysisResponse,
    MagikaAnalysisResponse,
    CAPAAnalysisResponse,
    VirusTotalAnalysisResponse,
    StringsAnalysisResponse
)
from app.storage import FileStorage
from app.config import settings

router = APIRouter(prefix="/api/v1/samples", tags=["analysis"])
logger = logging.getLogger(__name__)

# Storage instance
file_storage = FileStorage()


@router.post("/{sha512}/rescan")
async def rescan_sample(
    sha512: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Trigger all relevant analyzers for a specific sample

    - Queues PE/ELF metadata extraction, CAPA analysis, VirusTotal, Strings, and Magika analysis
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

        # Queue Magika analysis for all files
        from app.workers.tasks import analyze_sample_with_magika
        try:
            task = analyze_sample_with_magika.delay(sample.sha512)
            queued['magika'] = task.id
            logger.info(f"Magika analysis task queued: {task.id}")
        except Exception as e:
            logger.error(f"Failed to queue Magika analysis: {e}")

        # Queue VirusTotal analysis for all files
        from app.workers.tasks import analyze_sample_with_virustotal
        try:
            task = analyze_sample_with_virustotal.delay(sample.sha512)
            queued['virustotal'] = task.id
            logger.info(f"VirusTotal analysis task queued: {task.id}")
        except Exception as e:
            logger.error(f"Failed to queue VirusTotal analysis: {e}")

        # Queue Strings analysis for all files
        from app.workers.tasks import analyze_sample_with_strings
        try:
            task = analyze_sample_with_strings.delay(sample.sha512)
            queued['strings'] = task.id
            logger.info(f"Strings analysis task queued: {task.id}")
        except Exception as e:
            logger.error(f"Failed to queue Strings analysis: {e}")

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


@router.post("/{sha512}/virustotal/upload")
async def upload_sample_to_virustotal(
    sha512: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload a sample to VirusTotal for scanning
    
    - **sha512**: SHA512 hash of the sample to upload
    
    Returns upload status and analysis tracking information
    """
    # Check if VT API key is configured
    if not settings.virustotal_api_key or settings.virustotal_api_key == "":
        raise HTTPException(
            status_code=503, 
            detail="VirusTotal API key not configured. Please configure VIRUSTOTAL_API_KEY in settings."
        )
    
    sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    # Queue the upload task
    from app.workers.tasks import upload_sample_to_virustotal_task
    
    try:
        task = upload_sample_to_virustotal_task.delay(sha512)
        logger.info(f"VirusTotal upload task queued: {task.id} for sample: {sha512}")
        
        return {
            "status": "queued",
            "sha512": sha512,
            "task_id": task.id,
            "message": "Upload task queued. Results will be available once VirusTotal completes analysis."
        }
    except Exception as e:
        logger.error(f"Failed to queue VirusTotal upload task: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to queue upload task: {str(e)}"
        )


@router.post("/virustotal/upload/bulk")
async def upload_samples_to_virustotal_bulk(
    sha512_list: List[str],
    db: Session = Depends(get_db),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload multiple samples to VirusTotal for scanning
    
    - **sha512_list**: List of SHA512 hashes to upload
    
    Returns upload status for each sample
    """
    # Check if VT API key is configured
    if not settings.virustotal_api_key or settings.virustotal_api_key == "":
        raise HTTPException(
            status_code=503, 
            detail="VirusTotal API key not configured. Please configure VIRUSTOTAL_API_KEY in settings."
        )
    
    if not sha512_list or len(sha512_list) == 0:
        raise HTTPException(status_code=400, detail="No samples provided")
    
    if len(sha512_list) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 samples can be uploaded at once")
    
    from app.workers.tasks import upload_sample_to_virustotal_task
    
    results = []
    
    for sha512 in sha512_list:
        try:
            # Verify sample exists
            sample = db.query(MalwareSample).filter(MalwareSample.sha512 == sha512).first()
            
            if not sample:
                results.append({
                    "sha512": sha512,
                    "status": "error",
                    "message": "Sample not found"
                })
                continue
            
            # Queue the upload task
            task = upload_sample_to_virustotal_task.delay(sha512)
            logger.info(f"VirusTotal upload task queued: {task.id} for sample: {sha512}")
            
            results.append({
                "sha512": sha512,
                "status": "queued",
                "task_id": task.id,
                "message": "Upload task queued"
            })
        except Exception as e:
            logger.error(f"Error queueing upload for {sha512}: {e}")
            results.append({
                "sha512": sha512,
                "status": "error",
                "message": str(e)
            })
    
    success_count = sum(1 for r in results if r['status'] == 'queued')
    error_count = len(results) - success_count
    
    return {
        "total": len(results),
        "queued": success_count,
        "errors": error_count,
        "results": results
    }


@router.get("/{sha512}/analyze/status")
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


@router.post("/batch/analyze/capa")
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


@router.get("/{sha512}/capa")
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
    
    if not sample.capa_analysis or not sample.capa_analysis.analysis_date:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Parse JSON fields from capa_analysis
    capabilities = json.loads(sample.capa_analysis.capabilities) if sample.capa_analysis.capabilities else {}
    attack = json.loads(sample.capa_analysis.attack) if sample.capa_analysis.attack else []
    mbc = json.loads(sample.capa_analysis.mbc) if sample.capa_analysis.mbc else []
    
    return {
        "sha512": sha512,
        "filename": sample.filename,
        "analysis_date": sample.capa_analysis.analysis_date,
        "total_capabilities": sample.capa_analysis.total_capabilities,
        "capabilities": capabilities,
        "attack_techniques": attack,
        "mbc_objectives": mbc
    }


@router.get("/{sha512}/capa/document")
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
    
    if not sample.capa_analysis or not sample.capa_analysis.result_document:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Return the full result document
    return json.loads(sample.capa_analysis.result_document)


@router.get("/{sha512}/capa/explorer")
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
    
    if not sample.capa_analysis or not sample.capa_analysis.result_document:
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
    capa_json_data = sample.capa_analysis.result_document
    
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


@router.get("/{sha512}/capa/explorer-wrapped")
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
    
    if not sample.capa_analysis or not sample.capa_analysis.result_document:
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
    template_path = Path(__file__).parent.parent.parent / "templates" / "capa_explorer_wrapper.html"
    
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


@router.get("/{sha512}/capa/download")
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
    
    if not sample.capa_analysis or not sample.capa_analysis.result_document:
        raise HTTPException(status_code=404, detail="CAPA analysis not available for this sample")
    
    # Create a filename based on the sample
    filename = f"capa-{sample.md5[:8]}.json"
    
    # Return the JSON as a downloadable file
    return JSONResponse(
        content=json.loads(sample.capa_analysis.result_document),
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


# ==================== Individual Analyzer Result Routes ====================

@router.get("/{sha512}/analysis/pe", response_model=Optional[PEAnalysisResponse])
async def get_pe_analysis(sha512: str, db: Session = Depends(get_db)):
    """
    Get PE analysis results for a specific sample
    
    Returns None if no PE analysis is available
    """
    pe_analysis = db.query(PEAnalysis).filter(PEAnalysis.sha512 == sha512).first()
    
    if not pe_analysis:
        return None
    
    return pe_analysis


@router.get("/{sha512}/analysis/elf", response_model=Optional[ELFAnalysisResponse])
async def get_elf_analysis(sha512: str, db: Session = Depends(get_db)):
    """
    Get ELF analysis results for a specific sample
    
    Returns None if no ELF analysis is available
    """
    elf_analysis = db.query(ELFAnalysis).filter(ELFAnalysis.sha512 == sha512).first()
    
    if not elf_analysis:
        return None
    
    return elf_analysis


@router.get("/{sha512}/analysis/magika", response_model=Optional[MagikaAnalysisResponse])
async def get_magika_analysis(sha512: str, db: Session = Depends(get_db)):
    """
    Get Magika file type detection results for a specific sample
    
    Returns None if no Magika analysis is available
    """
    magika_analysis = db.query(MagikaAnalysis).filter(MagikaAnalysis.sha512 == sha512).first()
    
    if not magika_analysis:
        return None
    
    return magika_analysis


@router.get("/{sha512}/analysis/virustotal", response_model=Optional[VirusTotalAnalysisResponse])
async def get_virustotal_analysis(sha512: str, db: Session = Depends(get_db)):
    """
    Get VirusTotal scan results for a specific sample
    
    Returns None if no VirusTotal analysis is available
    """
    vt_analysis = db.query(VirusTotalAnalysis).filter(VirusTotalAnalysis.sha512 == sha512).first()
    
    if not vt_analysis:
        return None
    
    return vt_analysis


@router.get("/{sha512}/analysis/strings", response_model=Optional[StringsAnalysisResponse])
async def get_strings_analysis(sha512: str, db: Session = Depends(get_db)):
    """
    Get Strings extraction results for a specific sample
    
    Returns None if no Strings analysis is available
    """
    strings_analysis = db.query(StringsAnalysis).filter(StringsAnalysis.sha512 == sha512).first()
    
    if not strings_analysis:
        return None
    
    return strings_analysis
