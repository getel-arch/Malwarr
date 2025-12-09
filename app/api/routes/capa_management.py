"""CAPA management routes - rules and explorer management"""
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from pathlib import Path
import tempfile

from app.api.dependencies import verify_api_key
from app.analyzers.capa.capa_rules_manager import CapaRulesManager
from app.analyzers.capa.capa_explorer_manager import CapaExplorerManager

router = APIRouter(prefix="/api/v1/capa", tags=["capa-management"])


# CAPA Rules Management

@router.get("/rules/status")
async def get_capa_rules_status():
    """Get CAPA rules installation status"""
    rules_manager = CapaRulesManager()
    return rules_manager.get_rules_info()


@router.post("/rules/download")
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


@router.post("/rules/upload")
async def upload_capa_rules(
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key)
):
    """
    Upload CAPA rules from a ZIP file
    
    Args:
        file: ZIP file containing CAPA rules
    """
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


@router.delete("/rules")
async def delete_capa_rules(api_key: str = Depends(verify_api_key)):
    """Delete all CAPA rules"""
    rules_manager = CapaRulesManager()
    result = rules_manager.delete_rules()
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to delete rules"))
    
    return result


# CAPA Explorer Management

@router.get("/explorer/status")
async def get_capa_explorer_status():
    """Get CAPA Explorer installation status"""
    explorer_manager = CapaExplorerManager()
    return explorer_manager.get_explorer_info()


@router.post("/explorer/download")
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


@router.delete("/explorer")
async def delete_capa_explorer(api_key: str = Depends(verify_api_key)):
    """Delete CAPA Explorer"""
    explorer_manager = CapaExplorerManager()
    result = explorer_manager.delete_explorer()
    
    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to delete explorer"))
    
    return result
