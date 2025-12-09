"""System routes - version, health, and system information"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from app.api.dependencies import get_db
from app.api.schemas import SystemInfo
from app.models import MalwareSample
from app.storage import FileStorage
from app.config import app_name, app_version
from app.version import __version__, get_full_version

router = APIRouter(prefix="/api/v1", tags=["system"])
health_router = APIRouter(tags=["health"])

# Storage instance
file_storage = FileStorage()


@router.get("/version")
async def get_version():
    """Get application version information"""
    return {
        "version": __version__,
        "app_name": app_name,
        "full_version": get_full_version()
    }


@router.get("/system", response_model=SystemInfo)
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


@health_router.get("/health")
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
