"""Statistics routes - file type and family statistics"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.api.dependencies import get_db
from app.models import MalwareSample

router = APIRouter(prefix="/api/v1/stats", tags=["statistics"])


@router.get("/types")
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


@router.get("/families")
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
