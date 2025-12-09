"""System schemas"""
from pydantic import BaseModel


class SystemInfo(BaseModel):
    """System information response"""
    app_name: str
    version: str
    total_samples: int
    storage_used: int  # bytes
    database_status: str
