"""Authentication dependencies"""
from fastapi import Header, HTTPException
from app.config import settings


def verify_api_key(x_api_key: str = Header(None)):
    """Verify API key for protected endpoints"""
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key
