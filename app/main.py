"""Main application entry point"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import logging

from app.database import engine, Base
from app.config import settings, app_name, app_version
from app.api.routes import (
    system_router,
    health_router,
    samples_router,
    analysis_router,
    stats_router,
    capa_management_router,
    tasks_router,
    search_router
)

logger = logging.getLogger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

# Create FastAPI application
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

# Include API routers
app.include_router(health_router)
app.include_router(system_router)
app.include_router(samples_router)
app.include_router(analysis_router)
app.include_router(stats_router)
app.include_router(capa_management_router)
app.include_router(tasks_router)
app.include_router(search_router)

# Mount static files for frontend (CSS, JS, etc.)
static_path = Path(__file__).parent / "static"
static_assets_path = static_path / "static"  # React build puts assets in /static subdirectory
if static_assets_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_assets_path)), name="static")

# Mount CAPA Explorer if it exists
capa_explorer_path = Path(settings.capa_explorer_path)
if capa_explorer_path.exists() and (capa_explorer_path / "index.html").exists():
    app.mount("/capa-explorer", StaticFiles(directory=str(capa_explorer_path), html=True), name="capa-explorer")


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
