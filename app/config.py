from pydantic_settings import BaseSettings
from app.version import __version__, APP_NAME


class Settings(BaseSettings):
    """Application settings"""
    
    # Database
    database_url: str = "postgresql://malwarr:malwarr@localhost:5432/malwarr"
    
    # Redis (for Celery)
    redis_url: str = "redis://localhost:6379/0"
    
    # Storage
    storage_path: str = "/data/samples"
    
    # CAPA
    capa_rules_path: str = "/data/capa-rules"
    capa_explorer_path: str = "/data/capa-explorer"
    
    # API
    api_key: str = "your-api-key-here"
    
    # VirusTotal
    virustotal_api_key: str = ""
    
    # Application
    debug: bool = False
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()

# Application constants (not configurable via .env)
app_name = APP_NAME
app_version = __version__
