from pydantic_settings import BaseSettings


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
    
    # Application
    app_name: str = "Malwarr"
    app_version: str = "1.0.0"
    debug: bool = False
    
    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()
