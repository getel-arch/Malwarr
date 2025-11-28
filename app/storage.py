import os
import shutil
from pathlib import Path
from typing import Optional
from app.config import settings


class FileStorage:
    """Handle file storage operations"""
    
    def __init__(self, storage_path: str = None):
        self.storage_path = Path(storage_path or settings.storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def save_file(self, file_content: bytes, relative_path: str) -> str:
        """Save file to storage"""
        full_path = self.storage_path / relative_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(full_path, 'wb') as f:
            f.write(file_content)
        
        return str(full_path)
    
    def get_file(self, relative_path: str) -> Optional[bytes]:
        """Retrieve file from storage"""
        full_path = self.storage_path / relative_path
        
        if not full_path.exists():
            return None
        
        with open(full_path, 'rb') as f:
            return f.read()
    
    def delete_file(self, relative_path: str) -> bool:
        """Delete file from storage"""
        full_path = self.storage_path / relative_path
        
        if not full_path.exists():
            return False
        
        full_path.unlink()
        
        # Clean up empty directories
        try:
            full_path.parent.rmdir()
            full_path.parent.parent.rmdir()
        except OSError:
            pass  # Directory not empty
        
        return True
    
    def file_exists(self, relative_path: str) -> bool:
        """Check if file exists in storage"""
        full_path = self.storage_path / relative_path
        return full_path.exists()
    
    def get_storage_size(self) -> int:
        """Get total storage size in bytes"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(self.storage_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                total_size += os.path.getsize(filepath)
        return total_size
