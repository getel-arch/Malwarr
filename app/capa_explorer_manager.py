"""
CAPA Explorer Manager
Handles downloading and hosting the CAPA Explorer web interface
"""

import logging
import shutil
from pathlib import Path
from typing import Dict, Any
import subprocess
import tempfile
import os
import zipfile

from app.config import settings

logger = logging.getLogger(__name__)


class CapaExplorerManager:
    """Manager for CAPA Explorer web interface"""
    
    def __init__(self, explorer_path: str = None):
        """
        Initialize explorer manager
        
        Args:
            explorer_path: Path where explorer files should be stored. 
                          If None, uses settings.capa_explorer_path
        """
        self.explorer_path = Path(explorer_path or settings.capa_explorer_path)
        
    def download_explorer(self, version: str = "latest") -> Dict[str, Any]:
        """
        Download CAPA Explorer from GitHub
        
        Args:
            version: Version tag to download (e.g., 'v7.0.1' or 'latest')
            
        Returns:
            Dictionary with download status
        """
        try:
            # GitHub repository for CAPA
            repo_url = "https://github.com/mandiant/capa"
            
            # If version is latest, fetch the actual latest release tag
            if version == "latest":
                logger.info("Fetching latest CAPA version...")
                result = subprocess.run(
                    ["git", "ls-remote", "--tags", "--refs", repo_url],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    # Parse tags to find the latest
                    tags = [line.split('refs/tags/')[-1] for line in result.stdout.strip().split('\n') if 'refs/tags/' in line]
                    if tags:
                        version = tags[-1]
                        logger.info(f"Latest version: {version}")
                    else:
                        version = "main"  # Fallback to main branch
                else:
                    logger.warning("Could not fetch tags, using main branch")
                    version = "main"
            
            # Create temporary directory for download
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Clone the repository with specific tag/branch - sparse checkout for explorer only
                logger.info(f"Cloning CAPA repository (version: {version})...")
                
                repo_path = temp_path / "capa"
                
                # Initialize git repo
                subprocess.run(
                    ["git", "init"],
                    cwd=temp_path,
                    capture_output=True,
                    timeout=10
                )
                
                # Add remote
                subprocess.run(
                    ["git", "remote", "add", "origin", repo_url],
                    cwd=temp_path,
                    capture_output=True,
                    timeout=10
                )
                
                # Enable sparse checkout
                subprocess.run(
                    ["git", "config", "core.sparseCheckout", "true"],
                    cwd=temp_path,
                    capture_output=True,
                    timeout=10
                )
                
                # Specify we only want the web directory
                sparse_checkout_file = temp_path / ".git" / "info" / "sparse-checkout"
                sparse_checkout_file.parent.mkdir(parents=True, exist_ok=True)
                sparse_checkout_file.write_text("web/*\n")
                
                # Pull the specific version
                pull_cmd = ["git", "pull", "--depth", "1", "origin"]
                if version != "main":
                    pull_cmd.append(version)
                else:
                    pull_cmd.append("main")
                
                result = subprocess.run(
                    pull_cmd,
                    cwd=temp_path,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode != 0:
                    error_msg = f"Failed to clone repository: {result.stderr}"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                # Check if web directory exists
                web_source = temp_path / "web" / "explorer"
                if not web_source.exists():
                    error_msg = "Web explorer directory not found in repository"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                # Check for pre-built release
                releases_dir = web_source / "releases"
                if releases_dir.exists():
                    # Find the zip file
                    zip_files = list(releases_dir.glob("*.zip"))
                    if zip_files:
                        logger.info(f"Found pre-built release: {zip_files[0].name}")
                        
                        # Remove old explorer if it exists
                        if self.explorer_path.exists():
                            logger.info(f"Removing old explorer from {self.explorer_path}")
                            shutil.rmtree(self.explorer_path)
                        
                        # Create the explorer directory
                        self.explorer_path.mkdir(parents=True, exist_ok=True)
                        
                        # Extract the pre-built release to a temporary location
                        logger.info(f"Extracting release")
                        with tempfile.TemporaryDirectory() as extract_dir:
                            extract_path = Path(extract_dir)
                            with zipfile.ZipFile(zip_files[0], 'r') as zip_ref:
                                zip_ref.extractall(extract_path)
                            
                            # The zip extracts to a subdirectory, find it and move its contents
                            extracted_items = list(extract_path.iterdir())
                            if len(extracted_items) == 1 and extracted_items[0].is_dir():
                                # Single directory, move its contents to explorer_path
                                source_dir = extracted_items[0]
                                logger.info(f"Moving contents from {source_dir.name} to {self.explorer_path}")
                                # Copy contents of the directory, not the directory itself
                                for item in source_dir.iterdir():
                                    dest = self.explorer_path / item.name
                                    if item.is_dir():
                                        shutil.copytree(item, dest)
                                    else:
                                        shutil.copy2(item, dest)
                            else:
                                # Multiple items or files, move all to explorer_path
                                logger.info(f"Moving multiple items to {self.explorer_path}")
                                for item in extract_path.iterdir():
                                    dest = self.explorer_path / item.name
                                    if item.is_dir():
                                        shutil.copytree(item, dest)
                                    else:
                                        shutil.copy2(item, dest)
                        
                        # Count files
                        files = list(self.explorer_path.rglob("*"))
                        file_count = len([f for f in files if f.is_file()])
                        
                        logger.info(f"Successfully installed CAPA Explorer with {file_count} files")
                        
                        return {
                            "success": True,
                            "version": version,
                            "file_count": file_count,
                            "explorer_path": str(self.explorer_path)
                        }
                
                # Fallback: if no pre-built release, we can't use the source
                error_msg = "No pre-built release found. CAPA Explorer requires a built version."
                logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg
                }
                
        except subprocess.TimeoutExpired:
            error_msg = "Download timed out"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Error downloading explorer: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
    
    def get_explorer_info(self) -> Dict[str, Any]:
        """
        Get information about installed explorer
        
        Returns:
            Dictionary with explorer information
        """
        info = {
            "installed": False,
            "explorer_path": str(self.explorer_path),
            "file_count": 0,
            "last_updated": None,
            "size_mb": 0,
            "index_exists": False
        }
        
        if not self.explorer_path.exists():
            return info
        
        # Check for index.html
        index_file = self.explorer_path / "index.html"
        info["index_exists"] = index_file.exists()
        info["installed"] = info["index_exists"]
        
        # Count files
        files = list(self.explorer_path.rglob("*"))
        file_list = [f for f in files if f.is_file()]
        info["file_count"] = len(file_list)
        
        # Get last modified time
        if self.explorer_path.exists():
            stat_info = os.stat(self.explorer_path)
            from datetime import datetime
            info["last_updated"] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            
            # Calculate total size
            total_size = sum(f.stat().st_size for f in file_list)
            info["size_mb"] = round(total_size / (1024 * 1024), 2)
        
        return info
    
    def delete_explorer(self) -> Dict[str, Any]:
        """
        Delete installed explorer
        
        Returns:
            Dictionary with deletion status
        """
        try:
            if self.explorer_path.exists():
                shutil.rmtree(self.explorer_path)
                logger.info(f"Deleted explorer from {self.explorer_path}")
                return {
                    "success": True,
                    "message": "Explorer deleted successfully"
                }
            else:
                return {
                    "success": True,
                    "message": "No explorer to delete"
                }
        except Exception as e:
            error_msg = f"Error deleting explorer: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
