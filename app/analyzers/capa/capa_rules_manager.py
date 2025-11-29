"""
CAPA Rules Manager
Handles downloading and updating CAPA rules
"""

import logging
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional
import subprocess
import tempfile
import os

from app.config import settings

logger = logging.getLogger(__name__)


class CapaRulesManager:
    """Manager for CAPA rules"""
    
    def __init__(self, rules_path: str = None):
        """
        Initialize rules manager
        
        Args:
            rules_path: Path where rules should be stored. 
                       If None, uses settings.capa_rules_path
        """
        self.rules_path = Path(rules_path or settings.capa_rules_path)
        
    def download_rules(self, version: str = "latest") -> Dict[str, Any]:
        """
        Download CAPA rules from GitHub
        
        Args:
            version: Version tag to download (e.g., 'v7.0.1' or 'latest')
            
        Returns:
            Dictionary with download status
        """
        try:
            # GitHub repository for CAPA rules
            repo_url = "https://github.com/mandiant/capa-rules"
            
            # If version is latest, fetch the actual latest release tag
            if version == "latest":
                logger.info("Fetching latest CAPA rules version...")
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
                
                # Clone the repository with specific tag/branch
                logger.info(f"Cloning CAPA rules repository (version: {version})...")
                
                clone_cmd = ["git", "clone", "--depth", "1"]
                if version != "main":
                    clone_cmd.extend(["--branch", version])
                clone_cmd.extend([repo_url, str(temp_path / "capa-rules")])
                
                result = subprocess.run(
                    clone_cmd,
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
                
                # Copy rules to destination
                rules_source = temp_path / "capa-rules"
                
                # Remove old rules if they exist
                if self.rules_path.exists():
                    logger.info(f"Removing old rules from {self.rules_path}")
                    shutil.rmtree(self.rules_path)
                
                # Create parent directory if it doesn't exist
                self.rules_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy new rules
                logger.info(f"Installing rules to {self.rules_path}")
                shutil.copytree(rules_source, self.rules_path)
                
                # Count installed rules
                rule_files = list(self.rules_path.rglob("*.yml")) + list(self.rules_path.rglob("*.yaml"))
                rules_count = len(rule_files)
                
                logger.info(f"Successfully installed {rules_count} CAPA rules")
                
                return {
                    "success": True,
                    "version": version,
                    "rules_count": rules_count,
                    "rules_path": str(self.rules_path)
                }
                
        except subprocess.TimeoutExpired:
            error_msg = "Download timed out"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Error downloading rules: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
    
    def upload_rules(self, zip_file_path: str) -> Dict[str, Any]:
        """
        Upload and extract CAPA rules from a ZIP file
        
        Args:
            zip_file_path: Path to the ZIP file containing rules
            
        Returns:
            Dictionary with upload status
        """
        try:
            logger.info(f"Uploading rules from {zip_file_path}")
            
            # Verify it's a valid ZIP file
            if not zipfile.is_zipfile(zip_file_path):
                return {
                    "success": False,
                    "error": "Invalid ZIP file"
                }
            
            # Create temporary directory for extraction
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Extract ZIP file
                with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_path)
                
                # Find the rules directory (should contain .yml or .yaml files)
                rule_files = list(temp_path.rglob("*.yml")) + list(temp_path.rglob("*.yaml"))
                
                if not rule_files:
                    return {
                        "success": False,
                        "error": "No rule files (.yml or .yaml) found in the ZIP file"
                    }
                
                # Find the common root directory containing rules
                rules_root = temp_path
                for rule_file in rule_files:
                    # Try to find a common parent
                    if "rules" in str(rule_file).lower():
                        parts = rule_file.parts
                        for i, part in enumerate(parts):
                            if "rules" in part.lower():
                                potential_root = Path(*parts[:i+1])
                                if potential_root.exists():
                                    rules_root = potential_root
                                    break
                        break
                
                # Remove old rules if they exist
                if self.rules_path.exists():
                    logger.info(f"Removing old rules from {self.rules_path}")
                    shutil.rmtree(self.rules_path)
                
                # Create parent directory if it doesn't exist
                self.rules_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy new rules
                logger.info(f"Installing rules to {self.rules_path}")
                shutil.copytree(rules_root, self.rules_path)
                
                # Count installed rules
                installed_rules = list(self.rules_path.rglob("*.yml")) + list(self.rules_path.rglob("*.yaml"))
                rules_count = len(installed_rules)
                
                logger.info(f"Successfully uploaded {rules_count} CAPA rules")
                
                return {
                    "success": True,
                    "rules_count": rules_count,
                    "rules_path": str(self.rules_path)
                }
                
        except Exception as e:
            error_msg = f"Error uploading rules: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
    
    def get_rules_info(self) -> Dict[str, Any]:
        """
        Get information about installed rules
        
        Returns:
            Dictionary with rules information
        """
        info = {
            "installed": False,
            "rules_path": str(self.rules_path),
            "rules_count": 0,
            "last_updated": None,
            "size_mb": 0
        }
        
        if not self.rules_path.exists():
            return info
        
        # Count rules
        rule_files = list(self.rules_path.rglob("*.yml")) + list(self.rules_path.rglob("*.yaml"))
        info["installed"] = len(rule_files) > 0
        info["rules_count"] = len(rule_files)
        
        # Get last modified time
        if self.rules_path.exists():
            stat_info = os.stat(self.rules_path)
            from datetime import datetime
            info["last_updated"] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            
            # Calculate total size
            total_size = 0
            for rule_file in rule_files:
                total_size += rule_file.stat().st_size
            info["size_mb"] = round(total_size / (1024 * 1024), 2)
        
        return info
    
    def delete_rules(self) -> Dict[str, Any]:
        """
        Delete all installed rules
        
        Returns:
            Dictionary with deletion status
        """
        try:
            if self.rules_path.exists():
                shutil.rmtree(self.rules_path)
                logger.info(f"Deleted rules from {self.rules_path}")
                return {
                    "success": True,
                    "message": "Rules deleted successfully"
                }
            else:
                return {
                    "success": True,
                    "message": "No rules to delete"
                }
        except Exception as e:
            error_msg = f"Error deleting rules: {str(e)}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
