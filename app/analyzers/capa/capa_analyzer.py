"""
CAPA Analyzer Service
Analyzes executable files to detect capabilities using FLARE CAPA
"""

import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import logging

# Import capa Python API
import capa.main
import capa.rules
import capa.loader
import capa.capabilities.common
import capa.render.result_document as rd
import capa.render.json
from capa.exceptions import UnsupportedFormatError, UnsupportedRuntimeError

from app.config import settings

logger = logging.getLogger(__name__)


class CapaAnalyzer:
    """Service for analyzing files with CAPA to detect capabilities"""
    
    def __init__(self, capa_path: Optional[str] = None, rules_path: Optional[str] = None):
        """
        Initialize CAPA analyzer
        
        Args:
            capa_path: Not used (kept for compatibility). CAPA Python API is used instead
            rules_path: Path to CAPA rules directory. If None, uses settings.capa_rules_path
        """
        self.rules_path = rules_path or settings.capa_rules_path
        self.rules = None
        self._load_rules()
    
    def _load_rules(self) -> bool:
        """
        Load CAPA rules from the rules directory
        
        Returns:
            True if rules were loaded successfully, False otherwise
        """
        try:
            rules_dir = Path(self.rules_path)
            
            # Check if rules directory exists
            if not rules_dir.exists() or not rules_dir.is_dir():
                logger.warning(f"CAPA rules directory not found at {self.rules_path}")
                logger.info("Please download rules using the API endpoint: POST /api/v1/capa/rules/download")
                return False
            
            # Load rules from directory
            logger.info(f"Loading CAPA rules from: {self.rules_path}")
            self.rules = capa.rules.get_rules([rules_dir])
            
            rule_count = len(self.rules)
            logger.info(f"Successfully loaded {rule_count} CAPA rules")
            return True
            
        except Exception as e:
            logger.error(f"Error loading CAPA rules: {e}")
            return False
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a file with CAPA and extract capabilities
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing CAPA analysis results
        """
        try:
            # Reload rules if not loaded
            if self.rules is None:
                if not self._load_rules():
                    return self._create_error_result(
                        "CAPA rules not loaded. Please download rules using: POST /api/v1/capa/rules/download"
                    )
            
            # Use capa Python API to analyze the file
            logger.info(f"Analyzing file with CAPA: {file_path}")
            
            input_path = Path(file_path)
            
            # Get default signatures (handles embedded or fallback)
            try:
                sigpaths = capa.main.get_default_signatures()
            except Exception as e:
                logger.warning(f"Could not get default signatures: {e}, using empty list")
                sigpaths = []
            
            # Auto-detect file format
            input_format = capa.main.get_auto_format(input_path)
            
            # Check for unsupported formats
            # CAPA currently supports: pe, elf, sc32, sc64, shellcode, freeze, result
            # Formats like dotnet, auto, unknown are not fully supported
            SUPPORTED_FORMATS = ['pe', 'elf', 'sc32', 'sc64', 'shellcode', 'freeze', 'result']
            if input_format not in SUPPORTED_FORMATS:
                logger.warning(f"Unsupported file format detected: {input_format}")
                return self._create_error_result(
                    f"Unsupported file format: {input_format}. CAPA currently supports: {', '.join(SUPPORTED_FORMATS)}"
                )
            
            # Get OS based on sample
            os_ = capa.loader.get_os(input_path)
            
            # Determine appropriate backend based on format
            # Use vivisect (VIV) backend for PE and ELF files for full capability analysis
            # pefile backend only supports file-level features
            backend = capa.main.BACKEND_VIV
            
            logger.info(f"Using format: {input_format}, OS: {os_}, backend: {backend}")
            
            # Get the extractor for the file using capa.loader
            extractor = capa.loader.get_extractor(
                input_path=input_path,
                input_format=input_format,
                os_=os_,
                backend=backend,
                sigpaths=sigpaths,
                should_save_workspace=False,
                disable_progress=True
            )
            
            # Extract capabilities
            capabilities = capa.capabilities.common.find_capabilities(
                self.rules, extractor, disable_progress=True
            )
            
            # Get file metadata
            meta = capa.loader.collect_metadata(
                [],  # argv
                input_path,
                input_format,
                os_,
                [Path(self.rules_path)],  # rules_path
                extractor,
                capabilities
            )
            
            # Generate JSON result using CAPA's render.json module
            # This produces output compatible with CAPA Explorer Web
            json_output = capa.render.json.render(meta, self.rules, capabilities.matches)
            
            # Parse the JSON string to a dictionary
            result_dict = json.loads(json_output)
            
            # Parse and structure the results
            analysis_result = self._parse_capa_output(result_dict)
            
            # Store the full result document for CAPA Explorer
            analysis_result["result_document"] = result_dict
            
            return analysis_result
            
        except UnsupportedFormatError as e:
            logger.error(f"Unsupported file format: {e}")
            return self._create_error_result(f"Unsupported file format: {e}")
        except UnsupportedRuntimeError as e:
            logger.error(f"Unsupported runtime: {e}")
            return self._create_error_result(f"Unsupported runtime: {e}")
        except ValueError as e:
            # Catch ValueError which may be raised for unsupported formats
            error_msg = str(e)
            if "unexpected format" in error_msg.lower():
                logger.error(f"Unsupported file format: {e}")
                return self._create_error_result(f"Unsupported file format: {e}")
            else:
                logger.error(f"CAPA analysis error: {e}", exc_info=True)
                return self._create_error_result(str(e))
        except Exception as e:
            logger.error(f"CAPA analysis error: {e}", exc_info=True)
            return self._create_error_result(str(e))
    
    def _parse_capa_output(self, capa_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and structure CAPA JSON output
        
        Args:
            capa_output: Raw CAPA JSON output
            
        Returns:
            Structured analysis results
        """
        result = {
            "success": True,
            "error": None,
            "meta": {},
            "rules": {},
            "capabilities": [],
            "attack": [],
            "mbc": [],
            "namespace_counts": {}
        }
        
        # Extract metadata
        if "meta" in capa_output:
            meta = capa_output["meta"]
            result["meta"] = {
                "timestamp": meta.get("timestamp"),
                "version": meta.get("version"),
                "argv": meta.get("argv"),
                "sample": {
                    "md5": meta.get("sample", {}).get("md5"),
                    "sha1": meta.get("sample", {}).get("sha1"),
                    "sha256": meta.get("sample", {}).get("sha256"),
                    "path": meta.get("sample", {}).get("path")
                },
                "analysis": meta.get("analysis", {})
            }
        
        # Extract rules/capabilities
        if "rules" in capa_output:
            rules = capa_output["rules"]
            result["rules"] = rules
            
            # Organize capabilities by category
            capabilities_by_namespace = {}
            attack_techniques = set()
            mbc_objectives = set()
            
            for rule_name, rule_data in rules.items():
                if not isinstance(rule_data, dict):
                    continue
                
                meta = rule_data.get("meta", {})
                namespace = meta.get("namespace", "unknown")
                
                # Track namespace counts
                if namespace not in result["namespace_counts"]:
                    result["namespace_counts"][namespace] = 0
                result["namespace_counts"][namespace] += 1
                
                # Build capability entry
                capability = {
                    "name": rule_name,
                    "namespace": namespace,
                    "description": meta.get("description", ""),
                    "scope": meta.get("scope", ""),
                    "attack": meta.get("attack", []),
                    "mbc": meta.get("mbc", []),
                    "references": meta.get("references", []),
                    "examples": meta.get("examples", [])
                }
                
                # Add to namespace grouping
                if namespace not in capabilities_by_namespace:
                    capabilities_by_namespace[namespace] = []
                capabilities_by_namespace[namespace].append(capability)
                
                # Collect ATT&CK techniques
                for attack in meta.get("attack", []):
                    if isinstance(attack, dict):
                        attack_techniques.add(f"{attack.get('id', '')} - {attack.get('tactic', '')}")
                    elif isinstance(attack, str):
                        attack_techniques.add(attack)
                
                # Collect MBC objectives
                for mbc in meta.get("mbc", []):
                    if isinstance(mbc, dict):
                        mbc_objectives.add(f"{mbc.get('id', '')} - {mbc.get('objective', '')}")
                    elif isinstance(mbc, str):
                        mbc_objectives.add(mbc)
            
            result["capabilities"] = capabilities_by_namespace
            result["attack"] = sorted(list(attack_techniques))
            result["mbc"] = sorted(list(mbc_objectives))
        
        return result
    
    def _create_error_result(self, error_message: str) -> Dict[str, Any]:
        """
        Create an error result structure
        
        Args:
            error_message: Error message to include
            
        Returns:
            Error result dictionary
        """
        return {
            "success": False,
            "error": error_message,
            "meta": {},
            "rules": {},
            "capabilities": [],
            "attack": [],
            "mbc": [],
            "namespace_counts": {}
        }
    
    def get_capability_summary(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of detected capabilities
        
        Args:
            analysis_result: CAPA analysis result
            
        Returns:
            Summary dictionary with key statistics
        """
        if not analysis_result.get("success"):
            return {
                "total_capabilities": 0,
                "namespaces": {},
                "attack_techniques_count": 0,
                "mbc_objectives_count": 0,
                "top_namespaces": []
            }
        
        namespace_counts = analysis_result.get("namespace_counts", {})
        top_namespaces = sorted(
            namespace_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]
        
        return {
            "total_capabilities": sum(namespace_counts.values()),
            "namespaces": namespace_counts,
            "attack_techniques_count": len(analysis_result.get("attack", [])),
            "mbc_objectives_count": len(analysis_result.get("mbc", [])),
            "top_namespaces": [{"namespace": ns, "count": count} for ns, count in top_namespaces]
        }
    
    def get_capabilities_by_category(self, analysis_result: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Get capabilities organized by high-level categories
        
        Args:
            analysis_result: CAPA analysis result
            
        Returns:
            Dictionary mapping categories to capability names
        """
        capabilities = analysis_result.get("capabilities", {})
        
        # Define high-level categories based on namespace prefixes
        categories = {
            "Anti-Analysis": [],
            "Collection": [],
            "Communication": [],
            "Cryptography": [],
            "Data Manipulation": [],
            "Executable": [],
            "File Operations": [],
            "Host Interaction": [],
            "Persistence": [],
            "Malware": [],
            "Other": []
        }
        
        category_mapping = {
            "anti-analysis": "Anti-Analysis",
            "collection": "Collection",
            "communication": "Communication",
            "data-manipulation": "Data Manipulation",
            "executable": "Executable",
            "file-system": "File Operations",
            "host-interaction": "Host Interaction",
            "persistence": "Persistence",
            "malware": "Malware",
            "crypto": "Cryptography"
        }
        
        for namespace, caps in capabilities.items():
            # Determine category from namespace
            category = "Other"
            for key, cat_name in category_mapping.items():
                if key in namespace.lower():
                    category = cat_name
                    break
            
            # Add capability names to category
            for cap in caps:
                categories[category].append(cap["name"])
        
        # Remove empty categories
        return {k: v for k, v in categories.items() if v}
    
    def get_rules_status(self) -> Dict[str, Any]:
        """
        Get status of CAPA rules installation
        
        Returns:
            Dictionary with rules status information
        """
        rules_dir = Path(self.rules_path)
        
        status = {
            "rules_path": self.rules_path,
            "rules_installed": False,
            "rules_count": 0,
            "last_updated": None,
            "version": None
        }
        
        if not rules_dir.exists():
            return status
        
        # Check if rules directory contains .yml or .yaml files
        rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
        status["rules_installed"] = len(rule_files) > 0
        status["rules_count"] = len(rule_files)
        
        # Try to get last modified time
        if rules_dir.exists():
            import os
            stat_info = os.stat(rules_dir)
            from datetime import datetime
            status["last_updated"] = datetime.fromtimestamp(stat_info.st_mtime).isoformat()
        
        return status

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Wrapper method to analyze a file and return results.
        This ensures compatibility with worker execution.
        """
        return self.analyze_file(file_path)


def analyze_with_capa(file_path: str, capa_path: Optional[str] = None, rules_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to analyze a file with CAPA
    
    Args:
        file_path: Path to the file to analyze
        capa_path: Optional path to CAPA executable
        rules_path: Optional path to CAPA rules directory
        
    Returns:
        CAPA analysis results
    """
    analyzer = CapaAnalyzer(capa_path, rules_path)
    return analyzer.analyze_file(file_path)
