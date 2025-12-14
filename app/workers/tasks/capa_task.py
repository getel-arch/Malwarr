import json
import logging
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List

# Import capa Python API
import capa.main
import capa.rules
import capa.loader
import capa.capabilities.common
import capa.render.result_document as rd
import capa.render.json
from capa.exceptions import UnsupportedFormatError, UnsupportedRuntimeError

from app.config import settings
from app.models import MalwareSample, CAPAAnalysis, FileType
from app.workers.tasks.base_analysis_task import AnalysisTask
from app.workers.celery_app import celery_app

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
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Wrapper method to analyze a file and return results.
        This ensures compatibility with worker execution.
        """
        return self.analyze_file(file_path)


class CAPAAnalysisTask(AnalysisTask):
    """CAPA capabilities analysis task"""
    
    @property
    def task_name(self) -> str:
        return "CAPA"
    
    def get_supported_file_types(self) -> Optional[List[FileType]]:
        return [FileType.PE, FileType.ELF]
    
    def perform_analysis(self, sample: MalwareSample, file_path: str) -> Dict[str, Any]:
        """
        Perform CAPA analysis using temporary file.
        Note: CAPA uses temp file instead of direct path access.
        """
        # Get file content from storage
        file_content = self.storage.get_file(sample.storage_path)
        if not file_content:
            logger.error(f"Sample file not found in storage: {sample.storage_path}")
            return {
                "success": False,
                "error": "Sample file not found in storage"
            }
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(sample.filename).suffix) as tmp:
            tmp.write(file_content)
            tmp_path = tmp.name
        
        try:
            capa_result = self.capa_analyzer.analyze_file(tmp_path)
            
            if capa_result.get("success"):
                return {
                    "success": True,
                    "capa_result": capa_result
                }
            else:
                error_msg = capa_result.get('error', 'Unknown error')
                return {
                    "success": False,
                    "error": error_msg
                }
        finally:
            Path(tmp_path).unlink(missing_ok=True)
    
    def save_analysis_results(self, sample: MalwareSample, analysis_result: Dict[str, Any]) -> None:
        """Save CAPA analysis results to database"""
        capa_result = analysis_result.get("capa_result", {})
        
        # Check if CAPA analysis already exists
        capa_analysis = self.db.query(CAPAAnalysis).filter(
            CAPAAnalysis.sha512 == sample.sha512
        ).first()
        
        if not capa_analysis:
            # Create new CAPA analysis record
            capa_analysis = CAPAAnalysis(
                sha512=sample.sha512,
                analysis_date=datetime.utcnow()
            )
            self.db.add(capa_analysis)
        
        # Update CAPA analysis with results
        capa_analysis.capabilities = json.dumps(capa_result.get("capabilities", {}))
        capa_analysis.attack = json.dumps(capa_result.get("attack", []))
        capa_analysis.mbc = json.dumps(capa_result.get("mbc", []))
        capa_analysis.result_document = json.dumps(capa_result.get("result_document", {}))
        capa_analysis.total_capabilities = sum(
            capa_result.get("namespace_counts", {}).values()
        )
        capa_analysis.analysis_date = datetime.utcnow()
        
        logger.info(f"CAPA analysis saved: {capa_analysis.total_capabilities} capabilities detected")
        
        self.db.commit()


@celery_app.task(base=CAPAAnalysisTask, bind=True, name='app.workers.tasks.capa_task')
def analyze_sample_with_capa(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with CAPA in the background

    Args:
        sha512: SHA512 hash of the sample to analyze

    Returns:
        Dictionary with analysis results
    """
    return self.run_analysis(sha512)