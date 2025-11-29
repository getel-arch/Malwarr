#!/usr/bin/env python3
"""
Setup script to download CAPA Explorer and rules during Docker image build
"""

import sys
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Import the managers
from app.analyzers.capa.capa_explorer_manager import CapaExplorerManager
from app.analyzers.capa.capa_rules_manager import CapaRulesManager
from app.config import settings


def main():
    """Download CAPA Explorer and rules"""
    logger.info("Starting CAPA resources download...")
    
    # Download CAPA rules
    logger.info("Downloading CAPA rules...")
    rules_manager = CapaRulesManager()
    rules_result = rules_manager.download_rules(version="latest")
    
    if rules_result["success"]:
        logger.info(f"✓ Successfully downloaded {rules_result.get('rules_count', 0)} CAPA rules")
        logger.info(f"  Version: {rules_result.get('version', 'unknown')}")
        logger.info(f"  Path: {rules_result.get('rules_path', 'unknown')}")
    else:
        logger.error(f"✗ Failed to download CAPA rules: {rules_result.get('error', 'unknown error')}")
        sys.exit(1)
    
    # Download CAPA Explorer
    logger.info("Downloading CAPA Explorer...")
    explorer_manager = CapaExplorerManager()
    explorer_result = explorer_manager.download_explorer(version="latest")
    
    if explorer_result["success"]:
        logger.info(f"✓ Successfully downloaded CAPA Explorer")
        logger.info(f"  Version: {explorer_result.get('version', 'unknown')}")
        logger.info(f"  Files: {explorer_result.get('file_count', 0)}")
        logger.info(f"  Path: {explorer_result.get('explorer_path', 'unknown')}")
    else:
        logger.error(f"✗ Failed to download CAPA Explorer: {explorer_result.get('error', 'unknown error')}")
        sys.exit(1)
    
    logger.info("CAPA resources setup completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
