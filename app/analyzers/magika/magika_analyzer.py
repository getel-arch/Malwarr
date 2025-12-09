"""
Magika Analyzer - Deep Learning-based file type detection
Uses Google's Magika for accurate file type identification
"""
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

# Global Magika instance - initialized once for performance
_magika_instance = None


def _get_magika():
    """Get or initialize the global Magika instance"""
    global _magika_instance
    if _magika_instance is None:
        try:
            from magika import Magika
            _magika_instance = Magika()
            logger.info("Magika analyzer initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Magika: {e}", exc_info=True)
            raise
    return _magika_instance


def extract_magika_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract file type information using Magika deep learning model
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Dictionary containing Magika analysis results:
        - label: Detected file type label
        - score: Confidence score (0-1)
        - description: Human-readable description
        - mime_type: Detected MIME type
        - magic: Magic bytes pattern
        - group: File type group/category
        - is_text: Whether file is text-based
        - extensions: List of common extensions for this type
    """
    try:
        magika = _get_magika()
        
        # Analyze the file
        result = magika.identify_path(Path(file_path))
        
        metadata = {
            'label': result.output.ct_label,
            'score': float(result.output.score),
            'mime_type': result.output.mime_type,
            'group': result.output.group,
            'description': result.output.description if hasattr(result.output, 'description') else None,
            'magic': result.output.magic if hasattr(result.output, 'magic') else None,
            'is_text': result.output.is_text if hasattr(result.output, 'is_text') else None,
        }
        
        # Add extensions if available
        if hasattr(result.output, 'extensions'):
            metadata['extensions'] = result.output.extensions
        
        logger.info(f"Magika analysis completed: {metadata['label']} (score: {metadata['score']:.3f})")
        return metadata
        
    except Exception as e:
        logger.error(f"Magika analysis failed for {file_path}: {e}", exc_info=True)
        return {
            'label': None,
            'score': None,
            'mime_type': None,
            'group': None,
            'description': f"Analysis failed: {str(e)}",
            'magic': None,
            'is_text': None,
            'extensions': None
        }


def analyze_bytes(file_bytes: bytes) -> Dict[str, Any]:
    """
    Analyze file bytes directly without writing to disk
    
    Args:
        file_bytes: Raw file content as bytes
        
    Returns:
        Dictionary containing Magika analysis results
    """
    try:
        magika = _get_magika()
        
        # Analyze the bytes
        result = magika.identify_bytes(file_bytes)
        
        metadata = {
            'label': result.output.ct_label,
            'score': float(result.output.score),
            'mime_type': result.output.mime_type,
            'group': result.output.group,
            'description': result.output.description if hasattr(result.output, 'description') else None,
            'magic': result.output.magic if hasattr(result.output, 'magic') else None,
            'is_text': result.output.is_text if hasattr(result.output, 'is_text') else None,
        }
        
        # Add extensions if available
        if hasattr(result.output, 'extensions'):
            metadata['extensions'] = result.output.extensions
        
        logger.info(f"Magika bytes analysis completed: {metadata['label']} (score: {metadata['score']:.3f})")
        return metadata
        
    except Exception as e:
        logger.error(f"Magika bytes analysis failed: {e}", exc_info=True)
        return {
            'label': None,
            'score': None,
            'mime_type': None,
            'group': None,
            'description': f"Analysis failed: {str(e)}",
            'magic': None,
            'is_text': None,
            'extensions': None
        }
