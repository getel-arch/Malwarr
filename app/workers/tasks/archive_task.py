"""
Celery task for archive extraction
"""
import logging
import zipfile
import tarfile
import tempfile
import io
import gzip
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from app.workers.celery_app import celery_app
from app.workers.tasks.database_task import DatabaseTask
from app.models import MalwareSample

logger = logging.getLogger(__name__)


class ArchiveExtractionTask(DatabaseTask):
    """Archive extraction task"""
    
    def _extract_zip(
        self,
        file_content: bytes,
        password: Optional[str] = None,
        max_size: int = 500 * 1024 * 1024
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Extract files from a ZIP archive"""
        extracted_files = []
        
        try:
            # Try pyzipper first for AES encryption support
            try:
                import pyzipper
                ZipFileClass = pyzipper.AESZipFile
                use_pyzipper = True
                logger.info("Using pyzipper.AESZipFile for ZIP extraction")
            except ImportError:
                ZipFileClass = zipfile.ZipFile
                use_pyzipper = False
                logger.info("Using standard zipfile for ZIP extraction")
            
            with ZipFileClass(io.BytesIO(file_content)) as zf:
                # Set password for AES encryption if provided
                if password:
                    if hasattr(zf, 'setpassword'):
                        zf.setpassword(password.encode('utf-8'))
                
                # Check if password is required (only if no password provided)
                if not password and zf.namelist():
                    # Try to read first file to check if password is needed
                    try:
                        first_file = zf.namelist()[0]
                        if not zf.getinfo(first_file).is_dir():
                            zf.read(first_file)
                    except RuntimeError as e:
                        if 'password required' in str(e).lower() or 'encrypted' in str(e).lower() or 'bad password' in str(e).lower():
                            return False, [], "Archive is password protected. Please provide a password."
                
                for member in zf.namelist():
                    info = zf.getinfo(member)
                    
                    # Skip directories
                    if info.is_dir():
                        continue
                    
                    # Check file size
                    if info.file_size > max_size:
                        logger.warning(f"Skipping {member} - exceeds size limit ({info.file_size} bytes)")
                        continue
                    
                    try:
                        # Read the file (password already set via setpassword if needed)
                        content = zf.read(member)
                        
                        extracted_files.append({
                            'filename': member,
                            'content': content
                        })
                    except RuntimeError as e:
                        error_str = str(e).lower()
                        
                        if 'password required' in error_str or 'bad password' in error_str:
                            return False, [], "Incorrect password or password required"
                        elif 'compression method' in error_str or 'not supported' in error_str:
                            logger.warning(f"Unsupported compression method for {member}: {e}")
                            continue
                        else:
                            logger.error(f"Error extracting {member}: {e}")
                            continue
                        
            return True, extracted_files, None
            
        except zipfile.BadZipFile:
            return False, [], "Invalid or corrupted ZIP file"
        except Exception as e:
            return False, [], f"Error extracting ZIP: {str(e)}"

    def _extract_rar(
        self,
        file_content: bytes,
        password: Optional[str] = None,
        max_size: int = 500 * 1024 * 1024
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Extract files from a RAR archive"""
        try:
            import rarfile
        except ImportError:
            return False, [], "RAR support not available. Please install rarfile and unrar tool."
        
        extracted_files = []
        
        try:
            # Create temporary file for RAR extraction
            with tempfile.NamedTemporaryFile(delete=False, suffix='.rar') as temp_file:
                temp_file.write(file_content)
                temp_path = temp_file.name
            
            try:
                with rarfile.RarFile(temp_path) as rf:
                    # Check if password is required
                    if rf.needs_password() and password is None:
                        return False, [], "Archive is password protected. Please provide a password."
                    
                    # Set password if provided
                    if password:
                        rf.setpassword(password)
                    
                    for member in rf.infolist():
                        # Skip directories
                        if member.is_dir():
                            continue
                        
                        # Check file size
                        if member.file_size > max_size:
                            logger.warning(f"Skipping {member.filename} - exceeds size limit ({member.file_size} bytes)")
                            continue
                        
                        try:
                            content = rf.read(member)
                            extracted_files.append({
                                'filename': member.filename,
                                'content': content
                            })
                        except rarfile.BadRarFile as e:
                            logger.error(f"Error extracting {member.filename}: {e}")
                        except rarfile.PasswordRequired:
                            return False, [], "Password required for encrypted archive"
                        except rarfile.BadPassword:
                            return False, [], "Incorrect password"
                
                return True, extracted_files, None
                
            finally:
                Path(temp_path).unlink(missing_ok=True)
                
        except rarfile.BadRarFile:
            return False, [], "Invalid or corrupted RAR file"
        except Exception as e:
            return False, [], f"Error extracting RAR: {str(e)}"

    def _extract_7z(
        self,
        file_content: bytes,
        password: Optional[str] = None,
        max_size: int = 500 * 1024 * 1024
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Extract files from a 7z archive"""
        try:
            import py7zr
        except ImportError:
            return False, [], "7z support not available. Please install py7zr."
        
        extracted_files = []
        
        try:
            with py7zr.SevenZipFile(io.BytesIO(file_content), mode='r', password=password) as archive:
                # Get all file names
                all_files = archive.getnames()
                
                for filename in all_files:
                    # Skip if it looks like a directory
                    if filename.endswith('/'):
                        continue
                    
                    try:
                        # Read specific file
                        extracted = archive.read([filename])
                        if filename in extracted:
                            content = extracted[filename].read()
                            
                            # Check size
                            if len(content) > max_size:
                                logger.warning(f"Skipping {filename} - exceeds size limit ({len(content)} bytes)")
                                continue
                            
                            extracted_files.append({
                                'filename': filename,
                                'content': content
                            })
                    except Exception as e:
                        logger.error(f"Error extracting {filename}: {e}")
            
            return True, extracted_files, None
            
        except py7zr.Bad7zFile:
            return False, [], "Invalid or corrupted 7z file"
        except py7zr.PasswordRequired:
            return False, [], "Archive is password protected. Please provide a password."
        except Exception as e:
            error_str = str(e).lower()
            if 'password' in error_str or 'encrypted' in error_str:
                return False, [], "Incorrect password or password required"
            return False, [], f"Error extracting 7z: {str(e)}"

    def _extract_tar(
        self,
        file_content: bytes,
        max_size: int = 500 * 1024 * 1024
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Extract files from a TAR archive (including compressed variants)"""
        extracted_files = []
        
        try:
            with tarfile.open(fileobj=io.BytesIO(file_content)) as tf:
                for member in tf.getmembers():
                    # Skip directories and special files
                    if not member.isfile():
                        continue
                    
                    # Check file size
                    if member.size > max_size:
                        logger.warning(f"Skipping {member.name} - exceeds size limit ({member.size} bytes)")
                        continue
                    
                    try:
                        extracted_file = tf.extractfile(member)
                        if extracted_file:
                            content = extracted_file.read()
                            extracted_files.append({
                                'filename': member.name,
                                'content': content
                            })
                    except Exception as e:
                        logger.error(f"Error extracting {member.name}: {e}")
            
            return True, extracted_files, None
            
        except tarfile.TarError:
            return False, [], "Invalid or corrupted TAR file"
        except Exception as e:
            return False, [], f"Error extracting TAR: {str(e)}"

    def _extract_gzip(
        self,
        file_content: bytes,
        original_filename: str,
        max_size: int = 500 * 1024 * 1024
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Extract a GZIP compressed file"""
        try:
            content = gzip.decompress(file_content)
            
            # Check size
            if len(content) > max_size:
                return False, [], f"Decompressed file exceeds size limit ({len(content)} bytes)"
            
            # Determine output filename (remove .gz extension)
            output_filename = original_filename[:-3] if original_filename.endswith('.gz') else original_filename + '.decompressed'
            
            extracted_files = [{
                'filename': output_filename,
                'content': content
            }]
            
            return True, extracted_files, None
            
        except Exception as e:
            return False, [], f"Error extracting GZIP: {str(e)}"

    def _extract_archive(
        self,
        file_content: bytes,
        filename: str,
        password: Optional[str] = None,
        max_size: int = 500 * 1024 * 1024
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Extract files from an archive
        
        Args:
            file_content: Raw archive bytes
            filename: Original filename (used to determine archive type)
            password: Optional password for encrypted archives
            max_size: Maximum size for extracted files (default 500 MB)
            
        Returns:
            Tuple of (success: bool, extracted_files: List[Dict], error_message: Optional[str])
            Each extracted file dict contains: {'filename': str, 'content': bytes}
        """
        extracted_files = []
        filename_lower = filename.lower()
        
        try:
            # ZIP archives
            if filename_lower.endswith('.zip'):
                success, files, error = self._extract_zip(file_content, password, max_size)
                if not success:
                    return False, [], error
                extracted_files.extend(files)
            
            # RAR archives
            elif filename_lower.endswith('.rar'):
                success, files, error = self._extract_rar(file_content, password, max_size)
                if not success:
                    return False, [], error
                extracted_files.extend(files)
            
            # 7z archives
            elif filename_lower.endswith('.7z'):
                success, files, error = self._extract_7z(file_content, password, max_size)
                if not success:
                    return False, [], error
                extracted_files.extend(files)
            
            # TAR archives (including .tar.gz, .tar.bz2, .tar.xz)
            elif any(filename_lower.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz']):
                success, files, error = self._extract_tar(file_content, max_size)
                if not success:
                    return False, [], error
                extracted_files.extend(files)
            
            # GZIP (single file compression)
            elif filename_lower.endswith('.gz') and not filename_lower.endswith('.tar.gz'):
                success, files, error = self._extract_gzip(file_content, filename, max_size)
                if not success:
                    return False, [], error
                extracted_files.extend(files)
            
            else:
                return False, [], f"Unsupported archive format: {filename}"
            
            if not extracted_files:
                return False, [], "Archive is empty or contains no extractable files"
            
            logger.info(f"Successfully extracted {len(extracted_files)} files from {filename}")
            return True, extracted_files, None
            
        except Exception as e:
            logger.error(f"Error extracting archive {filename}: {e}")
            return False, [], str(e)
    
    def run_extraction(
        self,
        archive_sha512: str,
        archive_password: Optional[str] = None,
        tags: Optional[List[str]] = None,
        family: Optional[str] = None,
        classification: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extract files from an archive and ingest them
        
        Args:
            archive_sha512: SHA512 hash of the archive to extract
            archive_password: Optional password for encrypted archives
            tags: Optional tags to apply to extracted files
            family: Optional family to apply to extracted files
            classification: Optional classification to apply to extracted files
            
        Returns:
            Dict with extraction results
        """
        try:
            # Get the archive sample
            archive_sample = self.db.query(MalwareSample).filter(
                MalwareSample.sha512 == archive_sha512
            ).first()
            
            if not archive_sample:
                error_msg = f"Archive not found: {archive_sha512}"
                logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg,
                    "extracted_count": 0,
                    "extracted_samples": []
                }
            
            # Load the archive file content from storage
            archive_path = self.storage.get_full_path(archive_sample.storage_path)
            with open(archive_path, 'rb') as f:
                archive_content = f.read()
            
            logger.info(f"Extracting archive: {archive_sample.filename}")
            
            # Extract files from archive
            success, extracted_files, error_msg = self._extract_archive(
                archive_content,
                archive_sample.filename,
                archive_password
            )
            
            if not success:
                logger.error(f"Failed to extract archive {archive_sample.filename}: {error_msg}")
                return {
                    "success": False,
                    "error": error_msg,
                    "extracted_count": 0,
                    "extracted_samples": []
                }
            
            # Import IngestionTask here to avoid circular imports
            from app.workers.tasks.ingestion_task import IngestionTask
            ingestion_task_instance = IngestionTask()
            
            extracted_samples = []
            for extracted_file in extracted_files:
                try:
                    # Recursively ingest the extracted file
                    # Note: This will handle nested archives automatically
                    extracted_sample, nested_samples = ingestion_task_instance.ingest_file(
                        file_content=extracted_file['content'],
                        filename=extracted_file['filename'],
                        tags=tags,
                        family=family,
                        classification=classification,
                        notes=None,
                        archive_password=archive_password,  # Try same password for nested archives
                        parent_archive_sha512=archive_sha512
                    )
                    
                    extracted_samples.append(extracted_sample)
                    extracted_samples.extend(nested_samples)  # Add any nested extracted files
                    
                except Exception as e:
                    logger.error(f"Failed to ingest extracted file {extracted_file['filename']}: {e}")
                    continue
            
            # Update the archive sample with extraction count
            archive_sample.extracted_file_count = len(extracted_samples)
            self.db.commit()
            
            logger.info(f"Extracted and processed {len(extracted_samples)} files from {archive_sample.filename}")
            
            return {
                "success": True,
                "error": None,
                "extracted_count": len(extracted_samples),
                "extracted_samples": [
                    {
                        "sha512": s.sha512,
                        "filename": s.filename,
                        "file_type": s.file_type.value if s.file_type else None
                    }
                    for s in extracted_samples
                ]
            }
            
        except Exception as e:
            logger.error(f"Failed to extract archive {archive_sha512}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "extracted_count": 0,
                "extracted_samples": []
            }


@celery_app.task(
    bind=True,
    name='app.workers.tasks.extract_archive',
    base=ArchiveExtractionTask,
    max_retries=2,
    default_retry_delay=60
)
def extract_archive_task(
    self,
    archive_sha512: str,
    archive_password: Optional[str] = None,
    tags: Optional[List[str]] = None,
    family: Optional[str] = None,
    classification: Optional[str] = None
) -> Dict[str, Any]:
    """
    Celery task to extract files from an archive
    
    Args:
        archive_sha512: SHA512 hash of the archive to extract
        archive_password: Optional password for encrypted archives
        tags: Optional tags to apply to extracted files
        family: Optional family to apply to extracted files
        classification: Optional classification to apply to extracted files
        
    Returns:
        Dict with extraction results
    """
    try:
        return self.run_extraction(
            archive_sha512=archive_sha512,
            archive_password=archive_password,
            tags=tags,
            family=family,
            classification=classification
        )
    except Exception as e:
        logger.error(f"Archive extraction task failed: {e}", exc_info=True)
        # Retry on failure
        raise self.retry(exc=e)
