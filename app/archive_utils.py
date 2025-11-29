import zipfile
import tarfile
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import io

logger = logging.getLogger(__name__)


def is_archive(mime_type: str, magic_description: str, filename: Optional[str] = None) -> bool:
    """
    Determine if a file is an archive based on MIME type, magic description, and filename
    
    Args:
        mime_type: MIME type of the file
        magic_description: File magic description
        filename: Optional filename to check extension
        
    Returns:
        True if file is an archive, False otherwise
    """
    mime_lower = mime_type.lower()
    desc_lower = magic_description.lower()
    
    # Common archive indicators
    archive_mimes = [
        'application/zip',
        'application/x-zip-compressed',
        'application/x-rar',
        'application/x-rar-compressed',
        'application/vnd.rar',
        'application/x-7z-compressed',
        'application/x-tar',
        'application/x-gzip',
        'application/gzip',
        'application/x-bzip2',
        'application/x-xz',
        'application/x-compressed-tar',
        'application/x-gtar',
    ]
    
    archive_keywords = [
        'zip',
        'rar',
        '7-zip',
        'tar',
        'gzip',
        'bzip2',
        'archive',
        'compressed',
    ]
    
    # Check MIME type
    if any(archive_mime in mime_lower for archive_mime in archive_mimes):
        return True
    
    # Check description
    if any(keyword in desc_lower for keyword in archive_keywords):
        return True
    
    # Check filename extension (important for encrypted archives that may not have proper MIME types)
    if filename:
        filename_lower = filename.lower()
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.gz']
        if any(filename_lower.endswith(ext) for ext in archive_extensions):
            return True
    
    return False


def extract_archive(
    file_content: bytes,
    filename: str,
    password: Optional[str] = None,
    max_size: int = 500 * 1024 * 1024  # 500 MB limit per extracted file
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
            success, files, error = _extract_zip(file_content, password, max_size)
            if not success:
                return False, [], error
            extracted_files.extend(files)
        
        # RAR archives
        elif filename_lower.endswith('.rar'):
            success, files, error = _extract_rar(file_content, password, max_size)
            if not success:
                return False, [], error
            extracted_files.extend(files)
        
        # 7z archives
        elif filename_lower.endswith('.7z'):
            success, files, error = _extract_7z(file_content, password, max_size)
            if not success:
                return False, [], error
            extracted_files.extend(files)
        
        # TAR archives (including .tar.gz, .tar.bz2, .tar.xz)
        elif any(filename_lower.endswith(ext) for ext in ['.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz']):
            success, files, error = _extract_tar(file_content, max_size)
            if not success:
                return False, [], error
            extracted_files.extend(files)
        
        # GZIP (single file compression)
        elif filename_lower.endswith('.gz') and not filename_lower.endswith('.tar.gz'):
            success, files, error = _extract_gzip(file_content, filename, max_size)
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


def _extract_zip(
    file_content: bytes,
    password: Optional[str] = None,
    max_size: int = 500 * 1024 * 1024
) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    """Extract files from a ZIP archive"""
    extracted_files = []
    
    # Debug: write password to file
    with open('/tmp/password_debug.txt', 'w') as f:
        f.write(f"Password received: {password!r}\n")
        f.write(f"Password type: {type(password)}\n")
        f.write(f"Password len: {len(password) if password else 'None'}\n")
    
    logger.info(f"_extract_zip called with password={password!r}")
    
    try:
        # Try pyzipper first for AES encryption support
        try:
            import pyzipper
            # Use AESZipFile for better AES encryption support
            ZipFileClass = pyzipper.AESZipFile
            use_pyzipper = True
            logger.info("Using pyzipper.AESZipFile for ZIP extraction")
        except ImportError:
            import zipfile
            ZipFileClass = zipfile.ZipFile
            use_pyzipper = False
            logger.info("Using standard zipfile for ZIP extraction")
        
        with open('/tmp/zip_module_debug.txt', 'w') as f:
            f.write(f"Using pyzipper: {use_pyzipper}\n")
            f.write(f"ZipFileClass: {ZipFileClass}\n")
        
        with ZipFileClass(io.BytesIO(file_content)) as zf:
            # Set password for AES encryption if provided (required for pyzipper)
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
                    # Debug: write error to file
                    with open('/tmp/extract_error.txt', 'w') as f:
                        f.write(f"RuntimeError: {e}\n")
                        f.write(f"Error string: {error_str}\n")
                        f.write(f"Has 'password required': {'password required' in error_str}\n")
                        f.write(f"Has 'bad password': {'bad password' in error_str}\n")
                    
                    if 'password required' in error_str or 'bad password' in error_str:
                        return False, [], "Incorrect password or password required"
                    elif 'compression method' in error_str or 'not supported' in error_str:
                        logger.warning(f"Unsupported compression method for {member}: {e}")
                        # Continue with other files instead of failing completely
                        continue
                    else:
                        logger.error(f"Error extracting {member}: {e}")
                        continue
                    
        return True, extracted_files, None
        
    except zipfile.BadZipFile:
        return False, [], "Invalid or corrupted ZIP file"
    except Exception as e:
        return False, [], f"Error extracting ZIP: {str(e)}"
                    
        return True, extracted_files, None
        
    except zipfile.BadZipFile:
        return False, [], "Invalid or corrupted ZIP file"
    except Exception as e:
        return False, [], f"Error extracting ZIP: {str(e)}"


def _extract_rar(
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
    file_content: bytes,
    original_filename: str,
    max_size: int = 500 * 1024 * 1024
) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    """Extract a GZIP compressed file"""
    import gzip
    
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
