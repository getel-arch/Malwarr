"""
VirusTotal analyzer - Check file hash against VirusTotal database
"""
import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
import vt

from app.models import MalwareSample, VirusTotalAnalysis

logger = logging.getLogger(__name__)


def analyze_sample_virustotal(
    db: Session,
    sample_id: str,
    api_key: str
) -> Optional[Dict[str, Any]]:
    """
    Analyze a sample using VirusTotal API
    
    Args:
        db: Database session
        sample_id: SHA512 hash of the sample (primary key)
        api_key: VirusTotal API key
        
    Returns:
        Dictionary with VirusTotal results or None if not found/error
    """
    if not api_key or api_key == "":
        logger.warning("VirusTotal API key not configured, skipping VT analysis")
        return None
    
    # Fetch sample from database
    sample = db.query(MalwareSample).filter(
        MalwareSample.sha512 == sample_id
    ).first()
    
    if not sample:
        logger.error(f"Sample not found in database: {sample_id}")
        return None
    
    # Use SHA256 for VT lookup (VT prefers SHA256)
    file_hash = sample.sha256
    logger.info(f"Checking VirusTotal for sample {sample_id} with hash: {file_hash}")
    
    try:
        client = vt.Client(api_key)
        
        try:
            # Get file report by hash
            file_obj = client.get_object(f"/files/{file_hash}")
            
            # Extract relevant data
            last_analysis_stats = file_obj.last_analysis_stats
            last_analysis_results = file_obj.last_analysis_results
            
            # Calculate positives
            positives = last_analysis_stats.get('malicious', 0) + \
                       last_analysis_stats.get('suspicious', 0)
            
            # Calculate total scanners
            total = sum([
                last_analysis_stats.get('malicious', 0),
                last_analysis_stats.get('suspicious', 0),
                last_analysis_stats.get('undetected', 0),
                last_analysis_stats.get('harmless', 0)
            ])
            
            # Format individual scanner results
            scans = {}
            if last_analysis_results:
                for scanner_name, result in last_analysis_results.items():
                    scans[scanner_name] = {
                        'detected': result.get('category') in ['malicious', 'suspicious'],
                        'result': result.get('result', None),
                        'category': result.get('category', 'unknown'),
                        'engine_name': result.get('engine_name', scanner_name),
                        'engine_version': result.get('engine_version', None),
                        'engine_update': result.get('engine_update', None),
                        'method': result.get('method', None)
                    }
            
            # Get scan date - VT API returns datetime objects, not timestamps
            scan_date = None
            if hasattr(file_obj, 'last_analysis_date') and file_obj.last_analysis_date:
                scan_date = file_obj.last_analysis_date if isinstance(file_obj.last_analysis_date, datetime) else datetime.fromtimestamp(file_obj.last_analysis_date)
            
            # Build permalink
            permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
            
            result = {
                'positives': positives,
                'total': total,
                'detection_ratio': f"{positives}/{total}",
                'scan_date': scan_date,
                'permalink': permalink,
                'scans': scans,
                'scan_id': file_obj.id if hasattr(file_obj, 'id') else file_hash,
                'verbose_msg': f"Scan finished, information embedded",
                'analysis_stats': last_analysis_stats,
                'sha256': file_obj.sha256 if hasattr(file_obj, 'sha256') else None,
                'md5': file_obj.md5 if hasattr(file_obj, 'md5') else None,
                'sha1': file_obj.sha1 if hasattr(file_obj, 'sha1') else None,
                'file_size': file_obj.size if hasattr(file_obj, 'size') else None,
                'type_description': file_obj.type_description if hasattr(file_obj, 'type_description') else None,
                'meaningful_name': file_obj.meaningful_name if hasattr(file_obj, 'meaningful_name') else None,
                'times_submitted': file_obj.times_submitted if hasattr(file_obj, 'times_submitted') else None,
                'first_submission_date': file_obj.first_submission_date if (hasattr(file_obj, 'first_submission_date') and isinstance(file_obj.first_submission_date, datetime)) else (datetime.fromtimestamp(file_obj.first_submission_date) if hasattr(file_obj, 'first_submission_date') else None),
                'last_submission_date': file_obj.last_submission_date if (hasattr(file_obj, 'last_submission_date') and isinstance(file_obj.last_submission_date, datetime)) else (datetime.fromtimestamp(file_obj.last_submission_date) if hasattr(file_obj, 'last_submission_date') else None),
            }
            
            logger.info(f"VirusTotal analysis complete: {positives}/{total} detections for {file_hash}")
            
            # Check if VT analysis already exists
            vt_analysis = db.query(VirusTotalAnalysis).filter(
                VirusTotalAnalysis.sha512 == sample_id
            ).first()
            
            if not vt_analysis:
                # Create new VT analysis record
                vt_analysis = VirusTotalAnalysis(
                    sha512=sample_id,
                    analysis_date=datetime.utcnow()
                )
                db.add(vt_analysis)
            
            # Update VT analysis with results
            vt_analysis.positives = result.get('positives')
            vt_analysis.total = result.get('total')
            vt_analysis.detection_ratio = result.get('detection_ratio')
            vt_analysis.scan_date = result.get('scan_date')
            vt_analysis.permalink = result.get('permalink')
            vt_analysis.scan_id = result.get('scan_id')
            vt_analysis.verbose_msg = result.get('verbose_msg')
            vt_analysis.analysis_date = datetime.utcnow()
            
            # Store individual scanner results as JSON
            if scans:
                vt_analysis.scans = json.dumps(scans)
            
            # Update virustotal_link field in sample for compatibility
            sample.virustotal_link = result.get('permalink')
            
            db.commit()
            
            return result
            
        except vt.APIError as e:
            if e.code == "NotFoundError":
                logger.info(f"Hash not found in VirusTotal: {file_hash}")
                result = {
                    'positives': 0,
                    'total': 0,
                    'detection_ratio': "0/0",
                    'scan_date': None,
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'scans': {},
                    'scan_id': None,
                    'verbose_msg': "Hash not found in VirusTotal database",
                    'not_found': True
                }
                
                # Check if VT analysis already exists
                vt_analysis = db.query(VirusTotalAnalysis).filter(
                    VirusTotalAnalysis.sha512 == sample_id
                ).first()
                
                if not vt_analysis:
                    # Create new VT analysis record
                    vt_analysis = VirusTotalAnalysis(
                        sha512=sample_id,
                        analysis_date=datetime.utcnow()
                    )
                    db.add(vt_analysis)
                
                # Update sample even when not found
                vt_analysis.positives = 0
                vt_analysis.total = 0
                vt_analysis.detection_ratio = "0/0"
                vt_analysis.permalink = result.get('permalink')
                vt_analysis.verbose_msg = result.get('verbose_msg')
                vt_analysis.analysis_date = datetime.utcnow()
                
                sample.virustotal_link = result.get('permalink')
                
                db.commit()
                
                return result
            else:
                logger.error(f"VirusTotal API error: {e}")
                raise
        
        finally:
            client.close()
            
    except Exception as e:
        logger.error(f"Error checking VirusTotal: {e}", exc_info=True)
        return None


async def upload_to_virustotal(
    db: Session,
    sample_id: str,
    api_key: str
) -> Optional[Dict[str, Any]]:
    """
    Upload a sample file to VirusTotal for scanning (async version)
    
    Args:
        db: Database session
        sample_id: SHA512 hash of the sample (primary key)
        api_key: VirusTotal API key
        
    Returns:
        Dictionary with upload results including analysis ID, or None if error
    """
    if not api_key or api_key == "":
        logger.warning("VirusTotal API key not configured, cannot upload to VT")
        return None
    
    # Fetch sample from database
    sample = db.query(MalwareSample).filter(
        MalwareSample.sha512 == sample_id
    ).first()
    
    if not sample:
        logger.error(f"Sample not found in database: {sample_id}")
        return None
    
    # Get the file from storage
    from app.storage import FileStorage
    storage = FileStorage()
    
    try:
        # Construct the file path using the storage path and sha512
        # Files are stored as: storage_path / first_two_chars / second_two_chars / sha512
        relative_path = f"{sample.sha512[:2]}/{sample.sha512[2:4]}/{sample.sha512}"
        file_path = storage.storage_path / relative_path
        
        if not file_path.exists():
            logger.error(f"Sample file not found in storage: {file_path}")
            return {
                'success': False,
                'error': 'Sample file not found in storage'
            }
        
        logger.info(f"Uploading file to VirusTotal: {sample.filename} (SHA256: {sample.sha256})")
        
        async with vt.Client(api_key) as client:
            try:
                # Upload file to VirusTotal
                with open(file_path, "rb") as f:
                    analysis = await client.scan_file_async(f)
                
                # Get analysis ID
                analysis_id = analysis.id if hasattr(analysis, 'id') else None
                
                logger.info(f"File uploaded to VirusTotal successfully. Analysis ID: {analysis_id}")
                
                # Update VT analysis record to indicate upload in progress
                vt_analysis = db.query(VirusTotalAnalysis).filter(
                    VirusTotalAnalysis.sha512 == sample_id
                ).first()
                
                if not vt_analysis:
                    vt_analysis = VirusTotalAnalysis(
                        sha512=sample_id,
                        analysis_date=datetime.utcnow()
                    )
                    db.add(vt_analysis)
                
                # Update with upload status
                vt_analysis.scan_id = analysis_id
                vt_analysis.verbose_msg = "File uploaded to VirusTotal, analysis in progress"
                vt_analysis.analysis_date = datetime.utcnow()
                
                db.commit()
                
                return {
                    'success': True,
                    'analysis_id': analysis_id,
                    'message': 'File uploaded to VirusTotal successfully. Analysis in progress.',
                    'sha256': sample.sha256
                }
                
            except vt.APIError as e:
                logger.error(f"VirusTotal API error during upload: {e}")
                return {
                    'success': False,
                    'error': f"VirusTotal API error: {e.code} - {e.message if hasattr(e, 'message') else str(e)}"
                }
            
    except Exception as e:
        logger.error(f"Error uploading to VirusTotal: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e)
        }


def check_virustotal_analysis_status(
    db: Session,
    sample_id: str,
    analysis_id: str,
    api_key: str
) -> Optional[Dict[str, Any]]:
    """
    Check the status of a VirusTotal analysis and update database if complete
    
    Args:
        db: Database session
        sample_id: SHA512 hash of the sample (primary key)
        analysis_id: VT analysis ID returned from upload
        api_key: VirusTotal API key
        
    Returns:
        Dictionary with status update or None if error
    """
    if not api_key or api_key == "":
        logger.warning("VirusTotal API key not configured")
        return None
    
    # Fetch sample from database
    sample = db.query(MalwareSample).filter(
        MalwareSample.sha512 == sample_id
    ).first()
    
    if not sample:
        logger.error(f"Sample not found in database: {sample_id}")
        return None
    
    try:
        client = vt.Client(api_key)
        
        try:
            # Get analysis object
            analysis = client.get_object(f"/analyses/{analysis_id}")
            
            status = analysis.status
            logger.info(f"VT Analysis {analysis_id} status: {status}")
            
            # If analysis is still queued or in progress, return status
            if status in ["queued", "in-progress"]:
                return {
                    'status': status,
                    'complete': False,
                    'analysis_id': analysis_id
                }
            
            # If analysis is complete, fetch the file report
            if status == "completed":
                # Get file hash from sample
                file_hash = sample.sha256
                
                try:
                    # Fetch the full file report
                    file_obj = client.get_object(f"/files/{file_hash}")
                    
                    # Extract relevant data (same as analyze_sample_virustotal)
                    last_analysis_stats = file_obj.last_analysis_stats
                    last_analysis_results = file_obj.last_analysis_results
                    
                    # Calculate positives
                    positives = last_analysis_stats.get('malicious', 0) + \
                               last_analysis_stats.get('suspicious', 0)
                    
                    # Calculate total scanners
                    total = sum([
                        last_analysis_stats.get('malicious', 0),
                        last_analysis_stats.get('suspicious', 0),
                        last_analysis_stats.get('undetected', 0),
                        last_analysis_stats.get('harmless', 0)
                    ])
                    
                    # Format individual scanner results
                    scans = {}
                    if last_analysis_results:
                        for scanner_name, result in last_analysis_results.items():
                            scans[scanner_name] = {
                                'detected': result.get('category') in ['malicious', 'suspicious'],
                                'result': result.get('result', None),
                                'category': result.get('category', 'unknown'),
                                'engine_name': result.get('engine_name', scanner_name),
                                'engine_version': result.get('engine_version', None),
                                'engine_update': result.get('engine_update', None),
                                'method': result.get('method', None)
                            }
                    
                    # Get scan date
                    scan_date = None
                    if hasattr(file_obj, 'last_analysis_date') and file_obj.last_analysis_date:
                        scan_date = file_obj.last_analysis_date if isinstance(file_obj.last_analysis_date, datetime) else datetime.fromtimestamp(file_obj.last_analysis_date)
                    
                    permalink = f"https://www.virustotal.com/gui/file/{file_hash}"
                    
                    # Update VT analysis record
                    vt_analysis = db.query(VirusTotalAnalysis).filter(
                        VirusTotalAnalysis.sha512 == sample_id
                    ).first()
                    
                    if vt_analysis:
                        vt_analysis.positives = positives
                        vt_analysis.total = total
                        vt_analysis.detection_ratio = f"{positives}/{total}"
                        vt_analysis.scan_date = scan_date
                        vt_analysis.permalink = permalink
                        vt_analysis.scan_id = file_obj.id if hasattr(file_obj, 'id') else file_hash
                        vt_analysis.verbose_msg = "Scan finished, information embedded"
                        vt_analysis.analysis_date = datetime.utcnow()
                        
                        # Store individual scanner results as JSON
                        if scans:
                            vt_analysis.scans = json.dumps(scans)
                        
                        # Update virustotal_link field in sample
                        sample.virustotal_link = permalink
                        
                        db.commit()
                        
                        logger.info(f"Updated VT results for {sample_id}: {positives}/{total} detections")
                        
                        return {
                            'status': 'completed',
                            'complete': True,
                            'positives': positives,
                            'total': total,
                            'detection_ratio': f"{positives}/{total}"
                        }
                
                except vt.APIError as e:
                    logger.error(f"Error fetching file report after analysis complete: {e}")
                    return {
                        'status': 'error',
                        'complete': False,
                        'error': str(e)
                    }
            
            # Handle other statuses (failure, etc.)
            return {
                'status': status,
                'complete': True,
                'error': f"Analysis ended with status: {status}"
            }
            
        except vt.APIError as e:
            logger.error(f"VirusTotal API error checking analysis status: {e}")
            return {
                'status': 'error',
                'complete': False,
                'error': str(e)
            }
        finally:
            client.close()
            
    except Exception as e:
        logger.error(f"Error checking VirusTotal analysis status: {e}", exc_info=True)
        return None
