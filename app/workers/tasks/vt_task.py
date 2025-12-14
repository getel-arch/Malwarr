"""
Celery task for VirusTotal analysis
"""
import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime
import vt
from app.models import MalwareSample, VirusTotalAnalysis
from app.workers.tasks.database_task import DatabaseTask
from app.workers.celery_app import celery_app
from app.config import settings

logger = logging.getLogger(__name__)


class VirusTotalTask(DatabaseTask):
    """VirusTotal hash lookup task"""
    
    def validate_api_key(self) -> bool:
        """Check if VirusTotal API key is configured"""
        return bool(settings.virustotal_api_key and settings.virustotal_api_key != "")
    
    def analyze_sample_virustotal(
        self,
        sample_id: str,
        api_key: str
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a sample using VirusTotal API
        
        Args:
            sample_id: SHA512 hash of the sample (primary key)
            api_key: VirusTotal API key
            
        Returns:
            Dictionary with VirusTotal results or None if not found/error
        """
        if not api_key or api_key == "":
            logger.warning("VirusTotal API key not configured, skipping VT analysis")
            return None
        
        # Fetch sample from database
        sample = self.db.query(MalwareSample).filter(
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
                vt_analysis = self.db.query(VirusTotalAnalysis).filter(
                    VirusTotalAnalysis.sha512 == sample_id
                ).first()
                
                if not vt_analysis:
                    # Create new VT analysis record
                    vt_analysis = VirusTotalAnalysis(
                        sha512=sample_id,
                        analysis_date=datetime.utcnow()
                    )
                    self.db.add(vt_analysis)
                
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
                
                self.db.commit()
                
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
                    vt_analysis = self.db.query(VirusTotalAnalysis).filter(
                        VirusTotalAnalysis.sha512 == sample_id
                    ).first()
                    
                    if not vt_analysis:
                        # Create new VT analysis record
                        vt_analysis = VirusTotalAnalysis(
                            sha512=sample_id,
                            analysis_date=datetime.utcnow()
                        )
                        self.db.add(vt_analysis)
                    
                    # Update sample even when not found
                    vt_analysis.positives = 0
                    vt_analysis.total = 0
                    vt_analysis.detection_ratio = "0/0"
                    vt_analysis.permalink = result.get('permalink')
                    vt_analysis.verbose_msg = result.get('verbose_msg')
                    vt_analysis.analysis_date = datetime.utcnow()
                    
                    sample.virustotal_link = result.get('permalink')
                    
                    self.db.commit()
                    
                    return result
                else:
                    logger.error(f"VirusTotal API error: {e}")
                    raise
            
            finally:
                client.close()
                
        except Exception as e:
            logger.error(f"Error checking VirusTotal: {e}", exc_info=True)
            return None

    def run_virustotal_analysis(self, sha512: str) -> Dict[str, Any]:
        """
        Perform VirusTotal hash lookup analysis
        
        Args:
            sha512: SHA512 hash of the sample to analyze
            
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Starting VirusTotal analysis for sample: {sha512}")
        
        try:
            # Check if VT API key is configured
            if not self.validate_api_key():
                logger.warning("VirusTotal API key not configured, skipping VT analysis")
                return {
                    "success": False,
                    "error": "VirusTotal API key not configured"
                }
            
            # Analyze with VirusTotal
            logger.info(f"Running VirusTotal analysis for sample: {sha512}")
            vt_result = self.analyze_sample_virustotal(
                sample_id=sha512,
                api_key=settings.virustotal_api_key
            )
            
            if vt_result:
                logger.info(
                    f"VirusTotal analysis completed for sample: {sha512} "
                    f"({vt_result.get('positives', 0)}/{vt_result.get('total', 0)} detections)"
                )
                
                return {
                    "success": True,
                    "sha512": sha512,
                    "vt_result": {
                        "positives": vt_result.get('positives'),
                        "total": vt_result.get('total'),
                        "detection_ratio": vt_result.get('detection_ratio'),
                        "permalink": vt_result.get('permalink'),
                        "not_found": vt_result.get('not_found', False)
                    }
                }
            else:
                logger.warning(f"VirusTotal analysis returned no results for sample: {sha512}")
                return {
                    "success": False,
                    "error": "VirusTotal analysis failed"
                }
                
        except Exception as e:
            logger.error(f"Error in VirusTotal analysis task: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }
    
    async def upload_to_virustotal(
        self,
        sample_id: str,
        api_key: str
    ) -> Optional[Dict[str, Any]]:
        """
        Upload a sample file to VirusTotal for scanning (async version)
        
        Args:
            sample_id: SHA512 hash of the sample (primary key)
            api_key: VirusTotal API key
            
        Returns:
            Dictionary with upload results including analysis ID, or None if error
        """
        if not api_key or api_key == "":
            logger.warning("VirusTotal API key not configured, cannot upload to VT")
            return None
        
        # Fetch sample from database
        sample = self.db.query(MalwareSample).filter(
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
                    vt_analysis = self.db.query(VirusTotalAnalysis).filter(
                        VirusTotalAnalysis.sha512 == sample_id
                    ).first()

                    if not vt_analysis:
                        vt_analysis = VirusTotalAnalysis(
                            sha512=sample_id,
                            analysis_date=datetime.utcnow()
                        )
                        self.db.add(vt_analysis)

                    # Update with upload status
                    vt_analysis.scan_id = analysis_id
                    vt_analysis.verbose_msg = "File uploaded to VirusTotal, analysis in progress"
                    vt_analysis.analysis_date = datetime.utcnow()

                    self.db.commit()

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
        self,
        sample_id: str,
        analysis_id: str,
        api_key: str
    ) -> Optional[Dict[str, Any]]:
        """
        Check the status of a VirusTotal analysis and update database if complete
        
        Args:
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
        sample = self.db.query(MalwareSample).filter(
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
                        vt_analysis = self.db.query(VirusTotalAnalysis).filter(
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
                            
                            self.db.commit()
                            
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
    
    def get_pending_analyses(self) -> list:
        """Retrieve all pending VT analysis records from database"""
        return self.db.query(VirusTotalAnalysis).filter(
            VirusTotalAnalysis.verbose_msg.like('%upload%'),
            VirusTotalAnalysis.scan_id.isnot(None)
        ).all()
    
    def check_single_analysis(self, vt_analysis: VirusTotalAnalysis) -> Dict[str, Any]:
        """
        Check status of a single VT analysis
        
        Args:
            vt_analysis: VirusTotalAnalysis record to check
            
        Returns:
            Dictionary with status: 'completed', 'pending', or 'error'
        """
        try:
            result = self.check_virustotal_analysis_status(
                sample_id=vt_analysis.sha512,
                analysis_id=vt_analysis.scan_id,
                api_key=settings.virustotal_api_key
            )
            
            if not result:
                logger.error(f"Failed to check analysis status for {vt_analysis.sha512}")
                return {"status": "error"}
            
            if result.get('complete'):
                if result.get('status') == 'completed':
                    logger.info(f"Analysis completed for {vt_analysis.sha512}: {result.get('detection_ratio')}")
                    return {"status": "completed"}
                else:
                    logger.warning(f"Analysis ended with status: {result.get('status')} for {vt_analysis.sha512}")
                    return {"status": "error"}
            else:
                logger.debug(f"Analysis still {result.get('status')} for {vt_analysis.sha512}")
                return {"status": "pending"}
                
        except Exception as e:
            logger.error(f"Error checking VT analysis for {vt_analysis.sha512}: {e}", exc_info=True)
            return {"status": "error"}
    
    def run_polling(self) -> Dict[str, Any]:
        """
        Poll VirusTotal for pending analysis results
        
        Returns:
            Dictionary with polling summary
        """
        logger.info("Starting VirusTotal polling task")
        
        try:
            # Check if VT API key is configured
            if not self.validate_api_key():
                logger.warning("VirusTotal API key not configured, skipping VT polling")
                return {
                    "success": False,
                    "error": "VirusTotal API key not configured"
                }
            
            # Find all pending analyses
            pending_analyses = self.get_pending_analyses()
            
            if not pending_analyses:
                logger.info("No pending VT analyses found")
                return {
                    "success": True,
                    "pending_count": 0,
                    "checked": 0,
                    "completed": 0,
                    "still_pending": 0,
                    "errors": 0
                }
            
            logger.info(f"Found {len(pending_analyses)} pending VT analyses to check")
            
            # Process each pending analysis
            checked = 0
            completed = 0
            still_pending = 0
            errors = 0
            
            for vt_analysis in pending_analyses:
                result = self.check_single_analysis(vt_analysis)
                checked += 1
                
                status = result.get("status")
                if status == "completed":
                    completed += 1
                elif status == "pending":
                    still_pending += 1
                else:  # error
                    errors += 1
            
            summary = {
                "success": True,
                "pending_count": len(pending_analyses),
                "checked": checked,
                "completed": completed,
                "still_pending": still_pending,
                "errors": errors
            }
            
            logger.info(f"VT polling completed: {completed} completed, {still_pending} still pending, {errors} errors")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error in VT polling task: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }


@celery_app.task(base=VirusTotalTask, bind=True, name='app.workers.tasks.vt_task')
def analyze_sample_with_virustotal(self, sha512: str) -> Dict[str, Any]:
    """
    Analyze a sample with VirusTotal hash lookup
    
    Args:
        sha512: SHA512 hash of the sample to analyze
        
    Returns:
        Dictionary with analysis results
    """
    return self.run_virustotal_analysis(sha512)


@celery_app.task(base=VirusTotalTask, bind=True, name='app.workers.tasks.vt_polling_task')
def poll_pending_virustotal_analyses(self) -> Dict[str, Any]:
    """
    Poll VirusTotal for pending analysis results
    
    This task runs periodically to check uploaded files that are still being analyzed
    by VirusTotal and updates the database when results are available.
    
    Returns:
        Dictionary with polling summary
    """
    return self.run_polling()
