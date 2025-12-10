import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FaUpload, FaFile, FaLink, FaLock, FaArchive, FaEye, FaEyeSlash, FaTimes, FaCheck, FaSpinner } from 'react-icons/fa';
import { malwarrApi } from '../services/api';
import './Upload.css';

const Upload: React.FC = () => {
  const navigate = useNavigate();
  const [uploadMode, setUploadMode] = useState<'file' | 'url'>('file');
  const [files, setFiles] = useState<File[]>([]);
  const [url, setUrl] = useState('');
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<Array<{ filename: string; status: string; taskId?: string }>>([]);
  const [isArchive, setIsArchive] = useState(false);
  const [showPasswordInput, setShowPasswordInput] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [metadata, setMetadata] = useState({
    family: '',
    classification: '',
    tags: '',
    notes: '',
    archive_password: 'infected', // Default password
  });

  const formatSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  // Detect if file is an archive based on extension
  useEffect(() => {
    if (files.length > 0) {
      const hasArchive = files.some(file => {
        const filename = file.name.toLowerCase();
        const archiveExtensions = ['.zip', '.rar', '.7z', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.gz'];
        return archiveExtensions.some(ext => filename.endsWith(ext));
      });
      setIsArchive(hasArchive);
      setShowPasswordInput(hasArchive);
    } else {
      setIsArchive(false);
      setShowPasswordInput(false);
    }
  }, [files]);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files);
    if (droppedFiles.length > 0) {
      setFiles(droppedFiles);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = e.target.files;
    if (selectedFiles && selectedFiles.length > 0) {
      setFiles(Array.from(selectedFiles));
    }
  };

  const removeFile = (index: number) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const pollTaskStatus = async (taskId: string, filename: string): Promise<string | null> => {
    // Poll task status every 2 seconds for up to 30 seconds
    const maxAttempts = 15;
    let attempts = 0;

    while (attempts < maxAttempts) {
      try {
        const taskStatus = await malwarrApi.getTaskStatus(taskId);
        
        if (taskStatus.state === 'SUCCESS' && taskStatus.result?.sha512) {
          return taskStatus.result.sha512;
        } else if (taskStatus.state === 'FAILURE') {
          console.error('Task failed:', taskStatus.error);
          return null;
        }
        
        // Wait 2 seconds before next poll
        await new Promise(resolve => setTimeout(resolve, 2000));
        attempts++;
      } catch (error) {
        console.error('Error polling task status:', error);
        return null;
      }
    }
    
    // Timeout - task is taking too long
    return null;
  };

  const handleUpload = async () => {
    if (uploadMode === 'file' && files.length === 0) return;
    if (uploadMode === 'url' && !url.trim()) return;

    // Check if API key is set
    const apiKey = localStorage.getItem('malwarr_api_key');
    if (!apiKey) {
      alert('Upload failed. Make sure you have set your API key in Settings.');
      return;
    }

    try {
      setUploading(true);
      setUploadProgress([]);
      
      if (uploadMode === 'file' && files.length > 0) {
        // Use bulk upload if multiple files, otherwise single upload
        if (files.length > 1) {
          const result = await malwarrApi.uploadBulkSamples(files, {
            ...metadata,
            archive_password: metadata.archive_password || undefined
          });
          
          setUploadProgress(result.files.map(f => ({
            filename: f.filename,
            status: 'queued',
            taskId: f.task_id
          })));
          
          alert(`${result.total_files} files queued for processing! Check the Tasks page for status.`);
          navigate('/tasks');
        } else {
          const result = await malwarrApi.uploadSample(files[0], {
            ...metadata,
            archive_password: metadata.archive_password || undefined
          });
          
          setUploadProgress([{
            filename: result.filename,
            status: 'processing',
            taskId: result.task_id
          }]);
          
          // Poll task status and redirect to sample page when complete
          const sha512 = await pollTaskStatus(result.task_id, result.filename);
          
          if (sha512) {
            navigate(`/samples/${sha512}`);
          } else {
            alert('Sample uploaded and queued for processing. Check the Tasks page for status.');
            navigate('/tasks');
          }
        }
      } else if (uploadMode === 'url') {
        // Parse tags for URL upload
        const tagList = metadata.tags ? metadata.tags.split(',').map((t: string) => t.trim()).filter((t: string) => t) : [];
        const result = await malwarrApi.uploadSampleFromUrl({
          url: url.trim(),
          tags: tagList,
          family: metadata.family || undefined,
          classification: metadata.classification || undefined,
          notes: metadata.notes || undefined,
          archive_password: metadata.archive_password || undefined,
        });
        
        setUploadProgress([{
          filename: result.filename,
          status: 'processing',
          taskId: result.task_id
        }]);
        
        // Poll task status and redirect to sample page when complete
        const sha512 = await pollTaskStatus(result.task_id, result.filename);
        
        if (sha512) {
          navigate(`/samples/${sha512}`);
        } else {
          alert('Sample uploaded and queued for processing. Check the Tasks page for status.');
          navigate('/tasks');
        }
      }
    } catch (error: any) {
      const errorMessage = error.response?.data?.detail || error.message || 'Upload failed';
      if (error.response?.status === 401 || error.response?.status === 403) {
        alert('Upload failed. Invalid or missing API key. Please check your API key in Settings.');
      } else {
        alert(`Upload failed: ${errorMessage}`);
      }
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="upload-page">
      <div className="upload-container">
        {/* Mode toggle */}
        <div className="upload-mode-toggle">
          <button
            className={`mode-btn ${uploadMode === 'file' ? 'active' : ''}`}
            onClick={() => {
              setUploadMode('file');
              setUrl('');
            }}
          >
            <FaUpload /> File Upload
          </button>
          <button
            className={`mode-btn ${uploadMode === 'url' ? 'active' : ''}`}
            onClick={() => {
              setUploadMode('url');
              setFiles([]);
            }}
          >
            <FaLink /> URL Download
          </button>
        </div>

        {/* File upload section */}
        {uploadMode === 'file' && (
          <>
            <div
              className={`dropzone ${dragging ? 'dragging' : ''} ${files.length > 0 ? 'has-file' : ''}`}
              onDrop={handleDrop}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onClick={() => document.getElementById('file-input')?.click()}
            >
              {files.length > 0 ? (
                <div className="file-info">
                  <FaFile className="file-icon" />
                  <div className="file-details">
                    <div className="file-name">
                      {files.length === 1 ? files[0].name : `${files.length} files selected`}
                    </div>
                    {files.length === 1 && (
                      <div className="file-size">{formatSize(files[0].size)}</div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="drop-message">
                  <FaUpload className="upload-icon" />
                  <h3>Drag & drop file(s) here</h3>
                  <p>or click to browse (multiple files supported)</p>
                </div>
              )}
              <input
                id="file-input"
                type="file"
                onChange={handleFileSelect}
                multiple
                style={{ display: 'none' }}
              />
            </div>
            {files.length > 1 && (
              <div className="file-list">
                <h4>Selected Files:</h4>
                <ul>
                  {files.map((file, index) => (
                    <li key={index}>
                      <span>{file.name} ({formatSize(file.size)})</span>
                      <button onClick={(e) => { e.stopPropagation(); removeFile(index); }} className="remove-btn">
                        <FaTimes />
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}

        {/* URL input section */}
        {uploadMode === 'url' && (
          <div className="url-input-section">
            <div className="url-input-wrapper">
              <FaLink className="url-icon" />
              <input
                type="url"
                className="url-input"
                placeholder="Enter URL to download sample (e.g., https://example.com/sample.exe)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>
            {url && (
              <div className="url-preview">
                <p>URL: {url}</p>
              </div>
            )}
          </div>
        )}

        {((uploadMode === 'file' && files.length > 0) || (uploadMode === 'url' && url)) && (
          <div className="metadata-form">
            <h3>Sample Metadata (Optional)</h3>
            
            {/* Archive password input */}
            {isArchive && showPasswordInput && (
              <div className="form-group archive-password-section">
                <label>
                  <FaLock /> Archive Password
                  <span className="optional-label"> (if encrypted)</span>
                </label>
                <div className="password-input-wrapper">
                  <input
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter password for encrypted archive"
                    value={metadata.archive_password}
                    onChange={(e) => setMetadata({ ...metadata, archive_password: e.target.value })}
                    className="password-input"
                  />
                  <button
                    type="button"
                    className="password-toggle-btn"
                    onClick={() => setShowPassword(!showPassword)}
                    title={showPassword ? "Hide password" : "Show password"}
                  >
                    {showPassword ? <FaEyeSlash /> : <FaEye />}
                  </button>
                </div>
                <small className="help-text">
                  <FaArchive /> Archive detected! Default password is "infected". 
                  Each file will be extracted and scanned separately.
                </small>
              </div>
            )}
            
            <div className="form-group">
              <label>Malware Family</label>
              <input
                type="text"
                placeholder="e.g., Emotet, WannaCry"
                value={metadata.family}
                onChange={(e) => setMetadata({ ...metadata, family: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label>Classification</label>
              <input
                type="text"
                placeholder="e.g., trojan, ransomware"
                value={metadata.classification}
                onChange={(e) => setMetadata({ ...metadata, classification: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label>Tags</label>
              <input
                type="text"
                placeholder="e.g., banking, loader, dropper (comma-separated)"
                value={metadata.tags}
                onChange={(e) => setMetadata({ ...metadata, tags: e.target.value })}
              />
            </div>

            <div className="form-group">
              <label>Notes</label>
              <textarea
                rows={4}
                placeholder="Additional notes about this sample..."
                value={metadata.notes}
                onChange={(e) => setMetadata({ ...metadata, notes: e.target.value })}
              />
            </div>

            <div className="form-actions">
              <button
                className="btn btn-primary"
                onClick={handleUpload}
                disabled={uploading}
              >
                {uploading ? (
                  files.length === 1 || uploadMode === 'url' ? 'Processing...' : 'Uploading...'
                ) : (
                  files.length > 1 ? `Upload ${files.length} Samples` : 'Upload Sample'
                )}
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setFiles([]);
                  setUrl('');
                  setMetadata({ family: '', classification: '', tags: '', notes: '', archive_password: 'infected' });
                }}
                disabled={uploading}
              >
                Clear
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Upload;
