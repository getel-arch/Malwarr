import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { FaUpload, FaFile, FaLink, FaLock, FaArchive, FaCheckCircle, FaEye, FaEyeSlash } from 'react-icons/fa';
import { malwarrApi } from '../services/api';
import './Upload.css';

const Upload: React.FC = () => {
  const navigate = useNavigate();
  const [uploadMode, setUploadMode] = useState<'file' | 'url'>('file');
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [isArchive, setIsArchive] = useState(false);
  const [showPasswordInput, setShowPasswordInput] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [uploadResult, setUploadResult] = useState<any>(null);
  const [metadata, setMetadata] = useState({
    family: '',
    classification: '',
    tags: '',
    notes: '',
    archive_password: 'infected', // Default password
  });

  // Detect if file is an archive based on extension
  useEffect(() => {
    if (file) {
      const filename = file.name.toLowerCase();
      const archiveExtensions = ['.zip', '.rar', '.7z', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.gz'];
      const isArchiveFile = archiveExtensions.some(ext => filename.endsWith(ext));
      setIsArchive(isArchiveFile);
      setShowPasswordInput(isArchiveFile);
    } else {
      setIsArchive(false);
      setShowPasswordInput(false);
    }
  }, [file]);

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
    }
  };

  const handleUpload = async () => {
    if (uploadMode === 'file' && !file) return;
    if (uploadMode === 'url' && !url.trim()) return;

    // Check if API key is set
    const apiKey = localStorage.getItem('malwarr_api_key');
    if (!apiKey) {
      alert('Upload failed. Make sure you have set your API key in Settings.');
      return;
    }

    try {
      setUploading(true);
      setUploadResult(null);
      let result: any = null;
      
      if (uploadMode === 'file' && file) {
        result = await malwarrApi.uploadSample(file, {
          ...metadata,
          archive_password: metadata.archive_password || undefined
        });
      } else if (uploadMode === 'url') {
        // Parse tags for URL upload
        const tagList = metadata.tags ? metadata.tags.split(',').map((t: string) => t.trim()).filter((t: string) => t) : [];
        result = await malwarrApi.uploadSampleFromUrl({
          url: url.trim(),
          tags: tagList,
          family: metadata.family || undefined,
          classification: metadata.classification || undefined,
          notes: metadata.notes || undefined,
          archive_password: metadata.archive_password || undefined,
        });
      }
      
      if (result) {
        setUploadResult(result);
        
        // If it's not an archive or extraction failed, navigate immediately
        if (!result.is_archive || result.extraction_count === 0) {
          setTimeout(() => {
            navigate(`/samples/${result.sample.sha512}`);
          }, 1500);
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
              setFile(null);
            }}
          >
            <FaLink /> URL Download
          </button>
        </div>

        {/* File upload section */}
        {uploadMode === 'file' && (
          <div
            className={`dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onClick={() => document.getElementById('file-input')?.click()}
          >
            {file ? (
              <div className="file-info">
                <FaFile className="file-icon" />
                <div className="file-details">
                  <div className="file-name">{file.name}</div>
                  <div className="file-size">{(file.size / 1024).toFixed(2)} KB</div>
                </div>
              </div>
            ) : (
              <div className="drop-message">
                <FaUpload className="upload-icon" />
                <h3>Drag & drop a file here</h3>
                <p>or click to browse</p>
              </div>
            )}
            <input
              id="file-input"
              type="file"
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
          </div>
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

        {((uploadMode === 'file' && file) || (uploadMode === 'url' && url)) && (
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
                {uploading ? 'Uploading...' : 'Upload Sample'}
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => {
                  setFile(null);
                  setUrl('');
                  setUploadResult(null);
                  setMetadata({ family: '', classification: '', tags: '', notes: '', archive_password: 'infected' });
                }}
                disabled={uploading}
              >
                Clear
              </button>
            </div>
          </div>
        )}

        {/* Upload result display */}
        {uploadResult && (
          <div className="upload-result">
            <div className="result-header">
              <FaCheckCircle className="success-icon" />
              <h3>Upload Successful!</h3>
            </div>
            
            <div className="result-sample">
              <h4>Uploaded Sample</h4>
              <div className="sample-info">
                <p><strong>Filename:</strong> {uploadResult.sample.filename}</p>
                <p><strong>SHA256:</strong> <code>{uploadResult.sample.sha256}</code></p>
                <p><strong>File Type:</strong> {uploadResult.sample.file_type}</p>
                {uploadResult.sample.file_size && (
                  <p><strong>Size:</strong> {(uploadResult.sample.file_size / 1024).toFixed(2)} KB</p>
                )}
              </div>
              <button 
                className="btn btn-primary"
                onClick={() => navigate(`/samples/${uploadResult.sample.sha512}`)}
              >
                View Details
              </button>
            </div>

            {uploadResult.is_archive && uploadResult.extraction_count > 0 && (
              <div className="result-extracted">
                <h4>
                  <FaArchive /> Extracted {uploadResult.extraction_count} {uploadResult.extraction_count === 1 ? 'File' : 'Files'}
                </h4>
                <div className="extracted-files-list">
                  {uploadResult.extracted_samples.map((sample: any, index: number) => (
                    <div key={sample.sha512} className="extracted-file-item">
                      <div className="extracted-file-info">
                        <strong>{sample.filename}</strong>
                        <span className="file-type-badge">{sample.file_type}</span>
                      </div>
                      <button
                        className="btn btn-sm"
                        onClick={() => navigate(`/samples/${sample.sha512}`)}
                      >
                        View
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Upload;
