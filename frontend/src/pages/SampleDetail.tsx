import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { FaDownload, FaTrash, FaEdit, FaSave, FaTimes, FaSearch } from 'react-icons/fa';
import { malwarrApi, MalwareSample } from '../services/api';
import './SampleDetail.css';

const SampleDetail: React.FC = () => {
  const { sha512 } = useParams<{ sha512: string }>();
  const navigate = useNavigate();
  const [sample, setSample] = useState<MalwareSample | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState<any>({});
  const [capaAnalyzing, setCapaAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'analyzers'>('overview');
  const [activeAnalyzerTab, setActiveAnalyzerTab] = useState<'capa' | 'pe'>('capa');

  useEffect(() => {
    if (sha512) {
      loadSample();
    }
  }, [sha512]);

  // Auto-refresh when analysis is in progress
  useEffect(() => {
    if (!sample) return;

    const isAnalyzing = sample.analysis_status === 'pending' || sample.analysis_status === 'analyzing';
    
    if (isAnalyzing) {
      const interval = setInterval(() => {
        loadSample();
      }, 5000); // Refresh every 5 seconds

      return () => clearInterval(interval);
    }
  }, [sample?.analysis_status]);

  const loadSample = async () => {
    try {
      const data = await malwarrApi.getSample(sha512!);
      setSample(data);
      setEditData({
        family: data.family || '',
        classification: data.classification || '',
        notes: data.notes || '',
        tags: data.tags && Array.isArray(data.tags) ? data.tags.join(', ') : '',
      });
    } catch (error) {
      console.error('Failed to load sample:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    if (sample) {
      try {
        await malwarrApi.downloadSample(sample.sha512, sample.filename);
      } catch (error: any) {
        alert('Download failed. Make sure you have set your API key in Settings.');
      }
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this sample?')) return;
    
    try {
      await malwarrApi.deleteSample(sha512!);
      navigate('/samples');
    } catch (error) {
      alert('Delete failed. Make sure you have set your API key in Settings.');
    }
  };

  const handleSave = async () => {
    try {
      const tags = editData.tags.split(',').map((t: string) => t.trim()).filter((t: string) => t);
      await malwarrApi.updateSample(sha512!, {
        family: editData.family,
        classification: editData.classification,
        notes: editData.notes,
        tags,
      });
      setEditing(false);
      loadSample();
    } catch (error) {
      alert('Update failed. Make sure you have set your API key in Settings.');
    }
  };

  const handleRunCapaAnalysis = async () => {
    if (!window.confirm('Run CAPA analysis on this sample? This may take a few minutes.')) return;
    
    setCapaAnalyzing(true);
    try {
      await malwarrApi.runCapaAnalysis(sha512!);
      // Reload sample to get updated status - auto-refresh will handle the rest
      await loadSample();
      setCapaAnalyzing(false);
    } catch (error: any) {
      const errorMsg = error.response?.data?.detail || 'CAPA analysis failed. Make sure you have set your API key in Settings.';
      alert(errorMsg);
      setCapaAnalyzing(false);
    }
  };

  if (loading) {
    return <div className="loading">Loading sample details...</div>;
  }

  if (!sample) {
    return <div className="error">Sample not found</div>;
  }

  const parseTags = () => {
    try {
      return sample.tags && Array.isArray(sample.tags) ? sample.tags : [];
    } catch {
      return [];
    }
  };

  return (
    <div className="sample-detail">
      <div className="detail-header">
        <h2>{sample.filename}</h2>
        <div className="actions">
          {!editing ? (
            <>
              <button className="btn btn-primary" onClick={() => setEditing(true)}>
                <FaEdit /> Edit
              </button>
              <button className="btn btn-success" onClick={handleDownload}>
                <FaDownload /> Download
              </button>
              <button className="btn btn-danger" onClick={handleDelete}>
                <FaTrash /> Delete
              </button>
            </>
          ) : (
            <>
              <button className="btn btn-success" onClick={handleSave}>
                <FaSave /> Save
              </button>
              <button className="btn btn-secondary" onClick={() => setEditing(false)}>
                <FaTimes /> Cancel
              </button>
            </>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="tabs">
        <button 
          className={`tab ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          Overview
        </button>
        <button 
          className={`tab ${activeTab === 'analyzers' ? 'active' : ''}`}
          onClick={() => setActiveTab('analyzers')}
        >
          Analyzers
        </button>
      </div>

      {/* Overview Tab Content */}
      {activeTab === 'overview' && (
      <div className="detail-grid">{/* File Information Section */}
        <div className="detail-section">
          <h3>File Information</h3>
          <div className="info-grid">
            <div className="info-row">
              <span className="label">File Type:</span>
              <span className={`type-badge type-${sample.file_type}`}>{sample.file_type.toUpperCase()}</span>
            </div>
            <div className="info-row">
              <span className="label">Size:</span>
              <span>{sample.file_size.toLocaleString()} bytes</span>
            </div>
            <div className="info-row">
              <span className="label">MIME Type:</span>
              <span>{sample.mime_type}</span>
            </div>
            <div className="info-row">
              <span className="label">Entropy:</span>
              <span>{sample.entropy}</span>
            </div>
            <div className="info-row">
              <span className="label">Strings:</span>
              <span>{sample.strings_count}</span>
            </div>
          </div>
        </div>

        <div className="detail-section">
          <h3>Hashes</h3>
          <div className="hash-list">
            <div className="hash-item">
              <span className="hash-type">SHA512:</span>
              <code>{sample.sha512}</code>
            </div>
            <div className="hash-item">
              <span className="hash-type">SHA256:</span>
              <code>{sample.sha256}</code>
            </div>
            <div className="hash-item">
              <span className="hash-type">SHA1:</span>
              <code>{sample.sha1}</code>
            </div>
            <div className="hash-item">
              <span className="hash-type">MD5:</span>
              <code>{sample.md5}</code>
            </div>
            {sample.pe_imphash && (
              <div className="hash-item">
                <span className="hash-type">ImpHash:</span>
                <code>{sample.pe_imphash}</code>
              </div>
            )}
          </div>
        </div>

        <div className="detail-section full-width">
          <h3>Classification</h3>
          {editing ? (
            <div className="edit-grid">
              <input
                type="text"
                placeholder="Family"
                value={editData.family}
                onChange={(e) => setEditData({ ...editData, family: e.target.value })}
              />
              <input
                type="text"
                placeholder="Classification"
                value={editData.classification}
                onChange={(e) => setEditData({ ...editData, classification: e.target.value })}
              />
              <input
                type="text"
                placeholder="Tags (comma-separated)"
                value={editData.tags}
                onChange={(e) => setEditData({ ...editData, tags: e.target.value })}
              />
              <textarea
                placeholder="Notes"
                value={editData.notes}
                onChange={(e) => setEditData({ ...editData, notes: e.target.value })}
                rows={4}
              />
            </div>
          ) : (
            <div className="info-grid">
              <div className="info-row">
                <span className="label">Family:</span>
                <span>{sample.family || '-'}</span>
              </div>
              <div className="info-row">
                <span className="label">Classification:</span>
                <span>{sample.classification || '-'}</span>
              </div>
              <div className="info-row">
                <span className="label">Tags:</span>
                <div className="tags">
                  {parseTags().length > 0 ? parseTags().map((tag: string) => (
                    <span key={tag} className="tag">{tag}</span>
                  )) : '-'}
                </div>
              </div>
              {sample.notes && (
                <div className="info-row full-width">
                  <span className="label">Notes:</span>
                  <p>{sample.notes}</p>
                </div>
              )}
            </div>
          )}
        </div>

        {sample.file_type === 'pe' && (sample.pe_sections || sample.pe_imports) && (
          <div className="detail-section full-width">
            <h3>PE Analysis</h3>
            {sample.pe_compilation_timestamp && (
              <div className="info-row">
                <span className="label">Compilation:</span>
                <span>{new Date(sample.pe_compilation_timestamp).toLocaleString()}</span>
              </div>
            )}
            {sample.pe_entry_point && (
              <div className="info-row">
                <span className="label">Entry Point:</span>
                <code>{sample.pe_entry_point}</code>
              </div>
            )}
          </div>
        )}

        {sample.capa_capabilities && (
          <div className="detail-section full-width">
            <h3>CAPA Analysis</h3>
            <div className="info-grid">
              {sample.capa_total_capabilities !== undefined && (
                <div className="info-row">
                  <span className="label">Total Capabilities:</span>
                  <span className="badge">{sample.capa_total_capabilities}</span>
                </div>
              )}
              {sample.capa_analysis_date && (
                <div className="info-row">
                  <span className="label">Analysis Date:</span>
                  <span>{new Date(sample.capa_analysis_date).toLocaleString()}</span>
                </div>
              )}
              <div className="info-row full-width">
                <button 
                  className="btn btn-primary" 
                  onClick={() => navigate(`/samples/${sha512}/capa`)}
                >
                  <FaSearch /> View in CAPA Explorer
                </button>
              </div>
            </div>
          </div>
        )}

        {!sample.capa_capabilities && (sample.file_type === 'pe' || sample.file_type === 'elf') && (
          <div className="detail-section full-width">
            <h3>CAPA Analysis</h3>
            <div className="info-grid">
              <div className="info-row">
                <span className="label">Status:</span>
                <span>
                  {sample.analysis_status === 'pending' && 'Analysis queued, waiting to start...'}
                  {sample.analysis_status === 'analyzing' && 'Analysis in progress...'}
                  {sample.analysis_status === 'failed' && 'Analysis failed'}
                  {sample.analysis_status === 'skipped' && 'Analysis skipped (unsupported file type)'}
                  {!sample.analysis_status && 'No CAPA analysis has been run yet'}
                </span>
              </div>
              <div className="info-row">
                <button 
                  className="btn btn-primary" 
                  onClick={handleRunCapaAnalysis}
                  disabled={capaAnalyzing || sample.analysis_status === 'pending' || sample.analysis_status === 'analyzing'}
                >
                  <FaSearch /> {capaAnalyzing || sample.analysis_status === 'pending' || sample.analysis_status === 'analyzing' ? 'Running Analysis...' : 'Run CAPA Analysis'}
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="detail-section full-width">
          <h3>Timestamps</h3>
          <div className="info-grid">
            <div className="info-row">
              <span className="label">First Seen:</span>
              <span>{new Date(sample.first_seen).toLocaleString()}</span>
            </div>
            <div className="info-row">
              <span className="label">Uploaded:</span>
              <span>{new Date(sample.upload_date).toLocaleString()}</span>
            </div>
            <div className="info-row">
              <span className="label">Last Updated:</span>
              <span>{new Date(sample.last_updated).toLocaleString()}</span>
            </div>
          </div>
        </div>
      </div>
      )}

      {/* Analyzers Tab Content */}
      {activeTab === 'analyzers' && (
        <div className="analyzers-tab">
          {/* Analyzer Sub-tabs */}
          <div className="sub-tabs">
            <button 
              className={`sub-tab ${activeAnalyzerTab === 'capa' ? 'active' : ''}`}
              onClick={() => setActiveAnalyzerTab('capa')}
            >
              CAPA
            </button>
            {sample.file_type === 'pe' && (
              <button 
                className={`sub-tab ${activeAnalyzerTab === 'pe' ? 'active' : ''}`}
                onClick={() => setActiveAnalyzerTab('pe')}
              >
                PE
              </button>
            )}
          </div>

          {/* CAPA Sub-tab Content */}
          {activeAnalyzerTab === 'capa' && (
            <div className="analyzer-content">
              {sample.capa_capabilities ? (
                <div className="detail-section full-width">
                  <h3>CAPA Analysis Results</h3>
                  <div className="info-grid">
                    {sample.capa_total_capabilities !== undefined && (
                      <div className="info-row">
                        <span className="label">Total Capabilities:</span>
                        <span className="badge">{sample.capa_total_capabilities}</span>
                      </div>
                    )}
                    {sample.capa_analysis_date && (
                      <div className="info-row">
                        <span className="label">Analysis Date:</span>
                        <span>{new Date(sample.capa_analysis_date).toLocaleString()}</span>
                      </div>
                    )}
                    <div className="info-row full-width">
                      <button 
                        className="btn btn-primary" 
                        onClick={() => navigate(`/samples/${sha512}/capa`)}
                      >
                        <FaSearch /> View in CAPA Explorer
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="detail-section full-width">
                  <h3>CAPA Analysis</h3>
                  {(sample.file_type === 'pe' || sample.file_type === 'elf') ? (
                    <div className="info-grid">
                      <div className="info-row">
                        <span className="label">Status:</span>
                        <span>
                          {sample.analysis_status === 'pending' && 'Analysis queued, waiting to start...'}
                          {sample.analysis_status === 'analyzing' && 'Analysis in progress...'}
                          {sample.analysis_status === 'failed' && 'Analysis failed'}
                          {sample.analysis_status === 'skipped' && 'Analysis skipped (unsupported file type)'}
                          {!sample.analysis_status && 'No CAPA analysis has been run yet'}
                        </span>
                      </div>
                      <div className="info-row">
                        <button 
                          className="btn btn-primary" 
                          onClick={handleRunCapaAnalysis}
                          disabled={capaAnalyzing || sample.analysis_status === 'pending' || sample.analysis_status === 'analyzing'}
                        >
                          <FaSearch /> {capaAnalyzing || sample.analysis_status === 'pending' || sample.analysis_status === 'analyzing' ? 'Running Analysis...' : 'Run CAPA Analysis'}
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="info-row">
                      <p>CAPA analysis is only available for PE and ELF files.</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* PE Analyzer Sub-tab Content */}
          {activeAnalyzerTab === 'pe' && sample.file_type === 'pe' && (
            <div className="analyzer-content">
              <div className="detail-section full-width">
                <h3>PE Header Information</h3>
                <div className="info-grid">
                  {sample.pe_imphash && (
                    <div className="info-row">
                      <span className="label">Import Hash (ImpHash):</span>
                      <code>{sample.pe_imphash}</code>
                    </div>
                  )}
                  {sample.pe_compilation_timestamp && (
                    <div className="info-row">
                      <span className="label">Compilation Timestamp:</span>
                      <span>{new Date(sample.pe_compilation_timestamp).toLocaleString()}</span>
                    </div>
                  )}
                  {sample.pe_entry_point && (
                    <div className="info-row">
                      <span className="label">Entry Point:</span>
                      <code>{sample.pe_entry_point}</code>
                    </div>
                  )}
                </div>
              </div>

              {/* Sections */}
              {sample.pe_sections && (() => {
                try {
                  const sections = JSON.parse(sample.pe_sections);
                  return (
                    <div className="detail-section full-width">
                      <h3>PE Sections ({sections.length})</h3>
                      <div className="table-container">
                        <table className="pe-sections-table">
                          <thead>
                            <tr>
                              <th>Name</th>
                              <th>Virtual Address</th>
                              <th>Virtual Size</th>
                              <th>Raw Size</th>
                              <th>Entropy</th>
                            </tr>
                          </thead>
                          <tbody>
                            {sections.map((section: any, index: number) => (
                              <tr key={index}>
                                <td><code>{section.name}</code></td>
                                <td><code>{section.virtual_address}</code></td>
                                <td>{section.virtual_size.toLocaleString()}</td>
                                <td>{section.raw_size.toLocaleString()}</td>
                                <td>
                                  <span className={`entropy-badge ${section.entropy > 7 ? 'high' : section.entropy > 6 ? 'medium' : 'low'}`}>
                                    {section.entropy.toFixed(2)}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  );
                } catch (e) {
                  return null;
                }
              })()}

              {/* Imports */}
              {sample.pe_imports && (() => {
                try {
                  const imports = JSON.parse(sample.pe_imports);
                  return (
                    <div className="detail-section full-width">
                      <h3>PE Imports ({imports.length} DLLs)</h3>
                      <div className="imports-container">
                        {imports.map((imp: any, index: number) => (
                          <div key={index} className="import-dll">
                            <h4>{imp.dll}</h4>
                            <div className="import-functions">
                              {imp.functions.map((func: string, fIndex: number) => (
                                <code key={fIndex} className="import-function">{func}</code>
                              ))}
                              {imp.functions.length === 0 && <span className="no-functions">No named functions</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                } catch (e) {
                  return null;
                }
              })()}

              {/* Exports */}
              {sample.pe_exports && (() => {
                try {
                  const exports = JSON.parse(sample.pe_exports);
                  if (exports.length > 0) {
                    return (
                      <div className="detail-section full-width">
                        <h3>PE Exports ({exports.length})</h3>
                        <div className="exports-container">
                          {exports.map((exp: string, index: number) => (
                            <code key={index} className="export-function">{exp}</code>
                          ))}
                        </div>
                      </div>
                    );
                  }
                  return null;
                } catch (e) {
                  return null;
                }
              })()}

              {/* Show message if no PE data available */}
              {!sample.pe_sections && !sample.pe_imports && !sample.pe_exports && (
                <div className="detail-section full-width">
                  <p>No PE analysis data available for this sample.</p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SampleDetail;
