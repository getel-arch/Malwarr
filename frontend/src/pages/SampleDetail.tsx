import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { FaDownload, FaTrash, FaEdit, FaSave, FaTimes, FaSearch, FaChevronDown, FaChevronRight } from 'react-icons/fa';
import { malwarrApi, MalwareSample } from '../services/api';
import './SampleDetail.css';

// Collapsible Section Component
interface CollapsibleSectionProps {
  title: string;
  defaultCollapsed?: boolean;
  children: React.ReactNode;
}

const CollapsibleSection: React.FC<CollapsibleSectionProps> = ({ 
  title, 
  defaultCollapsed = true, 
  children 
}) => {
  const [isCollapsed, setIsCollapsed] = useState(defaultCollapsed);

  return (
    <div className="collapsible-section">
      <div 
        className="collapsible-header" 
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <h4>
          {isCollapsed ? <FaChevronRight /> : <FaChevronDown />}
          {title}
        </h4>
      </div>
      {!isCollapsed && (
        <div className="collapsible-content">
          {children}
        </div>
      )}
    </div>
  );
};

const SampleDetail: React.FC = () => {
  const { sha512 } = useParams<{ sha512: string }>();
  const navigate = useNavigate();
  const [sample, setSample] = useState<MalwareSample | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [editData, setEditData] = useState<any>({});
  const [capaAnalyzing, setCapaAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'analyzers' | 'relations'>('overview');
  const [activeAnalyzerTab, setActiveAnalyzerTab] = useState<'capa' | 'pe' | 'elf'>('capa');
  const [relatedSamples, setRelatedSamples] = useState<{
    parentArchive?: MalwareSample;
    extractedFiles?: MalwareSample[];
  }>({});

  const formatSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  useEffect(() => {
    if (sha512) {
      loadSample();
      loadRelatedSamples();
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

  const loadRelatedSamples = async () => {
    try {
      const data = await malwarrApi.getSample(sha512!);
      
      // Load parent archive if this sample was extracted from one
      if (data.parent_archive_sha512) {
        try {
          const parentArchive = await malwarrApi.getSample(data.parent_archive_sha512);
          setRelatedSamples(prev => ({ ...prev, parentArchive }));
        } catch (error) {
          console.error('Failed to load parent archive:', error);
        }
      }
      
      // Load extracted files if this sample is an archive
      if (data.is_archive === 'true' && data.extracted_file_count && data.extracted_file_count > 0) {
        try {
          // Search for samples that have this sample as their parent
          const allSamples = await malwarrApi.getSamples({ limit: 1000 });
          const extractedFiles = allSamples.filter(s => s.parent_archive_sha512 === sha512);
          setRelatedSamples(prev => ({ ...prev, extractedFiles }));
        } catch (error) {
          console.error('Failed to load extracted files:', error);
        }
      }
    } catch (error) {
      console.error('Failed to load related samples:', error);
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
        <button 
          className={`tab ${activeTab === 'relations' ? 'active' : ''}`}
          onClick={() => setActiveTab('relations')}
        >
          Relations
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
              <span>{formatSize(sample.file_size)}</span>
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
            {sample.file_type === 'elf' && (
              <button 
                className={`sub-tab ${activeAnalyzerTab === 'elf' ? 'active' : ''}`}
                onClick={() => setActiveAnalyzerTab('elf')}
              >
                ELF
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
                
                {/* PE Header Information */}
                <CollapsibleSection title="PE Header Information" defaultCollapsed={false}>
                  <div className="info-grid">
                    {sample.pe_machine && (
                      <div className="info-row">
                        <span className="label">Machine Type:</span>
                        <code>{sample.pe_machine}</code>
                      </div>
                    )}
                    {sample.pe_magic && (
                      <div className="info-row">
                        <span className="label">Magic (PE Type):</span>
                        <code>{sample.pe_magic}</code>
                      </div>
                    )}
                    {sample.pe_subsystem && (
                      <div className="info-row">
                        <span className="label">Subsystem:</span>
                        <code>{sample.pe_subsystem}</code>
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
                    {sample.pe_image_base && (
                      <div className="info-row">
                        <span className="label">Image Base:</span>
                        <code>{sample.pe_image_base}</code>
                      </div>
                    )}
                    {sample.pe_base_of_code && (
                      <div className="info-row">
                        <span className="label">Base of Code:</span>
                        <code>{sample.pe_base_of_code}</code>
                      </div>
                    )}
                    {sample.pe_size_of_image && (
                      <div className="info-row">
                        <span className="label">Size of Image:</span>
                        <span>{sample.pe_size_of_image.toLocaleString()} bytes</span>
                      </div>
                    )}
                    {sample.pe_size_of_headers && (
                      <div className="info-row">
                        <span className="label">Size of Headers:</span>
                        <span>{sample.pe_size_of_headers.toLocaleString()} bytes</span>
                      </div>
                    )}
                    {sample.pe_number_of_sections !== undefined && (
                      <div className="info-row">
                        <span className="label">Number of Sections:</span>
                        <span>{sample.pe_number_of_sections}</span>
                      </div>
                    )}
                    {sample.pe_characteristics && (
                      <div className="info-row">
                        <span className="label">Characteristics:</span>
                        <code>{sample.pe_characteristics}</code>
                      </div>
                    )}
                    {sample.pe_dll_characteristics && (
                      <div className="info-row">
                        <span className="label">DLL Characteristics:</span>
                        <code>{sample.pe_dll_characteristics}</code>
                      </div>
                    )}
                    {sample.pe_checksum && (
                      <div className="info-row">
                        <span className="label">Checksum:</span>
                        <code>{sample.pe_checksum}</code>
                      </div>
                    )}
                    {sample.pe_imphash && (
                      <div className="info-row">
                        <span className="label">Import Hash (ImpHash):</span>
                        <code>{sample.pe_imphash}</code>
                      </div>
                    )}
                  </div>
                </CollapsibleSection>

                {/* Version Information */}
                {(sample.pe_linker_version || sample.pe_os_version || sample.pe_image_version || sample.pe_subsystem_version) && (
                  <CollapsibleSection title="PE Version Information" defaultCollapsed={true}>
                    <div className="info-grid">
                      {sample.pe_linker_version && (
                        <div className="info-row">
                          <span className="label">Linker Version:</span>
                          <span>{sample.pe_linker_version}</span>
                        </div>
                      )}
                      {sample.pe_os_version && (
                        <div className="info-row">
                          <span className="label">OS Version:</span>
                          <span>{sample.pe_os_version}</span>
                        </div>
                      )}
                      {sample.pe_image_version && (
                        <div className="info-row">
                          <span className="label">Image Version:</span>
                          <span>{sample.pe_image_version}</span>
                        </div>
                      )}
                      {sample.pe_subsystem_version && (
                        <div className="info-row">
                          <span className="label">Subsystem Version:</span>
                          <span>{sample.pe_subsystem_version}</span>
                        </div>
                      )}
                    </div>
                  </CollapsibleSection>
                )}

                {/* Digital Signature */}
                {(sample.pe_is_signed !== undefined) && (
                  <CollapsibleSection title="Digital Signature" defaultCollapsed={true}>
                    <div className="info-grid">
                      <div className="info-row">
                        <span className="label">Signed:</span>
                        <span className={sample.pe_is_signed ? 'badge-success' : 'badge-warning'}>
                          {sample.pe_is_signed ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {sample.pe_signature_info && (() => {
                        try {
                          const sigInfo = JSON.parse(sample.pe_signature_info);
                          return (
                            <>
                              {sigInfo.present && (
                                <div className="info-row">
                                  <span className="label">Signature Size:</span>
                                  <span>{sigInfo.size} bytes</span>
                                </div>
                              )}
                            </>
                          );
                        } catch (e) {
                          return null;
                        }
                      })()}
                    </div>
                  </CollapsibleSection>
                )}

                {/* Sections */}
                {sample.pe_sections && (() => {
                  try {
                    const sections = JSON.parse(sample.pe_sections);
                    return (
                      <CollapsibleSection title={`PE Sections (${sections.length})`} defaultCollapsed={true}>
                        <div className="table-container">
                          <table className="pe-sections-table">
                            <thead>
                              <tr>
                                <th>Name</th>
                                <th>Virtual Address</th>
                                <th>Virtual Size</th>
                                <th>Raw Size</th>
                                <th>Characteristics</th>
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
                                  <td><code>{section.characteristics}</code></td>
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
                      </CollapsibleSection>
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
                      <CollapsibleSection 
                        title={`PE Imports (${sample.pe_import_dll_count || imports.length} DLLs, ${sample.pe_imported_functions_count || 0} functions)`} 
                        defaultCollapsed={true}
                      >
                        <div className="imports-container">
                          {imports.map((imp: any, index: number) => (
                            <div key={index} className="import-dll">
                              <h4>{imp.dll} <span className="function-count">({imp.functions.length} functions)</span></h4>
                              <div className="import-functions">
                                {imp.functions.map((func: string, fIndex: number) => (
                                  <code key={fIndex} className="import-function">{func}</code>
                                ))}
                                {imp.functions.length === 0 && <span className="no-functions">No named functions</span>}
                              </div>
                            </div>
                          ))}
                        </div>
                      </CollapsibleSection>
                    );
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Exports */}
                {sample.pe_exports && (() => {
                  try {
                    const exportData = JSON.parse(sample.pe_exports);
                    if (exportData.exports && exportData.exports.length > 0) {
                      return (
                        <CollapsibleSection 
                          title={`PE Exports (${sample.pe_export_count || exportData.exports.length})`} 
                          defaultCollapsed={true}
                        >
                          <div className="info-grid">
                            {exportData.dll_name && (
                              <div className="info-row">
                                <span className="label">Export DLL Name:</span>
                                <code>{exportData.dll_name}</code>
                              </div>
                            )}
                          </div>
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Name</th>
                                  <th>Ordinal</th>
                                  <th>Address</th>
                                </tr>
                              </thead>
                              <tbody>
                                {exportData.exports.map((exp: any, index: number) => (
                                  <tr key={index}>
                                    <td><code>{exp.name}</code></td>
                                    <td>{exp.ordinal}</td>
                                    <td><code>{exp.address || 'N/A'}</code></td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Resources */}
                {sample.pe_resources && (() => {
                  try {
                    const resources = JSON.parse(sample.pe_resources);
                    if (resources.length > 0) {
                      return (
                        <CollapsibleSection 
                          title={`PE Resources (${sample.pe_resource_count || resources.length})`} 
                          defaultCollapsed={true}
                        >
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Type</th>
                                  <th>Name</th>
                                  <th>Language</th>
                                  <th>Size</th>
                                  <th>Offset</th>
                                </tr>
                              </thead>
                              <tbody>
                                {resources.map((resource: any, index: number) => (
                                  <tr key={index}>
                                    <td>{resource.type}</td>
                                    <td><code>{resource.name}</code></td>
                                    <td>{resource.language || 'N/A'}</td>
                                    <td>{resource.size.toLocaleString()} bytes</td>
                                    <td><code>{resource.offset}</code></td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Version Info */}
                {sample.pe_version_info && (() => {
                  try {
                    const versionInfo = JSON.parse(sample.pe_version_info);
                    const entries = Object.entries(versionInfo);
                    if (entries.length > 0) {
                      return (
                        <CollapsibleSection title="PE Version Info" defaultCollapsed={true}>
                          <div className="info-grid">
                            {entries.map(([key, value]: [string, any]) => (
                              <div key={key} className="info-row">
                                <span className="label">{key}:</span>
                                <span>{typeof value === 'string' ? value : JSON.stringify(value)}</span>
                              </div>
                            ))}
                          </div>
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Debug Info */}
                {sample.pe_debug_info && (() => {
                  try {
                    const debugInfo = JSON.parse(sample.pe_debug_info);
                    if (debugInfo.length > 0) {
                      return (
                        <CollapsibleSection title="PE Debug Info" defaultCollapsed={true}>
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Type</th>
                                  <th>Timestamp</th>
                                  <th>Size</th>
                                  <th>PDB Path</th>
                                </tr>
                              </thead>
                              <tbody>
                                {debugInfo.map((debug: any, index: number) => (
                                  <tr key={index}>
                                    <td>{debug.type}</td>
                                    <td>{debug.timestamp}</td>
                                    <td>{debug.size.toLocaleString()} bytes</td>
                                    <td><code>{debug.pdb_path || 'N/A'}</code></td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* TLS Info */}
                {sample.pe_tls_info && (() => {
                  try {
                    const tlsInfo = JSON.parse(sample.pe_tls_info);
                    return (
                      <CollapsibleSection title="PE TLS (Thread Local Storage)" defaultCollapsed={true}>
                        <div className="info-grid">
                          {tlsInfo.callback_address && (
                            <div className="info-row">
                              <span className="label">Callback Address:</span>
                              <code>{tlsInfo.callback_address}</code>
                            </div>
                          )}
                        </div>
                      </CollapsibleSection>
                    );
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Rich Header */}
                {sample.pe_rich_header && (() => {
                  try {
                    const richHeader = JSON.parse(sample.pe_rich_header);
                    return (
                      <CollapsibleSection title="Rich Header" defaultCollapsed={true}>
                        <div className="info-grid">
                          {richHeader.checksum && (
                            <div className="info-row">
                              <span className="label">Checksum:</span>
                              <code>{richHeader.checksum}</code>
                            </div>
                          )}
                        </div>
                        {richHeader.values && richHeader.values.length > 0 && (
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Product ID</th>
                                  <th>Build ID</th>
                                  <th>Count</th>
                                </tr>
                              </thead>
                              <tbody>
                                {richHeader.values.map((entry: any, index: number) => (
                                  <tr key={index}>
                                    <td>{entry.product_id}</td>
                                    <td>{entry.build_id}</td>
                                    <td>{entry.count}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </CollapsibleSection>
                    );
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Show message if no PE data available */}
                {!sample.pe_sections && !sample.pe_imports && !sample.pe_exports && !sample.pe_imphash && 
                 !sample.pe_compilation_timestamp && !sample.pe_entry_point && !sample.pe_machine && (
                  <p>No PE analysis data available for this sample.</p>
                )}
              </div>
            </div>
          )}

          {/* ELF Analyzer Sub-tab Content */}
          {activeAnalyzerTab === 'elf' && sample.file_type === 'elf' && (
            <div className="analyzer-content">
              <div className="detail-section full-width">
                
                {/* ELF Header Information */}
                <CollapsibleSection title="ELF Header Information" defaultCollapsed={false}>
                  <div className="info-grid">
                    {sample.elf_machine && (
                      <div className="info-row">
                        <span className="label">Machine Type:</span>
                        <code>{sample.elf_machine}</code>
                      </div>
                    )}
                    {sample.elf_type && (
                      <div className="info-row">
                        <span className="label">ELF Type:</span>
                        <code>{sample.elf_type}</code>
                      </div>
                    )}
                    {sample.elf_entry_point && (
                      <div className="info-row">
                        <span className="label">Entry Point:</span>
                        <code>{sample.elf_entry_point}</code>
                      </div>
                    )}
                    {sample.elf_file_class && (
                      <div className="info-row">
                        <span className="label">File Class:</span>
                        <code>{sample.elf_file_class}</code>
                      </div>
                    )}
                    {sample.elf_data_encoding && (
                      <div className="info-row">
                        <span className="label">Data Encoding:</span>
                        <code>{sample.elf_data_encoding}</code>
                      </div>
                    )}
                    {sample.elf_os_abi && (
                      <div className="info-row">
                        <span className="label">OS/ABI:</span>
                        <code>{sample.elf_os_abi}</code>
                      </div>
                    )}
                    {sample.elf_abi_version !== undefined && (
                      <div className="info-row">
                        <span className="label">ABI Version:</span>
                        <span>{sample.elf_abi_version}</span>
                      </div>
                    )}
                    {sample.elf_version && (
                      <div className="info-row">
                        <span className="label">ELF Version:</span>
                        <span>{sample.elf_version}</span>
                      </div>
                    )}
                    {sample.elf_flags && (
                      <div className="info-row">
                        <span className="label">Flags:</span>
                        <code>{sample.elf_flags}</code>
                      </div>
                    )}
                    {sample.elf_header_size && (
                      <div className="info-row">
                        <span className="label">Header Size:</span>
                        <span>{sample.elf_header_size} bytes</span>
                      </div>
                    )}
                    {sample.elf_program_header_offset && (
                      <div className="info-row">
                        <span className="label">Program Header Offset:</span>
                        <code>{sample.elf_program_header_offset}</code>
                      </div>
                    )}
                    {sample.elf_section_header_offset && (
                      <div className="info-row">
                        <span className="label">Section Header Offset:</span>
                        <code>{sample.elf_section_header_offset}</code>
                      </div>
                    )}
                    {sample.elf_program_header_count !== undefined && (
                      <div className="info-row">
                        <span className="label">Program Headers:</span>
                        <span>{sample.elf_program_header_count}</span>
                      </div>
                    )}
                    {sample.elf_section_header_count !== undefined && (
                      <div className="info-row">
                        <span className="label">Section Headers:</span>
                        <span>{sample.elf_section_header_count}</span>
                      </div>
                    )}
                    {sample.elf_interpreter && (
                      <div className="info-row">
                        <span className="label">Interpreter:</span>
                        <code>{sample.elf_interpreter}</code>
                      </div>
                    )}
                  </div>
                </CollapsibleSection>

                {/* Program Headers / Segments */}
                {sample.elf_segments && (() => {
                  try {
                    const segments = JSON.parse(sample.elf_segments);
                    return (
                      <CollapsibleSection title={`ELF Program Headers (${segments.length})`} defaultCollapsed={true}>
                        <div className="table-container">
                          <table className="pe-sections-table">
                            <thead>
                              <tr>
                                <th>Type</th>
                                <th>Virtual Address</th>
                                <th>Physical Address</th>
                                <th>Offset</th>
                                <th>File Size</th>
                                <th>Memory Size</th>
                                <th>Flags</th>
                                <th>Alignment</th>
                              </tr>
                            </thead>
                            <tbody>
                              {segments.map((segment: any, index: number) => (
                                <tr key={index}>
                                  <td>{segment.type}</td>
                                  <td><code>{segment.virtual_address}</code></td>
                                  <td><code>{segment.physical_address}</code></td>
                                  <td><code>{segment.offset}</code></td>
                                  <td>{segment.file_size.toLocaleString()}</td>
                                  <td>{segment.memory_size.toLocaleString()}</td>
                                  <td>{segment.flags}</td>
                                  <td>{segment.alignment}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </CollapsibleSection>
                    );
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Sections */}
                {sample.elf_sections && (() => {
                  try {
                    const sections = JSON.parse(sample.elf_sections);
                    return (
                      <CollapsibleSection title={`ELF Sections (${sections.length})`} defaultCollapsed={true}>
                        <div className="table-container">
                          <table className="pe-sections-table">
                            <thead>
                              <tr>
                                <th>Name</th>
                                <th>Type</th>
                                <th>Address</th>
                                <th>Offset</th>
                                <th>Size</th>
                                <th>Flags</th>
                                <th>Entropy</th>
                              </tr>
                            </thead>
                            <tbody>
                              {sections.map((section: any, index: number) => (
                                <tr key={index}>
                                  <td><code>{section.name}</code></td>
                                  <td>{section.type}</td>
                                  <td><code>{section.address}</code></td>
                                  <td><code>{section.offset}</code></td>
                                  <td>{section.size.toLocaleString()}</td>
                                  <td><code>{section.flags}</code></td>
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
                      </CollapsibleSection>
                    );
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Shared Libraries */}
                {sample.elf_shared_libraries && (() => {
                  try {
                    const libraries = JSON.parse(sample.elf_shared_libraries);
                    if (libraries.length > 0) {
                      return (
                        <CollapsibleSection 
                          title={`Shared Libraries (${sample.elf_shared_library_count || libraries.length})`} 
                          defaultCollapsed={true}
                        >
                          <div className="imports-container">
                            {libraries.map((lib: string, index: number) => (
                              <code key={index} className="import-function">{lib}</code>
                            ))}
                          </div>
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Symbols */}
                {sample.elf_symbols && (() => {
                  try {
                    const symbols = JSON.parse(sample.elf_symbols);
                    if (symbols.length > 0) {
                      return (
                        <CollapsibleSection 
                          title={`Symbols (${sample.elf_symbol_count || symbols.length}${sample.elf_symbol_count && sample.elf_symbol_count >= 500 ? '+' : ''})`} 
                          defaultCollapsed={true}
                        >
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Name</th>
                                  <th>Value</th>
                                  <th>Size</th>
                                  <th>Type</th>
                                  <th>Binding</th>
                                  <th>Section</th>
                                </tr>
                              </thead>
                              <tbody>
                                {symbols.map((symbol: any, index: number) => (
                                  <tr key={index}>
                                    <td><code>{symbol.name}</code></td>
                                    <td><code>{symbol.value}</code></td>
                                    <td>{symbol.size.toLocaleString()}</td>
                                    <td>{symbol.type}</td>
                                    <td>{symbol.binding}</td>
                                    <td>{symbol.section_index}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          {sample.elf_symbol_count && sample.elf_symbol_count >= 500 && (
                            <p className="note">Note: Showing first 500 symbols only</p>
                          )}
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Relocations */}
                {sample.elf_relocations && (() => {
                  try {
                    const relocations = JSON.parse(sample.elf_relocations);
                    if (relocations.length > 0) {
                      return (
                        <CollapsibleSection 
                          title={`Relocations (${sample.elf_relocation_count || relocations.length}${sample.elf_relocation_count && sample.elf_relocation_count >= 200 ? '+' : ''})`} 
                          defaultCollapsed={true}
                        >
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Offset</th>
                                  <th>Info</th>
                                  <th>Type</th>
                                </tr>
                              </thead>
                              <tbody>
                                {relocations.map((reloc: any, index: number) => (
                                  <tr key={index}>
                                    <td><code>{reloc.offset}</code></td>
                                    <td><code>{reloc.info}</code></td>
                                    <td>{reloc.type}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          {sample.elf_relocation_count && sample.elf_relocation_count >= 200 && (
                            <p className="note">Note: Showing first 200 relocations only</p>
                          )}
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Dynamic Tags */}
                {sample.elf_dynamic_tags && (() => {
                  try {
                    const dynamicTags = JSON.parse(sample.elf_dynamic_tags);
                    if (dynamicTags.length > 0) {
                      return (
                        <CollapsibleSection title={`Dynamic Tags (${dynamicTags.length})`} defaultCollapsed={true}>
                          <div className="table-container">
                            <table className="pe-sections-table">
                              <thead>
                                <tr>
                                  <th>Tag</th>
                                  <th>Value</th>
                                </tr>
                              </thead>
                              <tbody>
                                {dynamicTags.map((tag: any, index: number) => (
                                  <tr key={index}>
                                    <td>{tag.tag}</td>
                                    <td><code>{tag.value}</code></td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </CollapsibleSection>
                      );
                    }
                    return null;
                  } catch (e) {
                    return null;
                  }
                })()}

                {/* Show message if no ELF data available */}
                {!sample.elf_sections && !sample.elf_machine && !sample.elf_entry_point && (
                  <p>No ELF analysis data available for this sample.</p>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Relations Tab Content */}
      {activeTab === 'relations' && (
        <div className="relations-tab">
          <div className="detail-grid">
            
            {/* Source URL Section */}
            {sample.source_url && (
              <div className="detail-section full-width">
                <h3>Source Information</h3>
                <div className="info-grid">
                  <div className="info-row">
                    <span className="label">Downloaded from URL:</span>
                    <a 
                      href={sample.source_url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="source-url"
                    >
                      {sample.source_url}
                    </a>
                  </div>
                </div>
              </div>
            )}

            {/* Parent Archive Section */}
            {sample.parent_archive_sha512 && relatedSamples.parentArchive && (
              <div className="detail-section full-width">
                <h3>Parent Archive</h3>
                <div className="info-grid">
                  <div className="info-row">
                    <span className="label">This file was extracted from:</span>
                  </div>
                  <div className="related-sample-card">
                    <div className="sample-info">
                      <div className="sample-filename">
                        {relatedSamples.parentArchive.filename}
                      </div>
                      <div className="sample-hashes">
                        <div><strong>SHA256:</strong> <code>{relatedSamples.parentArchive.sha256}</code></div>
                        <div><strong>MD5:</strong> <code>{relatedSamples.parentArchive.md5}</code></div>
                      </div>
                      <div className="sample-meta">
                        <span className={`type-badge type-${relatedSamples.parentArchive.file_type}`}>
                          {relatedSamples.parentArchive.file_type.toUpperCase()}
                        </span>
                        <span>{formatSize(relatedSamples.parentArchive.file_size)}</span>
                      </div>
                    </div>
                    <button 
                      className="btn btn-primary"
                      onClick={() => navigate(`/samples/${relatedSamples.parentArchive!.sha512}`)}
                    >
                      View Archive
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Extracted Files Section */}
            {sample.is_archive === 'true' && relatedSamples.extractedFiles && relatedSamples.extractedFiles.length > 0 && (
              <div className="detail-section full-width">
                <h3>Extracted Files ({relatedSamples.extractedFiles.length})</h3>
                <div className="extracted-files-container">
                  {relatedSamples.extractedFiles.map((extractedFile) => (
                    <div key={extractedFile.sha512} className="related-sample-card">
                      <div className="sample-info">
                        <div className="sample-filename">
                          {extractedFile.filename}
                        </div>
                        <div className="sample-hashes">
                          <div><strong>SHA256:</strong> <code>{extractedFile.sha256}</code></div>
                          <div><strong>MD5:</strong> <code>{extractedFile.md5}</code></div>
                        </div>
                        <div className="sample-meta">
                          <span className={`type-badge type-${extractedFile.file_type}`}>
                            {extractedFile.file_type.toUpperCase()}
                          </span>
                          <span>{formatSize(extractedFile.file_size)}</span>
                          {extractedFile.entropy && (
                            <span>Entropy: {extractedFile.entropy}</span>
                          )}
                        </div>
                      </div>
                      <button 
                        className="btn btn-primary"
                        onClick={() => navigate(`/samples/${extractedFile.sha512}`)}
                      >
                        View Sample
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* No Relations Message */}
            {!sample.source_url && !sample.parent_archive_sha512 && sample.is_archive !== 'true' && (
              <div className="detail-section full-width">
                <p className="no-relations-message">No relationship information available for this sample.</p>
              </div>
            )}

            {/* Archive with no extracted files */}
            {sample.is_archive === 'true' && (!relatedSamples.extractedFiles || relatedSamples.extractedFiles.length === 0) && (
              <div className="detail-section full-width">
                <p className="no-relations-message">This archive has no extracted files stored in the database.</p>
              </div>
            )}

          </div>
        </div>
      )}
    </div>
  );
};

export default SampleDetail;
