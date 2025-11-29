import React, { useState, useEffect } from 'react';
import { FaSave, FaKey, FaDownload, FaUpload, FaTrash, FaSync, FaCogs, FaInfo, FaNetworkWired } from 'react-icons/fa';
import { useApp } from '../contexts/AppContext';
import { 
  setApiKey, 
  getCapaRulesStatus, 
  downloadCapaRules, 
  uploadCapaRules, 
  deleteCapaRules,
  getCapaExplorerStatus,
  downloadCapaExplorer,
  deleteCapaExplorer
} from '../services/api';
import './Settings.css';

type MainTab = 'api' | 'analyzers' | 'about' | 'endpoints';
type AnalyzerTab = 'capa';

const Settings: React.FC = () => {
  const { appName, version } = useApp();
  const [mainTab, setMainTab] = useState<MainTab>('api');
  const [analyzerTab, setAnalyzerTab] = useState<AnalyzerTab>('capa');
  const [apiKey, setApiKeyState] = useState('');
  const [saved, setSaved] = useState(false);
  
  // CAPA Rules state
  const [capaRulesStatus, setCapaRulesStatus] = useState<any>(null);
  const [capaLoading, setCapaLoading] = useState(false);
  const [capaMessage, setCapaMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  
  // CAPA Explorer state
  const [capaExplorerStatus, setCapaExplorerStatus] = useState<any>(null);
  const [explorerLoading, setExplorerLoading] = useState(false);
  const [explorerMessage, setExplorerMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    const stored = localStorage.getItem('malwarr_api_key');
    if (stored) {
      setApiKeyState(stored);
    }
    
    // Load CAPA rules and explorer status
    loadCapaRulesStatus();
    loadCapaExplorerStatus();
  }, []);

  const loadCapaRulesStatus = async () => {
    try {
      const status = await getCapaRulesStatus();
      setCapaRulesStatus(status);
    } catch (error) {
      console.error('Failed to load CAPA rules status:', error);
    }
  };
  
  const loadCapaExplorerStatus = async () => {
    try {
      const status = await getCapaExplorerStatus();
      setCapaExplorerStatus(status);
    } catch (error) {
      console.error('Failed to load CAPA explorer status:', error);
    }
  };

  const handleSave = () => {
    setApiKey(apiKey);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleDownloadRules = async () => {
    setCapaLoading(true);
    setCapaMessage(null);
    
    try {
      const result = await downloadCapaRules('latest');
      setCapaMessage({ type: 'success', text: `Successfully downloaded ${result.rules_count} rules (version: ${result.version})` });
      await loadCapaRulesStatus();
    } catch (error: any) {
      setCapaMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to download rules' });
    } finally {
      setCapaLoading(false);
    }
  };

  const handleUploadRules = async () => {
    if (!uploadFile) {
      setCapaMessage({ type: 'error', text: 'Please select a ZIP file' });
      return;
    }

    setCapaLoading(true);
    setCapaMessage(null);

    try {
      const result = await uploadCapaRules(uploadFile);
      setCapaMessage({ type: 'success', text: `Successfully uploaded ${result.rules_count} rules` });
      setUploadFile(null);
      await loadCapaRulesStatus();
    } catch (error: any) {
      setCapaMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to upload rules' });
    } finally {
      setCapaLoading(false);
    }
  };

  const handleDeleteRules = async () => {
    if (!window.confirm('Are you sure you want to delete all CAPA rules?')) {
      return;
    }

    setCapaLoading(true);
    setCapaMessage(null);

    try {
      await deleteCapaRules();
      setCapaMessage({ type: 'success', text: 'Rules deleted successfully' });
      await loadCapaRulesStatus();
    } catch (error: any) {
      setCapaMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to delete rules' });
    } finally {
      setCapaLoading(false);
    }
  };
  
  const handleDownloadExplorer = async () => {
    setExplorerLoading(true);
    setExplorerMessage(null);
    
    try {
      const result = await downloadCapaExplorer('latest');
      setExplorerMessage({ type: 'success', text: `Successfully downloaded CAPA Explorer (version: ${result.version})` });
      await loadCapaExplorerStatus();
    } catch (error: any) {
      setExplorerMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to download explorer' });
    } finally {
      setExplorerLoading(false);
    }
  };

  const handleDeleteExplorer = async () => {
    if (!window.confirm('Are you sure you want to delete the CAPA Explorer?')) {
      return;
    }

    setExplorerLoading(true);
    setExplorerMessage(null);

    try {
      await deleteCapaExplorer();
      setExplorerMessage({ type: 'success', text: 'Explorer deleted successfully' });
      await loadCapaExplorerStatus();
    } catch (error: any) {
      setExplorerMessage({ type: 'error', text: error.response?.data?.detail || 'Failed to delete explorer' });
    } finally {
      setExplorerLoading(false);
    }
  };

  return (
    <div className="settings-page">
      <div className="settings-tabs">
        <button 
          className={`tab-button ${mainTab === 'api' ? 'active' : ''}`}
          onClick={() => setMainTab('api')}
        >
          <FaKey /> API Configuration
        </button>
        <button 
          className={`tab-button ${mainTab === 'analyzers' ? 'active' : ''}`}
          onClick={() => setMainTab('analyzers')}
        >
          <FaCogs /> Analyzers
        </button>
        <button 
          className={`tab-button ${mainTab === 'about' ? 'active' : ''}`}
          onClick={() => setMainTab('about')}
        >
          <FaInfo /> About
        </button>
        <button 
          className={`tab-button ${mainTab === 'endpoints' ? 'active' : ''}`}
          onClick={() => setMainTab('endpoints')}
        >
          <FaNetworkWired /> API Endpoints
        </button>
      </div>

      <div className="settings-container">
        {mainTab === 'api' && (
          <div className="settings-section">
            <h2>
              <FaKey /> API Configuration
            </h2>
            <p className="section-description">
              Set your API key to enable protected operations like uploading, downloading, and deleting samples.
            </p>

            <div className="form-group">
              <label>API Key</label>
              <input
                type="password"
                placeholder="Enter your API key"
                value={apiKey}
                onChange={(e) => setApiKeyState(e.target.value)}
              />
              <small>You can find your API key in the .env file on the server.</small>
            </div>

            <button className="btn btn-primary" onClick={handleSave}>
              <FaSave /> Save Settings
            </button>

            {saved && (
              <div className="success-message">
                ✓ Settings saved successfully!
              </div>
            )}
          </div>
        )}

        {mainTab === 'analyzers' && (
          <>
            <div className="analyzer-tabs">
              <button 
                className={`analyzer-tab-button ${analyzerTab === 'capa' ? 'active' : ''}`}
                onClick={() => setAnalyzerTab('capa')}
              >
                CAPA
              </button>
            </div>

            {analyzerTab === 'capa' && (
              <div className="settings-section">
                <h2>
                  <FaCogs /> CAPA Analyzer
                </h2>
                <p className="section-description">
                  Manage CAPA (Capability Analysis) components for detecting malware capabilities.
                </p>

                {/* CAPA Rules Section */}
                <div className="capa-subsection">
              <h3 className="subsection-title">Rules</h3>
              
              {capaRulesStatus && (
                <div className="capa-status">
                  <div className="status-grid">
                    <div className="status-item">
                      <span className="label">Rules Installed:</span>
                      <span className={capaRulesStatus.installed ? 'status-yes' : 'status-no'}>
                        {capaRulesStatus.installed ? '✓ Yes' : '✗ No'}
                      </span>
                    </div>
                    <div className="status-item">
                      <span className="label">Rules Count:</span>
                      <span>{capaRulesStatus.rules_count}</span>
                    </div>
                    <div className="status-item">
                      <span className="label">Last Updated:</span>
                      <span>{capaRulesStatus.last_updated ? new Date(capaRulesStatus.last_updated).toLocaleString() : 'Never'}</span>
                    </div>
                    <div className="status-item">
                      <span className="label">Size:</span>
                      <span>{capaRulesStatus.size_mb} MB</span>
                    </div>
                  </div>
                </div>
              )}

              {capaMessage && (
                <div className={`message ${capaMessage.type === 'success' ? 'success-message' : 'error-message'}`}>
                  {capaMessage.type === 'success' ? '✓' : '✗'} {capaMessage.text}
                </div>
              )}

              <div className="capa-actions">
                <div className="action-group">
                  <h3>Download Rules</h3>
                  <p>Download the latest CAPA rules from GitHub (recommended)</p>
                  <button 
                    className="btn btn-primary" 
                    onClick={handleDownloadRules}
                    disabled={capaLoading}
                  >
                    <FaDownload /> {capaLoading ? 'Downloading...' : 'Download Latest Rules'}
                  </button>
                </div>

                <div className="action-group">
                  <h3>Upload Custom Rules</h3>
                  <p>Upload your own CAPA rules from a ZIP file</p>
                  <div className="upload-group">
                    <input
                      type="file"
                      accept=".zip"
                      onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                      disabled={capaLoading}
                    />
                    <button 
                      className="btn btn-secondary" 
                      onClick={handleUploadRules}
                      disabled={capaLoading || !uploadFile}
                    >
                      <FaUpload /> {capaLoading ? 'Uploading...' : 'Upload Rules'}
                    </button>
                  </div>
                </div>

                <div className="action-group">
                  <h3>Delete Rules</h3>
                  <p>Remove all installed CAPA rules</p>
                  <button 
                    className="btn btn-danger" 
                    onClick={handleDeleteRules}
                    disabled={capaLoading || !capaRulesStatus?.installed}
                  >
                    <FaTrash /> Delete All Rules
                  </button>
                </div>
              </div>
            </div>

            {/* CAPA Explorer Section */}
            <div className="capa-subsection">
              <h3 className="subsection-title">Explorer</h3>
              
              {capaExplorerStatus && (
                <div className="capa-status">
                  <div className="status-grid">
                    <div className="status-item">
                      <span className="label">Explorer Installed:</span>
                      <span className={capaExplorerStatus.installed ? 'status-yes' : 'status-no'}>
                        {capaExplorerStatus.installed ? '✓ Yes' : '✗ No'}
                      </span>
                    </div>
                    <div className="status-item">
                      <span className="label">Files Count:</span>
                      <span>{capaExplorerStatus.file_count}</span>
                    </div>
                    <div className="status-item">
                      <span className="label">Last Updated:</span>
                      <span>{capaExplorerStatus.last_updated ? new Date(capaExplorerStatus.last_updated).toLocaleString() : 'Never'}</span>
                    </div>
                    <div className="status-item">
                      <span className="label">Size:</span>
                      <span>{capaExplorerStatus.size_mb} MB</span>
                    </div>
                  </div>
                </div>
              )}

              {explorerMessage && (
                <div className={`message ${explorerMessage.type === 'success' ? 'success-message' : 'error-message'}`}>
                  {explorerMessage.type === 'success' ? '✓' : '✗'} {explorerMessage.text}
                </div>
              )}

              <div className="capa-actions">
                <div className="action-group">
                  <h3>Download Explorer</h3>
                  <p>Download the latest CAPA Explorer from GitHub (recommended for better UI/UX)</p>
                  <button 
                    className="btn btn-primary" 
                    onClick={handleDownloadExplorer}
                    disabled={explorerLoading}
                  >
                    <FaDownload /> {explorerLoading ? 'Downloading...' : 'Download CAPA Explorer'}
                  </button>
                </div>

                <div className="action-group">
                  <h3>Delete Explorer</h3>
                  <p>Remove the installed CAPA Explorer</p>
                  <button 
                    className="btn btn-danger" 
                    onClick={handleDeleteExplorer}
                    disabled={explorerLoading || !capaExplorerStatus?.installed}
                  >
                    <FaTrash /> Delete Explorer
                  </button>
                </div>
              </div>
            </div>
              </div>
            )}
          </>
        )}

        {mainTab === 'about' && (
          <div className="settings-section">
            <h2>About {appName}</h2>
            <div className="about-info">
              <div className="info-row">
                <span className="label">Version:</span>
                <span>{version}</span>
              </div>
              <div className="info-row">
                <span className="label">Description:</span>
                <span>Malware Repository Management System</span>
              </div>
              <div className="info-row">
                <span className="label">License:</span>
                <span>MIT</span>
              </div>
            </div>
          </div>
        )}

        {mainTab === 'endpoints' && (
          <div className="settings-section">
            <h2>API Endpoints</h2>
            <div className="endpoints-list">
              <div className="endpoint">
                <code>GET /api/v1/system</code>
                <span>System information</span>
              </div>
              <div className="endpoint">
                <code>GET /api/v1/samples</code>
                <span>List samples</span>
              </div>
              <div className="endpoint">
                <code>POST /api/v1/samples</code>
                <span>Upload sample (requires API key)</span>
              </div>
              <div className="endpoint">
                <code>GET /api/v1/samples/:sha512</code>
                <span>Get sample details</span>
              </div>
              <div className="endpoint">
                <code>GET /api/v1/samples/:sha512/download</code>
                <span>Download sample (requires API key)</span>
              </div>
              <div className="endpoint">
                <code>PATCH /api/v1/samples/:sha512</code>
                <span>Update sample (requires API key)</span>
              </div>
              <div className="endpoint">
                <code>DELETE /api/v1/samples/:sha512</code>
                <span>Delete sample (requires API key)</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Settings;
