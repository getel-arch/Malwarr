import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { malwarrApi, getCapaExplorerStatus } from '../services/api';
import './CapaExplorer.css';

const CapaExplorer: React.FC = () => {
  const { sha512 } = useParams<{ sha512: string }>();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [capaData, setCapaData] = useState<any>(null);
  const [useLocalExplorer, setUseLocalExplorer] = useState(false);
  const [explorerUrl, setExplorerUrl] = useState<string>('');
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    checkExplorerAndLoadData();
  }, [sha512]);

  const checkExplorerAndLoadData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Check if local CAPA Explorer is installed
      const status = await getCapaExplorerStatus();
      
      // Always use the wrapped version for best auto-loading experience
      setUseLocalExplorer(true);
      setExplorerUrl(`/api/v1/samples/${sha512}/capa/explorer-wrapped`);
      setLoading(false);
      
    } catch (error) {
      console.error('Failed to load CAPA Explorer:', error);
      setError('Failed to load CAPA Explorer. Please try again.');
      setLoading(false);
    }
  };

  const loadCapaDataForRemoteExplorer = async () => {
    try {
      const response = await fetch(`/api/v1/samples/${sha512}/capa/document`);
      
      if (!response.ok) {
        if (response.status === 404) {
          setError('CAPA analysis not available for this sample');
        } else {
          setError('Failed to load CAPA analysis');
        }
        setLoading(false);
        return;
      }
      
      const data = await response.json();
      setCapaData(data);
      setExplorerUrl('https://mandiant.github.io/capa/explorer/');
      setLoading(false);
      
      // Try to automatically pass data to iframe once it loads
      setupIframeMessagePassing(data);
    } catch (err: any) {
      console.error('Failed to load CAPA data:', err);
      setError('Failed to load CAPA analysis data');
      setLoading(false);
    }
  };

  // Setup automatic data passing to iframe for remote CAPA Explorer
  const setupIframeMessagePassing = (data: any) => {
    const attemptDataTransfer = () => {
      if (iframeRef.current && iframeRef.current.contentWindow) {
        try {
          // Try to pass data via postMessage
          iframeRef.current.contentWindow.postMessage(
            {
              type: 'LOAD_CAPA_DATA',
              data: data
            },
            'https://mandiant.github.io'
          );
          console.log('[Malwarr] Sent CAPA data to iframe via postMessage');
        } catch (e) {
          console.warn('[Malwarr] Failed to send data via postMessage:', e);
        }
      }
    };

    // Try immediately and also after iframe loads
    if (iframeRef.current) {
      iframeRef.current.addEventListener('load', () => {
        // Give the iframe app time to initialize
        setTimeout(attemptDataTransfer, 500);
        setTimeout(attemptDataTransfer, 1500);
        setTimeout(attemptDataTransfer, 3000);
      });
    }
  };

  const handleBackClick = () => {
    navigate(`/samples/${sha512}`);
  };

  const handleDownloadJson = async () => {
    try {
      const response = await fetch(`/api/v1/samples/${sha512}/capa/document`);
      if (response.ok) {
        const data = await response.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `capa-${sha512}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Failed to download JSON:', error);
      alert('Failed to download JSON data');
    }
  };

  if (loading) {
    return (
      <div className="capa-explorer-container">
        <div className="loading">Loading CAPA Explorer...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="capa-explorer-container">
        <div className="error-container">
          <h2>Error</h2>
          <p>{error}</p>
          <button className="btn btn-primary" onClick={handleBackClick}>
            Back to Sample Details
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="capa-explorer-container">
      <div className="explorer-header">
        <button className="btn btn-secondary" onClick={handleBackClick}>
          ← Back to Sample
        </button>
        <h2>CAPA Explorer - {useLocalExplorer ? 'Local' : 'Remote'}</h2>
        <button className="btn btn-primary" onClick={handleDownloadJson}>
          Download JSON
        </button>
      </div>
      <div className="explorer-info">
        <p>
          <strong>CAPA Explorer</strong> with <strong>automatic JSON loading</strong>. 
          The analysis results are being automatically injected into CAPA Explorer.
          {' '}Please wait a moment for the data to load.
        </p>
        <p className="info-note">
          <strong>Note:</strong> The JSON data is available in <code>window.CAPA_DATA</code> if manual loading is needed.
          You can also download the JSON file separately using the button above.
        </p>
      </div>
      <iframe
        ref={iframeRef}
        id="capa-iframe"
        src={explorerUrl}
        title="CAPA Explorer"
        className="capa-iframe"
        sandbox="allow-scripts allow-same-origin allow-popups allow-forms"
      />
    </div>
  );
};

export default CapaExplorer;
