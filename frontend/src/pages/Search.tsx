import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FaSearch, FaInfoCircle, FaTimes, FaSpinner, FaExternalLinkAlt } from 'react-icons/fa';
import { searchSamples, getSearchFields } from '../services/api';
import './Search.css';

interface SearchResult {
  sha512: string;
  sha256: string;
  filename: string;
  file_size: number;
  file_type: string;
  mime_type?: string;
  family?: string;
  classification?: string;
  tags: string[];
  entropy?: string;
  first_seen?: string;
  analysis_status?: string;
  has_pe_analysis: boolean;
  has_elf_analysis: boolean;
  has_capa_analysis: boolean;
  has_magika_analysis: boolean;
  has_vt_analysis: boolean;
  has_strings_analysis: boolean;
  pe?: {
    imphash?: string;
    machine?: string;
    subsystem?: string;
    is_signed?: boolean;
  };
  vt?: {
    positives?: number;
    total?: number;
    detection_ratio?: string;
  };
}

interface SearchResponse {
  query: string;
  total: number;
  limit: number;
  offset: number;
  results: SearchResult[];
}

interface FieldInfo {
  type: string;
  description: string;
  values?: string[];
}

interface FieldsResponse {
  fields: Record<string, Record<string, FieldInfo>>;
  operators: string[];
  logical_operators: string[];
  examples: string[];
}

const Search: React.FC = () => {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [searchResults, setSearchResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [fieldsInfo, setFieldsInfo] = useState<FieldsResponse | null>(null);

  const exampleQueries = [
    'file_type=pe AND pe.is_signed=false',
    'vt.positives>10 AND file_size<1000000',
    'filename LIKE "trojan" OR family="emotet"',
    'magika.label=pe AND capa.total_capabilities>50',
    'strings.url_count>0 AND strings.ip_count>5',
    'file_type=elf AND elf.machine="x86-64"',
    'analysis_status=completed',
    'tags CONTAINS "ransomware"',
  ];

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!query.trim()) {
      setError('Please enter a search query');
      return;
    }

    setLoading(true);
    setError(null);
    setSearchResults(null);

    try {
      const results = await searchSamples(query);
      setSearchResults(results);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Search failed. Please check your query syntax.');
    } finally {
      setLoading(false);
    }
  };

  const loadFieldsInfo = async () => {
    if (fieldsInfo) return; // Already loaded
    
    try {
      const fields = await getSearchFields();
      setFieldsInfo(fields);
    } catch (err) {
      console.error('Failed to load fields info:', err);
    }
  };

  const toggleHelp = () => {
    if (!showHelp) {
      loadFieldsInfo();
    }
    setShowHelp(!showHelp);
  };

  const setExampleQuery = (exampleQuery: string) => {
    setQuery(exampleQuery);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  const handleResultClick = (sha512: string, e: React.MouseEvent) => {
    // Check if middle click or ctrl/cmd + click for new tab
    if (e.button === 1 || e.ctrlKey || e.metaKey) {
      window.open(`/samples/${sha512}`, '_blank');
      e.preventDefault();
    } else {
      navigate(`/samples/${sha512}`);
    }
  };

  return (
    <div className="search-container">
      <div className="search-header">
        <h1>Search Samples</h1>
        <p className="search-subtitle">Use advanced query syntax to search samples and analyzer results</p>
      </div>

      <div className="search-bar-container">
        <form onSubmit={handleSearch} className="search-form">
          <div className="search-input-wrapper">
            <FaSearch className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder='e.g., file_type=pe AND vt.positives>10'
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              disabled={loading}
            />
            {query && (
              <button
                type="button"
                className="clear-button"
                onClick={() => setQuery('')}
                disabled={loading}
              >
                <FaTimes />
              </button>
            )}
          </div>
          <button type="submit" className="search-button" disabled={loading}>
            {loading ? (
              <>
                <FaSpinner className="spinner" />
                Searching...
              </>
            ) : (
              <>
                <FaSearch />
                Search
              </>
            )}
          </button>
          <button
            type="button"
            className="help-button"
            onClick={toggleHelp}
          >
            <FaInfoCircle />
            {showHelp ? 'Hide Help' : 'Show Help'}
          </button>
        </form>
      </div>

      {showHelp && (
        <div className="help-panel">
          <h3>Search Syntax</h3>
          <div className="help-content">
            <div className="help-section">
              <h4>Operators</h4>
              <ul>
                <li><code>=</code> - Exact match</li>
                <li><code>!=</code> - Not equal</li>
                <li><code>&gt;</code>, <code>&lt;</code>, <code>&gt;=</code>, <code>&lt;=</code> - Numeric comparison</li>
                <li><code>LIKE</code> - Pattern matching (e.g., <code>filename LIKE "malware"</code>)</li>
                <li><code>CONTAINS</code> - Contains text (for JSON/text fields)</li>
                <li><code>AND</code>, <code>OR</code> - Logical operators</li>
              </ul>
            </div>

            <div className="help-section">
              <h4>Common Fields</h4>
              <div className="fields-grid">
                <div className="field-category">
                  <h5>Sample Fields</h5>
                  <ul>
                    <li><code>filename</code> - Filename</li>
                    <li><code>file_type</code> - Type (pe, elf, etc.)</li>
                    <li><code>file_size</code> - Size in bytes</li>
                    <li><code>family</code> - Malware family</li>
                    <li><code>tags</code> - Tags</li>
                    <li><code>sha256</code>, <code>md5</code> - Hashes</li>
                  </ul>
                </div>
                <div className="field-category">
                  <h5>PE Fields</h5>
                  <ul>
                    <li><code>pe.imphash</code> - Import hash</li>
                    <li><code>pe.machine</code> - Machine type</li>
                    <li><code>pe.is_signed</code> - Signed (true/false)</li>
                    <li><code>pe.import_dll_count</code> - DLL count</li>
                  </ul>
                </div>
                <div className="field-category">
                  <h5>VirusTotal Fields</h5>
                  <ul>
                    <li><code>vt.positives</code> - Detections</li>
                    <li><code>vt.total</code> - Total scanners</li>
                    <li><code>vt.detection_ratio</code> - Ratio</li>
                  </ul>
                </div>
                <div className="field-category">
                  <h5>Other Analyzers</h5>
                  <ul>
                    <li><code>capa.total_capabilities</code> - CAPA capabilities</li>
                    <li><code>strings.url_count</code> - URL count</li>
                    <li><code>magika.label</code> - File type label</li>
                    <li><code>elf.machine</code> - ELF architecture</li>
                  </ul>
                </div>
              </div>
            </div>

            <div className="help-section">
              <h4>Example Queries</h4>
              <div className="examples-list">
                {exampleQueries.map((example, idx) => (
                  <div key={idx} className="example-item">
                    <code>{example}</code>
                    <button
                      className="use-example-button"
                      onClick={() => setExampleQuery(example)}
                    >
                      Use
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="error-message">
          <strong>Error:</strong> {error}
        </div>
      )}

      {searchResults && (
        <div className="search-results">
          <div className="results-header">
            <h2>Results</h2>
            <div className="results-stats">
              Found <strong>{searchResults.total}</strong> samples
              {searchResults.total > searchResults.results.length && (
                <span className="results-showing">
                  {' '}(showing {searchResults.results.length})
                </span>
              )}
            </div>
          </div>

          {searchResults.results.length === 0 ? (
            <div className="no-results">
              <p>No samples found matching your query.</p>
            </div>
          ) : (
            <div className="results-table-wrapper">
              <table className="results-table">
                <thead>
                  <tr>
                    <th>Filename</th>
                    <th>SHA256</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Family</th>
                    <th>Status</th>
                    <th>Analyzers</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {searchResults.results.map((result) => (
                    <tr
                      key={result.sha512}
                      onClick={(e) => handleResultClick(result.sha512, e)}
                      onAuxClick={(e) => {
                        if (e.button === 1) {
                          window.open(`/samples/${result.sha512}`, '_blank');
                          e.preventDefault();
                        }
                      }}
                      className="result-row"
                    >
                      <td className="filename-cell">
                        <div className="filename">{result.filename}</div>
                        {result.tags.length > 0 && (
                          <div className="tags">
                            {result.tags.map((tag, idx) => (
                              <span key={idx} className="tag">
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="hash-cell">
                        <code>{result.sha256.substring(0, 16)}...</code>
                      </td>
                      <td>
                        <span className={`file-type-badge ${result.file_type}`}>
                          {result.file_type.toUpperCase()}
                        </span>
                      </td>
                      <td>{formatFileSize(result.file_size)}</td>
                      <td>{result.family || '-'}</td>
                      <td>
                        <span className={`status-badge ${result.analysis_status}`}>
                          {result.analysis_status || 'pending'}
                        </span>
                      </td>
                      <td>
                        <div className="analyzer-badges">
                          {result.has_pe_analysis && (
                            <span className="analyzer-badge pe">PE</span>
                          )}
                          {result.has_elf_analysis && (
                            <span className="analyzer-badge elf">ELF</span>
                          )}
                          {result.has_capa_analysis && (
                            <span className="analyzer-badge capa">CAPA</span>
                          )}
                          {result.has_vt_analysis && (
                            <span className="analyzer-badge vt">VT</span>
                          )}
                          {result.has_strings_analysis && (
                            <span className="analyzer-badge strings">STR</span>
                          )}
                          {result.has_magika_analysis && (
                            <span className="analyzer-badge magika">MAG</span>
                          )}
                        </div>
                      </td>
                      <td className="actions-cell">
                        <button
                          className="action-button"
                          onClick={(e) => {
                            e.stopPropagation();
                            window.open(`/samples/${result.sha512}`, '_blank');
                          }}
                          title="Open in new tab"
                        >
                          <FaExternalLinkAlt />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default Search;
