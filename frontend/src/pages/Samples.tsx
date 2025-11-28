import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FaSearch, FaFilter, FaDownload } from 'react-icons/fa';
import { malwarrApi, MalwareSample } from '../services/api';
import './Samples.css';

const Samples: React.FC = () => {
  const [samples, setSamples] = useState<MalwareSample[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [fileTypeFilter, setFileTypeFilter] = useState('');
  const [familyFilter, setFamilyFilter] = useState('');

  useEffect(() => {
    loadSamples();
  }, [fileTypeFilter, familyFilter]);

  const loadSamples = async () => {
    try {
      setLoading(true);
      const data = await malwarrApi.getSamples({
        limit: 100,
        file_type: fileTypeFilter || undefined,
        family: familyFilter || undefined,
      });
      setSamples(data);
    } catch (error) {
      console.error('Failed to load samples:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      loadSamples();
      return;
    }

    try {
      setLoading(true);
      const results = await malwarrApi.searchSamples(searchQuery);
      setSamples(results);
    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <div className="samples-page">
      <div className="page-header">
        <div className="search-bar">
          <FaSearch className="search-icon" />
          <input
            type="text"
            placeholder="Search by hash, filename, or family..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          />
          <button className="search-btn" onClick={handleSearch}>Search</button>
        </div>

        <div className="filters">
          <FaFilter className="filter-icon" />
          <select value={fileTypeFilter} onChange={(e) => setFileTypeFilter(e.target.value)}>
            <option value="">All Types</option>
            <option value="pe">PE</option>
            <option value="elf">ELF</option>
            <option value="macho">Mach-O</option>
            <option value="script">Script</option>
            <option value="archive">Archive</option>
            <option value="document">Document</option>
            <option value="other">Other</option>
          </select>

          <input
            type="text"
            placeholder="Filter by family..."
            value={familyFilter}
            onChange={(e) => setFamilyFilter(e.target.value)}
          />
        </div>
      </div>

      {loading ? (
        <div className="loading">Loading samples...</div>
      ) : (
        <div className="samples-grid">
          {samples.map(sample => (
            <div key={sample.sha512} className="sample-card">
              <div className="sample-header">
                <span className={`type-badge type-${sample.file_type}`}>
                  {sample.file_type.toUpperCase()}
                </span>
                <span className="sample-size">{formatSize(sample.file_size)}</span>
              </div>

              <div className="sample-body">
                <h3 className="sample-filename">
                  <Link to={`/samples/${sample.sha512}`}>{sample.filename}</Link>
                </h3>

                {sample.family && (
                  <div className="sample-family">
                    <strong>Family:</strong> {sample.family}
                  </div>
                )}

                <div className="sample-hashes">
                  <div className="hash-row">
                    <span className="hash-label">SHA256:</span>
                    <code>{sample.sha256.substring(0, 32)}...</code>
                  </div>
                  <div className="hash-row">
                    <span className="hash-label">MD5:</span>
                    <code>{sample.md5}</code>
                  </div>
                </div>

                {sample.tags && Array.isArray(sample.tags) && sample.tags.length > 0 && (
                  <div className="sample-tags">
                    {sample.tags.map((tag: string) => (
                      <span key={tag} className="tag">{tag}</span>
                    ))}
                  </div>
                )}
              </div>

              <div className="sample-footer">
                <span className="upload-date">
                  {new Date(sample.upload_date).toLocaleDateString()}
                </span>
                <Link to={`/samples/${sample.sha512}`} className="view-btn">
                  View Details
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}

      {!loading && samples.length === 0 && (
        <div className="no-results">
          <p>No samples found.</p>
          <Link to="/upload" className="upload-link">Upload a sample</Link>
        </div>
      )}
    </div>
  );
};

export default Samples;
