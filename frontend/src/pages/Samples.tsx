import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useSamples } from '../hooks';
import { samplesService } from '../services';
import { MalwareSample } from '../types';
import { SearchBar, LoadingSpinner, FilterControls } from '../components/common';
import { formatSize, formatHash } from '../utils';
import { FILE_TYPES } from '../constants';
import './Samples.css';

const Samples: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');
  const [fileTypeFilter, setFileTypeFilter] = useState(searchParams.get('type') || '');
  const [familyFilter, setFamilyFilter] = useState(searchParams.get('family') || '');
  const [searchResults, setSearchResults] = useState<MalwareSample[] | null>(null);
  const [searching, setSearching] = useState(false);

  const { samples, loading, refetch } = useSamples({
    limit: 100,
    file_type: fileTypeFilter || undefined,
    family: familyFilter || undefined,
    autoLoad: !searchResults,
  });

  const displaySamples = searchResults || samples;

  const updateUrlParams = (query: string, type: string, family: string) => {
    const params = new URLSearchParams();
    if (query) params.set('q', query);
    if (type) params.set('type', type);
    if (family) params.set('family', family);
    setSearchParams(params, { replace: true });
  };

  const handleSearchQueryChange = (value: string) => {
    setSearchQuery(value);
    updateUrlParams(value, fileTypeFilter, familyFilter);
  };

  const handleFileTypeChange = (value: string) => {
    setFileTypeFilter(value);
    updateUrlParams(searchQuery, value, familyFilter);
  };

  const handleFamilyFilterChange = (value: string) => {
    setFamilyFilter(value);
    updateUrlParams(searchQuery, fileTypeFilter, value);
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      setSearchResults(null);
      refetch();
      return;
    }

    try {
      setSearching(true);
      const results = await samplesService.searchSamples(searchQuery);
      setSearchResults(results);
    } catch (error) {
      console.error('Search failed:', error);
    } finally {
      setSearching(false);
    }
  };

  useEffect(() => {
    if (!searchQuery) {
      setSearchResults(null);
    }
  }, [fileTypeFilter, familyFilter]);
  
  // Trigger search on mount if query param exists
  useEffect(() => {
    if (searchParams.get('q')) {
      handleSearch();
    }
  }, []);

  return (
    <div className="samples-page">
      <div className="page-header">
        <SearchBar
          value={searchQuery}
          onChange={handleSearchQueryChange}
          onSearch={handleSearch}
          placeholder="Search by hash, filename, or family..."
        />

        <FilterControls>
          <select value={fileTypeFilter} onChange={(e) => handleFileTypeChange(e.target.value)}>
            {FILE_TYPES.map(type => (
              <option key={type.value} value={type.value}>{type.label}</option>
            ))}
          </select>

          <input
            type="text"
            placeholder="Filter by family..."
            value={familyFilter}
            onChange={(e) => handleFamilyFilterChange(e.target.value)}
          />
        </FilterControls>
      </div>

      {(loading || searching) ? (
        <LoadingSpinner message="Loading samples..." />
      ) : (
        <div className="samples-grid">
          {displaySamples.map(sample => (
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
                    <code>{formatHash(sample.sha256, 32)}</code>
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

      {!loading && !searching && displaySamples.length === 0 && (
        <div className="no-results">
          <p>No samples found.</p>
          <Link to="/upload" className="upload-link">Upload a sample</Link>
        </div>
      )}
    </div>
  );
};

export default Samples;
