import React from 'react';
import { FaSearch } from 'react-icons/fa';
import './SearchBar.css';

interface SearchBarProps {
  value: string;
  onChange: (value: string) => void;
  onSearch: () => void;
  placeholder?: string;
  className?: string;
}

const SearchBar: React.FC<SearchBarProps> = ({
  value,
  onChange,
  onSearch,
  placeholder = 'Search...',
  className = '',
}) => {
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      onSearch();
    }
  };

  return (
    <div className={`search-bar ${className}`}>
      <FaSearch className="search-icon" />
      <input
        type="text"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyPress={handleKeyPress}
      />
      <button className="search-btn" onClick={onSearch}>
        Search
      </button>
    </div>
  );
};

export default SearchBar;
