import React from 'react';
import './Header.css';

interface HeaderProps {
  title: string;
}

const Header: React.FC<HeaderProps> = ({ title }) => {
  return (
    <header className="header">
      <div className="header-content">
        <h1 className="page-title">{title}</h1>
        <div className="header-actions">
          {/* Future: Add search, notifications, user menu */}
        </div>
      </div>
    </header>
  );
};

export default Header;
