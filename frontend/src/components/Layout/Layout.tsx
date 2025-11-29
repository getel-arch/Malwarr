import React, { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useApp } from '../../contexts/AppContext';
import Sidebar from './Sidebar';
import Header from './Header';
import './Layout.css';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();
  const { appName } = useApp();

  const getPageTitle = () => {
    const path = location.pathname;
    if (path === '/') return 'Dashboard';
    if (path === '/samples') return 'Samples';
    if (path.startsWith('/samples/')) return 'Sample Details';
    if (path === '/upload') return 'Upload Sample';
    if (path === '/settings') return 'Settings';
    return appName;
  };

  return (
    <div className="layout">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />
      <div className={`main-content ${sidebarCollapsed ? 'expanded' : ''}`}>
        <Header title={getPageTitle()} />
        <div className="page-content">
          {children}
        </div>
      </div>
    </div>
  );
};

export default Layout;
