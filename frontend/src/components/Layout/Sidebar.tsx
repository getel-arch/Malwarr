import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  FaHome, 
  FaBiohazard, 
  FaUpload, 
  FaCog, 
  FaBars,
  FaChartBar 
} from 'react-icons/fa';
import './Sidebar.css';

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ collapsed, onToggle }) => {
  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <div className="logo">
          <FaBiohazard className="logo-icon" />
          {!collapsed && <span className="logo-text">Malwarr</span>}
        </div>
        <button className="toggle-btn" onClick={onToggle}>
          <FaBars />
        </button>
      </div>

      <nav className="sidebar-nav">
        <NavLink 
          to="/" 
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          end
        >
          <FaHome className="nav-icon" />
          {!collapsed && <span>Dashboard</span>}
        </NavLink>

        <NavLink 
          to="/samples" 
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <FaBiohazard className="nav-icon" />
          {!collapsed && <span>Samples</span>}
        </NavLink>

        <NavLink 
          to="/upload" 
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <FaUpload className="nav-icon" />
          {!collapsed && <span>Upload</span>}
        </NavLink>

        <NavLink 
          to="/settings" 
          className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
        >
          <FaCog className="nav-icon" />
          {!collapsed && <span>Settings</span>}
        </NavLink>
      </nav>

      <div className="sidebar-footer">
        {!collapsed && (
          <div className="version-info">
            <small>Version 1.0.0</small>
          </div>
        )}
      </div>
    </div>
  );
};

export default Sidebar;
