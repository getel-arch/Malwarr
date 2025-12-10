import React, { ReactNode } from 'react';
import './StatCard.css';

interface StatCardProps {
  icon: ReactNode;
  label: string;
  value: string | number;
  className?: string;
}

const StatCard: React.FC<StatCardProps> = ({ 
  icon, 
  label, 
  value, 
  className = '' 
}) => {
  return (
    <div className={`stat-card ${className}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-content">
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
      </div>
    </div>
  );
};

export default StatCard;
