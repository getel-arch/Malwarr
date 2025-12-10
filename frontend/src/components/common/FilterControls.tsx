import React, { ReactNode } from 'react';
import { FaFilter } from 'react-icons/fa';
import './FilterControls.css';

interface FilterControlsProps {
  children: ReactNode;
  className?: string;
}

const FilterControls: React.FC<FilterControlsProps> = ({ 
  children, 
  className = '' 
}) => {
  return (
    <div className={`filter-controls ${className}`}>
      <FaFilter className="filter-icon" />
      {children}
    </div>
  );
};

export default FilterControls;
