import React from 'react';
import './ElectricBorder.css';

export const ElectricBorder = ({
  children,
  color = '#3b82f6',
  glowColor = '#60a5fa',
  className = '',
  style = {},
}) => {
  return (
    <div
      className={`electric-border ${className}`}
      style={{
        '--electric-border-color': color,
        '--electric-light-color': glowColor,
        ...style,
      }}
    >
      <div className="eb-layers">
        <div className="eb-glow-outer" />
        <div className="eb-glow-border" />
      </div>
      <div className="eb-content">
        {children}
      </div>
    </div>
  );
};

export default ElectricBorder;
