import React from 'react';

export const RiskBadge = ({ risk, size = 'md' }) => {
  const normRisk = String(risk || 'Unknown').trim();

  let colors = 'bg-slate-700/60 text-slate-300 border-slate-600';
  if (normRisk === 'High' || normRisk === 'High Risk') {
    colors = 'bg-red-500/15 text-red-400 border-red-500/30';
  } else if (normRisk === 'Medium' || normRisk === 'Suspicious') {
    colors = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
  } else if (normRisk === 'Low' || normRisk === 'Safe') {
    colors = 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
  }

  const py = size === 'sm' ? 'py-0.5 px-2 text-xs' : 'py-1 px-3 text-sm';

  return (
    <span className={`inline-flex items-center font-semibold border rounded-full ${colors} ${py}`}>
      {normRisk}
    </span>
  );
};

export default RiskBadge;
