import React from 'react';

export const ThreatBadge = ({ risk, size = 'md' }) => {
  const normRisk = String(risk || 'Unknown').trim();

  let styles = 'bg-slate-800/80 text-slate-300 border-slate-700/80';
  let dotColor = 'bg-slate-400';

  if (normRisk === 'High' || normRisk === 'High Risk') {
    styles = 'bg-red-500/10 text-red-400 border-red-500/30 shadow-sm shadow-red-950/40';
    dotColor = 'bg-red-400 animate-pulse';
  } else if (normRisk === 'Medium' || normRisk === 'Suspicious') {
    styles = 'bg-amber-500/10 text-amber-400 border-amber-500/30 shadow-sm shadow-amber-950/40';
    dotColor = 'bg-amber-400 animate-pulse';
  } else if (normRisk === 'Low' || normRisk === 'Safe') {
    styles = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-sm shadow-emerald-950/40';
    dotColor = 'bg-emerald-400';
  }

  const padding = size === 'sm' ? 'py-0.5 px-2 text-[11px]' : 'py-1 px-3 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono font-semibold border rounded-full ${styles} ${padding}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      {normRisk}
    </span>
  );
};

export default ThreatBadge;
